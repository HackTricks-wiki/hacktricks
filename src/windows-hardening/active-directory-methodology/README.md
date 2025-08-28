# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory**, ağ yöneticilerinin bir ağ içinde **domain**, **users** ve **objects** oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir şekilde tasarlanmış olup çok sayıda kullanıcıyı yönetilebilir **groups** ve **subgroups** içine organize etmeyi ve farklı seviyelerde **access rights** kontrol etmeyi mümkün kılar.

**Active Directory** yapısı üç ana katmandan oluşur: **domains**, **trees** ve **forests**. Bir **domain**, ortak bir veritabanını paylaşan **users** veya **devices** gibi nesnelerin koleksiyonunu kapsar. **Trees**, ortak bir yapıya bağlı domain gruplarıdır ve bir **forest**, birbirleriyle **trust relationships** aracılığıyla bağlı birden çok tree koleksiyonunu temsil ederek organizasyon yapısının en üst katmanını oluşturur. Her bir seviyede belirli **access** ve **communication rights** atanabilir.

Active Directory içindeki temel kavramlar şunlardır:

1. **Directory** – Active Directory nesneleri ile ilgili tüm bilgilerin tutulduğu yer.
2. **Object** – Directory içindeki varlıkları ifade eder; örneğin **users**, **groups** veya **shared folders**.
3. **Domain** – Directory nesneleri için bir kapsayıcıdır; bir **forest** içinde birden fazla domain bulunabilir ve her biri kendi nesne koleksiyonunu tutar.
4. **Tree** – Ortak bir root domain paylaşan domainlerin gruplandırılması.
5. **Forest** – Active Directory’de organizasyon yapısının zirvesi; birden fazla tree’den ve bunlar arasındaki **trust relationships**’ten oluşur.

**Active Directory Domain Services (AD DS)**, ağ içinde merkezi yönetim ve iletişim için kritik bir dizi hizmeti kapsar. Bu hizmetler şunlardır:

1. **Domain Services** – Verilerin merkezi depolanmasını sağlar ve **users** ile **domains** arasındaki etkileşimleri, **authentication** ve **search** fonksiyonları dahil olmak üzere yönetir.
2. **Certificate Services** – Güvenli **digital certificates** oluşturma, dağıtma ve yönetmeyi denetler.
3. **Lightweight Directory Services** – LDAP protokolü aracılığıyla directory-etkin uygulamaları destekler.
4. **Directory Federation Services** – Tek oturum açma (**single-sign-on**) yetenekleri sağlayarak kullanıcıların birden fazla web uygulamasında tek oturumda kimlik doğrulaması yapmasına olanak tanır.
5. **Rights Management** – Telif hakkı materyallerinin yetkisiz dağıtımını ve kullanımını kısıtlayarak korunmasına yardımcı olur.
6. **DNS Service** – **domain names** çözümü için kritik öneme sahiptir.

Daha ayrıntılı bilgi için bakınız: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir **AD**'yi nasıl atacığınızı öğrenmek için **Kerberos authentication process**'i gerçekten iyi **anlamanız** gerekir.\
[**Bu sayfayı hâlâ nasıl çalıştığını bilmiyorsanız okuyun.**](kerberos-authentication.md)

## Cheat Sheet

Hangi komutları kullanarak bir AD'yi enumerate/exploit edebileceğinize hızlıca bakmak için [https://wadcoms.github.io/](https://wadcoms.github.io) adresine göz atabilirsiniz.

> [!WARNING]
> Kerberos iletişimi eylemler için **tam nitelikli alan adı (FQDN)** gerektirir. Bir makineye IP adresiyle erişmeye çalışırsanız, **NTLM kullanılır ve Kerberos kullanılmaz**.

## Recon Active Directory (No creds/sessions)

Eğer bir AD ortamına erişiminiz var ama herhangi bir credentials/sessions yoksa, şunları yapabilirsiniz:

- **Pentest the network:**
- Ağı tarayın, makineleri ve açık portları bulun ve **zafiyetlerden yararlanmaya** veya bu makinelerden **kimlik bilgilerini elde etmeye** çalışın (örneğin, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS enumere etmek, domain içindeki web, printers, shares, vpn, media gibi kilit sunucular hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Daha fazla bilgi için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına bakın.
- **Check for null and Guest access on smb services** (modern Windows sürümlerinde bu çalışmayabilir):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB sunucusunu nasıl enumerate edeceğinize dair daha detaylı bir rehber şurada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'ı nasıl enumerate edeceğinize dair daha detaylı bir rehber şurada (özellikle anonymous access'a **dikkat**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder ile **impersonating services** yaparak kimlik bilgileri toplayın (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ile hostlara erişin
- Kötü amaçlı UPnP servisleri açarak **kimlik bilgilerini** toplayın (evil-S) (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- İç dokümanlar, sosyal medya, domain içindeki servisler (özellikle web) ve kamuya açık kaynaklardan kullanıcı adları/isimler çıkarın.
- Eğer şirket çalışanlarının tam isimlerini bulursanız, farklı AD **username conventions** deneyebilirsiniz ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın konvansiyonlar: _NameSurname_, _Name.Surname_, _NamSur_ (her iki isimden 3'er harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: Geçersiz bir username istendiğinde sunucu **Kerberos error** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile cevap vererek kullanıcının geçersiz olduğunu belirlememize izin verir. **Valid usernames** ya bir AS-REP içinde **TGT** döndürür ya da kullanıcının pre-authentication yapması gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını verir.
- **No Authentication against MS-NRPC**: Domain controller'larda MS-NRPC (Netlogon) arayüzüne auth-level = 1 (No authentication) kullanarak erişim. Yöntem, MS-NRPC arayüzüne bind ettikten sonra `DsrGetDcNameEx2` fonksiyonunu çağırarak herhangi bir credential olmadan kullanıcının veya bilgisayarın var olup olmadığını kontrol eder. Bu tür bir enumerasyonu uygulayan araç [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)'dir. Araştırma şu adreste bulunabilir: [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Sunucusu**

Ağda bu sunuculardan birini bulduysanız, ayrıca bunun üzerinde **user enumeration against it** gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Bir veya birkaç kullanıcı adını bilmek

Tamam, geçerli bir kullanıcı adına zaten sahip olduğunuzu biliyorsanız ama şifre yoksa... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Eğer bir kullanıcı **_DONT_REQ_PREAUTH_** özniteliğine **sahip değilse** o kullanıcı için **AS_REP message** talep edebilirsiniz; bu mesaj kullanıcı parolasından türetilen bir anahtarla şifrelenmiş bazı veriler içerir.
- [**Password Spraying**](password-spraying.md): Bulunan her kullanıcı için en yaygın şifreleri deneyin, belki bazı kullanıcılar zayıf bir şifre kullanıyordur (şifre politikasını unutmayın!).
- Not: ayrıca kullanıcıların posta sunucularına erişmeye çalışmak için **OWA sunucularını da spray** edebilirsiniz.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Bazı challenge **hashes** elde ederek ağın bazı protokollerini **poisoning** edip bunları kırabilirsiniz:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Kimlik Bilgileri/oturum ile Active Directory'yi keşfetme

Bu aşama için geçerli bir domain hesabının **kimlik bilgilerini veya oturumunu ele geçirmiş** olmanız gerekir. Eğer bazı geçerli kimlik bilgilerine veya domain kullanıcısı olarak bir shell'e sahipseniz, **önceki seçeneklerin diğer kullanıcıları ele geçirmek için hâlâ geçerli olduğunu** unutmayın.

Yetkili enumerate işlemine başlamadan önce **Kerberos double hop problem**'in ne olduğunu bilmelisiniz.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir hesabı ele geçirmek, tüm domain'i ele geçirmek için **büyük bir adımdır**, çünkü Active Directory Enumeration'a başlayabileceksiniz:

[**ASREPRoast**](asreproast.md) hakkında artık her olası savunmasız kullanıcıyı bulabilirsiniz ve [**Password Spraying**](password-spraying.md) ile tüm kullanıcı adlarının bir listesini alıp ele geçirilen hesabın şifresini, boş şifreleri veya umut vadeden yeni şifreleri deneyebilirsiniz.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows'tan tüm domain kullanıcı adlarını almak çok kolaydır (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Linux'ta ise şunu kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting, servislerle ilişkilendirilmiş kullanıcı hesapları tarafından kullanılan **TGS tickets** elde etmeyi ve bunların şifrelemesini—ki bu şifreleme kullanıcı parolalarına dayanır—**offline** kırmayı içerir.

More about this in:

{{#ref}}
kerberoast.md
{{#endref}}

### Uzaktan bağlantı (RDP, SSH, FTP, Win-RM, etc)

Bazı kimlik bilgilerini elde ettikten sonra herhangi bir **makineye** erişiminiz olup olmadığını kontrol edebilirsiniz. Bu amaçla, port taramalarınıza göre farklı protokollerle birçok sunucuya bağlanmayı denemek için **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Eğer normal bir domain kullanıcısı olarak kimlik bilgilerini veya oturumu ele geçirdiyseniz ve bu kullanıcıyla domain içindeki herhangi bir **makineye** erişiminiz varsa, yerel ayrıcalıkları yükseltmenin ve kimlik bilgilerini toplamaya çalışmanın yollarını aramalısınız. Çünkü sadece yerel administrator ayrıcalıklarıyla diğer kullanıcıların hash'lerini bellekte (LSASS) ve yerelde (SAM) **dump** edebilirsiniz.

Bu kitapta [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) hakkında tam bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Current Session Tickets

Mevcut kullanıcıda beklenmedik kaynaklara erişim izni veren **tickets** bulmanız çok **olasılık dışı**dır, ama şunları kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Eğer Active Directory'yi enumerate etmeyi başardıysanız **daha fazla e-posta ve ağ hakkında daha iyi bir anlayışa** sahip olursunuz. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** zorlayabiliyor olabilirsiniz.**

### Looks for Creds in Computer Shares | SMB Shares

Artık bazı temel kimlik bilgilerine sahipseniz, **AD içinde paylaşılan herhangi bir ilginç dosyayı bulup bulamayacağınızı** kontrol etmelisiniz. Bunu manuel yapabilirsiniz ama çok sıkıcı ve tekrarlayan bir iştir (ve yüzlerce doküman bulursanız kontrol etmeniz daha da uzun sürer).

[**Bu araçları öğrenmek için bu linke tıklayın.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Eğer diğer PC'lere veya paylaşımlara **erişebiliyorsanız**, birinin erişmesi durumunda size karşı bir **NTLM authentication'ı tetikleyecek dosyalar** (ör. bir SCF dosyası) **yerleştirebilir** ve böylece kırmak için **NTLM challenge'ını çalabilirsiniz**:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu zafiyet herhangi bir doğrulanmış kullanıcının **domain controller'ı ele geçirmesine** izin veriyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Aşağıdaki teknikler için normal bir domain user yeterli değildir; bu saldırıları gerçekleştirmek için bazı özel ayrıcalıklar/kimlik bilgilerine ihtiyacınız vardır.**

### Hash extraction

Umarız [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relay dahil), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) gibi yöntemlerle **birkaç local admin hesabını compromise etmeyi** başarmışsınızdır.  
Sonra, şimdi tüm hash'leri bellekten ve yerelden dump etme zamanı.  
[**Hash'leri elde etmenin farklı yolları hakkında bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ine sahip olduğunuzda**, onu **taklit etmek** için kullanabilirsiniz.  
Bu hash'i kullanarak **NTLM authentication** gerçekleştirecek bir **tool** kullanmanız gerekir veya yeni bir **sessionlogon** oluşturup bu **hash'i LSASS içine inject** ederek, herhangi bir **NTLM authentication** yapıldığında o **hash'in kullanılması** sağlanabilir. Son seçenek mimikatz'in yaptığı yöntemdir.  
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın olarak kullanılan NTLM üzerinden Pass The Hash'e alternatif olarak **kullanıcının NTLM hash'ini kullanıp Kerberos ticket istemeyi** hedefler. Bu yüzden **NTLM protokolünün devre dışı bırakıldığı** ve yalnızca **Kerberos'un kimlik doğrulama protokolü olarak izin verildiği** ağlarda özellikle faydalı olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) saldırı yönteminde, saldırganlar parola veya hash değerleri yerine bir kullanıcının **kimlik doğrulama ticket'ını çalar**. Bu çalınan ticket daha sonra kullanıcıyı **taklit etmek** için kullanılarak ağ içindeki kaynaklara ve servislere yetkisiz erişim sağlar.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Eğer bir local administrator'un **hash'ine** veya **parolasına** sahipseniz, bununla diğer **PC'lere lokal olarak login** olmaya çalışmalısınız.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bu oldukça **gürültülü** olduğunu ve **LAPS** bunun için **hafifletebileceğini** unutmayın.

### MSSQL Abuse & Trusted Links

Eğer bir kullanıcı **MSSQL instance**larına erişim ayrıcalıklarına sahipse, bunu MSSQL hostunda **komut çalıştırmak** (eğer SA olarak çalışıyorsa), NetNTLM **hash**ini **çalmak** veya hatta bir **relay attack** gerçekleştirmek için kullanabilir.\
Ayrıca, eğer bir MSSQL instance başka bir MSSQL instance tarafından trusted (database link) ise ve kullanıcı trusted veritabanı üzerinde yetkiye sahipse, **trust ilişkisinden faydalanarak diğer instance üzerinde de sorgu çalıştırabilecek**. Bu trustlar zincirlenebilir ve bir noktada kullanıcı komut çalıştırabileceği yanlış yapılandırılmış bir veritabanı bulabilir.\
**Veritabanları arasındaki linkler forest trust'ları boyunca bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Üçüncü taraf envanter ve deployment suite'leri sıklıkla kimlik bilgilerine ve kod yürütmeye güçlü yollar açar. Bakınız:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Eğer herhangi bir Computer object'inde [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) attribute'u bulunuyorsa ve bilgisayar üzerinde domain ayrıcalıklarınız varsa, bilgisayara oturum açan her kullanıcının belleğinden TGT'leri dökebilirsiniz.\
Dolayısıyla, eğer bir **Domain Admin bilgisayara logon olursa**, onun TGT'sini döküp [Pass the Ticket](pass-the-ticket.md) kullanarak onu taklit edebilirsiniz.\
Constrained delegation sayesinde **otomatik olarak bir Print Server'ı bile ele geçirebilirsiniz** (umarız DC olmaz).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Eğer bir kullanıcı veya computer "Constrained Delegation" için izinliyse, bu kullanıcı **bir bilgisayardaki bazı servislere erişmek için herhangi bir kullanıcıyı taklit edebilir**.\
Buna ek olarak, eğer bu kullanıcı/computer'ın **hash'ini ele geçirirseniz**, bazı servislere erişmek için **herhangi bir kullanıcıyı** (hatta domain admin'leri) **taklit edebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir bilgisayarın Active Directory objesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** kod yürütme elde etmeyi mümkün kılar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Kompromize edilmiş kullanıcı bazı domain objeleri üzerinde ilginç **ayrıcalıklara** sahip olabilir; bu da size daha sonra lateral **hareket**/yükselme imkanı verebilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Domain içinde **Spool service'in dinlediğini** keşfetmek, yeni kimlik bilgileri **elde etmek** ve **ayrıcalıkları yükseltmek** için **kötüye kullanılabilir**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Eğer **diğer kullanıcılar** **kompromize olmuş** makineye **erişiyorsa**, bellekten **kimlik bilgileri toplanabilir** ve hatta onların süreçlerine **beacon enjekte edilerek** onları taklit etmek mümkün olabilir.\
Genelde kullanıcılar sisteme RDP ile erişir, bu yüzden üçüncü taraf RDP oturumlarına karşı birkaç saldırının nasıl gerçekleştirileceği burada yer alıyor:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e bağlı bilgisayarlarda **local Administrator parolası**nın yönetimi için bir sistem sağlar; parolanın **rastgele**, benzersiz ve sık **değiştirildiğinden** emin olur. Bu parolalar Active Directory'de saklanır ve erişim yalnızca ACL'lerle yetkilendirilmiş kullanıcılarla kontrol edilir. Bu parolalara erişim için yeterli izinlere sahipseniz, diğer bilgisayarlara pivot yapmak mümkün olur.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Kompromize olmuş makinadan **sertifikaları toplamak**, ortam içinde ayrıcalık yükseltme için bir yol olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Eğer **zayıf template'ler** yapılandırılmışsa, bunları ayrıcalıkları yükseltmek için kötüye kullanmak mümkün olabilir:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Bir kez **Domain Admin** veya daha iyisi **Enterprise Admin** ayrıcalıklarını elde ettiğinizde, **domain veritabanını** (_ntds.dit_) **dökebilirsiniz**.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Önceden tartışılan bazı teknikler persistence için kullanılabilir.\
Örneğin şunları yapabilirsiniz:

- Kullanıcıları [**Kerberoast**](kerberoast.md) için savunmasız hale getirmek

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kullanıcıları [**ASREPRoast**](asreproast.md) için savunmasız hale getirmek

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Bir kullanıcıya [**DCSync**](#dcsync) ayrıcalıkları vermek

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**, belirli bir hizmet için **meşru bir Ticket Granting Service (TGS) ticket'ı** oluşturur; bunu örneğin **PC account**'ın **NTLM hash**ini kullanarak yapar. Bu yöntem hizmet ayrıcalıklarına **erişmek** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**, bir saldırganın Active Directory ortamında **krbtgt account**ının **NTLM hash**ine erişmesiyle ilgilidir. Bu hesap, tüm **Ticket Granting Ticket (TGT)**'leri imzalamak için kullanıldığından özeldir; TGT'ler AD ağı içinde kimlik doğrulama için gereklidir.

Saldırgan bu hash'i elde ettiğinde, istediği herhangi bir hesap için **TGT** oluşturabilir (Silver ticket saldırısına benzer şekilde).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, common golden ticket tespit mekanizmalarını **aşacak şekilde** sahte olarak üretilmiş golden ticket'lardır.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Bir hesabın sertifikalarına sahip olmak veya onları talep edebilmek, kullanıcının hesabında (parolayı değiştirse bile) **kalıcı olmak** için çok iyi bir yoldur:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Sertifikaları kullanarak**, domain içinde yüksek ayrıcalıklarla **kalıcı olmak** da mümkündür:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** objesi, **privileged grupların** (ör. Domain Admins ve Enterprise Admins) güvenliğini sağlamak için bu gruplara standart bir **Access Control List (ACL)** uygular ve yetkisiz değişiklikleri engeller. Ancak, bu özellik kötüye kullanılabilir; eğer bir saldırgan AdminSDHolder'ın ACL'ini normal bir kullanıcıya tam erişim verecek şekilde değiştirirse, o kullanıcı tüm privileged gruplar üzerinde geniş kontrol kazanır. Bu güvenlik önlemi, yakından izlenmezse istenmeyen erişime yol açabilir.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Her **Domain Controller (DC)** içinde bir **local administrator** hesabı bulunur. Böyle bir makine üzerinde admin hakları elde ederek, local Administrator hash'ini **mimikatz** kullanarak çıkarabilirsiniz. Ardından bu parolanın **kullanılabilmesi için** registry üzerinde bir değişiklik yapmanız gerekir; bu sayede local Administrator hesabına uzaktan erişim sağlanabilir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Belirli domain objeleri üzerinde bir **kullanıcıya** bazı **özel izinler** verebilir ve bu izinler kullanıcının gelecekte **ayrıcalık yükseltmesi** yapmasını sağlayabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor**ler, bir objenin üzerindeki **izinleri** **depolamak** için kullanılır. Eğer bir objenin security descriptor'unda küçük bir **değişiklik** yapabilirseniz, o objenin üzerinde üyeliğe gerek olmadan çok ilginç ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS'i bellekte değiştirerek **evrensel bir parola** oluşturun; bu, tüm domain hesaplarına erişim sağlar.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Kendi **SSP**'nizi oluşturup makineye erişimde kullanılan **kimlik bilgilerini** **plaintext** olarak **yakalayabilirsiniz**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Yeni bir **Domain Controller** kaydeder ve bunu belirli objelere (SIDHistory, SPN'ler...) **attribute push** etmek için kullanır; yapılan **değişikliklerle** ilgili **log** bırakmaz. Bunun için **DA** ayrıcalıkları ve **root domain** içinde olmanız gerekir.\
Yanlış veri kullanırsanız, oldukça kötü log'lar oluşacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Daha önce LAPS parolalarını **okuma iznine** sahip olduğunuzda ayrıcalıkları nasıl yükseltebileceğinizi tartışmıştık. Ancak bu parolalar aynı zamanda **persistence** için de kullanılabilir.\
Bakınız:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft, **Forest**'u güvenlik sınırı olarak görür. Bu, **tek bir domain'in ele geçirilmesinin tüm Forest'in ele geçirilmesine yol açabileceği** anlamına gelir.

### Basic Information

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir domain'deki kullanıcının başka bir domain'deki kaynaklara erişmesini sağlayan bir güvenlik mekanizmasıdır. Temelde iki domain'in kimlik doğrulama sistemleri arasında bir bağlantı oluşturur, böylece kimlik doğrulama doğrulamaları sorunsuzca akabilir. Domainler bir trust kurduğunda, DC'lerinde trust'ın bütünlüğü için önemli olan belirli **anahtarlar** değiş tokuş edilir ve saklanır.

Tipik bir senaryoda, bir kullanıcı trusted domain'deki bir servise erişmek istiyorsa önce kendi domaininin DC'sinden bir **inter-realm TGT** talep etmelidir. Bu TGT, her iki domainin üzerinde anlaştığı paylaşılan bir **anahtar** ile şifrelenmiştir. Kullanıcı sonra bu TGT'yi **trusted domain'in DC'sine** sunarak bir servis ticket'ı (**TGS**) alır. Trusted domain'in DC'si inter-realm TGT'yi doğruladığında, servise erişim vermek için bir TGS çıkarır.

**Adımlar**:

1. **Domain 1**'de bir **istemci bilgisayar**, **NTLM hash**ini kullanarak **Domain Controller (DC1)**'den bir **Ticket Granting Ticket (TGT)** talep etmeye başlar.
2. DC1 istemci başarıyla kimlik doğrulaması yapıldıysa yeni bir TGT verir.
3. İstemci daha sonra **Domain 2** kaynaklarına erişmek için gerekli olan bir **inter-realm TGT**'yi DC1'den talep eder.
4. Inter-realm TGT, iki yönlü domain trust'ın bir parçası olarak DC1 ve DC2 arasında paylaşılan bir **trust key** ile şifrelenir.
5. İstemci inter-realm TGT'yi **Domain 2'nin Domain Controller (DC2)**'sine götürür.
6. DC2, inter-realm TGT'yi kendi paylaşılan trust key'iyle doğrular ve geçerliyse istemcinin erişmek istediği Domain 2 içindeki sunucu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak, istemci bu TGS'yi sunucuya sunar; TGS sunucunun account hash'i ile şifrelenmiştir ve bu sayede Domain 2'deki hizmete erişim sağlar.

### Different trusts

Bir trust'ın **tek yönlü veya iki yönlü** olabileceğini fark etmek önemlidir. İki yönlü seçimde her iki domain de birbirine güvenir, ancak **tek yönlü** trust ilişkisinde bir domain **trusted** diğeri ise **trusting** olur. Bu durumda, **trusted** olan domain'den **trusting** domain içindeki kaynaklara erişebilirsiniz.

Eğer Domain A, Domain B'ye trust veriyorsa, A trusting domain'dir ve B trusted olandır. Ayrıca, **Domain A**'de bu bir **Outbound trust**; ve **Domain B**'de bu bir **Inbound trust** olur.

**Farklı trusting ilişkileri**

- **Parent-Child Trusts**: Aynı forest içinde yaygın bir kurulumdur; bir child domain otomatik olarak parent domain ile iki yönlü transitif trust'a sahiptir. Bu, kimlik doğrulama isteklerinin parent ve child arasında sorunsuz akabileceği anlamına gelir.
- **Cross-link Trusts**: "shortcut trusts" olarak da adlandırılır; child domainler arasında referral süreçlerini hızlandırmak için kurulur. Karmaşık forest'larda kimlik doğrulama referral'ları genellikle forest root'a kadar çıkıp hedef domaine tekrar inmek zorunda kalır; cross-link'ler bu yolu kısaltır ve coğrafi dağıtılmış ortamlarda faydalıdır.
- **External Trusts**: Farklı, ilişkili olmayan domain'ler arasında kurulur ve doğası gereği non-transitive'dir. Microsoft'un belgesine göre (<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trust'lar forest dışında kalan ve forest trust ile bağlı olmayan bir domain'deki kaynaklara erişim için kullanışlıdır. Güvenlik, external trust'larla SID filtering ile güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak kurulur. Sıklıkla karşılaşılan bir durum olmamakla birlikte, tree-root trust'lar yeni domain ağaçlarının bir forest'a eklenmesi için önemlidir; onlara benzersiz bir domain adı sunar ve iki yönlü transitiviteyi sağlar. Daha fazla bilgi Microsoft'un rehberinde bulunabilir (<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: İki forest root domain arasında iki yönlü transitif trust'tır; aynı zamanda SID filtering uygular.
- **MIT Trusts**: Bu trust'lar, Windows olmayan, [RFC4120-uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos domain'leri ile kurulur. MIT trust'lar daha özelleşmiş olup Windows ekosistemi dışındaki Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlar için uygundur.

#### Other differences in **trusting relationships**

- Bir trust ilişkisi ayrıca **transitive** (A B'ye trust veriyorsa, B C'ye trust veriyorsa A C'ye trust verir) veya **non-transitive** olabilir.
- Bir trust ilişkisi **çift yönlü trust** (her iki taraf da birbirine güvenir) veya **tek yönlü trust** (sadece biri diğerine güvenir) olarak kurulabilir.

### Attack Path

1. **Trusting ilişkilerini** enumerate edin
2. Hangi **security principal**(user/group/computer)'un diğer **domain**in kaynaklarına **erişimi** olup olmadığını kontrol edin; belki ACE girdileriyle veya diğer domain'in gruplarında yer alarak. **Domainler arası ilişkiler**i arayın (trust mu bu amaçla oluşturulmuş olabilir).
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. **Pivot** yapabilecek **hesapları** **kompromize** edin.

Başka bir domaine kaynaklara erişimi olan saldırganların üç ana mekanizma yoluyla erişimi olabilir:

- **Local Group Membership**: Principal'lar makinelerdeki “Administrators” gibi local gruplara eklenmiş olabilir; bu onların o makine üzerinde önemli kontrol elde etmelerini sağlar.
- **Foreign Domain Group Membership**: Principal'lar yabancı domain içindeki grupların da üyeleri olabilir. Ancak bu yöntemin etkinliği, trust'ın doğasına ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar bir **ACL** içinde, özellikle bir **DACL** içindeki **ACE** olarak tanımlanmış olabilir ve bu onlara belirli kaynaklara erişim verir. ACL'lerin, DACL'lerin ve ACE'lerin mekaniklerine derinlemesine dalmak isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” isimli whitepaper çok değerli bir kaynaktır.

### Find external users/groups with permissions

Yabancı security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kontrol edebilirsiniz. Bunlar **dış bir domain/forest**ten gelen user/group olacaktır.

Bunu **Bloodhound**'da veya powerview kullanarak kontrol edebilirsiniz:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Etki alanı güvenlerini listelemenin diğer yolları:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> İki adet **trusted key** var, biri _Child --> Parent_ ve diğeri _Parent_ --> _Child_.\
> Hangi anahtarın mevcut domain tarafından kullanıldığını şu komutlarla görebilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Güveni suistimal ederek SID-History injection ile child/parent domain'e Enterprise admin olarak yükseltme:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)'nin nasıl suistimal edilebileceğini anlamak kritik öneme sahiptir. Configuration NC, Active Directory (AD) ortamlarında bir forest içindeki konfigürasyon verileri için merkezi bir depo görevi görür. Bu veriler forest içindeki her Domain Controller (DC)'ye replikasyon edilir ve yazılabilir DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu suistimal edebilmek için bir DC üzerinde **SYSTEM ayrıcalıklarına** sahip olmak gerekir; tercihen bir child DC.

**Link GPO to root DC site**

Configuration NC'nin Sites container'ı, AD forest içindeki tüm domaine bağlı bilgisayarların site bilgilerini içerir. Herhangi bir DC üzerinde SYSTEM ayrıcalıkları ile işlem yaparak, saldırganlar GPO'ları root DC site'larına bağlayabilir. Bu eylem, bu site'lara uygulanan politikaları manipüle ederek root domain'i potansiyel olarak tehlikeye atabilir.

Daha derinlemesine bilgi için şu araştırma incelenebilir: [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Bir saldırı vektörü, domain içindeki ayrıcalıklı gMSA'ları hedeflemeyi içerir. gMSA'ların parolalarını hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM ayrıcalıkları ile KDS Root key'e erişmek ve forest genelindeki herhangi bir gMSA için parolaları hesaplamak mümkündür.

Detaylı analiz ve adım adım rehberlik için bakınız:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA saldırısı (BadSuccessor – migration attribute'larını suistimal etme):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek dış araştırma: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Bu yöntem sabır gerektirir; yeni ayrıcalıklı AD nesnelerinin oluşturulmasını beklemeyi içerir. SYSTEM ayrıcalıkları ile bir saldırgan AD Schema'yı değiştirerek herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verebilir. Bu, yeni oluşturulan AD nesneleri üzerinde yetkisiz erişim ve kontrol ile sonuçlanabilir.

Daha fazla okuma için: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 zafiyeti, forest içindeki herhangi bir kullanıcı olarak kimlik doğrulama sağlayan bir sertifika şablonu oluşturmak için Public Key Infrastructure (PKI) nesneleri üzerinde kontrol sağlamayı hedefler. PKI nesneleri Configuration NC içinde bulunduğundan, yazılabilir bir child DC'nin ele geçirilmesi ESC5 saldırılarının gerçekleştirilmesini mümkün kılar.

Bununla ilgili daha fazla detayı şurada okuyabilirsiniz: [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). ADCS olmayan senaryolarda saldırgan gerekli bileşenleri kurma imkânına sahiptir; bu konu şu kaynakta tartışılmaktadır: [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Harici Forest Domain - Tek Yönlü (Inbound) veya çift yönlü
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Bu senaryoda **domain'iniz**, dış bir domain tarafından güveniliyor ve size onun üzerinde **belirsiz izinler** veriliyor. Dış domain üzerinde hangi erişimlere sahip olduğunuzu belirlemek için **domain'inizin hangi principals'larının hangi erişimlere sahip olduğunu** bulmanız ve ardından bunları suistimal etmeyi denemeniz gerekecek:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Harici Orman Domain - Tek Yönlü (Giden)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In this senaryoda **domain’iniz** farklı bir domain’den bir principal’a bazı **privileges** veriyor.

Ancak, bir **domain is trusted** olduğunda, trusting domain tarafından, trusted domain **predictable name** ile bir **user** oluşturur ve **password** olarak trusted password’u kullanır. Bu, trusting domain’deki bir kullanıcıya erişip trusted domain’in içine girerek onu enumerate etmek ve daha fazla ayrıcalık için yükseltme denemesi yapmanın mümkün olduğu anlamına gelir:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain’i ele geçirmenin bir diğer yolu, domain trust’ın **opposite direction**’ında oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain’i ele geçirmenin bir diğer yolu da, **trusted domain**’den bir kullanıcının **RDP** ile erişebildiği bir makinede beklemektir. Ardından saldırgan RDP session sürecine kod enjekte edebilir ve oradan **victim**’in origin domain’ine erişebilir.\
Ayrıca, eğer **victim** sabit diskini mount ettiyse, saldırgan **RDP session** sürecinden hard drive’ın startup klasörüne **backdoors** koyabilir. Bu teknik **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID history attribute’u kullanılarak forest trust’lar üzerinden yapılan saldırı riski, tüm inter-forest trust’larda varsayılan olarak etkin olan SID Filtering ile azaltılır. Bu, Microsoft’un ormandan (forest) ziyade domain’i güvenlik sınırı olarak görme yaklaşımına dayanarak intra-forest trust’ların güvenli olduğu varsayımına dayanmaktadır.
- Ancak bir sorun vardır: SID Filtering uygulamaları ve kullanıcı erişimini bozabilir, bu yüzden bazen devre dışı bırakılabilir.

### **Selective Authentication:**

- Inter-forest trust’lar için Selective Authentication kullanmak, iki forest’tan gelen kullanıcıların otomatik olarak authenticate edilmemesini sağlar. Bunun yerine, trusting domain veya forest içindeki domain ve sunuculara erişim için açık izinler gereklidir.
- Bu önlemlerin writable Configuration Naming Context (NC) veya trust account’a yönelik saldırılara karşı koruma sağlamadığını not etmek önemlidir.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Kimlik bilgilerini nasıl koruyacağınızı buradan öğrenin.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins sadece Domain Controllers’a giriş yapacak şekilde sınırlandırılmalı; diğer hostlarda kullanılmaları engellenmelidir.
- **Service Account Privileges**: Servisler DA (Domain Admin) ayrıcalıkları ile çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA ayrıcalıkları gerektiren görevler için bu süre sınırlandırılmalıdır. Bu şu şekilde yapılabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Deception uygulamak, password’ları expire olmayan veya Trusted for Delegation olarak işaretlenmiş sahte kullanıcılar ya da bilgisayarlar gibi tuzaklar kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya bunları yüksek ayrıcalıklı gruplara eklemeyi içerir.
- Pratik bir örnek şu araçları kullanmayı içerir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception tekniklerinin dağıtımı hakkında daha fazla bilgi için [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) bakılabilir.

### **Identifying Deception**

- **For User Objects**: Şüpheli göstergeler arasında olağandışı ObjectSID, nadir logon’lar, oluşturulma tarihleri ve düşük bad password sayıları bulunur.
- **General Indicators**: Potansiyel decoy nesnelerin özniteliklerini gerçek nesnelerle karşılaştırmak tutarsızlıkları ortaya çıkarabilir. Bu tür deception’ları tespit etmeye yardımcı olmak için [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar kullanılabilir.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA tespitini önlemek için Domain Controllers üzerinde oturum (session) enumerate etmekten kaçınmak.
- **Ticket Impersonation**: aes anahtarlarını kullanarak ticket oluşturmak, NTLM’e downgrade etmeyerek tespitten kaçınmaya yardımcı olur.
- **DCSync Attacks**: ATA tespiti tetiklenmemesi için DCSync işlemlerinin bir Domain Controller’dan değil, başka bir makinadan yürütülmesi tavsiye edilir; çünkü doğrudan Domain Controller’dan yürütülmesi uyarılara neden olur.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
