# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory**, ağ yöneticilerinin **domain**, **kullanıcı** ve **nesneleri** verimli şekilde oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir şekilde tasarlanmıştır; çok sayıda kullanıcıyı yönetilebilir **gruplar** ve **alt gruplar** halinde organize etmeye ve farklı seviyelerde **erişim haklarını** kontrol etmeye imkan verir.

**Active Directory** yapısı üç ana katmandan oluşur: **domains**, **trees** ve **forests**. Bir **domain**, ortak bir veritabanını paylaşan **kullanıcı** veya **cihaz** gibi nesneler koleksiyonunu kapsar. **Trees**, ortak bir yapıyı paylaşan bu domainlerin gruplarıdır ve bir **forest**, birden fazla tree’nin **trust relationships** aracılığıyla birbirine bağlandığı en üst organizasyon katmanını temsil eder. Her seviyede belirli **erişim** ve **iletişim hakları** atanabilir.

Active Directory içindeki temel kavramlar şunlardır:

1. **Directory** – Active Directory nesnelerine ait tüm bilgileri barındırır.
2. **Object** – Directory içindeki varlıkları ifade eder; örneğin **users**, **groups** veya **shared folders**.
3. **Domain** – Directory nesneleri için bir konteyner görevi görür; bir **forest** içinde birden fazla domain bulunabilir ve her biri kendi nesne koleksiyonunu tutar.
4. **Tree** – Ortak bir root domaini paylaşan domainlerin gruplandırılması.
5. **Forest** – Active Directory’de organizasyon yapısının en üst seviyesi; birden fazla tree’den oluşur ve bunlar arasında **trust relationships** bulunur.

**Active Directory Domain Services (AD DS)**, ağ içinde merkezi yönetim ve iletişim için kritik olan çeşitli servisleri kapsar. Bu servisler şunlardır:

1. **Domain Services** – Verilerin merkezi depolanmasını sağlar ve **users** ile **domains** arasındaki etkileşimleri, **authentication** ve **search** fonksiyonlarını yönetir.
2. **Certificate Services** – Güvenli **digital certificates** oluşturma, dağıtma ve yönetme işlerini denetler.
3. **Lightweight Directory Services** – **LDAP protocol** aracılığıyla directory-enabled uygulamaları destekler.
4. **Directory Federation Services** – Birden fazla web uygulamasında **single-sign-on** ile kullanıcıların tek oturumda doğrulanmasını sağlar.
5. **Rights Management** – Telif hakkı materyallerinin yetkisiz dağıtımını ve kullanılmasını kontrol ederek korumaya yardımcı olur.
6. **DNS Service** – **domain names** çözümlemesi için kritik öneme sahiptir.

Daha detaylı açıklama için bakınız: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Bir **AD’ye saldırmayı** öğrenmek istiyorsanız **Kerberos authentication process**i gerçekten iyi **anlamanız** gerekir.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Hangi komutlarla bir AD’yi enumerate/exploit edebileceğinize hızlıca bakmak için [https://wadcoms.github.io/](https://wadcoms.github.io) adresinden faydalanabilirsiniz.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Eğer bir AD ortamına erişiminiz varsa fakat herhangi bir credential/session yoksa şu işlemleri yapabilirsiniz:

- **Pentest the network:**
- Ağ taraması yapın, makineleri ve açık portları bulun, **vulnerabilities**i exploit etmeyi veya bu makinelerden **credentials** çıkarmayı deneyin (örneğin, [printers could be very interesting targets](ad-information-in-printers.md) çok ilgi çekici hedefler olabilir).
- DNS enumerasyonu, domain içindeki web, printers, shares, vpn, media gibi önemli sunucular hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunu nasıl yapacağınıza dair daha fazla bilgi için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına göz atın.
- **Check for null and Guest access on smb services** (bu modern Windows sürümlerinde çalışmayacaktır):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB sunucusunu enumerate etme ile ilgili daha detaylı rehber şurada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP enumerate etme hakkında daha ayrıntılı rehber burada bulunabilir (anonim erişime **özellikle dikkat edin**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder ile **impersonating services** yaparak credentials toplayın (gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md))
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ile hostlara erişin
- evil-S ile **fake UPnP services** açarak credentials toplayın (gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856))
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- İç belgeler, sosyal medya, domain içindeki servisler (özellikle web) ve genel olarak kamuya açık kaynaklardan kullanıcı adları/isimler çıkarın.
- Şirket çalışanlarının tam isimlerini bulursanız, farklı AD **username conventions**larını deneyebilirsiniz ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın conventionlar: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _rasgele harf ve 3 rasgele sayı_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: Geçersiz bir username istenildiğinde sunucu **Kerberos error** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıt verecek ve bu sayede username’in geçersiz olduğu anlaşılacaktır. **Valid usernames** ya AS-REP içindeki **TGT** ile cevap alır ya da kullanıcının pre-authentication yapması gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını döndürür.
- **No Authentication against MS-NRPC**: Domain controllerlar üzerindeki MS-NRPC (Netlogon) arayüzüne auth-level = 1 (No authentication) ile bağlanmak. Bu yöntem MS-NRPC arayüzüne bind ettikten sonra `DsrGetDcNameEx2` fonksiyonunu çağırarak kullanıcı veya bilgisayarın var olup olmadığını herhangi bir credential olmadan kontrol eder. Bu tip enumeration’u uygulayan araç [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tarafından gerçekleştirilir. Araştırma şurada bulunabilir: [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ağda bu sunuculardan birini bulduysanız, ayrıca **user enumeration against it** gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Kullanıcı adı listelerini [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  ve bunun içinde ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) bulabilirsiniz.
>
> Ancak, daha önce yapmış olmanız gereken recon adımından şirket çalışanlarının **isimlerini** edinmiş olmalısınız. İsim ve soyadıyla potansiyel geçerli kullanıcı adları üretmek için [**namemash.py**](https://gist.github.com/superkojiman/11076951) script'ini kullanabilirsiniz.

### Knowing one or several usernames

Tamam, geçerli bir kullanıcı adına zaten sahip olduğunuzu ama parolanız olmadığını biliyorsunuz... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Eğer bir kullanıcının _DONT_REQ_PREAUTH_ özniteliği **yoksa**, o kullanıcı için parola türeviyle şifrelenmiş bazı veriler içerecek bir **AS_REP message** talep edebilirsiniz.
- [**Password Spraying**](password-spraying.md): Keşfedilen her kullanıcı ile en **common passwords**'ları deneyin; belki bazı kullanıcılar zayıf parola kullanıyordur (parola politikasını unutmayın!).
- Ayrıca kullanıcıların mail sunucularına erişim elde etmeye çalışmak için **spray OWA servers** yapabileceğinizi unutmayın.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ağın bazı protokollerini **poisoning** yaparak kırmak için bazı **challenge** **hashes** elde edebilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Eğer Active Directory'yi enumerate etmeyi başardıysanız, **daha fazla e-posta ve ağ hakkında daha iyi bir anlayış** elde etmiş olursunuz. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zorlayarak AD ortamına erişim sağlayabilirsiniz.

### Steal NTLM Creds

Eğer **null or guest user** ile **other PCs or shares**'lara **access** edebiliyorsanız, erişildiğinde size karşı **trigger an NTLM authentication against you** edecek dosyaları (ör. bir SCF file) **place files** edebilir ve böylece kırmak için **steal** edebileceğiniz **NTLM challenge**'ları elde edebilirsiniz:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Bu aşama için geçerli bir domain hesabının **kimlik bilgilerini veya oturumunu ele geçirmiş** olmanız gerekir. Eğer geçerli kimlik bilgilerine veya domain kullanıcısı olarak bir shell'e sahipseniz, **önceki seçeneklerin diğer kullanıcıları ele geçirmek için hâlâ geçerli olduğunu** unutmayın.

Kimlikli enumeration'a başlamadan önce **Kerberos double hop problem**'in ne olduğunu bilmelisiniz.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir hesabı ele geçirmek, tüm domain'i ele geçirmek için büyük bir adımdır; çünkü artık **Active Directory Enumeration:**'a başlayabileceksiniz.

[**ASREPRoast**](asreproast.md) ile şimdi her olası zayıf kullanıcıyı bulabilirsiniz ve [**Password Spraying**](password-spraying.md) ile tüm kullanıcı adlarının bir **list of all the usernames**'ını alıp ele geçirilen hesabın parolasını, boş parolaları ve yeni umut verici parolaları deneyebilirsiniz.

- Temel keşif yapmak için [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) kullanabilirsiniz.
- Daha gizli olması için [**powershell for recon**](../basic-powershell-for-pentesters/index.html) kullanabilirsiniz.
- Daha detaylı bilgi çıkarmak için [**use powerview**](../basic-powershell-for-pentesters/powerview.md) kullanabilirsiniz.
- Active Directory keşfi için müthiş bir araç da [**BloodHound**](bloodhound.md). (Kullanılan collection yöntemlerine bağlı olarak) **çok stealthy** değildir, ama bunu umursamıyorsanız denemelisiniz. Kullanıcıların nereden RDP yapabildiğini, diğer gruplara giden yolları bulun vb.
- **Diğer otomatik AD enumeration araçları:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) ilginç bilgiler içerebilir.
- Directory'yi enumerate etmek için GUI tabanlı bir araç olarak **AdExplorer.exe** (SysInternal Suite) kullanabilirsiniz.
- LDAP veritabanında **ldapsearch** ile _userPassword_ & _unixUserPassword_ alanlarında ya da _Description_ içinde kimlik bilgisi arayabilirsiniz. Diğer yöntemler için bkz. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- **Linux** kullanıyorsanız domain'i enumerate etmek için [**pywerview**](https://github.com/the-useless-one/pywerview)'u da kullanabilirsiniz.
- Ayrıca otomatik araçları deneyebilirsiniz:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows'tan tüm domain kullanıcı adlarını almak çok kolaydır (`net user /domain` ,`Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta ise şu komutları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı hizmetler tarafından kullanılan **TGS tickets**'ları elde etmeyi ve bu biletlerin şifrelemesini — kullanıcı parolalarına dayalı — **offline** olarak kırmayı içerir.

Daha fazla bilgi için:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Bazı kimlik bilgileri elde ettiğinizde herhangi bir **machine**'e erişiminiz olup olmadığını kontrol edebilirsiniz. Bu amaçla, port taramalarınıza göre çeşitli protokollerle birden fazla sunucuya bağlanmayı denemek için **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Eğer sıradan bir domain kullanıcısı olarak kimlik bilgilerini veya bir oturumu ele geçirdiyseniz ve bu kullanıcıyla domain içindeki **any machine in the domain**'e **access** hakkınız varsa, yerel ayrıcalıkları yükseltmek ve kimlik bilgilerini yağmalamak için yollar aramalısınız. Çünkü sadece yerel administrator ayrıcalıklarıyla diğer kullanıcıların hash'lerini bellekte (LSASS) ve yerelde (SAM) **dump** edebilirsiniz.

Bu kitapta [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) hakkında tam bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Current Session Tickets

Mevcut kullanıcıda beklenmeyen kaynaklara erişim izni veren **tickets** bulmanız çok **unlikely**, ancak yine de kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **daha fazla e-posta ve ağ hakkında daha iyi bir anlayış**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Now that you have some basic credentials you should check if you can **find** any **AD içinde paylaşılan ilginç dosyalar**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **other PC'lere veya shares'a erişmek** you could **dosya yerleştirmek** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **domain controller'ı ele geçirmek**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Aşağıdaki teknikler için normal bir domain kullanıcısı yeterli değildir, bu saldırıları gerçekleştirmek için bazı özel ayrıcalıklar/credentials gerekir.**

### Hash extraction

Umarım [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relaying dahil), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [yerel ayrıcalıkları yükseltme](../windows-local-privilege-escalation/index.html) vb. kullanarak **bazı local admin hesaplarını ele geçirmeyi** başarmışsınızdır.\
Şimdi, hafızadaki ve yereldeki tüm hashleri dump etme zamanı.\
[**Farklı yollarla hashleri elde etme hakkında bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ini elde ettikten sonra**, onu **taklit etmek** için kullanabilirsiniz.\
Bu hash'i kullanarak **NTLM authentication** gerçekleştirecek bir **tool** kullanmanız gerekir, **veya** yeni bir **sessionlogon** oluşturarak o **hash'i LSASS içine inject** edebilirseniz, böylece herhangi bir **NTLM authentication** yapıldığında o **hash** kullanılacaktır. Son seçenek mimikatz'in yaptığı şeydir.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash over NTLM protokolüne alternatif olarak **kullanıcı NTLM hash'ini Kerberos biletleri istemek için** kullanmayı hedefler. Bu nedenle, NTLM protokolünün devre dışı bırakıldığı ve yalnızca **Kerberos**'un kimlik doğrulama protokolü olarak izin verildiği ağlarda özellikle **useful** olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **bir kullanıcının authentication ticket'ını çalarlar** instead of their password or hash values. This stolen ticket is then used to **kullanıcının yerine geçmek**, network içinde kaynaklara ve servislere yetkisiz erişim sağlamak için.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrato**r you should try to **başka PC'lere yerel olarak login olmak** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bunun oldukça **gürültülü** olduğunu ve **LAPS**'in bunu **hafifletebileceğini** unutmayın.

### MSSQL Kötüye Kullanımı & Trusted Links

Eğer bir kullanıcının **MSSQL instance'larına erişim** yetkisi varsa, bunu MSSQL host üzerinde (SA olarak çalışıyorsa) **komut çalıştırmak**, NetNTLM **hash**'ini **çalmak** veya hatta bir **relay attack** gerçekleştirmek için kullanabilir.\
Ayrıca, eğer bir MSSQL instance'ı farklı bir MSSQL instance tarafından trusted (database link) ise ve kullanıcı trusted veritabanı üzerinde yetkiye sahipse, **güven ilişkisini kullanarak diğer instance'ta da sorgu çalıştırabilecek**. Bu trust'lar zincirlenebilir ve kullanıcı sonunda bir şekilde yanlış yapılandırılmış bir veritabanı bularak komut çalıştırabilir.\
**Veritabanları arasındaki bağlantılar forest trusts boyunca bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platformlarının kötüye kullanımı

Üçüncü taraf envanter ve dağıtım paketleri genellikle kimlik bilgilerine ve kod yürütmeye güçlü yollar açar. Bakınız:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Eğer [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) özniteliğine sahip herhangi bir Computer objesi bulursanız ve o bilgisayarda domain ayrıcalıklarına sahipseniz, o bilgisayara oturum açan her kullanıcının belleğinden TGT'leri dump'layabilirsiniz.\
Dolayısıyla, eğer bir **Domain Admin bilgisayara giriş yaparsa**, TGT'sini dump'layabilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onu taklit edebilirsiniz.\
Constrained delegation sayesinde hatta **otomatik olarak bir Print Server'ı** (umarız bir DC olur) **ele geçirebilirsiniz**.


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Eğer bir kullanıcı veya bilgisayar "Constrained Delegation" için yetkilendirilmişse, belirli servislerde **herhangi bir kullanıcıyı taklit ederek** erişim sağlayabilir.\
Sonrasında, bu kullanıcı/bilgisayarın **hash'ini ele geçirirseniz**, bazı hizmetlere erişmek için **herhangi bir kullanıcıyı** (hatta domain admin'leri bile) **taklit edebilirsiniz**.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Uzak bir bilgisayarın Active Directory objesi üzerinde **WRITE** ayrıcalığına sahip olmak, **yükseltilmiş ayrıcalıklarla** kod yürütmeyi mümkün kılar:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Kötüye Kullanımı

Ele geçirilen kullanıcı, size daha sonra **lateral hareket**/ **yükseltme** yapma imkanı verebilecek bazı **ilginç ayrıcalıklara** sahip olabilir.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler servisi kötüye kullanımı

Domain içinde **Spool servisi dinleyen** bir sistem keşfetmek, **yeni kimlik bilgileri elde etmek** ve **ayrıcalıkları yükseltmek** için **kötüye kullanılabilir**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party oturumların kötüye kullanımı

Eğer **diğer kullanıcılar** **ele geçirilmiş** makineye **erişiyorsa**, bellekten **kimlik bilgileri toplamak** ve hatta **işlemlerine beacon enjekte ederek** onları taklit etmek mümkündür.\
Kullanıcılar genellikle sisteme RDP ile eriştiği için, üçüncü taraf RDP oturumlarına karşı yapılabilecek birkaç saldırı şöyle:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, domain'e üye bilgisayarlarda **local Administrator parolasını** yönetmek için bir sistem sağlar; parolaların **rastgele**, benzersiz ve sıkça **değiştirilmesini** güvence altına alır. Bu parolalar Active Directory'de saklanır ve erişim yalnızca yetkili kullanıcılar için ACL'lerle kontrol edilir. Bu parolalara erişmek için yeterli izinlere sahip olunursa, diğer bilgisayarlara pivot yapmak mümkün olur.


{{#ref}}
laps.md
{{#endref}}

### Sertifika Hırsızlığı

Ele geçirilen makineden **sertifikaların toplanması**, ortam içinde ayrıcalıkları yükseltmenin bir yolu olabilir:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Sertifika Şablonları Kötüye Kullanımı

Eğer **zayıf şablonlar** yapılandırılmışsa, bunları ayrıcalıkları yükseltmek için kötüye kullanmak mümkündür:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Yüksek ayrıcalıklı hesap ile post-exploitation

### Domain Kimlik Bilgilerinin Dökülmesi

Bir kere **Domain Admin** veya daha da iyisi **Enterprise Admin** ayrıcalıkları elde ettiğinizde, **domain veritabanını** (_ntds.dit_) **dökebilirsiniz**.

[**DCSync saldırısı hakkında daha fazla bilgi burada bulunabilir**](dcsync.md).

[**NTDS.dit'i nasıl çalacağınız hakkında daha fazla bilgi burada bulunabilir**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Kalıcılık İçin Privesc

Daha önce bahsedilen bazı teknikler kalıcılık için de kullanılabilir.\
Örneğin yapabilecekleriniz:

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

**Silver Ticket saldırısı**, belirli bir servis için **meşru bir Ticket Granting Service (TGS) ticket'ı** oluşturur; genellikle **NTLM hash**i kullanılarak (örneğin PC hesabının hash'i). Bu yöntem servis ayrıcalıklarına **erişim sağlamak** için kullanılır.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket saldırısı**, saldırganın Active Directory ortamında **krbtgt hesabının NTLM hash'ine** erişmesiyle gerçekleşir. Bu hesap, tüm **Ticket Granting Ticket (TGT)**'leri imzalamak için kullanıldığından özel bir öneme sahiptir ve AD içinde kimlik doğrulama için gereklidir.

Saldırgan bu hash'i elde ettikten sonra, istediği herhangi bir hesap için **TGT** oluşturabilir (Silver ticket saldırısına benzer şekilde).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, yaygın golden ticket tespit mekanizmalarını **atlayacak** şekilde sahte oluşturulmuş golden ticket'lara benzerler.


{{#ref}}
diamond-ticket.md
{{#endref}}

### Sertifikalar ile Hesap Kalıcılığı

Bir hesabın **sertifikalarına sahip olmak veya bunları talep edebilmek**, kullanıcının hesabında parolayı değiştirse bile **kalıcılık sağlamak** için çok iyi bir yoldur:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### Sertifikalar ile Domain Kalıcılığı

**Sertifikaları kullanarak** domain içinde yüksek ayrıcalıklarla da **kalıcılık sağlamak** mümkündür:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory'deki **AdminSDHolder** objesi, **privileged group'ların** (Domain Admins ve Enterprise Admins gibi) güvenliğini sağlamak için bu gruplara standart bir **Access Control List (ACL)** uygular ve yetkisiz değişiklikleri engeller. Ancak, bu özellik kötüye kullanılabilir; eğer bir saldırgan AdminSDHolder'ın ACL'sini değiştirip normal bir kullanıcıya tam erişim verirse, o kullanıcı tüm ayrıcalıklı gruplar üzerinde geniş kontrol elde eder. Bu güvenlik önlemi doğru şekilde izlenmezse, ters tepki vererek yetkisiz erişime yol açabilir.

[**AdminDSHolder Group hakkında daha fazla bilgi burada.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Kimlik Bilgileri

Her bir **Domain Controller (DC)** içinde bir **local administrator** hesabı vardır. Böyle bir makinede admin hakları elde ederek, local Administrator hash'i **mimikatz** ile çıkarılabilir. Ardından bu parolanın **kullanılabilmesini etkinleştirmek** için bir registry değişikliği gerekir; bu sayede local Administrator hesabına uzaktan erişim sağlanabilir.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Kalıcılığı

Bir kullanıcıya belirli domain objeleri üzerinde **özel izinler** vererek, o kullanıcının ileride **ayrıcalık yükseltmesi** yapmasını sağlayabilirsiniz.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor'lar**, bir **objenin** üzerinde hangi **izinlerin** bulunduğunu **saklamak** için kullanılır. Bir objenin security descriptor'unda **küçük bir değişiklik** yapabiliyorsanız, o obje üzerinde ayrıcalıklı grup üyesi olmanız gerekmeden çok ilginç ayrıcalıklar elde edebilirsiniz.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS belleğini değiştirerek **evrensel bir parola** oluşturun; bu, tüm domain hesaplarına erişim sağlar.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) nedir buradan öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Kendi **SSP**'nizi oluşturarak, makineye erişimde kullanılan **kimlik bilgilerini** **düz metin** halinde **yakalayabilirsiniz**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD'de yeni bir **Domain Controller** kaydeder ve belirtilen objeler üzerinde (SIDHistory, SPN'ler...) **değişiklikleri push etmek** için bunu kullanır; yapılan **değişikliklerle** ilgili **log** bırakmaz. Bunun için **DA** ayrıcalıklarına ve **root domain** içinde olmaya ihtiyacınız vardır.\
Yanlış veri kullanırsanız, oldukça çirkin log'lar ortaya çıkacağını unutmayın.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Kalıcılığı

Daha önce LAPS parolalarını **okuma** yetkisine sahip olmanın nasıl ayrıcalık yükseltmeye yol açabileceğini tartıştık. Bu parolalar aynı zamanda **kalıcılık** için de kullanılabilir.\
Bakınız:


{{#ref}}
laps.md
{{#endref}}

## Forest Ayrıcalık Yükseltmesi - Domain Trusts

Microsoft, **Forest**'ı güvenlik sınırı olarak görür. Bu, **tek bir domain'in ele geçirilmesinin tüm Forest'ın ele geçirilmesine yol açabileceği** anlamına gelir.

### Temel Bilgiler

Bir [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir domain'deki bir kullanıcının başka bir domain'deki kaynaklara erişmesini sağlayan bir güvenlik mekanizmasıdır. İki domainin kimlik doğrulama sistemleri arasında bir bağlantı oluşturur ve doğrulama taleplerinin akışını kolaylaştırır. Domainler bir trust kurduklarında, güvenin bütünlüğü için önemli olan belirli **anahtarları** Domain Controller (DC)'lerinde değiş tokuş eder ve saklarlar.

Tipik bir senaryoda, bir kullanıcı trusted domain'deki bir servise erişmek istediğinde önce kendi domain'inin DC'sinden özel bir ticket olan **inter-realm TGT**'yi talep etmelidir. Bu TGT, iki domain arasındaki trust kapsamında ortaklaşa paylaşılan bir **anahtar** ile şifrelenir. Kullanıcı daha sonra bu inter-realm TGT'yi **trusted domain**in DC'sine sunar ve bir servis ticket'ı (**TGS**) alır. Trusted domain'in DC'si inter-realm TGT'yi doğruladıktan sonra TGS'yi verir ve kullanıcı servise erişir.

**Adımlar**:

1. Bir **istemci bilgisayar** Domain 1'de, **NTLM hash**ini kullanarak **Ticket Granting Ticket (TGT)** talep etmek için Domain Controller'ı (DC1) ile iletişime başlar.
2. DC1, istemci başarıyla kimlik doğrulandıysa yeni bir TGT verir.
3. İstemci daha sonra **Domain 2** kaynaklarına erişmek için DC1'den bir **inter-realm TGT** talep eder.
4. Inter-realm TGT, iki yönlü domain trust kapsamında DC1 ve DC2 arasında paylaşılan bir **trust key** ile şifrelenir.
5. İstemci inter-realm TGT'yi **Domain 2'nin Domain Controller'ı (DC2)**'ye götürür.
6. DC2, inter-realm TGT'yi paylaşılan trust key ile doğrular ve geçerliyse istemcinin erişmek istediği Domain 2 içindeki sunucu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak, istemci bu TGS'yi sunucuya sunar; TGS sunucunun hesap hash'i ile şifrelenmiştir ve böylece Domain 2'deki servise erişim sağlanır.

### Farklı trust türleri

Bir trust'ın **1 yönlü** veya **2 yönlü** olabileceğini fark etmek önemlidir. 2 yönlü seçenekte her iki domain birbirine güvenir, fakat **1 yönlü** trust ilişkisinde bir domain **trusted**, diğeri ise **trusting** domain olur. Bu durumda, **trusted** domain'den **trusting** domain içindeki kaynaklara erişebilirsiniz.

Eğer Domain A, Domain B'ye güveniyorsa, A trusting domain; B ise trusted domain'dir. Ayrıca, **Domain A**'da bu bir **Outbound trust**; **Domain B**'de ise bir **Inbound trust** olur.

**Farklı trusting ilişkileri**

- **Parent-Child Trusts**: Aynı forest içinde yaygın bir yapı olup, child domain otomatik olarak parent domain ile iki yönlü ve transitif bir trust'a sahiptir. Bu, parent ve child arasında kimlik doğrulama taleplerinin sorunsuz akabileceği anlamına gelir.
- **Cross-link Trusts**: "shortcut trusts" olarak adlandırılır; child domain'ler arasında yönlendirme süreçlerini hızlandırmak için kurulur. Karmaşık forest'larda, kimlik doğrulama yönlendirmeleri genellikle forest root'a kadar yükselip hedef domain'e geri inmelidir. Cross-link'ler bu süreci kısaltır ve özellikle coğrafi olarak dağılmış ortamlarda faydalıdır.
- **External Trusts**: Farklı, ilişkisiz domain'ler arasında kurulur ve doğası gereği non-transitive'dir. [Microsoft dokümantasyonuna](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre, external trust'lar forest dışında kalan ve forest trust ile bağlı olmayan bir domain'deki kaynaklara erişim için kullanışlıdır. Güvenlik, external trust'larla SID filtering uygulanarak güçlendirilir.
- **Tree-root Trusts**: Forest root domain ile yeni eklenen bir tree root arasında otomatik olarak oluşturulan trust'lardır. Sık karşılaşılmasa da, yeni domain ağaçları eklerken önemlidir; iki yönlü transitivite sağlar ve yeni ağaçların benzersiz domain adını korumasına olanak tanır. Daha fazla bilgi için [Microsoft rehberine](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) bakabilirsiniz.
- **Forest Trusts**: İki forest root domain arasında kurulan iki yönlü transitif trust'lardır ve SID filtering ile güvenlik önlemleri uygulanır.
- **MIT Trusts**: Windows dışı, [RFC4120 uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos domain'leriyle kurulan trust'lardır. MIT trust'ları daha özel olup, Windows ekosisteminin dışındaki Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlara yöneliktir.

#### Trust ilişkilerindeki diğer farklılıklar

- Bir trust ilişkisi aynı zamanda **transitive** (A B'ye, B C'ye güveniyorsa A C'ye güvenir) veya **non-transitive** olabilir.
- Bir trust ilişkisi **çift yönlü trust** (her iki taraf da birbirine güvenir) veya **tek yönlü trust** (sadece biri diğerine güvenir) olarak kurulabilir.

### Saldırı Yolu

1. **Trusting ilişkilerini** enumerate edin
2. Hangi **security principal**(kullanıcı/grup/bilgisayar)'ın diğer domain kaynaklarına **erişimi** olup olmadığını kontrol edin; belki ACE girdileri veya diğer domain gruplarında üyelik yoluyla. **Domainler arası ilişkiler** arayın (trust büyük ihtimalle bunun için oluşturulmuştur).
1. Bu durumda kerberoast da başka bir seçenek olabilir.
3. Domainler arasında **pivot** yapabilecek **hesapları compromet** edin.

Başka bir domaine kaynaklara erişebilecek saldırganların erişimi üç ana mekanizma aracılığıyla olabilir:

- **Local Group Membership**: Principal'lar makinelere, örneğin bir sunucudaki “Administrators” grubuna eklenmiş olabilir; bu da o makine üzerinde önemli kontrol sağlar.
- **Foreign Domain Group Membership**: Principal'lar ayrıca yabancı domain içindeki grupların üyeleri olabilir. Ancak bu yöntemin etkinliği trust'ın doğasına ve grubun kapsamına bağlıdır.
- **Access Control Lists (ACLs)**: Principal'lar özellikle bir **DACL** içindeki **ACE**'lerde belirtilmiş olabilir ve belirli kaynaklara erişim sağlayabilir. ACL'ler, DACL'ler ve ACE'lerin mekanik detaylarına dalmak isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” whitepaper'ı değerli bir kaynaktır.

### Harici kullanıcı/grupları izinlere göre bulma

Domain içindeki foreign security principal'ları bulmak için **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** kontrol edebilirsiniz. Bunlar **harici bir domain/forest**'ten gelen kullanıcı/gruplar olacaktır.

Bunu **Bloodhound** veya powerview kullanarak kontrol edebilirsiniz:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Alt ormandan üst ormana ayrıcalık yükseltme
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
Domain trusts'leri enumerate etmenin diğer yolları:
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
> Toplam **2 güvenilen anahtar** vardır; biri _Child --> Parent_ için, diğeri ise _Parent_ --> _Child_ içindir.\
> Geçerli alan tarafından kullanılan anahtarı şu komutlarla görebilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection ile trust'ı suistimal ederek child/parent alanına Enterprise admin olarak yükseltme:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)'nin nasıl istismar edilebileceğini anlamak kritik öneme sahiptir. Configuration NC, Active Directory (AD) ortamlarında bir forest içindeki yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler forest içindeki her Domain Controller (DC)'ye replike edilir; yazılabilir DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu istismar edebilmek için bir DC üzerinde **SYSTEM ayrıcalıklarına** sahip olmak gerekir; tercihen child DC üzerinde.

**Link GPO to root DC site**

Configuration NC'nin Sites container'ı, AD forest içindeki tüm alana katılmış bilgisayarların site bilgilerini içerir. Herhangi bir DC üzerinde SYSTEM ayrıcalıklarıyla hareket ederek, saldırganlar GPO'ları root DC site'larına linkleyebilirler. Bu eylem, bu sitelere uygulanan politikaları manipüle ederek root domain'in tehlikeye girmesine yol açabilir.

Detaylı bilgi için [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) araştırmasına bakılabilir.

**Compromise any gMSA in the forest**

Bir saldırı vektörü, alandaki ayrıcalıklı gMSA'ları hedeflemeyi içerir. gMSA'ların parolalarını hesaplamak için gerekli olan KDS Root key, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM ayrıcalıklarına sahip olarak, KDS Root key'e erişmek ve forest içindeki herhangi bir gMSA'nın parolasını hesaplamak mümkündür.

Detaylı analiz ve adım adım rehber için:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delegated MSA saldırısı (BadSuccessor – migration attribute'larını suistimal etme):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek dış araştırma: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Bu yöntem sabır gerektirir; yeni ayrıcalıklı AD nesnelerinin oluşturulmasını beklemeyi içerir. SYSTEM ayrıcalıkları ile bir saldırgan AD Şeması'nı, herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verecek şekilde değiştirebilir. Bu, yeni oluşturulan AD nesneleri üzerinde yetkisiz erişim ve kontrol ile sonuçlanabilir.

Daha fazla okumak için [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) kaynağına bakın.

**From DA to EA with ADCS ESC5**

ADCS ESC5 zafiyeti, PKI nesneleri üzerinde kontrol edin hedef alır ve forest içindeki herhangi bir kullanıcı olarak kimlik doğrulaması yapmayı sağlayan bir certificate template oluşturmayı mümkün kılar. PKI nesneleri Configuration NC içinde bulunduğundan, yazılabilir bir child DC'nin ele geçirilmesi ESC5 saldırılarının gerçekleştirilmesine imkan verir.

Bununla ilgili daha fazla detayı [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) makalesinde okuyabilirsiniz. ADCS olmayan senaryolarda, saldırgan gerekli bileşenleri kurma yeteneğine sahiptir; bu konu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) makalesinde tartışılmaktadır.

### External Forest Domain - One-Way (Inbound) or bidirectional
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
Bu senaryoda **domain'iniz** dış bir domain tarafından trusted edilmiş olup, size onun üzerinde **belirsiz permissions** vermiştir. Hangi domain principals'lerinizin dış domain üzerinde hangi erişime sahip olduğunu bulmanız ve ardından bunu exploit etmeye çalışmanız gerekecek:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Harici Forest Domain - Tek Yönlü (Outbound)
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
In this senaryoda **alanınız**, **farklı bir alandan** gelen bir principal'e bazı **yetkiler** veriyor.

Ancak, bir **domain trusting domain tarafından trust edildiğinde**, trusted domain, **tahmin edilebilir isimli bir kullanıcı** oluşturur ve **parola olarak trusted password** kullanır. Bu, trusting domain'deki bir kullanıcıya **erişerek trusted domaine girmek**, onu keşfetmek ve daha fazla ayrıcalık yükseltmeye çalışmak için mümkün olduğu anlamına gelir:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i ele geçirmenin bir diğer yolu, domain trust'unun **ters yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu çok yaygın değildir).

Trusted domain'i ele geçirmenin başka bir yolu da, **trusted domain'den bir kullanıcının RDP ile giriş yapabildiği** bir makinede beklemektir. Saldırgan daha sonra RDP oturumu sürecine kod enjekte edebilir ve oradan **kurbanın asıl domainine erişebilir**.  
Ayrıca, eğer **kurban sabit diskini mount ettiyse**, saldırgan **RDP session** sürecinden sabit diskin **startup folder**'ına **backdoors** yerleştirebilir. Bu teknik **RDPInception** olarak adlandırılır.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust kötüye kullanımı azaltma

### **SID Filtering:**

- Ormanlar arası trustlarda SID history özniteliğini kullanan saldırı riski, tüm inter-forest trust'larda varsayılan olarak etkin olan SID Filtering ile azaltılır. Bu, Microsoft'un yaklaşımına göre güvenlik sınırını domain yerine forest olarak kabul eden varsayıma dayanır.
- Ancak bir sorun vardır: SID Filtering uygulamaları ve kullanıcı erişimini bozabilir; bu yüzden zaman zaman devre dışı bırakılabilir.

### **Selective Authentication:**

- Inter-forest trust'lar için Selective Authentication kullanılması, iki ormandan gelen kullanıcıların otomatik olarak kimlik doğrulamasına izin verilmemesini sağlar. Bunun yerine, kullanıcıların trusting domain veya forest içindeki domainlere ve sunuculara erişebilmesi için açık izinler gerekir.
- Bu önlemlerin writable Configuration Naming Context (NC)'in kötüye kullanımı veya trust account'a yönelik saldırılara karşı koruma sağlamadığını not etmek önemlidir.

[**Domain trust'ları hakkında daha fazla bilgi ired.team'de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Kimlik bilgilerini koruma hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Kimlik Bilgilerini Koruma için Savunma Önlemleri**

- **Domain Admins Restrictions**: Domain Admins'in sadece Domain Controller'lara giriş yapmasına izin verilmesi ve diğer hostlarda kullanılmaması önerilir.
- **Service Account Privileges**: Servisler güvenlik için Domain Admin (DA) yetkileriyle çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA yetkisi gerektiren görevler için süre sınırlı olmalıdır. Bu şu komutla yapılabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Aldatma (Deception) Tekniklerini Uygulama**

- Aldatma uygulamak, parola süresi dolmayan veya Trusted for Delegation olarak işaretlenmiş gibi özelliklere sahip tuzak kullanıcılar veya bilgisayarlar oluşturmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya bunları yüksek ayrıcalıklı gruplara eklemeyi içerir.
- Pratik bir örnek aşağıdaki komutların kullanılmasını içerir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Aldatma tekniklerini dağıtma hakkında daha fazlasını [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)'ta bulabilirsiniz.

### **Aldatmayı Tespit Etme**

- **User Nesneleri için**: Şüpheli göstergeler arasında alışılmadık ObjectSID, nadir oturum açmalar, oluşturulma tarihleri ve düşük kötü parola sayıları bulunur.
- **Genel Göstergeler**: Potansiyel tuzak nesnelerin özniteliklerini gerçek nesnelerinkilerle karşılaştırmak tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar bu tür aldatmaları tespit etmede yardımcı olabilir.

### **Tespit Sistemlerini Atlama**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA tespitini önlemek için Domain Controller'larda oturum numaralandırmasından kaçınmak.
- **Ticket Impersonation**: Ticket oluşturmak için **aes** anahtarlarının kullanılması, NTLM'e düşürme yapmayarak tespitten kaçınmaya yardımcı olur.
- **DCSync Attacks**: ATA tespitini önlemek için bir Domain Controller olmayan makinadan yürütülmesi tavsiye edilir; çünkü doğrudan bir Domain Controller'dan yürütülmesi uyarıları tetikler.

## Referanslar

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
