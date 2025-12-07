# Active Directory Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **ağ yöneticilerinin** bir ağ içinde **domain**leri, **kullanıcıları** ve **nesneleri** verimli bir şekilde oluşturup yönetmesini sağlayan temel bir teknolojidir. Ölçeklenebilir olacak şekilde tasarlanmıştır; çok sayıda kullanıcıyı yönetilebilir **gruplar** ve **alt gruplar** halinde organize etmeye ve farklı seviyelerde **erişim haklarını** kontrol etmeye imkan verir.

**Active Directory** yapısı üç ana katmandan oluşur: **domain**ler, **tree**ler ve **forest**ler. Bir **domain**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesneler koleksiyonunu kapsar. **Tree**ler, ortak bir yapıyı paylaşan bu domainlerin gruplarıdır ve bir **forest**, birbirleriyle **trust relationships** aracılığıyla bağlantılı birden fazla tree koleksiyonunu temsil ederek organizasyon yapısının en üst katmanını oluşturur. Her bir seviyede belirli **erişim** ve **iletişim hakları** atanabilir.

Active Directory içindeki ana kavramlar şunlardır:

1. **Directory** – Active Directory nesnelerine ait tüm bilgileri barındırır.
2. **Object** – Directory içindeki varlıkları, örneğin **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** olarak tanımlar.
3. **Domain** – Directory nesneleri için bir konteyner görevi görür; bir **forest** içinde birden fazla domain bulunabilir ve her biri kendi nesne koleksiyonuna sahiptir.
4. **Tree** – Ortak bir root domaini paylaşan domainlerin gruplanmasıdır.
5. **Forest** – Active Directory'deki organizasyon yapısının zirvesidir; birbiriyle **trust relationships** içinde olan birden fazla tree'den oluşur.

**Active Directory Domain Services (AD DS)**, ağ içindeki merkezi yönetim ve iletişim için kritik olan çeşitli servisleri kapsar. Bu servisler şunlardır:

1. **Domain Services** – Veriyi merkezi olarak depolar ve **kullanıcılar** ile **domain**ler arasındaki etkileşimleri yönetir; **authentication** ve **search** fonksiyonlarını içerir.
2. **Certificate Services** – Güvenli **dijital sertifikaların** oluşturulması, dağıtımı ve yönetimini denetler.
3. **Lightweight Directory Services** – **LDAP protocol**ü ile directory destekli uygulamaları destekler.
4. **Directory Federation Services** – Birden fazla web uygulaması arasında tek oturum açma (**single-sign-on**) yeteneği sağlar.
5. **Rights Management** – Telif hakkı korumada, materyalin yetkisiz dağıtım ve kullanımını sınırlamada yardımcı olur.
6. **DNS Service** – **domain name** çözümlemesi için kritik öneme sahiptir.

Daha detaylı açıklama için bakınız: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD'ye nasıl saldırılacağını öğrenmek için **Kerberos authentication process**i çok iyi **anlamanız** gerekir.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

AD'yi enumerate/exploit etmek için hangi komutları çalıştırabileceğinizi hızlıca görmek için şu adrese bakabilirsiniz: [https://wadcoms.github.io/](https://wadcoms.github.io)

> [!WARNING]
> Kerberos iletişimi işlem yapabilmek için **full qualifid name (FQDN)** gerektirir. Bir makineye IP adresi ile erişmeye çalışırsanız, **NTLM kullanılır ve Kerberos kullanılmaz**.

## Recon Active Directory (No creds/sessions)

Eğer bir AD ortamına erişiminiz varsa fakat hiçbir kimlik bilgisine/oturuma sahip değilseniz, şunları yapabilirsiniz:

- **Pentest the network:**
- Ağı tarayın, makineleri ve açık portları bulun ve **vulnerabilities**i exploit etmeye veya bu makinelerden **credentials** çekmeye çalışın (örneğin, [printers could be very interesting targets](ad-information-in-printers.md)).
- DNS'i enumerate etmek domain içindeki web, printers, shares, vpn, media vb. gibi önemli sunucular hakkında bilgi verebilir.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunun nasıl yapılacağı hakkında daha fazla bilgi için Genel [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına bakın.
- **Check for null and Guest access on smb services** (bu modern Windows sürümlerinde çalışmayabilir):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB sunucusunu enumerate etme konusunda daha detaylı rehber burada bulunabilir:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'ı enumerate etme konusunda daha detaylı rehber burada bulunabilir (özellikle **anonymous access**e dikkat edin):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) ile kimlik bilgilerini toplayın
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ile hosta erişin
- **fake UPnP services with evil-S** ile **exposing** yaparak kimlik bilgileri toplayın (SDP) [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- İç belgelerden, sosyal medyadan, domain içindeki servislerden (özellikle web) ve genel olarak kamuya açık kaynaklardan kullanıcı adlarını/isimleri çıkarın.
- Şirket çalışanlarının tam isimlerini bulursanız, farklı AD **username conventions**lerini deneyebilirsiniz ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). En yaygın konvansiyonlar: _NameSurname_, _Name.Surname_, _NamSur_ (her birinden 3 harf), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _rastgele harf ve 3 rastgele sayı_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarına bakın.
- **Kerbrute enum**: Geçersiz bir kullanıcı adı istendiğinde sunucu **Kerberos error** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıt vererek kullanıcı adının geçersiz olduğunu doğrulamamıza izin verir. **Geçerli kullanıcı adları** ya bir **TGT in a AS-REP** yanıtı verecek ya da kullanıcının pre-authentication yapması gerektiğini belirten _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını döndürecektir.
- **No Authentication against MS-NRPC**: Domain controller'larda MS-NRPC (Netlogon) arayüzüne auth-level = 1 (No authentication) kullanarak bağlanmak. Yöntem, MS-NRPC arayüzüne bind edildikten sonra `DsrGetDcNameEx2` fonksiyonunu çağırarak kullanıcı veya bilgisayarın kimlik bilgisi olmadan var olup olmadığını kontrol eder. Bu tür bir enumeration’u uygulayan araç [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)'dir. Araştırma şuradan okunabilir: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Ağda bu sunuculardan birini bulursanız, ayrıca **user enumeration against it** gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
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
> Kullanıcı adı listelerini [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  ve şu ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) depolarında bulabilirsiniz.
>
> Ancak, bu noktadan önce yapmış olmanız gereken recon adımından şirkette çalışan kişilerin **isimlerini** elde etmiş olmalısınız. İsim ve soyisim ile potansiyel geçerli kullanıcı adları oluşturmak için [**namemash.py**](https://gist.github.com/superkojiman/11076951) scriptini kullanabilirsiniz.

### Knowing one or several usernames

Tamam, zaten geçerli bir kullanıcı adına sahipsiniz ama şifreler yok... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Eğer bir kullanıcının _DONT_REQ_PREAUTH_ özniteliği **yoksa**, o kullanıcı için şifre türetilmiş bir anahtarla şifrelenmiş bazı veriler içerecek bir **AS_REP message** talep edebilirsiniz.
- [**Password Spraying**](password-spraying.md): Keşfedilen her kullanıcı ile en **yaygın password'leri** deneyin; belki bazı kullanıcılar zayıf bir şifre kullanıyordur (şifre politikasını unutmayın!).
- Ayrıca kullanıcıların mail sunucularına erişmeye çalışmak için **spray OWA servers** da deneyebilirsiniz.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Ağın bazı protokollerini **poisoning** yaparak kırmak için bazı challenge **hashes** **obtain** edebilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Eğer Active Directory'yi enumerate etmeyi başardıysanız **daha fazla e-posta ve ağ hakkında daha iyi bir anlayışa** sahip olursunuz. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) zorlayarak AD ortamına erişim elde edebilirsiniz.

### Steal NTLM Creds

Eğer **null veya guest user** ile diğer PC'lere veya paylaşımlara **access** sağlayabiliyorsanız, erişildiğinde size karşı bir NTLM authentication'ı **trigger** edecek (ör. bir SCF file) **place files** koyabilirsiniz; böylece kırmak için **NTLM challenge**'ı **steal** edebilirsiniz:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Bu aşama için geçerli bir domain hesabının kimlik bilgilerini veya oturumunu **compromised** etmiş olmanız gerekir. Eğer domain kullanıcısı olarak geçerli kimlik bilgilerine veya bir shell'e sahipseniz, önce verilen seçeneklerin diğer kullanıcıları ele geçirmek için hâlâ seçenekler olduğunu unutmayın.

Authenticated enumeration'a başlamadan önce **Kerberos double hop problem**'i bilmelisiniz.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Bir hesabı ele geçirmek, tüm domain'i ele geçirmek için **büyük bir adımdır**, çünkü **Active Directory Enumeration**'a başlayabileceksiniz:

[**ASREPRoast**](asreproast.md) ile şimdi potansiyel olarak zayıf her kullanıcıyı bulabilirsiniz; [**Password Spraying**](password-spraying.md) ile tüm kullanıcı adlarının bir **listesini** elde edip ele geçirilmiş hesabın şifresini, boş şifreleri ve yeni umut vadeden şifreleri deneyebilirsiniz.

- Temel bir recon yapmak için [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) kullanabilirsiniz.
- Daha gizli olması açısından [**powershell for recon**](../basic-powershell-for-pentesters/index.html) da kullanabilirsiniz.
- Daha detaylı bilgi çıkarmak için [**use powerview**](../basic-powershell-for-pentesters/powerview.md) kullanabilirsiniz.
- Active Directory keşfinde başka harika bir araç da [**BloodHound**](bloodhound.md). Bu araç **çok da gizli değildir** (kullandığınız collection yöntemlerine bağlı olarak), ama **eğer bundan rahatsız değilseniz** kesinlikle denemelisiniz. Kullanıcıların nerelerde RDP yapabildiğini bulun, diğer gruplara giden yolları tespit edin, vb.
- **Diğer otomatik AD enumeration araçları şunlardır:** [**AD Explorer**](bloodhound.md#ad-explorer), [**ADRecon**](bloodhound.md#adrecon), [**Group3r**](bloodhound.md#group3r), [**PingCastle**](bloodhound.md#pingcastle).
- [**DNS records of the AD**](ad-dns-records.md) çünkü ilginç bilgiler içerebilir.
- Dizini enumerate etmek için kullanabileceğiniz bir **GUI tool** **AdExplorer.exe**'dir ve **SysInternal** Suite'ten gelir.
- LDAP veritabanında **ldapsearch** ile _userPassword_ & _unixUserPassword_ alanlarında kimlik bilgilerini ya da _Description_ içinde şifre arayabilirsiniz. Diğer yöntemler için bkz. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment).
- **Linux** kullanıyorsanız, domain'i [**pywerview**](https://github.com/the-useless-one/pywerview) ile de enumerate edebilirsiniz.
- Ayrıca şu otomatik araçları da deneyebilirsiniz:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)

**Extracting all domain users**

Windows'ta tüm domain kullanıcı adlarını elde etmek çok kolaydır (`net user /domain`, `Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta ise şunu kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Enumeration bölümü kısa görünse bile bu en önemli kısımdır. Linklere (özellikle cmd, powershell, powerview ve BloodHound olanlara) gidin, bir domain'i nasıl enumerate edeceğinizi öğrenin ve rahat hissedene kadar pratik yapın. Bir assessment sırasında burası DA'ya ulaşmanın yolunu bulmak ya da hiçbir şey yapılamayacağına karar vermek için kilit an olacaktır.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı hizmetler tarafından kullanılan **TGS tickets**'ı elde etmeyi ve bunların şifrelemesini —ki bu kullanıcı şifrelerine dayanır— **offline** olarak kırmayı içerir.

Detaylar için:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Bazı kimlik bilgileri elde ettiğinizde herhangi bir **machine**'a erişiminiz olup olmadığını kontrol edebilirsiniz. Bu amaçla, port taramalarınıza göre farklı protokollerle birden fazla sunucuya bağlanmayı denemek için **CrackMapExec** kullanabilirsiniz.

### Local Privilege Escalation

Eğer normal bir domain kullanıcısı olarak kimlik bilgilerini veya bir oturumu ele geçirdiyseniz ve bu kullanıcı ile domain içindeki herhangi bir **machine**'a erişiminiz varsa, yerel olarak yetki yükseltme yollarını aramalı ve kimlik bilgilerini toplamaya çalışmalısınız. Çünkü sadece local administrator yetkisiyle diğer kullanıcıların hash'lerini bellekten (LSASS) ve yerel olarak (SAM) dump edebilirsiniz.

Kitapta [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) konusunda tam bir sayfa ve bir [**checklist**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Current Session Tickets

Mevcut kullanıcıda beklenmeyen kaynaklara erişim izni veren **tickets** bulmanız çok **unlikely**, fakat yine de kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Active Directory'yi listelemeyi başardıysanız **daha fazla e-posta ve ağ hakkında daha iyi bir anlayış** elde etmiş olursunuz. NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** zorlayabilirsiniz.**

### Looks for Creds in Computer Shares | SMB Shares

Artık bazı temel kimlik bilgilerine sahipseniz, AD içinde paylaşılan herhangi bir **ilginç dosya** bulup bulamayacağınızı kontrol etmelisiniz. Bunu manuel yapabilirsiniz ama çok sıkıcı ve tekrarlayan bir iştir (ve yüzlerce belge bulursanız kontrol etmeniz gereken daha çok iş olur).

[**Bu bağlantıyı izleyerek kullanabileceğiniz araçları öğrenin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Eğer diğer PCs veya paylaşımlara erişebiliyorsanız, erişildiğinde sizin aleyhinize bir **NTLM authentication** tetikleyecek dosyalar (ör. bir SCF file) **yerleştirebilirsiniz**, böylece **NTLM challenge'ını çalıp** kırabilirsiniz:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu zafiyet herhangi bir doğrulanmış kullanıcıya **domain controller'ı ele geçirme** imkanı sağlıyordu.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Aşağıdaki teknikler için normal bir domain kullanıcısı yeterli değildir, bu saldırıları gerçekleştirmek için bazı özel ayrıcalıklar/kimlik bilgilerine ihtiyacınız vardır.**

### Hash extraction

Umarım [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (relay dahil), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) gibi yöntemlerle bazı local admin hesaplarını **compromise** etmeyi başarmışsınızdır.\
Sonra, bellekteki ve yereldeki tüm hash'leri dump etme zamanı.\
[**Farklı hash elde etme yöntemleri hakkında bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Bir kullanıcının hash'ini elde ettiğinizde**, bunu o kullanıcıyı **taklit etmek** için kullanabilirsiniz.\
Bu hash'i kullanarak **NTLM authentication** gerçekleştirecek bir **tool** kullanmanız gerekir, **veya** yeni bir **sessionlogon** oluşturup bu **hash**'i **LSASS** içine **inject** edebilirsiniz; böylece herhangi bir **NTLM authentication** yapıldığında o **hash** kullanılacaktır. Son seçenek mimikatz'in yaptığıdır.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Bu saldırı, yaygın Pass The Hash over NTLM protokolüne alternatif olarak, **kullanıcı NTLM hash'ini Kerberos ticket talep etmek için kullanmayı** hedefler. Bu nedenle, NTLM protokolünün devre dışı bırakıldığı ve yalnızca **Kerberos'un authentication protokolü olarak izin verildiği** ağlarda özellikle **kullanışlı** olabilir.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) saldırı yönteminde, saldırganlar şifre veya hash değerleri yerine bir kullanıcının **authentication ticket'ını çalarlar**. Çalınan bu ticket daha sonra kullanıcıyı **taklit etmek** için kullanılır ve ağ içindeki kaynaklara ve servislere yetkisiz erişim sağlar.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Eğer bir **local administrato**rın **hash**'ine veya **parolasına** sahipseniz, bunu kullanarak diğer **PCs**'lere **yerel olarak oturum açmayı** denemelisiniz.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **noisy** and **LAPS** would **mitigate** it.

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Ayrıca, eğer bir MSSQL instance'ı farklı bir MSSQL instance tarafından trusted (database link) olarak kabul ediliyorsa ve kullanıcı trusted database üzerinde yetkiye sahipse, **güven ilişkisini kullanarak diğer instance üzerinde de sorgu çalıştırabilecek**. Bu trust'lar zincirlenebilir ve nihayetinde kullanıcı komut çalıştırabileceği yanlış yapılandırılmış bir veritabanı bulabilir.\
**Databases arasındaki linkler forest trust'ları arasında bile çalışır.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Discovering a **Spool service listening** within the domain can be **abused** to **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** provides a system for managing the **local Administrator password** on domain-joined computers, ensuring it's **randomized**, unique, and frequently **changed**. These passwords are stored in Active Directory and access is controlled through ACLs to authorized users only. With sufficient permissions to access these passwords, pivoting to other computers becomes possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** from the compromised machine could be a way to escalate privileges inside the environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

If **vulnerable templates** are configured it's possible to abuse them to escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object in Active Directory ensures the security of **privileged groups** (like Domain Admins and Enterprise Admins) by applying a standard **Access Control List (ACL)** across these groups to prevent unauthorized changes. However, this feature can be exploited; if an attacker modifies the AdminSDHolder's ACL to give full access to a regular user, that user gains extensive control over all privileged groups. This security measure, meant to protect, can thus backfire, allowing unwarranted access unless closely monitored.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: This is a common setup within the same forest, where a child domain automatically has a two-way transitive trust with its parent domain. Essentially, this means that authentication requests can flow seamlessly between the parent and the child.
- **Cross-link Trusts**: Referred to as "shortcut trusts," these are established between child domains to expedite referral processes. In complex forests, authentication referrals typically have to travel up to the forest root and then down to the target domain. By creating cross-links, the journey is shortened, which is especially beneficial in geographically dispersed environments.
- **External Trusts**: These are set up between different, unrelated domains and are non-transitive by nature. According to [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts are useful for accessing resources in a domain outside of the current forest that isn't connected by a forest trust. Security is bolstered through SID filtering with external trusts.
- **Tree-root Trusts**: These trusts are automatically established between the forest root domain and a newly added tree root. While not commonly encountered, tree-root trusts are important for adding new domain trees to a forest, enabling them to maintain a unique domain name and ensuring two-way transitivity. More information can be found in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: This type of trust is a two-way transitive trust between two forest root domains, also enforcing SID filtering to enhance security measures.
- **MIT Trusts**: These trusts are established with non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts are a bit more specialized and cater to environments requiring integration with Kerberos-based systems outside the Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
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
Domain trusts'ları enumerate etmenin diğer yolları:
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
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> You can the one used by the current domain them with:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC)'nin nasıl kötüye kullanılabileceğini anlamak kritik öneme sahiptir. Configuration NC, Active Directory (AD) ortamlarında ormanda bulunan yapılandırma verilerinin merkezi deposu olarak çalışır. Bu veriler forest içindeki her Domain Controller (DC) ile replike edilir; writable DC'ler Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu kötüye kullanmak için bir DC üzerinde **SYSTEM** ayrıcalıklarına sahip olmak gerekir; tercihen bir child DC.

**Link GPO to root DC site**

Configuration NC'nin Sites konteyneri, AD forest içindeki tüm domaine katılmış bilgisayarların site bilgilerini içerir. Herhangi bir DC üzerinde SYSTEM ayrıcalıklarıyla hareket ederek, saldırganlar root DC site'larına GPO'lar bağlayabilir. Bu eylem, bu sitelere uygulanan politikaları manipüle ederek root domain'i potansiyel olarak ele geçirme riski taşır.

Detaylı bilgi için [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) üzerine yapılan araştırmalar incelenebilir.

**Compromise any gMSA in the forest**

Bir saldırı vektörü, domain içindeki ayrıcalıklı gMSA'ları hedeflemeyi içerir. gMSA'ların parolalarını hesaplamak için gerekli olan KDS Root anahtarı Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM ayrıcalıklarına sahip olunması durumunda, KDS Root anahtarına erişmek ve forest içindeki herhangi bir gMSA için parolaları hesaplamak mümkündür.

Detaylı analiz ve adım adım rehberlik için:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Tamamlayıcı delege edilmiş MSA saldırısı (BadSuccessor – migration attribute'larını kötüye kullanma):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ek dış araştırma: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Bu yöntem, yeni ayrıcalıklı AD objelerinin oluşturulmasını beklemeyi gerektirir. SYSTEM ayrıcalıkları ile bir saldırgan AD Schema'yı değiştirerek herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verebilir. Bu, yeni oluşturulan AD objeleri üzerinde yetkisiz erişim ve kontrol ile sonuçlanabilir.

Daha fazlası için [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) okunabilir.

**From DA to EA with ADCS ESC5**

ADCS ESC5 zafiyeti, PKI objeleri üzerinde kontrol sağlayarak forest içindeki herhangi bir kullanıcı olarak kimlik doğrulama yapmaya imkan veren bir certificate template oluşturmayı hedefler. PKI objeleri Configuration NC içinde bulunduğundan, yazılabilir bir child DC'nin ele geçirilmesi ESC5 saldırılarının gerçekleştirilmesine olanak tanır.

Bununla ilgili daha fazla detay için [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) okunabilir. ADCS olmayan senaryolarda, saldırgan gerekli bileşenleri kurma yeteneğine sahiptir; bu konu [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) üzerinde tartışılmaktadır.

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
Bu senaryoda **domain'iniz bir dış domain tarafından trusted** ve size onun üzerinde **belirsiz izinler** veriliyor. Dış domain üzerinde **domain'inizdeki hangi principals'in hangi erişimlere sahip olduğunu** bulup ardından bunu exploit etmeyi denemeniz gerekecek:

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
Bu senaryoda **domaininiz**, **farklı bir domain**'den gelen bir **principal**'e bazı **ayrıcalıklara** güveniyor.

Ancak, bir **domain** trusting domain tarafından **güvenildiğinde**, trusted domain **öngörülebilir bir isimle kullanıcı oluşturur** ve parola olarak **güvenilen parolayı** kullanır. Bu da, **trusting domain'den bir kullanıcıya erişip trusted domain'in içine girmek** suretiyle onu listeleyip daha fazla ayrıcalık elde etmeye çalışmanın mümkün olduğu anlamına gelir:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Trusted domain'i ele geçirmenin başka bir yolu, domain trust'ın **zıt yönünde** oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) bulmaktır (bu pek yaygın değildir).

Trusted domain'i ele geçirmenin bir diğer yolu, bir **trusted domain kullanıcısının RDP ile giriş yapabildiği** bir makinede beklemektir. Sonrasında saldırgan RDP oturumu sürecine kod enjekte edebilir ve oradan **kurbanın orijin domainine erişebilir**.\
Ayrıca, eğer **kurban sabit sürücüsünü bağladıysa**, **RDP oturumu** sürecinden saldırgan **backdoors**'u sabit sürücünün **startup folder**'ına yerleştirebilir. Bu teknik **RDPInception** olarak adlandırılır.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust istismarı azaltma

### **SID Filtering:**

- Forest'lar arası trust'larda SID history özniteliğini kullanan saldırı riski, tüm inter-forest trust'larda varsayılan olarak etkin olan SID Filtering ile azaltılır. Bu, Microsoft'un tutumuna göre güvenlik sınırını domain yerine forest olarak kabul eden ve intra-forest trust'ların güvenli olduğu varsayımına dayanır.
- Ancak bir sorun vardır: SID Filtering uygulamaları ve kullanıcı erişimini bozabilir, bu yüzden zaman zaman devre dışı bırakılabilir.

### **Selective Authentication:**

- Inter-forest trust'lar için Selective Authentication kullanılması, iki forest'taki kullanıcıların otomatik olarak kimlik doğrulanmamasını sağlar. Bunun yerine, kullanıcıların trusting domain veya forest içindeki domainlere ve sunuculara erişmesi için açık izinler gereklidir.
- Bu önlemlerin writable Configuration Naming Context (NC) istismarına veya trust hesabına yönelik saldırılara karşı koruma sağlamadığını not etmek önemlidir.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) bloodyAD-style LDAP primitives'ı x64 Beacon Object Files olarak yeniden uygular; bunlar tamamen bir on-host implant (ör. Adaptix C2) içinde çalışır. Operatörler paketi `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` ile derler, `ldap.axs`'i yükler ve beacon'dan `ldap <subcommand>` çağırır. Tüm trafik, imzalama/şifreleme ile LDAP (389) üzerinden veya otomatik sertifika onayıyla LDAPS (636) üzerinden mevcut oturum güvenlik bağlamını kullanır; bu yüzden socks proxy'leri veya disk artefaktlarına ihtiyaç yoktur.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` kısa isimleri/OU yollarını tam DN'lere çözer ve ilgili nesneleri döker.
- `get-object`, `get-attribute`, and `get-domaininfo` rastgele öznitelikleri (security descriptors dahil) ve `rootDSE`'den forest/domain metadata'sını çeker.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` LDAP üzerinden doğrudan roasting candidates, delegation ayarları ve mevcut [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) tanımlayıcılarını ortaya çıkarır.
- `get-acl` and `get-writable --detailed` DACL'i parse ederek trustees'i, hakları (GenericAll/WriteDACL/WriteOwner/attribute writes) ve inheritance'ı listeler; böylece ACL ayrıcalık yükseltmesi için anında hedefler sağlar.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP yazma primitifleri — yükseltme ve kalıcılık için

- Nesne oluşturma BOF'ları (`add-user`, `add-computer`, `add-group`, `add-ou`) operatörün yeni principal veya makine hesaplarını OU yetkilerinin bulunduğu yerlere yerleştirmesine izin verir. `add-groupmember`, `set-password`, `add-attribute` ve `set-attribute` yazma-özellik (write-property) hakları bulunduğunda hedefleri doğrudan ele geçirir.
- ACL odaklı komutlar (`add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, ve `add-dcsync`) herhangi bir AD nesnesindeki WriteDACL/WriteOwner'ı parola sıfırlamalarına, grup üyeliği kontrolüne veya DCSync replikasyon ayrıcalıklarına çevirir ve PowerShell/ADSI artıkları bırakmaz. `remove-*` karşılıkları enjekte edilen ACE'leri temizler.

### Delegation, roasting ve Kerberos kötüye kullanımı

- `add-spn`/`set-spn` ele geçirilmiş bir kullanıcıyı anında Kerberoastable yapar; `add-asreproastable` (UAC toggle) parolaya dokunmadan AS-REP roasting için işaretler.
- Delegation makroları (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) beacon üzerinden `msDS-AllowedToDelegateTo`, UAC bayraklarını veya `msDS-AllowedToActOnBehalfOfOtherIdentity`'yi yeniden yazarak constrained/unconstrained/RBCD saldırı yollarını mümkün kılar ve remote PowerShell veya RSAT ihtiyacını ortadan kaldırır.

### sidHistory enjeksiyonu, OU taşınması ve saldırı yüzeyi şekillendirme

- `add-sidhistory` kontrol edilen bir principal’in SID history’sine ayrıcalıklı SIDs enjekte eder (bkz. [SID-History Injection](sid-history-injection.md)), LDAP/LDAPS üzerinden tam gizli erişim mirası sağlar.
- `move-object` bilgisayarların veya kullanıcıların DN/OU'sunu değiştirir, saldırganın varolan delege edilmiş hakların bulunduğu OU'lara varlıkları sürükleyerek `set-password`, `add-groupmember` veya `add-spn`'i kötüye kullanmasına izin verir.
- Sıkı kapsamlı kaldırma komutları (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, vb.) operatör kimlik bilgilerini veya kalıcılığı topladıktan sonra hızlı geri alma sağlar ve telemetriyi en aza indirir.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Bazı Genel Savunmalar

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Kimlik Bilgisi Koruması için Savunma Önlemleri**

- **Domain Admins Restrictions**: Domain Admins'in yalnızca Domain Controllers'a giriş yapmasına izin verilmesi önerilir; diğer hostlarda kullanılmalarından kaçınılmalıdır.
- **Service Account Privileges**: Hizmetler güvenlik için Domain Admin (DA) ayrıcalıkları ile çalıştırılmamalıdır.
- **Temporal Privilege Limitation**: DA ayrıcalıkları gerektiren görevler için süre sınırlı tutulmalıdır. Bu şu şekilde sağlanabilir: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Aldatma (Deception) Tekniklerinin Uygulanması**

- Aldatma uygulamak, süresi dolmayan parolalar gibi özelliklere sahip veya Trusted for Delegation olarak işaretlenmiş yem kullanıcılar veya bilgisayarlar gibi tuzaklar kurmayı içerir. Ayrıntılı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya onları yüksek ayrıcalıklı gruplara eklemeyi içerir.
- Pratik bir örnek şu komutların kullanımını içerir: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Aldatma tekniklerinin uygulanması hakkında daha fazlasını şu adreste bulabilirsiniz: [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Aldatmayı Belirleme**

- **For User Objects**: Şüpheli göstergeler arasında atipik ObjectSID, seyrek oturum açma, oluşturulma tarihleri ve düşük hatalı parola sayıları bulunur.
- **General Indicators**: Olası yem nesnelerin özniteliklerinin gerçek nesnelerinkilerle karşılaştırılması tutarsızlıkları ortaya çıkarabilir. Bu tür aldatmaları tespit etmekte [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar yardımcı olabilir.

### **Tespit Sistemlerini Atlama**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA tespitini önlemek için Domain Controllers üzerinde oturum enumerasyonundan kaçınma.
- **Ticket Impersonation**: Bilet oluşturmak için **aes** anahtarlarının kullanılması, NTLM'e düşürmeyi engelleyerek tespitten kaçınmaya yardımcı olur.
- **DCSync Attacks**: ATA tespitinden kaçınmak için bir non-Domain Controller'dan yürütme önerilir; çünkü bir Domain Controller'dan doğrudan yürütme uyarıları tetikleyecektir.

## Referanslar

- http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/
- https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain
- LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation (https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
