# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Temel genel bakış

**Active Directory**, **ağ yöneticileri** için bir temel teknoloji olarak hizmet eder, **alanlar**, **kullanıcılar** ve **nesneler** oluşturup yönetmelerini sağlar. Ölçeklenebilir şekilde tasarlanmıştır, çok sayıda kullanıcıyı yönetilebilir **gruplara** ve **alt gruplara** organize etmeyi kolaylaştırırken, çeşitli seviyelerde **erişim haklarını** kontrol eder.

**Active Directory** yapısı üç ana katmandan oluşur: **alanlar**, **ağaçlar** ve **ormanlar**. Bir **alan**, ortak bir veritabanını paylaşan **kullanıcılar** veya **cihazlar** gibi nesnelerin bir koleksiyonunu kapsar. **Ağaçlar**, ortak bir yapı ile bağlantılı bu alanların gruplarıdır ve bir **orman**, birden fazla ağacın **güven ilişkileri** aracılığıyla birbirine bağlı olduğu koleksiyonu temsil eder, organizasyon yapısının en üst katmanını oluşturur. Bu seviyelerin her birinde belirli **erişim** ve **iletişim hakları** atanabilir.

**Active Directory** içindeki anahtar kavramlar şunlardır:

1. **Dizin** – Active Directory nesneleri ile ilgili tüm bilgileri barındırır.
2. **Nesne** – Dizin içindeki varlıkları, **kullanıcılar**, **gruplar** veya **paylaşılan klasörler** dahil olmak üzere belirtir.
3. **Alan** – Dizin nesneleri için bir konteyner görevi görür, bir **orman** içinde birden fazla alanın bir arada bulunabilme yeteneğine sahiptir, her biri kendi nesne koleksiyonunu korur.
4. **Ağaç** – Ortak bir kök alanı paylaşan alanların bir gruplamasıdır.
5. **Orman** – Active Directory'deki organizasyon yapısının zirvesi, aralarında **güven ilişkileri** bulunan birkaç ağaçtan oluşur.

**Active Directory Domain Services (AD DS)**, bir ağ içinde merkezi yönetim ve iletişim için kritik bir dizi hizmeti kapsar. Bu hizmetler şunları içerir:

1. **Alan Hizmetleri** – Veri depolamasını merkezileştirir ve **kullanıcılar** ile **alanlar** arasındaki etkileşimleri yönetir, **kimlik doğrulama** ve **arama** işlevselliklerini içerir.
2. **Sertifika Hizmetleri** – Güvenli **dijital sertifikaların** oluşturulması, dağıtımı ve yönetimini denetler.
3. **Hafif Dizin Hizmetleri** – **LDAP protokolü** aracılığıyla dizin destekli uygulamaları destekler.
4. **Dizin Federasyon Hizmetleri** – Bir oturumda birden fazla web uygulaması arasında kullanıcıları kimlik doğrulamak için **tek oturum açma** yetenekleri sağlar.
5. **Hak Yönetimi** – Telif hakkı materyalini korumaya yardımcı olur, yetkisiz dağıtım ve kullanımını düzenler.
6. **DNS Hizmeti** – **alan adlarının** çözümü için kritik öneme sahiptir.

Daha ayrıntılı bir açıklama için kontrol edin: [**TechTerms - Active Directory Tanımı**](https://techterms.com/definition/active_directory)

### **Kerberos Kimlik Doğrulaması**

Bir **AD'yi saldırmak** için **Kerberos kimlik doğrulama sürecini** gerçekten iyi **anlamanız** gerekir.\
[**Nasıl çalıştığını hala bilmiyorsanız bu sayfayı okuyun.**](kerberos-authentication.md)

## Hile Sayfası

AD'yi listelemek/sömürmek için hangi komutları çalıştırabileceğinizi hızlıca görmek için [https://wadcoms.github.io/](https://wadcoms.github.io) adresine göz atabilirsiniz.

## Active Directory'yi Keşfetme (Kimlik bilgisi/oturum yok)

Eğer sadece bir AD ortamına erişiminiz varsa ama hiçbir kimlik bilgisi/oturumunuz yoksa şunları yapabilirsiniz:

- **Ağı test et:**
- Ağı tarayın, makineleri ve açık portları bulun ve bunlardan **zayıflıkları sömürmeye** veya **kimlik bilgilerini çıkarmaya** çalışın (örneğin, [yazıcılar çok ilginç hedefler olabilir](ad-information-in-printers.md)).
- DNS'i listelemek, alan içindeki anahtar sunucular hakkında bilgi verebilir; web, yazıcılar, paylaşımlar, vpn, medya vb.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Bunu nasıl yapacağınız hakkında daha fazla bilgi bulmak için Genel [**Pentesting Metodolojisi**](../../generic-methodologies-and-resources/pentesting-methodology.md) sayfasına göz atın.
- **Smb hizmetlerinde null ve Misafir erişimini kontrol et** (bu modern Windows sürümlerinde çalışmayacaktır):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Bir SMB sunucusunu listelemek için daha ayrıntılı bir kılavuz burada bulunabilir:

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap'ı listele**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP'ı listelemek için daha ayrıntılı bir kılavuz burada bulunabilir (lütfen **anonim erişime** özel dikkat gösterin):

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Ağı zehirle**
- Kimlik bilgilerini [**Responder ile hizmetleri taklit ederek**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) toplayın.
- [**İletim saldırısını kötüye kullanarak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) ana makineye erişin.
- **Sahte UPnP hizmetlerini kötü-S ile** [**açığa çıkararak**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) ile kimlik bilgilerini toplayın.
- [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
- Alan ortamları içindeki iç belgelerden, sosyal medyadan, hizmetlerden (özellikle web) kullanıcı adlarını/isimlerini çıkarın ve ayrıca kamuya açık olanlardan.
- Eğer şirket çalışanlarının tam isimlerini bulursanız, farklı AD **kullanıcı adı konvansiyonlarını** deneyebilirsiniz (**[bunu okuyun](https://activedirectorypro.com/active-directory-user-naming-convention/)**). En yaygın konvansiyonlar şunlardır: _AdSoyad_, _Ad.Soyad_, _AdSoy_ (her birinin 3 harfi), _Ad.Soy_, _ASoyad_, _A.Soyad_, _SoyadAd_, _Soyad.Ad_, _SoyadA_, _Soyad.A_, 3 _rastgele harf ve 3 rastgele rakam_ (abc123).
- Araçlar:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Kullanıcı listeleme

- **Anonim SMB/LDAP listeleme:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) ve [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) sayfalarını kontrol edin.
- **Kerbrute listeleme**: Bir **geçersiz kullanıcı adı istendiğinde**, sunucu **Kerberos hatası** kodu _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ ile yanıt verecek, bu da kullanıcı adının geçersiz olduğunu belirlememizi sağlayacaktır. **Geçerli kullanıcı adları**, ya **AS-REP** yanıtında **TGT** alacak ya da _KRB5KDC_ERR_PREAUTH_REQUIRED_ hatasını verecek, bu da kullanıcının ön kimlik doğrulama yapması gerektiğini gösterir.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
- **OWA (Outlook Web Access) Sunucusu**

Eğer ağda bu sunuculardan birini bulursanız, ona karşı **kullanıcı sayımı** da gerçekleştirebilirsiniz. Örneğin, [**MailSniper**](https://github.com/dafthack/MailSniper) aracını kullanabilirsiniz:
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
> Kullanıcı adlarının listelerini [**bu github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* ve bu ([**istatistiksel-olasılıkta-kullanıcı-adları**](https://github.com/insidetrust/statistically-likely-usernames)) bulabilirsiniz.
>
> Ancak, bu adımdan önce gerçekleştirmiş olmanız gereken keşif aşamasından **şirket çalışanlarının isimlerini** almış olmalısınız. İsim ve soyadı ile [**namemash.py**](https://gist.github.com/superkojiman/11076951) scriptini kullanarak potansiyel geçerli kullanıcı adları oluşturabilirsiniz.

### Bir veya birkaç kullanıcı adını bilmek

Tamam, geçerli bir kullanıcı adınız var ama şifre yok... O zaman deneyin:

- [**ASREPRoast**](asreproast.md): Eğer bir kullanıcının _DONT_REQ_PREAUTH_ niteliği **yoksa**, o kullanıcı için **bir AS_REP mesajı talep edebilirsiniz**; bu mesaj, kullanıcının şifresinin bir türevine göre şifrelenmiş bazı veriler içerecektir.
- [**Password Spraying**](password-spraying.md): Bulduğunuz her kullanıcı için en **yaygın şifreleri** deneyelim, belki bazı kullanıcı kötü bir şifre kullanıyordur (şifre politikasını aklınızda bulundurun!).
- Ayrıca, kullanıcıların mail sunucularına erişim sağlamak için **OWA sunucularını da spray yapabilirsiniz**.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Zehirleme

Bazı zorluk **hash'lerini** elde edebilmek için **ağ** protokollerini **zehirleyerek** elde edebilirsiniz:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTML Relay

Eğer aktif dizini listelemeyi başardıysanız, **daha fazla e-posta ve ağ hakkında daha iyi bir anlayışa sahip olacaksınız**. NTML [**relay saldırılarını**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* zorlayarak AD ortamına erişim sağlayabilirsiniz.

### NTLM Kimlik Bilgilerini Çalmak

Eğer **null veya misafir kullanıcısı** ile **diğer PC'lere veya paylaşımlara erişiminiz varsa**, **dosyalar yerleştirebilirsiniz** (örneğin bir SCF dosyası) ve bu dosyaya bir şekilde erişildiğinde **sizinle NTML kimlik doğrulaması tetiklenecektir**, böylece **NTLM zorluğunu çalabilirsiniz**:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Kimlik Bilgileri/oturum ile Aktif Dizin Listeleme

Bu aşama için **geçerli bir alan hesabının kimlik bilgilerini veya oturumunu ele geçirmiş olmanız gerekir.** Eğer geçerli kimlik bilgilerine veya bir alan kullanıcısı olarak bir shell'e sahipseniz, **önceki seçeneklerin hala diğer kullanıcıları ele geçirmek için seçenekler olduğunu unutmamalısınız.**

Kimlik doğrulamalı listelemeye başlamadan önce **Kerberos çift atlama sorununu** bilmelisiniz.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Listeleme

Bir hesabı ele geçirmek, **tüm alanı ele geçirmeye başlamak için büyük bir adımdır**, çünkü **Aktif Dizin Listelemesine** başlayabileceksiniz:

[**ASREPRoast**](asreproast.md) ile artık her olası savunmasız kullanıcıyı bulabilirsiniz ve [**Password Spraying**](password-spraying.md) ile ele geçirilen hesabın şifresini, boş şifreleri ve yeni umut verici şifreleri deneyebilirsiniz.

- [**Temel bir keşif yapmak için CMD kullanabilirsiniz**](../basic-cmd-for-pentesters.md#domain-info)
- Ayrıca [**keşif için powershell kullanabilirsiniz**](../basic-powershell-for-pentesters/index.html) bu daha gizli olacaktır
- Daha ayrıntılı bilgi çıkarmak için [**powerview kullanabilirsiniz**](../basic-powershell-for-pentesters/powerview.md)
- Aktif dizinde keşif için başka bir harika araç [**BloodHound**](bloodhound.md). **Çok gizli değildir** (kullandığınız toplama yöntemlerine bağlı olarak), ama **bununla ilgilenmiyorsanız**, kesinlikle denemelisiniz. Kullanıcıların RDP yapabileceği yerleri bulun, diğer gruplara giden yolları keşfedin, vb.
- **Diğer otomatik AD listeleme araçları şunlardır:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD'nin DNS kayıtları**](ad-dns-records.md) ilginç bilgiler içerebilir.
- Dizin listelemek için kullanabileceğiniz bir **GUI aracı** **SysInternal** Suite'den **AdExplorer.exe**'dir.
- Ayrıca, _userPassword_ ve _unixUserPassword_ alanlarında veya hatta _Description_ için kimlik bilgilerini aramak üzere **ldapsearch** ile LDAP veritabanında arama yapabilirsiniz. Diğer yöntemler için [PayloadsAllTheThings'deki AD Kullanıcı yorumundaki Şifre](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) bağlantısına bakın.
- **Linux** kullanıyorsanız, [**pywerview**](https://github.com/the-useless-one/pywerview) kullanarak alanı da listeleyebilirsiniz.
- Ayrıca otomatik araçlar denemek isteyebilirsiniz:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Tüm alan kullanıcılarını çıkarmak**

Windows'tan tüm alan kullanıcı adlarını elde etmek çok kolaydır (`net user /domain`, `Get-DomainUser` veya `wmic useraccount get name,sid`). Linux'ta şunları kullanabilirsiniz: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` veya `enum4linux -a -u "user" -p "password" <DC IP>`

> Bu Listeleme bölümü küçük görünse de, bu tümünün en önemli kısmıdır. Bağlantılara erişin (özellikle cmd, powershell, powerview ve BloodHound olanlara), bir alanı nasıl listeleyeceğinizi öğrenin ve rahat hissettiğinizdeye kadar pratik yapın. Bir değerlendirme sırasında, bu DA'ya ulaşmak veya hiçbir şey yapılamayacağına karar vermek için ana an olacaktır.

### Kerberoast

Kerberoasting, kullanıcı hesaplarına bağlı hizmetler tarafından kullanılan **TGS biletlerini** elde etmeyi ve bunların şifrelemesini—kullanıcı şifrelerine dayalı olan—**çözmeyi** içerir.

Bununla ilgili daha fazla bilgi:

{{#ref}}
kerberoast.md
{{#endref}}

### Uzaktan bağlantı (RDP, SSH, FTP, Win-RM, vb.)

Bazı kimlik bilgilerini elde ettikten sonra, herhangi bir **makineye** erişiminiz olup olmadığını kontrol edebilirsiniz. Bu amaçla, **CrackMapExec** kullanarak farklı protokollerle birkaç sunucuya bağlanmayı deneyebilirsiniz.

### Yerel Yetki Yükseltme

Eğer ele geçirilmiş kimlik bilgilerine veya bir oturuma sahipseniz ve bu kullanıcı ile **alan içindeki herhangi bir makineye erişiminiz varsa**, **yerel olarak yetki yükseltme yollarını bulmaya ve kimlik bilgilerini çalmaya** çalışmalısınız. Çünkü yalnızca yerel yönetici ayrıcalıkları ile **diğer kullanıcıların** bellek (LSASS) ve yerel (SAM) içindeki hash'lerini **dökmek** mümkün olacaktır.

Bu kitapta [**Windows'ta yerel yetki yükseltme**](../windows-local-privilege-escalation/index.html) hakkında bir sayfa ve bir [**kontrol listesi**](../checklist-windows-privilege-escalation.md) bulunmaktadır. Ayrıca, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kullanmayı unutmayın.

### Mevcut Oturum Biletleri

Beklenmedik kaynaklara erişim izni veren **biletler** bulmanız çok **olasılık dışıdır**, ancak kontrol edebilirsiniz:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Eğer aktif dizini listelemeyi başardıysanız, **daha fazla e-posta ve ağ hakkında daha iyi bir anlayışa sahip olacaksınız**. NTML [**relay saldırılarını**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** gerçekleştirmeyi başarabilirsiniz.**

### **Bilgisayar Paylaşımlarında Kimlik Bilgilerini Arayın**

Artık bazı temel kimlik bilgilerine sahip olduğunuza göre, **AD içinde paylaşılan ilginç dosyaları bulup bulamayacağınızı kontrol etmelisiniz**. Bunu manuel olarak yapabilirsiniz ama bu çok sıkıcı ve tekrarlayan bir görevdir (ve kontrol etmeniz gereken yüzlerce belge bulursanız daha da fazla).

[**Kullanabileceğiniz araçlar hakkında bilgi edinmek için bu bağlantıyı takip edin.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Kimlik Bilgilerini Çal

Eğer **diğer PC'lere veya paylaşımlara erişiminiz varsa**, **dosyalar yerleştirebilirsiniz** (örneğin bir SCF dosyası) ve bu dosyalar bir şekilde erişildiğinde **sizinle NTML kimlik doğrulaması tetikleyecektir**, böylece **NTLM zorluğunu çalabilir** ve onu kırabilirsiniz:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Bu güvenlik açığı, herhangi bir kimlik doğrulaması yapılmış kullanıcının **alan denetleyicisini tehlikeye atmasına** izin verdi.

{{#ref}}
printnightmare.md
{{#endref}}

## Aktif Dizin'de Yetki Yükseltme Özel Yetkiler/Kullanıcı Oturumu ile

**Aşağıdaki teknikler için normal bir alan kullanıcısı yeterli değildir, bu saldırıları gerçekleştirmek için bazı özel yetkilere/kullanıcılara ihtiyacınız var.**

### Hash çıkarımı

Umarım [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) dahil olmak üzere relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [yerel olarak yetki yükseltme](../windows-local-privilege-escalation/index.html) kullanarak **bazı yerel yönetici** hesaplarını **tehlikeye atmayı başardınız**.\
Sonra, bellek ve yerel olarak tüm hash'leri dökme zamanı.\
[**Hash'leri elde etmenin farklı yolları hakkında bu sayfayı okuyun.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Hash'i Geç

**Bir kullanıcının hash'ine sahip olduğunuzda**, onu **taklit etmek için** kullanabilirsiniz.\
Bu **hash** ile **NTLM kimlik doğrulamasını gerçekleştirecek** bir **araç** kullanmalısınız, **ya da** yeni bir **sessionlogon** oluşturup **o hash'i** **LSASS** içine **enjekte** edebilirsiniz, böylece herhangi bir **NTLM kimlik doğrulaması yapıldığında**, o **hash kullanılacaktır.** Son seçenek, mimikatz'ın yaptığıdır.\
[**Daha fazla bilgi için bu sayfayı okuyun.**](../ntlm/index.html#pass-the-hash)

### Hash'i Aş/Key'i Geç

Bu saldırı, **kullanıcı NTLM hash'ini Kerberos biletleri talep etmek için kullanmayı** amaçlar; bu, NTLM protokolü üzerinden yaygın Pass The Hash'e alternatif olarak. Bu nedenle, bu özellikle **NTLM protokolünün devre dışı bırakıldığı** ve yalnızca **Kerberos'un** kimlik doğrulama protokolü olarak **izin verildiği** ağlarda **yararlı olabilir**.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Bileti Geç

**Pass The Ticket (PTT)** saldırı yönteminde, saldırganlar **bir kullanıcının kimlik doğrulama biletini** çalarlar, bunun yerine şifrelerini veya hash değerlerini alırlar. Bu çalınan bilet daha sonra **kullanıcıyı taklit etmek için** kullanılır ve bir ağ içindeki kaynaklara ve hizmetlere yetkisiz erişim sağlar.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Kimlik Bilgileri Yeniden Kullanımı

Eğer bir **yerel yönetici**nin **hash'ine** veya **şifresine** sahipseniz, bunu kullanarak diğer **PC'lere** **yerel olarak giriş yapmayı** denemelisiniz.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Bu durumun oldukça **gürültülü** olduğunu ve **LAPS**'ın bunu **azaltacağını** unutmayın.

### MSSQL Kötüye Kullanımı & Güvenilir Bağlantılar

Bir kullanıcının **MSSQL örneklerine erişim** yetkisi varsa, MSSQL ana bilgisayarında **komutlar çalıştırmak**, NetNTLM **hash**'ini **çalmak** veya hatta bir **relay** **saldırısı** gerçekleştirmek için bunu kullanabilir.\
Ayrıca, bir MSSQL örneği başka bir MSSQL örneği tarafından güvenilir (veritabanı bağlantısı) olarak işaretlenmişse ve kullanıcı güvenilir veritabanı üzerinde yetkilere sahipse, **güven ilişkisini kullanarak diğer örnekte de sorgular çalıştırabilecektir**. Bu güven ilişkileri zincirlenebilir ve bir noktada kullanıcı, komutları çalıştırabileceği yanlış yapılandırılmış bir veritabanı bulabilir.\
**Veritabanları arasındaki bağlantılar, orman güvenleri arasında bile çalışır.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Sınırsız Delegasyon

Eğer [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) niteliğine sahip herhangi bir Bilgisayar nesnesi bulursanız ve bilgisayarda alan yetkileriniz varsa, bilgisayara giriş yapan her kullanıcının TGT'sini bellekten dökme yeteneğine sahip olursunuz.\
Yani, eğer bir **Domain Admin bilgisayara giriş yaparsa**, onun TGT'sini dökebilir ve [Pass the Ticket](pass-the-ticket.md) kullanarak onu taklit edebilirsiniz.\
Sınırlı delegasyon sayesinde, bir Yazıcı Sunucusunu **otomatik olarak ele geçirebilirsiniz** (umarım bu bir DC olacaktır).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Sınırlı Delegasyon

Eğer bir kullanıcı veya bilgisayara "Sınırlı Delegasyon" izni verilmişse, bu, **bir kullanıcının bir bilgisayardaki bazı hizmetlere erişmek için herhangi bir kullanıcıyı taklit etmesine** olanak tanır.\
Sonrasında, eğer bu kullanıcı/bilgisayarın **hash'ini ele geçirirseniz**, **herhangi bir kullanıcıyı** (hatta alan yöneticilerini) taklit ederek bazı hizmetlere erişebilirsiniz.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Kaynak Tabanlı Sınırlı Delegasyon

Uzak bir bilgisayarın Active Directory nesnesinde **YAZMA** yetkisine sahip olmak, **yükseltilmiş yetkilerle** kod yürütme elde etmenizi sağlar:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### ACL'lerin Kötüye Kullanımı

Kompromize olmuş bir kullanıcının, bazı alan nesneleri üzerinde **ilginç yetkilere** sahip olması, daha sonra **yanal hareket etmenizi** veya **yetkileri yükseltmenizi** sağlayabilir.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Yazıcı Spooler Hizmeti Kötüye Kullanımı

Alan içinde bir **Spool hizmetinin dinlendiğini** keşfetmek, **yeni kimlik bilgileri edinmek** ve **yetkileri yükseltmek** için **kötüye kullanılabilir**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Üçüncü Taraf Oturumlarının Kötüye Kullanımı

Eğer **diğer kullanıcılar** **kompromize** olmuş makineye **erişirse**, bellekten **kimlik bilgilerini toplamak** ve hatta **onların süreçlerine beacon enjekte etmek** mümkündür.\
Genellikle kullanıcılar sisteme RDP aracılığıyla erişir, bu nedenle burada üçüncü taraf RDP oturumları üzerinde birkaç saldırı gerçekleştirme yöntemini bulabilirsiniz:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**, alan bağlı bilgisayarlardaki **yerel Yönetici parolasını** yönetmek için bir sistem sağlar, bunun **rastgele**, benzersiz ve sık sık **değiştirildiğinden** emin olur. Bu parolalar Active Directory'de saklanır ve erişim, yalnızca yetkili kullanıcılara ACL'ler aracılığıyla kontrol edilir. Bu parolalara erişim için yeterli izinlere sahip olduğunuzda, diğer bilgisayarlara geçiş yapmak mümkün hale gelir.

{{#ref}}
laps.md
{{#endref}}

### Sertifika Hırsızlığı

Kompromize olmuş makineden **sertifikaları toplamak**, ortam içinde yetkileri yükseltmenin bir yolu olabilir:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Sertifika Şablonlarının Kötüye Kullanımı

Eğer **savunmasız şablonlar** yapılandırılmışsa, bunları yetkileri yükseltmek için kötüye kullanmak mümkündür:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Yüksek Yetkili Hesap ile Post-Exploitation

### Alan Kimlik Bilgilerini Dökme

**Domain Admin** veya daha iyi bir **Enterprise Admin** yetkisi elde ettiğinizde, **alan veritabanını** dökebilirsiniz: _ntds.dit_.

[**DCSync saldırısı hakkında daha fazla bilgi burada bulunabilir**](dcsync.md).

[**NTDS.dit'i çalma hakkında daha fazla bilgi burada bulunabilir**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc olarak Süreklilik

Daha önce tartışılan bazı teknikler süreklilik için kullanılabilir.\
Örneğin, şunları yapabilirsiniz:

- Kullanıcıları [**Kerberoast**](kerberoast.md) için savunmasız hale getirin

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Kullanıcıları [**ASREPRoast**](asreproast.md) için savunmasız hale getirin

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Bir kullanıcıya [**DCSync**](#dcsync) yetkileri verin

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket saldırısı**, belirli bir hizmet için **geçerli bir Ticket Granting Service (TGS) bileti** oluşturur ve **NTLM hash**'ini kullanır (örneğin, **PC hesabının hash'i**). Bu yöntem, **hizmet yetkilerine erişmek** için kullanılır.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket saldırısı**, bir saldırganın Active Directory (AD) ortamında **krbtgt hesabının NTLM hash'ine** erişim sağlamasıdır. Bu hesap, AD ağında kimlik doğrulama için gerekli olan tüm **Ticket Granting Tickets (TGT'ler)**'i imzalamak için kullanıldığı için özeldir.

Saldırgan bu hash'i elde ettiğinde, istedikleri herhangi bir hesap için **TGT'ler** oluşturabilir (Silver ticket saldırısı).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Bunlar, **yaygın golden ticket tespit mekanizmalarını atlayacak şekilde** sahte olarak oluşturulmuş golden ticket'lardır.

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Sertifikalar Hesap Sürekliliği**

**Bir hesabın sertifikalarına sahip olmak veya bunları talep edebilmek**, kullanıcı hesabında sürekliliği sağlamak için çok iyi bir yoldur (kullanıcı parolasını değiştirse bile):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Sertifikalar Alan Sürekliliği**

**Sertifikaları kullanarak, alan içinde yüksek yetkilerle sürekliliği sağlamak da mümkündür:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Grubu

Active Directory'deki **AdminSDHolder** nesnesi, **yetkili grupların** (Domain Admins ve Enterprise Admins gibi) güvenliğini sağlamak için bu gruplar üzerinde standart bir **Erişim Kontrol Listesi (ACL)** uygular ve yetkisiz değişiklikleri önler. Ancak, bu özellik kötüye kullanılabilir; eğer bir saldırgan AdminSDHolder'ın ACL'sini düzenleyerek sıradan bir kullanıcıya tam erişim verirse, o kullanıcı tüm yetkili gruplar üzerinde geniş kontrol elde eder. Bu güvenlik önlemi, koruma amacıyla tasarlanmış olsa da, dikkatli bir şekilde izlenmediği takdirde istenmeyen erişimlere yol açabilir.

[**AdminDSHolder Grubu hakkında daha fazla bilgi burada.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Kimlik Bilgileri

Her **Domain Controller (DC)** içinde bir **yerel yönetici** hesabı bulunmaktadır. Böyle bir makinede yönetici hakları elde ederek, yerel Yönetici hash'ini **mimikatz** kullanarak çıkarabilirsiniz. Ardından, bu parolanın **kullanımını etkinleştirmek** için bir kayıt defteri değişikliği gereklidir; bu, yerel Yönetici hesabına uzaktan erişim sağlar.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Sürekliliği

Belirli alan nesneleri üzerinde bir **kullanıcıya** bazı **özel izinler** verebilir ve bu, kullanıcının gelecekte **yetkileri yükseltmesine** olanak tanır.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Güvenlik Tanımlayıcıları

**Güvenlik tanımlayıcıları**, bir **nesnenin** üzerinde **izinleri** **saklamak** için kullanılır. Eğer bir nesnenin **güvenlik tanımlayıcısında** sadece **küçük bir değişiklik** yapabilirseniz, o nesne üzerinde, ayrıcalıklı bir grubun üyesi olmanıza gerek kalmadan çok ilginç yetkilere sahip olabilirsiniz.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

**LSASS**'ı bellekte değiştirerek, tüm alan hesaplarına erişim sağlayan **evrensel bir parola** oluşturun.

{{#ref}}
skeleton-key.md
{{#endref}}

### Özel SSP

[Bir SSP'nin (Güvenlik Destek Sağlayıcısı) ne olduğunu burada öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Kendi **SSP'nizi** oluşturabilir ve makineye erişim için kullanılan **kimlik bilgilerini** **düz metin** olarak **yakalamak** için kullanabilirsiniz.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD'de **yeni bir Domain Controller** kaydeder ve belirli nesnelerde **özellikleri** (SIDHistory, SPNs...) **güncellemeleri** **log** bırakmadan **itme** işlemi yapar. **DA** yetkilerine sahip olmanız ve **kök alan** içinde olmanız gerekir.\
Yanlış veri kullanırsanız, oldukça kötü loglar ortaya çıkacaktır.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Sürekliliği

Daha önce, **LAPS parolalarını okuma iznine sahip olduğunuzda** yetkileri nasıl yükseltebileceğinizi tartıştık. Ancak, bu parolalar **sürekliliği sağlamak** için de kullanılabilir.\
Kontrol edin:

{{#ref}}
laps.md
{{#endref}}

## Orman Yetki Yükseltme - Alan Güvenleri

Microsoft, **Ormanı** güvenlik sınırı olarak görmektedir. Bu, **tek bir alanın ele geçirilmesinin, tüm Ormanın ele geçirilmesine yol açabileceği** anlamına gelir.

### Temel Bilgiler

Bir [**alan güveni**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>), bir **alan** kullanıcısının başka bir **alan** içindeki kaynaklara erişimini sağlayan bir güvenlik mekanizmasıdır. Temelde, iki alanın kimlik doğrulama sistemleri arasında bir bağlantı oluşturur ve kimlik doğrulama doğrulamalarının sorunsuz bir şekilde akmasına olanak tanır. Alanlar bir güven oluşturduğunda, güvenin bütünlüğü için kritik olan belirli **anahtarları** **Domain Controller'ları (DC'ler)** arasında değiş tokuş eder ve saklar.

Tipik bir senaryoda, bir kullanıcı **güvenilir bir alandaki** bir hizmete erişmek istiyorsa, önce kendi alanının DC'sinden **inter-realm TGT** olarak bilinen özel bir bilet talep etmelidir. Bu TGT, her iki alanın üzerinde anlaştığı bir **anahtar** ile şifrelenmiştir. Kullanıcı daha sonra bu TGT'yi **güvenilir alanın DC'sine** sunarak bir hizmet bileti (**TGS**) alır. Güvenilir alanın DC'si inter-realm TGT'yi başarıyla doğruladığında, bir TGS vererek kullanıcıya hizmete erişim izni verir.

**Adımlar**:

1. **Domain 1**'deki bir **istemci bilgisayar**, **Domain Controller (DC1)**'den **Ticket Granting Ticket (TGT)** talep etmek için **NTLM hash**'ini kullanarak süreci başlatır.
2. DC1, istemci başarılı bir şekilde kimlik doğrulandıysa yeni bir TGT verir.
3. İstemci daha sonra **Domain 2**'deki kaynaklara erişmek için gereken **inter-realm TGT**'yi DC1'den talep eder.
4. Inter-realm TGT, iki yönlü alan güveninin bir parçası olarak DC1 ve DC2 arasında paylaşılan bir **güven anahtarı** ile şifrelenmiştir.
5. İstemci, inter-realm TGT'yi **Domain 2'nin Domain Controller'ı (DC2)**'ye götürür.
6. DC2, inter-realm TGT'yi paylaşılan güven anahtarı ile doğrular ve geçerli ise, istemcinin erişmek istediği Domain 2'deki sunucu için bir **Ticket Granting Service (TGS)** verir.
7. Son olarak, istemci bu TGS'yi sunucuya sunar; bu, sunucunun hesap hash'i ile şifrelenmiştir ve Domain 2'deki hizmete erişim sağlar.

### Farklı Güvenler

**Bir güvenin 1 yönlü veya 2 yönlü olabileceğini** belirtmek önemlidir. 2 yönlü seçeneklerde, her iki alan birbirine güvenecektir, ancak **1 yönlü** güven ilişkisi durumunda bir alan **güvenilir** ve diğeri **güvenen** alan olacaktır. Son durumda, **güvenilir alandan güvenen alana** yalnızca güvenen alan içindeki kaynaklara erişim sağlayabilirsiniz.

Eğer Alan A, Alan B'ye güveniyorsa, A güvenen alan ve B güvenilir olanıdır. Ayrıca, **Alan A**'da bu bir **Çıkış güveni**; ve **Alan B**'de bu bir **Giriş güveni** olacaktır.

**Farklı güvenen ilişkileri**

- **Ana-Çocuk Güvenleri**: Bu, aynı orman içinde yaygın bir yapılandırmadır; burada bir çocuk alanı otomatik olarak ana alanı ile iki yönlü geçişli bir güvene sahiptir. Temelde, bu, kimlik doğrulama taleplerinin ana ve çocuk arasında sorunsuz bir şekilde akabileceği anlamına gelir.
- **Çapraz Bağlantı Güvenleri**: "Kısa yol güvenleri" olarak adlandırılan bu güvenler, referans süreçlerini hızlandırmak için çocuk alanları arasında kurulur. Karmaşık ormanlarda, kimlik doğrulama referanslarının genellikle orman köküne kadar gitmesi ve ardından hedef alana inmesi gerekir. Çapraz bağlantılar oluşturarak, yolculuk kısaltılır; bu, coğrafi olarak dağılmış ortamlarda özellikle faydalıdır.
- **Dış Güvenler**: Farklı, alakasız alanlar arasında kurulan bu güvenler doğası gereği geçişli değildir. [Microsoft'un belgelerine](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) göre, dış güvenler, mevcut ormanın dışında, orman güveni ile bağlı olmayan bir alandaki kaynaklara erişim için yararlıdır. Güvenlik, dış güvenlerle birlikte SID filtrelemesi ile artırılır.
- **Ağaç-kök Güvenleri**: Bu güvenler, orman kök alanı ile yeni eklenen bir ağaç kökü arasında otomatik olarak kurulur. Genellikle karşılaşılmasa da, ağaç-kök güvenleri, yeni alan ağaçlarını bir ormana eklemek için önemlidir; bu, benzersiz bir alan adı korumalarına olanak tanır ve iki yönlü geçişliliği sağlar. Daha fazla bilgi [Microsoft'un kılavuzunda](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) bulunabilir.
- **Orman Güvenleri**: Bu tür bir güven, iki orman kök alanı arasında iki yönlü geçişli bir güven olup, güvenlik önlemlerini artırmak için SID filtrelemesi uygular.
- **MIT Güvenleri**: Bu güvenler, Windows dışındaki [RFC4120 uyumlu](https://tools.ietf.org/html/rfc4120) Kerberos alanları ile kurulur. MIT güvenleri, Windows ekosisteminin dışındaki Kerberos tabanlı sistemlerle entegrasyon gerektiren ortamlara yönelik daha özel bir yapıdadır.

#### **Güvenen ilişkilerdeki diğer farklılıklar**

- Bir güven ilişkisi **geçişli** (A güveniyor B, B güveniyor C, o zaman A güveniyor C) veya **geçişli olmayan** olabilir.
- Bir güven ilişkisi **iki yönlü güven** (her ikisi de birbirine güvenir) veya **bir yönlü güven** (sadece biri diğerine güvenir) olarak kurulabilir.

### Saldırı Yolu

1. **Güvenen ilişkileri** listeleyin
2. Herhangi bir **güvenlik ilkesi** (kullanıcı/grup/bilgisayar) **diğer alanın** kaynaklarına **erişime** sahip olup olmadığını kontrol edin; belki ACE girişleri veya diğer alanın gruplarında yer alarak. **Alanlar arası ilişkileri** arayın (güven bu nedenle oluşturulmuş olabilir).
1. Bu durumda kerberoast başka bir seçenek olabilir.
3. **Hesapları ele geçirin** ve **alanlar arasında geçiş yapın**.

Saldırganlar, başka bir alandaki kaynaklara erişim sağlamak için üç ana mekanizma kullanabilir:

- **Yerel Grup Üyeliği**: İlkeler, makinelerdeki yerel gruplara eklenebilir; örneğin, bir sunucudaki "Yönetici" grubu, o makine üzerinde önemli kontrol sağlar.
- **Yabancı Alan Grup Üyeliği**: İlkeler, yabancı alandaki grupların üyeleri de olabilir. Ancak, bu yöntemin etkinliği güvenin doğasına ve grubun kapsamına bağlıdır.
- **Erişim Kontrol Listeleri (ACL'ler)**: İlkeler, belirli kaynaklara erişim sağlamak için bir **ACL**'de, özellikle bir **DACL** içindeki **ACE'ler** olarak belirtilmiş olabilir. ACL'ler, DACL'ler ve ACE'ler hakkında daha derinlemesine bilgi edinmek isteyenler için “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” başlıklı beyaz kağıt değerli bir kaynaktır.

### Çocuktan Ana Orman Yetki Yükseltmesi
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
> [!WARNING]
> **2 güvenilir anahtar** vardır, biri _Child --> Parent_ diğeri ise _Parent_ --> _Child_ için.\
> Mevcut alan tarafından kullanılanı şu şekilde bulabilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History enjeksiyonunu kullanarak çocuk/ebeveyn alanına Enterprise admin olarak yükselme:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Yazılabilir Configuration NC'yi istismar etme

Configuration Naming Context (NC)'nin nasıl istismar edilebileceğini anlamak çok önemlidir. Configuration NC, Active Directory (AD) ortamlarında bir orman genelinde yapılandırma verileri için merkezi bir depo görevi görür. Bu veriler, ormandaki her Domain Controller (DC) ile çoğaltılır ve yazılabilir DC'ler, Configuration NC'nin yazılabilir bir kopyasını tutar. Bunu istismar etmek için, bir DC üzerinde **SYSTEM ayrıcalıklarına** sahip olmak gerekir, tercihen bir çocuk DC.

**GPO'yu kök DC alanına bağlama**

Configuration NC'nin Sites konteyneri, AD ormanındaki tüm alan bağlı bilgisayarların alanları hakkında bilgi içerir. Herhangi bir DC üzerinde SYSTEM ayrıcalıkları ile çalışan saldırganlar, GPO'ları kök DC alanlarına bağlayabilir. Bu eylem, bu alanlara uygulanan politikaları manipüle ederek kök alanı tehlikeye atabilir.

Derinlemesine bilgi için, [SID Filtering'i Aşma](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) üzerine yapılan araştırmalara göz atılabilir.

**Ormandaki herhangi bir gMSA'yı tehlikeye atma**

Bir saldırı vektörü, alan içindeki ayrıcalıklı gMSA'ları hedef almaktır. gMSA'ların şifrelerini hesaplamak için gerekli olan KDS Root anahtarı, Configuration NC içinde saklanır. Herhangi bir DC üzerinde SYSTEM ayrıcalıkları ile, KDS Root anahtarına erişmek ve ormandaki herhangi bir gMSA'nın şifresini hesaplamak mümkündür.

Detaylı analiz, [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent) üzerine yapılan tartışmada bulunabilir.

**Şema değişikliği saldırısı**

Bu yöntem, yeni ayrıcalıklı AD nesnelerinin oluşturulmasını beklemeyi gerektirir. SYSTEM ayrıcalıkları ile, bir saldırgan AD Şemasını değiştirerek herhangi bir kullanıcıya tüm sınıflar üzerinde tam kontrol verebilir. Bu, yeni oluşturulan AD nesnelerine yetkisiz erişim ve kontrol sağlayabilir.

Daha fazla okuma için [Şema Değişikliği Güven Saldırıları](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) üzerine bakılabilir.

**DA'dan EA'ya ADCS ESC5 ile**

ADCS ESC5 açığı, ormandaki herhangi bir kullanıcı olarak kimlik doğrulamasını sağlayan bir sertifika şablonu oluşturmak için Kamu Anahtar Altyapısı (PKI) nesneleri üzerindeki kontrolü hedef alır. PKI nesneleri Configuration NC içinde bulunduğundan, yazılabilir bir çocuk DC'nin tehlikeye atılması ESC5 saldırılarının gerçekleştirilmesini sağlar.

Bununla ilgili daha fazla ayrıntı [DA'dan EA'ya ESC5 ile](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) makalesinde okunabilir. ADCS olmayan senaryolarda, saldırgan gerekli bileşenleri kurma yeteneğine sahiptir; bu konu [Çocuk Alan Yöneticilerinden Kurumsal Yöneticilere Yükselme](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) makalesinde tartışılmıştır.

### Dış Orman Alanı - Tek Yönlü (Giriş) veya iki yönlü
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Bu senaryoda **alanınız dış bir alan tarafından güvenilir** kılınmıştır ve size **belirsiz izinler** vermektedir. **Alanınızdaki hangi ilkelerin dış alana hangi erişime sahip olduğunu** bulmanız ve ardından bunu istismar etmeye çalışmanız gerekecek:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dış Orman Alanı - Tek Yönlü (Çıkış)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Bu senaryoda **domaininiz**, **farklı domainlerden** bir prensibe bazı **yetkiler** **güveniyor**.

Ancak, bir **domain güvenildiğinde**, güvenilen domain **tahmin edilebilir bir isimle** bir **kullanıcı oluşturur** ve bu kullanıcı **güvenilen şifreyi** **şifre** olarak kullanır. Bu, **güvenilen domain içindeki bir kullanıcıya erişim sağlamak için güvenen domainin bir kullanıcısının erişim sağlamasının mümkün olduğu** anlamına gelir ve bu kullanıcıyı listeleyip daha fazla yetki artırmaya çalışabilir:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Güvenilen domaini tehlikeye atmanın bir başka yolu, **domain güveni** yönünde **oluşturulmuş bir [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)** bulmaktır (bu çok yaygın değildir).

Güvenilen domaini tehlikeye atmanın bir başka yolu, **güvenilen domainin bir kullanıcısının erişebileceği** bir makinede beklemektir ve **RDP** üzerinden giriş yapmaktır. Ardından, saldırgan RDP oturum sürecine kod enjekte edebilir ve buradan **kurbanın orijinal domainine erişebilir**.\
Ayrıca, eğer **kurban sabit diskini bağladıysa**, **RDP oturumu** sürecinden saldırgan **sabit diskin başlangıç klasörüne** **arka kapılar** depolayabilir. Bu teknik **RDPInception** olarak adlandırılır.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain güveni kötüye kullanma azaltma

### **SID Filtreleme:**

- Orman güvenleri arasında SID geçmişi niteliğini kullanan saldırıların riski, varsayılan olarak tüm ormanlar arası güvenlerde etkinleştirilen SID Filtreleme ile azaltılmaktadır. Bu, Microsoft'un görüşüne göre ormanların güvenlik sınırı olarak kabul edilmesi nedeniyle, orman içi güvenlerin güvenli olduğu varsayımına dayanmaktadır.
- Ancak, bir sorun var: SID filtreleme, uygulamaları ve kullanıcı erişimini etkileyebilir, bu da bazen devre dışı bırakılmasına yol açabilir.

### **Seçici Kimlik Doğrulama:**

- Ormanlar arası güvenler için Seçici Kimlik Doğrulama kullanmak, iki ormandan gelen kullanıcıların otomatik olarak kimlik doğrulamasını sağlamaz. Bunun yerine, güvenen domain veya orman içindeki domainlere ve sunuculara erişim için açık izinler gereklidir.
- Bu önlemlerin, yazılabilir Yapılandırma İsimlendirme Bağlamı (NC) istismarına veya güven hesaplarına yönelik saldırılara karşı koruma sağlamadığını belirtmek önemlidir.

[**Domain güvenleri hakkında daha fazla bilgi için ired.team'e bakın.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity
{{#endref}}

## Bazı Genel Savunmalar

[**Kimlik bilgilerini koruma hakkında daha fazla bilgi edinin.**](../stealing-credentials/credentials-protections.md)

### **Kimlik Bilgisi Koruma için Savunma Önlemleri**

- **Domain Admins Kısıtlamaları**: Domain Admins'in yalnızca Domain Controller'lara giriş yapmasına izin verilmesi önerilir, diğer hostlarda kullanılmamalıdır.
- **Hizmet Hesabı Yetkileri**: Hizmetler, güvenliği sağlamak için Domain Admin (DA) yetkileri ile çalıştırılmamalıdır.
- **Geçici Yetki Sınırlaması**: DA yetkileri gerektiren görevler için süreleri sınırlı olmalıdır. Bu, `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)` ile gerçekleştirilebilir.

### **Aldatma Tekniklerini Uygulama**

- Aldatma uygulamak, şifrelerin süresiz olduğu veya Delegasyon için Güvenilir olarak işaretlendiği sahte kullanıcılar veya bilgisayarlar gibi tuzaklar kurmayı içerir. Detaylı bir yaklaşım, belirli haklara sahip kullanıcılar oluşturmayı veya bunları yüksek yetkili gruplara eklemeyi içerir.
- Pratik bir örnek, `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose` gibi araçlar kullanmaktır.
- Aldatma tekniklerini dağıtma hakkında daha fazla bilgi [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) adresinde bulunabilir.

### **Aldatmayı Tanımlama**

- **Kullanıcı Nesneleri için**: Şüpheli göstergeler arasında alışılmadık ObjectSID, nadir oturum açma, oluşturulma tarihleri ve düşük kötü şifre sayıları bulunur.
- **Genel Göstergeler**: Potansiyel sahte nesnelerin özelliklerini gerçek nesnelerin özellikleriyle karşılaştırmak, tutarsızlıkları ortaya çıkarabilir. [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) gibi araçlar, bu tür aldatmaları tanımlamaya yardımcı olabilir.

### **Algılama Sistemlerini Aşma**

- **Microsoft ATA Algılama Aşma**:
- **Kullanıcı Sayımı**: ATA algılamasını önlemek için Domain Controller'larda oturum sayımından kaçınmak.
- **Bilet Taklidi**: Bilet oluşturmak için **aes** anahtarlarını kullanmak, NTLM'ye düşmeden algılamadan kaçınmaya yardımcı olur.
- **DCSync Saldırıları**: ATA algılamasından kaçınmak için bir Domain Controller'dan değil, başka bir yerden yürütülmesi önerilir; çünkü doğrudan bir Domain Controller'dan yürütme, uyarıları tetikler.

## Referanslar

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
