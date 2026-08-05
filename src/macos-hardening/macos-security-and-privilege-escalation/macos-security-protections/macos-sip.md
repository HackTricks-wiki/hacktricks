# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Temel Bilgiler**

macOS'taki **System Integrity Protection (SIP)**, en ayrıcalıklı kullanıcıların bile temel sistem klasörlerinde yetkisiz değişiklikler yapmasını önlemek üzere tasarlanmış bir mekanizmadır. Bu özellik, korunan alanlarda dosya ekleme, değiştirme veya silme gibi işlemleri kısıtlayarak sistemin bütünlüğünü korumada kritik bir rol oynar. SIP tarafından korunan başlıca klasörler şunlardır:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP'nin davranışını yöneten kurallar, **`/System/Library/Sandbox/rootless.conf`** konumunda bulunan yapılandırma dosyasında tanımlanır. Bu dosyada, başında yıldız işareti (\*) bulunan yollar, SIP'nin diğer durumlarda uyguladığı katı kısıtlamaların istisnaları olarak belirtilir.

Aşağıdaki örneği inceleyin:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Bu snippet, SIP genel olarak **`/usr`** dizinini güvence altına alsa da, yollarının önünde yıldız işareti (*) bulunan belirli alt dizinlerde (`/usr/libexec/cups`, `/usr/local` ve `/usr/share/man`) değişiklik yapılmasına izin verildiğini belirtir.

Bir dizinin veya dosyanın SIP tarafından korunup korunmadığını doğrulamak için **`ls -lOd`** komutunu kullanarak **`restricted`** veya **`sunlnk`** flag'lerinin mevcut olup olmadığını kontrol edebilirsiniz. Örneğin:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Bu durumda **`sunlnk`** flag'i, `/usr/libexec/cups` dizininin kendisinin **silinemeyeceğini**, ancak içindeki dosyaların oluşturulabileceğini, değiştirilebileceğini veya silinebileceğini belirtir.

Öte yandan:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Burada **`restricted`** flag'i, `/usr/libexec` dizininin SIP tarafından korunduğunu belirtir. SIP tarafından korunan bir dizinde dosyalar oluşturulamaz, değiştirilemez veya silinemez.

Ayrıca, bir dosya **`com.apple.rootless`** extended **attribute** içeriyorsa, bu dosya da **SIP tarafından korunur**.

> [!TIP]
> **Sandbox** hook'u **`hook_vnode_check_setextattr`**, **`com.apple.rootless`** extended attribute'unu değiştirmeye yönelik tüm girişimleri engeller.

**SIP ayrıca diğer root işlemlerini de sınırlar**:

- Güvenilmeyen kernel extension'ları yükleme
- Apple tarafından imzalanmış işlemler için task-port'ları alma
- NVRAM değişkenlerini değiştirme
- Kernel debugging'e izin verme

Seçenekler, bir bitflag olarak nvram değişkeninde tutulur (Intel'de `csr-active-config`; ARM'de ise boot edilmiş Device Tree'den `lp-sip0` okunur). Flag'leri XNU source code'unda `csr.sh` içinde bulabilirsiniz:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Durumu

Aşağıdaki komutla sisteminizde SIP'in etkin olup olmadığını kontrol edebilirsiniz:
```bash
csrutil status
```
SIP'yi devre dışı bırakmanız gerekiyorsa bilgisayarınızı recovery mode'da yeniden başlatın (başlangıç sırasında Command+R tuşlarına basarak), ardından aşağıdaki komutu çalıştırın:
```bash
csrutil disable
```
SIP'i etkin tutmak ancak debugging korumalarını kaldırmak istiyorsanız, bunu şu şekilde yapabilirsiniz:
```bash
csrutil enable --without debug
```
### Diğer Kısıtlamalar

- **İmzasız kernel extension'ların** (kext'lerin) yüklenmesini engeller ve yalnızca doğrulanmış extension'ların sistem kernel'iyle etkileşime girmesini sağlar.
- macOS system process'lerinin **debugging** edilmesini önleyerek temel system component'lerini yetkisiz erişim ve değişikliklere karşı korur.
- `dtrace` gibi tool'ların system process'lerini incelemesini engelleyerek system operation bütünlüğünü daha da korur.

[**SIP info hakkında bu konuşmada daha fazla bilgi edinin**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **SIP ile ilgili Entitlements**

- `com.apple.rootless.xpc.bootstrap`: launchd'yi kontrol etme
- `com.apple.rootless.install[.heritable]`: file system'e erişim
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: UF_DATAVAULT'u yönetme
- `com.apple.rootless.xpc.bootstrap`: XPC setup capabilities
- `com.apple.rootless.xpc.effective-root`: launchd XPC üzerinden Root
- `com.apple.rootless.restricted-block-devices`: raw block devices'a erişim
- `com.apple.rootless.internal.installer-equivalent`: Kısıtlamasız file system erişimi
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: NVRAM'e tam erişim
- `com.apple.rootless.storage.label`: karşılık gelen label ile com.apple.rootless xattr tarafından kısıtlanan dosyaları değiştirme
- `com.apple.rootless.volume.VM.label`: volume üzerindeki VM swap'i koruma

## SIP Bypass'ları

SIP'i bypass etmek bir attacker'ın şunları yapmasını sağlar:

- **User Data'ya Erişme**: Tüm user account'larından mail, messages ve Safari history gibi hassas user data'larını okuma.
- **TCC Bypass**: Webcam, microphone ve diğer resources'lara yetkisiz erişim vermek için TCC (Transparency, Consent, and Control) database'ini doğrudan değiştirme.
- **Persistence Sağlama**: Malware'i SIP-protected location'lara yerleştirerek root privileges ile bile kaldırılmaya karşı dayanıklı hale getirme. Buna Malware Removal Tool (MRT) üzerinde oynama ihtimali de dahildir.
- **Kernel Extension'ları Yükleme**: Ek safeguards bulunmasına rağmen SIP'i bypass etmek, imzasız kernel extension'ları yükleme sürecini kolaylaştırır.

### Installer Packages

**Apple'ın certificate'ı ile imzalanmış installer packages**, onun protections'ını bypass edebilir. Bu, standard developer'lar tarafından imzalanmış package'ların bile SIP-protected directory'leri değiştirmeye çalışmaları halinde engelleneceği anlamına gelir.

### Mevcut Olmayan SIP Dosyası

Olası bir loophole, bir dosya **`rootless.conf` içinde belirtilmiş ancak şu anda mevcut değilse** oluşturulabilmesidir. Malware bunu system üzerinde **persistence sağlamak** için exploit edebilir. Örneğin malicious bir program, `/System/Library/LaunchDaemons` içinde, `rootless.conf` içinde listelenmiş ancak mevcut olmayan bir .plist dosyası oluşturabilir.

### com.apple.rootless.install.heritable

> [!CAUTION]
> **`com.apple.rootless.install.heritable`** entitlement'ı SIP'i bypass etmeye olanak tanır

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

System'in code **signature'ını** doğrulamasından sonra installer package'ı **swap etmenin** mümkün olduğu ve ardından system'in original package yerine malicious package'ı yüklediği keşfedildi. Bu actions **`system_installd`** tarafından gerçekleştirildiğinden SIP bypass edilebilirdi.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Bir package mounted image veya external drive'dan yüklendiyse **installer**, binary'yi SIP-protected location yerine **o file system'dan** **execute** ederdi. Bu da **`system_installd`**'ın arbitrary bir binary execute etmesini mümkün kılardı.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Bu blog post'un araştırmacıları**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/), macOS'un System Integrity Protection (SIP) mechanism'ında 'Shrootless' vulnerability olarak adlandırılan bir vulnerability keşfetti. Bu vulnerability, **`com.apple.rootless.install.heritable`** entitlement'ına sahip olan ve tüm child process'lerinin SIP'in file system restrictions'ını bypass etmesine olanak tanıyan **`system_installd`** daemon'ı üzerinde yoğunlaşır.<sup>[[4]](#references)</sup>

**`system_installd`** daemon'ı **Apple** tarafından imzalanmış package'ları install eder.

Araştırmacılar, Apple-signed package (.pkg file) installation'ı sırasında **`system_installd`**'ın package içinde bulunan tüm **post-install** script'lerini **run** ettiğini buldu. Bu script'ler default shell olan **`zsh`** tarafından execute edilir. `zsh`, non-interactive mode'da bile, mevcutsa **`/etc/zshenv`** file'ından commands'ları otomatik olarak **run** eder. Bu behaviour attacker'lar tarafından exploit edilebilirdi: malicious bir `/etc/zshenv` file'ı oluşturarak ve **`system_installd`'ın `zsh` invoke etmesini** bekleyerek device üzerinde arbitrary operations gerçekleştirebilirlerdi.<sup>[[4]](#references)</sup>

Ayrıca **`/etc/zshenv`'in yalnızca SIP bypass için değil, genel bir attack technique olarak da kullanılabileceği** keşfedildi. Her user profile, `/etc/zshenv` ile aynı şekilde davranan ancak root permissions gerektirmeyen bir `~/.zshenv` file'ına sahiptir. Bu file, `zsh` her başladığında trigger olarak bir persistence mechanism veya privilege elevation mechanism şeklinde kullanılabilirdi. Bir admin user `sudo -s` veya `sudo <command>` kullanarak root'a elevate olursa `~/.zshenv` file'ı trigger olur ve etkin şekilde root'a elevate ederdi.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) kapsamında, aynı **`system_installd`** process'inin hâlâ abuse edilebildiği keşfedildi; çünkü **post-install script'ini `/tmp` içinde SIP tarafından korunan, random isimli bir folder'ın içine koyuyordu**. Ancak **`/tmp`'nin kendisi SIP tarafından korunmaz**, bu nedenle üzerine bir **virtual image mount** etmek, ardından **installer**'ın **post-install script'ini** buraya koymasını sağlamak, virtual image'ı **unmount** etmek, tüm **folder'ları** yeniden oluşturmak ve execute edilecek **payload**'ı içeren **post-installation** script'ini eklemek mümkündü.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

**`fsck_cs`**'nin **symbolic link'leri** takip edebilmesi nedeniyle önemli bir file'ı bozacak şekilde yanıltıldığı bir vulnerability tespit edildi. Özellikle attacker'lar _`/dev/diskX`_'ten `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` file'ına bir link oluşturdu. _`/dev/diskX`_ üzerinde **`fsck_cs`** execute edildiğinde `Info.plist` bozuldu. Bu file'ın bütünlüğü, kernel extension'ların yüklenmesini kontrol eden işletim sisteminin SIP'ı (System Integrity Protection) için hayati önem taşır. Bozulduğunda SIP'in kernel exclusion'larını yönetme yeteneği tehlikeye girer.<sup>[[6]](#references)</sup>

Bu vulnerability'yi exploit etmek için kullanılacak commands şunlardır:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Bu güvenlik açığının istismar edilmesinin ciddi sonuçları vardır. Normalde kernel extensions için izinleri yönetmekten sorumlu olan `Info.plist` dosyası etkisiz hâle gelir. Buna, `AppleHWAccess.kext` gibi belirli extensions'ları blacklist'e alma yeteneğinin kaybedilmesi de dahildir. Sonuç olarak, SIP'nin kontrol mekanizması devre dışı kaldığında bu extension yüklenebilir ve sistemin RAM'ine yetkisiz okuma ve yazma erişimi sağlar.<sup>[[6]](#references)</sup>

#### [SIP tarafından korunan klasörlerin üzerine mount etme](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**Koruma mekanizmasını bypass etmek için SIP tarafından korunan klasörlerin üzerine yeni bir file system mount etmek** mümkündü.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Sistem, işletim sistemini yükseltmek için `Install macOS Sierra.app` içinde bulunan gömülü bir installer disk image'dan `bless` utility'si kullanılarak boot edilecek şekilde ayarlanır. Kullanılan komut aşağıdaki gibidir:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bu sürecin güvenliği, saldırgan önyükleme yapmadan önce upgrade image'ı (`InstallESD.dmg`) değiştirirse tehlikeye girebilir. Strateji, bir dynamic loader'ı (dyld) kötü amaçlı bir sürümle (`libBaseIA.dylib`) değiştirmeyi içerir. Bu değiştirme, installer başlatıldığında saldırganın kodunun çalıştırılmasını sağlar.<sup>[[7]](#references)</sup>

Saldırganın kodu, sistemin installer'a duyduğu güvenden yararlanarak upgrade süreci sırasında kontrolü ele geçirir. Saldırı, özellikle `extractBootBits` method'unu hedefleyen method swizzling aracılığıyla `InstallESD.dmg` image'ının değiştirilmesiyle gerçekleştirilir. Bu, disk image kullanılmadan önce kötü amaçlı kod enjekte edilmesini sağlar.<sup>[[7]](#references)</sup>

Ayrıca `InstallESD.dmg` içinde, upgrade code'un root file system'ı olarak kullanılan bir `BaseSystem.dmg` bulunur. Buraya bir dynamic library enjekte edilmesi, kötü amaçlı kodun OS-level dosyaları değiştirebilen bir process içinde çalışmasına olanak tanır ve sistemin tehlikeye atılma potansiyelini önemli ölçüde artırır.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) konuşmasında, **`systemmigrationd`**'nin (SIP'yi bypass edebilen) bir **bash** ve bir **perl** script'i çalıştırdığı ve bunun **`BASH_ENV`** ile **`PERL5OPT`** env variable'ları üzerinden abuse edilebildiği gösteriliyor.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**bu blog yazısında ayrıntılı olarak açıklandığı üzere**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `InstallAssistant.pkg` paketlerindeki bir `postinstall` script'inin çalıştırılmasına izin veriliyordu:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
ve `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` içinde bir symlink oluşturmak mümkündü; bu da bir kullanıcının **herhangi bir dosyadaki kısıtlamaları kaldırmasına ve SIP korumasını bypass etmesine** olanak tanıyordu.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> **`com.apple.rootless.install`** entitlement'ı SIP'i bypass etmeye olanak tanır

`com.apple.rootless.install` entitlement'ının macOS'ta System Integrity Protection'ı (SIP) bypass ettiği bilinmektedir. Bu durum özellikle [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) ile bağlantılı olarak belirtilmiştir.<sup>[[10]](#references)</sup>

Bu özel durumda, `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` konumunda bulunan sistem XPC service'i bu entitlement'a sahiptir. Bu, ilgili process'in SIP kısıtlamalarını aşmasına olanak tanır. Ayrıca bu service, herhangi bir security measure uygulamadan dosyaların taşınmasına izin veren bir method sunar.<sup>[[10]](#references)</sup>

## Sealed System Snapshots

Sealed System Snapshots, ek bir security ve system stability katmanı sağlamak amacıyla **macOS Big Sur (macOS 11)** ile birlikte Apple tarafından **System Integrity Protection (SIP)** mekanizmasının bir parçası olarak sunulan bir özelliktir. Bunlar esasen system volume'ün salt okunur sürümleridir.

Daha ayrıntılı bir inceleme:

1. **Immutable System**: Sealed System Snapshots, macOS system volume'ünü "immutable" hâle getirir; yani bu volume değiştirilemez. Bu, security veya system stability'yi tehlikeye atabilecek yetkisiz ya da kazara yapılan system değişikliklerini önler.
2. **System Software Updates**: macOS updates veya upgrades yüklediğinizde macOS yeni bir system snapshot oluşturur. macOS startup volume'ü daha sonra bu yeni snapshot'a geçmek için **APFS (Apple File System)** kullanır. Update sırasında bir sorun çıkması durumunda system her zaman önceki snapshot'a geri dönebildiğinden, update uygulama sürecinin tamamı daha güvenli ve güvenilir hâle gelir.
3. **Data Separation**: macOS Catalina ile sunulan Data ve System volume separation kavramıyla birlikte Sealed System Snapshot özelliği, tüm data ve settings bilgilerinizin ayrı bir "**Data**" volume'ünde saklanmasını sağlar. Bu separation, datanızı system'den bağımsız hâle getirir; bu da system updates sürecini basitleştirir ve system security'yi artırır.

Bu snapshot'ların macOS tarafından otomatik olarak yönetildiğini ve APFS'nin space sharing özellikleri sayesinde diskinizde ek alan kaplamadığını unutmayın. Ayrıca bu snapshot'ların, tüm system'in kullanıcı tarafından erişilebilen backup'ları olan **Time Machine snapshots**'larından farklı olduğunu belirtmek önemlidir.

### Snapshots'ları Kontrol Etme

**`diskutil apfs list`** komutu, **APFS volumes'larının ayrıntılarını** ve layout'unu listeler:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
|   Encrypted:                 No
</code></pre>

Önceki çıktıda **kullanıcının erişebildiği konumların** `/System/Volumes/Data` altında mount edildiği görülebilir.

Ayrıca **macOS System volume snapshot'ı** `/` konumuna mount edilmiş ve **sealed** durumdadır (OS tarafından cryptographically signed). Dolayısıyla SIP bypass edilip bu snapshot değiştirilirse **OS artık boot etmez**.

Ayrıca şu komutu çalıştırarak **seal'in etkin olduğunu doğrulamak** mümkündür:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Ayrıca, snapshot diski de **salt okunur** olarak bağlanır:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Referanslar

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple's fruitless rootless security broken by code that fits in a tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Bypassing Apple's System Integrity Protection - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple Mitigates Vulnerabilities in Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: The POC for SIP-Bypass Is Even Tweetable](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
