# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Temel Bilgiler**

macOS'teki **System Integrity Protection (SIP)**, en ayrıcalıklı kullanıcıların bile temel sistem klasörlerinde yetkisiz değişiklikler yapmasını önlemek için tasarlanmış bir mekanizmadır. Bu özellik, korunan alanlara dosya ekleme, dosyaları değiştirme veya silme gibi işlemleri kısıtlayarak sistemin bütünlüğünü korumada kritik bir rol oynar. SIP tarafından korunan başlıca klasörler şunlardır:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP'nin davranışını yöneten kurallar, **`/System/Library/Sandbox/rootless.conf`** konumunda bulunan yapılandırma dosyasında tanımlanır. Bu dosyada, yıldız işareti (\*) ile başlayan yollar, SIP'nin normalde katı olan kısıtlamalarının istisnaları olarak belirtilir.

Aşağıdaki örneği inceleyin:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Bu alıntı, SIP genel olarak **`/usr`** dizinini güvence altına alsa da, yollarının önündeki yıldız işaretiyle (\*) belirtildiği üzere belirli alt dizinlerde (`/usr/libexec/cups`, `/usr/local` ve `/usr/share/man`) değişiklik yapılmasına izin verildiğini ifade eder.

Bir dizinin veya dosyanın SIP tarafından korunup korunmadığını doğrulamak için **`ls -lOd`** komutunu kullanarak **`restricted`** veya **`sunlnk`** flag'lerinin mevcut olup olmadığını kontrol edebilirsiniz. Örneğin:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Bu durumda, **`sunlnk`** flag'i `/usr/libexec/cups` directory'sinin kendisinin **silinemeyeceği**, ancak içindeki dosyaların oluşturulabileceği, değiştirilebileceği veya silinebileceği anlamına gelir.

Öte yandan:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Burada **`restricted`** flag'i, `/usr/libexec` dizininin SIP tarafından korunduğunu belirtir. SIP tarafından korunan bir dizinde dosyalar oluşturulamaz, değiştirilemez veya silinemez.

Ayrıca bir dosya **`com.apple.rootless`** extended **attribute** içeriyorsa, bu dosya da **SIP tarafından korunur**.

> [!TIP]
> **Sandbox** hook'u **`hook_vnode_check_setextattr`**, **`com.apple.rootless`** extended attribute'unu değiştirmeye yönelik tüm girişimleri engeller.

**SIP, root tarafından gerçekleştirilebilecek diğer işlemleri de sınırlar**:

- Güvenilmeyen kernel extension'ları yükleme
- Apple tarafından imzalanmış process'ler için task-port alma
- NVRAM variable'larını değiştirme
- Kernel debugging'e izin verme

Seçenekler, bir bitflag olarak nvram variable'ında tutulur (Intel'de `csr-active-config`; ARM'de ise boot edilmiş Device Tree'den `lp-sip0` okunur). Flag'leri XNU source code içerisindeki `csr.sh` dosyasında bulabilirsiniz:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Durumu

Aşağıdaki command ile sisteminizde SIP'in etkin olup olmadığını kontrol edebilirsiniz:
```bash
csrutil status
```
SIP'yi devre dışı bırakmanız gerekirse bilgisayarınızı recovery mode'da yeniden başlatın (başlangıç sırasında Command+R tuşlarına basarak), ardından aşağıdaki komutu çalıştırın:
```bash
csrutil disable
```
SIP'i etkin tutup debugging korumalarını kaldırmak istiyorsanız, bunu şu şekilde yapabilirsiniz:
```bash
csrutil enable --without debug
```
### Diğer Kısıtlamalar

- **İmzalanmamış kernel extension'ların** (kext'lerin) yüklenmesini engeller ve yalnızca doğrulanmış extension'ların sistem kernel'iyle etkileşime girmesini sağlar.
- macOS sistem process'lerinin **debug edilmesini** önleyerek temel sistem bileşenlerini yetkisiz erişim ve değişikliklere karşı korur.
- Sistem process'lerini incelemek için dtrace gibi **tool'ların** kullanılmasını engelleyerek sistem işlemlerinin bütünlüğünü daha da korur.

[**Bu konuşmada SIP hakkında daha fazla bilgi edinin**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **SIP ile ilgili Entitlements**

- `com.apple.rootless.xpc.bootstrap`: launchd'yi kontrol etme
- `com.apple.rootless.install[.heritable]`: Dosya sistemine erişim
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: UF_DATAVAULT'ı yönetme
- `com.apple.rootless.xpc.bootstrap`: XPC kurulum yetenekleri
- `com.apple.rootless.xpc.effective-root`: launchd XPC üzerinden Root
- `com.apple.rootless.restricted-block-devices`: Raw block device'lara erişim
- `com.apple.rootless.internal.installer-equivalent`: Kısıtlanmamış dosya sistemi erişimi
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: NVRAM'a tam erişim
- `com.apple.rootless.storage.label`: İlgili label ile com.apple.rootless xattr tarafından kısıtlanan dosyaları değiştirme
- `com.apple.rootless.volume.VM.label`: Volume üzerinde VM swap'i koruma

## SIP Bypass'leri

SIP'i bypass etmek bir saldırganın şunları yapmasını sağlar:

- **Kullanıcı Verilerine Erişme**: Tüm kullanıcı hesaplarından mail, mesajlar ve Safari geçmişi gibi hassas kullanıcı verilerini okuma.
- **TCC Bypass**: Webcam, mikrofon ve diğer kaynaklara yetkisiz erişim vermek için TCC (Transparency, Consent, and Control) veritabanını doğrudan değiştirme.
- **Persistence Sağlama**: Malware'ı SIP tarafından korunan konumlara yerleştirerek Root yetkileriyle bile kaldırılmaya karşı dirençli hale getirme. Buna Malware Removal Tool'u (MRT) değiştirme potansiyeli de dahildir.
- **Kernel Extension Yükleme**: Ek güvenlik önlemleri bulunsa da SIP'i bypass etmek, imzalanmamış kernel extension'ları yükleme sürecini kolaylaştırır.

### Installer Package'ları

**Apple'ın sertifikasıyla imzalanmış Installer package'ları** korumalarını bypass edebilir. Bu, standart developer'lar tarafından imzalanan package'ların SIP tarafından korunan dizinleri değiştirmeye çalışmaları halinde engelleneceği anlamına gelir.

### Var olmayan SIP dosyası

Olası bir loophole, **`rootless.conf` içinde belirtilen ancak mevcut olmayan bir dosyanın** oluşturulabilmesidir. Malware bunu sistemde **persistence sağlamak** için exploit edebilir. Örneğin kötü amaçlı bir program, `/System/Library/LaunchDaemons` içinde `rootless.conf` dosyasında listelenen ancak mevcut olmayan bir .plist dosyası oluşturabilir.

### com.apple.rootless.install.heritable

> [!CAUTION]
> **`com.apple.rootless.install.heritable`** entitlement'ı SIP'i bypass etmeye izin verir

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Sistemin code signature'ını doğrulamasından sonra **Installer package'ın değiştirilebildiği** ve sistemin orijinal package yerine kötü amaçlı package'ı yüklediği keşfedildi. Bu işlemler **`system_installd`** tarafından gerçekleştirildiğinden SIP bypass edilebiliyordu.<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Bir package mounted image veya external drive'dan yüklenirse **installer**, binary'yi SIP tarafından korunan bir konum yerine **o file system'dan execute** eder ve **`system_installd`**'ın arbitrary bir binary execute etmesini mümkün kılardı.<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**Bu blog postundaki araştırmacılar**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) macOS'un System Integrity Protection (SIP) mekanizmasında 'Shrootless' olarak adlandırılan bir vulnerability keşfetti. Bu vulnerability, herhangi bir child process'in SIP file system kısıtlamalarını bypass etmesine izin veren **`com.apple.rootless.install.heritable`** entitlement'ına sahip olan **`system_installd`** daemon'ını hedef alır.<sup>[4]</sup>

**`system_installd`** daemon'ı **Apple** tarafından imzalanmış package'ları yükler.

Araştırmacılar, Apple tarafından imzalanmış bir package (.pkg file) yüklenirken **`system_installd`**'ın package içinde bulunan tüm **post-install** script'lerini **çalıştırdığını** keşfetti. Bu script'ler varsayılan shell olan **`zsh`** tarafından execute edilir ve `zsh`, etkileşimli olmayan mode'da bile mevcutsa **`/etc/zshenv`** dosyasındaki komutları otomatik olarak **çalıştırır**. Saldırganlar bu behaviour'ı exploit edebilirdi: Kötü amaçlı bir `/etc/zshenv` dosyası oluşturarak ve **`system_installd`'ın `zsh`'i invoke etmesini** bekleyerek cihaz üzerinde arbitrary işlemler gerçekleştirebilirlerdi.<sup>[4]</sup>

Ayrıca **`/etc/zshenv`'in yalnızca bir SIP bypass tekniği olarak değil, genel bir saldırı tekniği olarak da kullanılabildiği** keşfedildi. Her kullanıcı profile'ında `/etc/zshenv` ile aynı şekilde davranan, ancak Root permissions gerektirmeyen bir `~/.zshenv` dosyası bulunur. Bu dosya, `zsh` her başlatıldığında tetiklenerek persistence mekanizması veya privilege elevation mekanizması olarak kullanılabilir. Bir admin user `sudo -s` veya `sudo <command>` kullanarak Root'a yükselirse `~/.zshenv` dosyası tetiklenir ve etkin şekilde Root'a yükselme sağlanır.<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) içinde aynı **`system_installd`** process'inin hâlâ abuse edilebildiği keşfedildi; çünkü **post-install script'ini `/tmp` içinde SIP tarafından korunan, rastgele isimlendirilmiş bir folder'ın içine koyuyordu**. Sorun şu ki **`/tmp`'nin kendisi SIP tarafından korunmuyordu**. Bu nedenle buraya bir **virtual image mount** etmek, ardından **installer**'ın **post-install script'ini** buraya koymasını sağlamak, virtual image'ı **unmount** etmek, tüm **folder'ları yeniden oluşturmak** ve execute edilecek **payload'ı içeren post-install** script'ini **eklemek** mümkündü.<sup>[5]</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

**Symbolic link'leri** takip edebilmesi nedeniyle **`fsck_cs`**'in kritik bir dosyayı bozacak şekilde yanıltıldığı bir vulnerability tespit edildi. Saldırganlar özellikle _`/dev/diskX`_'ten `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` dosyasına bir link oluşturdu. _`/dev/diskX`_ üzerinde **`fsck_cs`** çalıştırılması `Info.plist` dosyasının bozulmasına yol açtı. Bu dosyanın bütünlüğü, kernel extension'ların yüklenmesini kontrol eden işletim sisteminin SIP'i (System Integrity Protection) için kritik öneme sahiptir. Dosya bozulduğunda SIP'in kernel exclusion'larını yönetme yeteneği tehlikeye girer.<sup>[6]</sup>

Bu vulnerability'ı exploit etmek için kullanılan komutlar:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Bu güvenlik açığının istismar edilmesinin ciddi sonuçları vardır. Normalde kernel extensions için izinleri yönetmekten sorumlu olan `Info.plist` dosyası etkisiz hâle gelir. Buna `AppleHWAccess.kext` gibi belirli extensions'ları blacklist'e alma özelliğinin kaybedilmesi de dahildir. Sonuç olarak, SIP'nin kontrol mekanizması devre dışı kaldığında bu extension yüklenebilir ve sistemin RAM'ine yetkisiz okuma ve yazma erişimi sağlar.<sup>[6]</sup>

#### [Mount over SIP protected folders](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP tarafından korunan klasörlerin üzerine mount ederek korumayı bypass etmek** mümkündü.<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Sistem, `bless` yardımcı programını kullanarak işletim sistemini yükseltmek için `Install macOS Sierra.app` içindeki gömülü bir yükleyici disk imajından önyükleme yapacak şekilde ayarlanır. Kullanılan komut aşağıdaki gibidir:<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bu sürecin güvenliği, saldırganın önyükleme öncesinde upgrade image (`InstallESD.dmg`) üzerinde değişiklik yapması durumunda tehlikeye girebilir. Strateji, dynamic loader'ı (dyld) kötü amaçlı bir sürümle (`libBaseIA.dylib`) değiştirmeyi içerir. Bu değiştirme, installer başlatıldığında saldırganın kodunun çalıştırılmasını sağlar.<sup>[7]</sup>

Saldırganın kodu, sistemin installer'a duyduğu güvenden yararlanarak upgrade süreci sırasında kontrolü ele geçirir. Saldırı, özellikle `extractBootBits` method'unu hedefleyerek, method swizzling aracılığıyla `InstallESD.dmg` image'ının değiştirilmesiyle gerçekleştirilir. Bu, disk image kullanılmadan önce kötü amaçlı kodun enjekte edilmesine olanak tanır.<sup>[7]</sup>

Ayrıca `InstallESD.dmg` içinde, upgrade code'un root file system'ı olarak görev yapan bir `BaseSystem.dmg` bulunur. Buraya bir dynamic library enjekte edilmesi, kötü amaçlı kodun OS seviyesindeki dosyaları değiştirebilen bir process içinde çalışmasına olanak tanır ve system compromise potansiyelini önemli ölçüde artırır.<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) konuşmasında, **SIP** bypass edebilen **`systemmigrationd`**'nin, **`BASH_ENV`** ve **`PERL5OPT`** env variable'ları üzerinden abuse edilebilen bir **bash** ve bir **perl** script'i çalıştırdığı gösterilmektedir.<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**bu blog post'unda ayrıntılı olarak açıklandığı üzere**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `InstallAssistant.pkg` packages içindeki bir `postinstall` script'inin çalıştırılmasına izin veriliyordu:<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
ve `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` içinde bir symlink oluşturmak mümkündü; bu da bir kullanıcının **herhangi bir dosyanın kısıtlamasını kaldırmasına ve SIP korumasını bypass etmesine** olanak sağlıyordu.<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> **`com.apple.rootless.install`** entitlement'ı SIP'i bypass etmeye olanak tanır

`com.apple.rootless.install` entitlement'ının macOS'ta System Integrity Protection'ı (SIP) bypass ettiği bilinmektedir. Bu durum özellikle [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) ile bağlantılı olarak belirtilmiştir.<sup>[10]</sup>

Bu özel durumda, `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` konumundaki sistem XPC servisi bu entitlement'a sahiptir. Bu, ilgili process'in SIP kısıtlamalarını aşmasına olanak tanır. Ayrıca bu servis, herhangi bir security measure uygulamadan dosyaların taşınmasına izin veren bir method sunmaktadır.<sup>[10]</sup>

## Sealed System Snapshots

Sealed System Snapshots, Apple tarafından **macOS Big Sur (macOS 11)** ile birlikte, ek bir security ve system stability katmanı sağlamak amacıyla **System Integrity Protection (SIP)** mekanizmasının bir parçası olarak sunulan bir özelliktir. Bunlar esas olarak system volume'ün read-only sürümleridir.

Daha ayrıntılı bir açıklama:

1. **Immutable System**: Sealed System Snapshots, macOS system volume'ünü "immutable" hâle getirir; yani volume değiştirilemez. Bu, security veya system stability'yi tehlikeye atabilecek yetkisiz ya da kazara yapılan system değişikliklerini önler.
2. **System Software Updates**: macOS update veya upgrade'lerini yüklediğinizde macOS yeni bir system snapshot oluşturur. macOS startup volume'ü daha sonra bu yeni snapshot'a geçmek için **APFS (Apple File System)** kullanır. Update sırasında bir sorun çıkması durumunda system her zaman önceki snapshot'a dönebileceğinden, update uygulama sürecinin tamamı daha güvenli ve güvenilir hâle gelir.
3. **Data Separation**: macOS Catalina ile sunulan Data ve System volume separation kavramıyla birlikte Sealed System Snapshot özelliği, tüm data ve setting'lerinizin ayrı bir "**Data**" volume'ünde saklanmasını sağlar. Bu separation, data'nızı system'den bağımsız hâle getirir; bu da system update sürecini basitleştirir ve system security'yi artırır.

Bu snapshot'ların macOS tarafından otomatik olarak yönetildiğini ve APFS'nin space sharing özellikleri sayesinde disk'inizde ek alan kullanmadığını unutmayın. Ayrıca bu snapshot'ların, tüm system'in user-accessible backup'ları olan **Time Machine snapshots**'larından farklı olduğunu belirtmek önemlidir.

### Snapshot'ları Kontrol Etme

**`diskutil apfs list`** command'i **APFS volume'lerinin ayrıntılarını** ve layout'unu listeler:

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

Önceki output'ta **user-accessible location'ların** `/System/Volumes/Data` altında mount edildiği görülebilir.

Ayrıca **macOS System volume snapshot'ı** `/` konumuna mount edilmiştir ve **sealed** durumdadır (OS tarafından cryptographically signed). Dolayısıyla SIP bypass edilerek bu volume modify edilirse **OS artık boot olmaz**.

Ayrıca aşağıdaki command'i çalıştırarak **seal'in enabled olduğunu verify etmek** mümkündür:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Ayrıca, snapshot diski **salt okunur** olarak da bağlanır:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Referanslar

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft, System Integrity Protection'ı bypass edebilen yeni macOS güvenlik açığı Shrootless'ı keşfetti](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Teknik Analiz: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple'ın fruitless rootless güvenliği, bir tweet'e sığan kodla bozuldu - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Apple'ın System Integrity Protection'ını bypass etme - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Migren Olmak - MacOS'ta Benzersiz SIP Bypass'ı - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple, Installer Script'lerindeki Güvenlik Açıklarını Azaltıyor - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: SIP-Bypass için POC Hatta Tweet'e Sığabiliyor](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
