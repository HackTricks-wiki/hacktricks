# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Temel Bilgiler**

macOS'taki **System Integrity Protection (SIP)**, en ayrıcalıklı kullanıcıların bile temel sistem klasörlerinde yetkisiz değişiklikler yapmasını önlemek üzere tasarlanmış bir mekanizmadır. Bu özellik; korunan alanlara dosya ekleme, dosyaları değiştirme veya silme gibi işlemleri kısıtlayarak sistemin bütünlüğünü korumada önemli bir rol oynar. SIP tarafından korunan başlıca klasörler şunlardır:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP'nin davranışını yöneten kurallar, **`/System/Library/Sandbox/rootless.conf`** konumunda bulunan yapılandırma dosyasında tanımlanır. Bu dosyada, başında yıldız (\*) bulunan yollar, aksi hâlde katı olan SIP kısıtlamalarının istisnaları olarak belirtilir.

Aşağıdaki örneği inceleyin:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Bu kod parçası, SIP genellikle **`/usr`** dizinini güvence altına alırken, yollarının önünde yıldız işareti (\*) bulunan belirli alt dizinlerde (`/usr/libexec/cups`, `/usr/local` ve `/usr/share/man`) değişiklik yapılmasına izin verildiğini belirtir.

Bir dizinin veya dosyanın SIP tarafından korunup korunmadığını doğrulamak için **`ls -lOd`** komutunu kullanarak **`restricted`** veya **`sunlnk`** flag'lerinin mevcut olup olmadığını kontrol edebilirsiniz. Örneğin:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Bu durumda **`sunlnk`** flag'i, `/usr/libexec/cups` dizininin kendisinin **silinemeyeceği**, ancak içindeki dosyaların oluşturulabileceği, değiştirilebileceği veya silinebileceği anlamına gelir.

Öte yandan:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Burada **`restricted`** flag'i, `/usr/libexec` dizininin SIP tarafından korunduğunu belirtir. SIP tarafından korunan bir dizinde dosyalar oluşturulamaz, değiştirilemez veya silinemez.

Ayrıca, bir dosya **`com.apple.rootless`** extended **attribute**'unu içeriyorsa, bu dosya da **SIP tarafından korunur**.

> [!TIP]
> **Sandbox** hook'u **`hook_vnode_check_setextattr`**, **`com.apple.rootless`** extended attribute'unu değiştirmeye yönelik tüm girişimleri engeller.

**SIP, diğer root eylemlerini de sınırlar**:

- Güvenilmeyen kernel extension'ları yükleme
- Apple tarafından imzalanmış process'ler için task-port alma
- NVRAM değişkenlerini değiştirme
- Kernel debugging'e izin verme

Seçenekler, bir bitflag olarak nvram değişkeninde tutulur (Intel'de `csr-active-config`, ARM'de ise boot edilen Device Tree'den okunan `lp-sip0`). Flag'leri XNU source code içindeki `csr.sh` dosyasında bulabilirsiniz:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Durumu

Aşağıdaki command ile sisteminizde SIP'in etkin olup olmadığını kontrol edebilirsiniz:
```bash
csrutil status
```
SIP'i devre dışı bırakmanız gerekiyorsa bilgisayarınızı recovery mode'da yeniden başlatmanız (başlangıç sırasında Command+R tuşlarına basarak), ardından aşağıdaki komutu çalıştırmanız gerekir:
```bash
csrutil disable
```
SIP'i etkin tutmak ancak debugging korumalarını kaldırmak istiyorsanız, bunu şu şekilde yapabilirsiniz:
```bash
csrutil enable --without debug
```
### Diğer Kısıtlamalar

- **İmzalanmamış kernel extensions** (kexts) yüklenmesini engeller ve yalnızca doğrulanmış extensions'ların sistem kernel'iyle etkileşime girmesini sağlar.
- macOS system processes'larının **debugging** edilmesini önleyerek temel system components'larını yetkisiz erişim ve değişikliklere karşı korur.
- **dtrace** gibi tools'ların system processes'larını incelemesini engelleyerek system operation'ın bütünlüğünü daha da korur.

[**SIP info hakkında bu konuşmada daha fazla bilgi edinin**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **SIP ile İlgili Entitlements**

- `com.apple.rootless.xpc.bootstrap`: launchd'yi kontrol eder
- `com.apple.rootless.install[.heritable]`: File system'e erişim
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: UF_DATAVAULT'ı yönetir
- `com.apple.rootless.xpc.bootstrap`: XPC setup capabilities
- `com.apple.rootless.xpc.effective-root`: launchd XPC üzerinden Root
- `com.apple.rootless.restricted-block-devices`: Raw block devices'a erişim
- `com.apple.rootless.internal.installer-equivalent`: Kısıtlanmamış filesystem erişimi
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: NVRAM'e tam erişim
- `com.apple.rootless.storage.label`: İlgili label ile com.apple.rootless xattr tarafından kısıtlanan files'ları değiştirir
- `com.apple.rootless.volume.VM.label`: Volume üzerindeki VM swap'i yönetir

## SIP Bypasses

SIP'i bypass etmek bir saldırgana şunları yapma olanağı sağlar:

- **User Data'ya Erişim**: Tüm user accounts'larından mail, messages ve Safari history gibi hassas user data'larını okuma.
- **TCC Bypass**: Webcam, microphone ve diğer resources'lara yetkisiz erişim vermek için TCC (Transparency, Consent, and Control) database'ini doğrudan manipüle etme.
- **Persistence Oluşturma**: Malware'i SIP-protected locations'lara yerleştirerek root privileges tarafından bile kaldırılmasına dirençli hâle getirme. Buna Malware Removal Tool (MRT) ile oynama olasılığı da dahildir.
- **Kernel Extensions Yükleme**: Ek safeguards bulunmasına rağmen SIP'i bypass etmek, unsigned kernel extensions yükleme sürecini kolaylaştırır.

### Installer Packages

**Apple'ın certificate'ı ile imzalanmış installer packages**, protections'larını bypass edebilir. Bu, standard developers tarafından imzalanan packages'ların SIP-protected directories'leri değiştirmeye çalışmaları durumunda engelleneceği anlamına gelir.

### Var Olmayan SIP file'ı

Olası bir loophole, **`rootless.conf` içinde belirtilen bir file'ın mevcut olmaması durumunda** oluşturulabilmesidir. Malware bunu system üzerinde **persistence oluşturmak** için kullanabilir. Örneğin, malicious bir program `/System/Library/LaunchDaemons` içinde, `rootless.conf` içinde listelenen ancak mevcut olmayan bir .plist file'ı oluşturabilir.

### com.apple.rootless.install.heritable

> [!CAUTION]
> **`com.apple.rootless.install.heritable`** entitlement'ı SIP'i bypass etmeye olanak tanır

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

System'in code signature'ını doğrulamasından sonra **installer package'in değiştirilebildiği** ve ardından system'in original package yerine malicious package'i yüklediği keşfedildi. Bu actions **`system_installd`** tarafından gerçekleştirildiğinden SIP bypass edilebiliyordu.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Bir package mounted image veya external drive'dan yüklenirse **installer**, binary'yi **file system'den** (SIP-protected location yerine) **execute** eder ve bu da **`system_installd`**'ın arbitrary bir binary execute etmesini sağlar.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Bu blog post'un araştırmacıları**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) macOS'un System Integrity Protection (SIP) mechanism'ında, 'Shrootless' vulnerability olarak adlandırılan bir vulnerability keşfetti. Bu vulnerability, **`com.apple.rootless.install.heritable`** entitlement'ına sahip olan **`system_installd`** daemon'ına odaklanır; bu entitlement, tüm child processes'larının SIP'in file system restrictions'larını bypass etmesine olanak tanır.<sup>[[4]](#references)</sup>

**`system_installd`** daemon'ı **Apple** tarafından imzalanmış packages'ları yükler.

Araştırmacılar, Apple-signed bir package (.pkg file) yüklenirken **`system_installd`**'ın package içinde bulunan tüm **post-install** scripts'lerini **çalıştırdığını** buldu. Bu scripts'ler default shell olan **`zsh`** tarafından çalıştırılır. `zsh`, non-interactive mode'da bile mevcutsa **`/etc/zshenv`** file'ındaki commands'ları otomatik olarak **çalıştırır**. Bu behaviour attackers tarafından exploit edilebilirdi: malicious bir `/etc/zshenv` file'ı oluşturup **`system_installd`'ın `zsh`'i invoke etmesini** bekleyerek device üzerinde arbitrary operations gerçekleştirebilirlerdi.<sup>[[4]](#references)</sup>

Ayrıca **`/etc/zshenv`'in yalnızca SIP bypass için değil, genel bir attack technique olarak kullanılabileceği** keşfedildi. Her user profile, `/etc/zshenv` ile aynı şekilde davranan ancak root permissions gerektirmeyen bir `~/.zshenv` file'ına sahiptir. Bu file, `zsh` her başlatıldığında tetiklenerek persistence mechanism olarak veya privilege elevation mechanism olarak kullanılabilir. Bir admin user `sudo -s` veya `sudo <command>` kullanarak root'a yükselirse `~/.zshenv` file'ı tetiklenir ve etkin şekilde root'a elevation gerçekleşir.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) kapsamında, aynı **`system_installd`** process'inin hâlâ abuse edilebildiği keşfedildi; çünkü **post-install script'ini `/tmp` içinde SIP tarafından korunan, random isimli bir folder'ın içine koyuyordu**. Sorun şu ki **`/tmp`'nin kendisi SIP tarafından korunmuyordu**. Bu nedenle üzerine bir **virtual image mount** etmek, ardından **installer**'ın **post-install script'ini** buraya koymasını sağlamak, virtual image'i **unmount** etmek, tüm **folders'ları yeniden oluşturmak** ve **execute edilecek payload'ı içeren post-install** script'ini eklemek mümkündü.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

**`fsck_cs`**'nin **symbolic links**'leri takip edebilmesi nedeniyle kritik bir file'ı bozması için yanıltıldığı bir vulnerability tespit edildi. Özellikle attackers, _`/dev/diskX`_'ten `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` file'ına bir link oluşturdu. _`/dev/diskX`_ üzerinde **`fsck_cs`** çalıştırılması `Info.plist`'in bozulmasına yol açtı. Bu file'ın bütünlüğü, kernel extensions'ların yüklenmesini kontrol eden operating system'in SIP'ı (System Integrity Protection) için hayati önem taşır. Bozulduğunda SIP'in kernel exclusions'larını yönetme yeteneği tehlikeye girer.<sup>[[6]](#references)</sup>

Bu vulnerability'yi exploit etmek için kullanılacak commands şunlardır:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Bu açığın istismar edilmesinin ciddi sonuçları vardır. Normalde kernel extensions için izinleri yönetmekten sorumlu olan `Info.plist` dosyası etkisiz hâle gelir. Buna, `AppleHWAccess.kext` gibi belirli extensions'ları blacklist'e alma işleminin yapılamaması da dahildir. Sonuç olarak, SIP'nin kontrol mekanizması devre dışı kaldığında bu extension yüklenebilir ve sistemin RAM'ine yetkisiz okuma ve yazma erişimi sağlanabilir.<sup>[[6]](#references)</sup>

#### [SIP tarafından korunan klasörlerin üzerine Mount](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**Koruma mekanizmasını bypass etmek için SIP tarafından korunan klasörlerin üzerine yeni bir file system mount etmek mümkündü**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Sistem, işletim sistemini yükseltmek için `bless` yardımcı programını kullanarak `Install macOS Sierra.app` içerisindeki gömülü yükleyici disk görüntüsünden önyükleme yapacak şekilde ayarlanır. Kullanılan komut aşağıdaki gibidir:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bu sürecin güvenliği, bir saldırganın boot işlemi öncesinde upgrade image (`InstallESD.dmg`) dosyasını değiştirmesi durumunda tehlikeye girebilir. Strateji, dynamic loader (dyld) bileşenini kötü amaçlı bir sürümle (`libBaseIA.dylib`) değiştirmeyi içerir. Bu değiştirme, installer başlatıldığında saldırganın kodunun çalıştırılmasını sağlar.<sup>[[7]](#references)</sup>

Saldırganın kodu, sistemin installer'a duyduğu güvenden yararlanarak upgrade süreci sırasında kontrolü ele geçirir. Saldırı, özellikle `extractBootBits` methodunu hedefleyen method swizzling aracılığıyla `InstallESD.dmg` image'ının değiştirilmesiyle gerçekleştirilir. Bu, disk image kullanılmadan önce kötü amaçlı kodun enjekte edilmesini sağlar.<sup>[[7]](#references)</sup>

Ayrıca `InstallESD.dmg` içinde, upgrade kodunun root file system'ı olarak görev yapan bir `BaseSystem.dmg` bulunur. Buraya bir dynamic library enjekte edilmesi, kötü amaçlı kodun OS-level dosyaları değiştirebilen bir process içinde çalışmasına olanak tanır ve sistemin ele geçirilme potansiyelini önemli ölçüde artırır.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) etkinliğindeki bu konuşmada, **`systemmigrationd`**'nin (SIP'i bypass edebilen) bir **bash** ve bir **perl** script'i çalıştırdığı ve bunun **`BASH_ENV`** ile **`PERL5OPT`** env variable'ları aracılığıyla abuse edilebildiği gösterilmektedir.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**bu blog gönderisinde ayrıntılı olarak açıklandığı üzere**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `InstallAssistant.pkg` paketlerindeki bir `postinstall` script'inin çalıştırılmasına izin veriliyordu:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
ve `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` içinde bir symlink oluşturmak mümkündü; bu da bir kullanıcının **herhangi bir dosyadaki kısıtlamayı kaldırmasına ve SIP korumasını atlamasına** olanak tanıyordu.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> **`com.apple.rootless.install`** entitlement'ı SIP'i bypass etmeye olanak tanır

`com.apple.rootless.install` entitlement'ının macOS'ta System Integrity Protection'ı (SIP) bypass ettiği bilinmektedir. Bu durum özellikle [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) ile bağlantılı olarak belirtilmiştir.<sup>[[10]](#references)</sup>

Bu özel durumda, `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` konumunda bulunan sistem XPC service'i bu entitlement'a sahiptir. Bu, ilgili process'in SIP kısıtlamalarını aşmasına olanak tanır. Ayrıca bu service, herhangi bir security measure uygulamadan dosyaların taşınmasına izin veren bir method sunmaktadır.<sup>[[10]](#references)</sup>

## Sealed System Snapshots

Sealed System Snapshots, Apple tarafından **macOS Big Sur (macOS 11)** ile birlikte **System Integrity Protection (SIP)** mekanizmasının bir parçası olarak, ek bir security ve system stability katmanı sağlamak amacıyla sunulan bir özelliktir. Bunlar esas olarak system volume'ün read-only sürümleridir.

Daha ayrıntılı bir açıklama:

1. **Immutable System**: Sealed System Snapshots, macOS system volume'ünü "immutable" hâle getirir; yani değiştirilemez. Bu, security veya system stability'yi tehlikeye atabilecek yetkisiz ya da kazara yapılan system değişikliklerini önler.
2. **System Software Updates**: macOS updates veya upgrades yüklediğinizde macOS yeni bir system snapshot oluşturur. macOS startup volume'ü daha sonra bu yeni snapshot'a geçmek için **APFS (Apple File System)** kullanır. Update sırasında bir sorun çıkması durumunda system her zaman önceki snapshot'a geri dönebildiğinden, updates uygulama sürecinin tamamı daha güvenli ve güvenilir hâle gelir.
3. **Data Separation**: macOS Catalina'da sunulan Data ve System volume separation kavramıyla birlikte Sealed System Snapshot özelliği, tüm data ve settings bilgilerinizin ayrı bir "**Data**" volume'ünde saklanmasını sağlar. Bu separation, data'nızı system'den bağımsız hâle getirir; bu da system updates sürecini basitleştirir ve system security'yi artırır.

Bu snapshot'ların macOS tarafından otomatik olarak yönetildiğini ve APFS'nin space sharing özellikleri sayesinde disk'inizde ek alan kaplamadığını unutmayın. Ayrıca bu snapshot'ların, tüm system'in kullanıcı tarafından erişilebilen backup'ları olan **Time Machine snapshots**'larından farklı olduğunu belirtmek önemlidir.

### Snapshots'ları Kontrol Etme

**`diskutil apfs list`** command'i **APFS volumes** ve bunların layout'ları hakkındaki **details** bilgilerini listeler:

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
</code></pre>

Önceki output'ta **kullanıcı tarafından erişilebilen konumların** `/System/Volumes/Data` altında mount edildiği görülebilir.

Ayrıca **macOS System volume snapshot'ı** `/` konumuna mount edilmiştir ve **sealed** durumundadır (OS tarafından cryptographically signed). Bu nedenle SIP bypass edilir ve bu volume modify edilirse **OS artık boot olmayacaktır**.

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
- [4] [Microsoft, System Integrity Protection'ı bypass edebilecek yeni macOS güvenlik açığı Shrootless'ı keşfetti](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple'ın fruitless rootless güvenliği, bir tweet'e sığan kodla kırıldı - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Apple'ın System Integrity Protection'ını bypass etme - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple, Installer Script'lerindeki güvenlik açıklarını azaltıyor - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: SIP-Bypass için POC artık bir tweet'e bile sığabiliyor](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
