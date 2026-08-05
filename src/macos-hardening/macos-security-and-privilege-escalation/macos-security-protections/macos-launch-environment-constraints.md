# macOS Launch/Environment Kısıtlamaları ve Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS'taki launch constraints, bir sürecin **nasıl, kim tarafından ve nereden başlatılabileceğini düzenleyerek** güvenliği artırmak amacıyla kullanıma sunulmuştur. macOS Ventura ile başlayan bu kısıtlamalar, **her system binary'sini farklı constraint kategorilerine ayıran** bir framework sağlar. Bu kategoriler, system binary'lerini ve bunlara karşılık gelen hash'leri içeren **trust cache** içinde tanımlanır. Bu kısıtlamalar sistemdeki her executable binary için geçerlidir ve **belirli bir binary'yi başlatmak** için karşılanması gereken gereksinimleri tanımlayan bir dizi **kural** içerir. Kurallar; bir binary'nin karşılaması gereken self constraints, parent process tarafından karşılanması gereken parent constraints ve diğer ilgili varlıkların uyması gereken responsible constraints içerir.

Bu mekanizma, macOS Sonoma'dan itibaren **Environment Constraints** aracılığıyla third-party app'lere de uygulanır ve geliştiricilerin **environment constraints için bir anahtar ve değer kümesi belirleyerek** app'lerini korumasına olanak tanır.

**launch environment ve library constraints**'ı, ya **`launchd` property list** dosyalarında ya da code signing sırasında kullandığınız **ayrı property list** dosyalarında sakladığınız constraint dictionary'lerinde tanımlarsınız.

4 tür constraint vardır:

- **Self Constraints**: **Çalışan** binary'ye uygulanan constraint'lerdir.
- **Parent Process**: Sürecin **parent'ına** uygulanan constraint'lerdir (örneğin, bir XP service'i çalıştıran **`launchd`**)
- **Responsible Constraints**: Bir XPC communication içinde **service'i çağıran sürece** uygulanan constraint'lerdir.
- **Library load constraints**: Yüklenebilecek code'u seçici bir şekilde tanımlamak için library load constraints kullanılır.

Bir process başka bir process'i başlatmaya çalıştığında — `execve(_:_:_:)` veya `posix_spawn(_:_:_:_:_:_:)` çağrısı yaparak — operating system, **executable** dosyanın **kendi self constraint**'ini karşılayıp karşılamadığını kontrol eder. Ayrıca **parent** **process**'in executable'ının, executable'ın **parent constraint**'ini karşılayıp karşılamadığını ve **responsible** **process**'in executable'ının executable'ın responsible process constrain**t**'ini karşılayıp karşılamadığını da kontrol eder. Bu launch constraint'lerinden herhangi biri karşılanmazsa operating system programı çalıştırmaz.

Bir library yüklenirken **library constraint**'in herhangi bir bölümü doğru değilse process'iniz library'yi **yüklemez**.

## LC Kategorileri

Bir LC, gerçekleri ve bu gerçekleri birleştiren **logical operation**'ları (and, or..) içerir.

Bir LC'nin kullanabileceği [**facts belgelenmiştir**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Örneğin:

- is-init-proc: Executable'ın operating system'in initialization process'i (`launchd`) olması gerekip gerekmediğini belirten Boolean değer.
- is-sip-protected: Executable'ın System Integrity Protection (SIP) tarafından korunan bir dosya olması gerekip gerekmediğini belirten Boolean değer.
- `on-authorized-authapfs-volume:` Operating system'in executable'ı yetkilendirilmiş ve doğrulanmış bir APFS volume'ünden yükleyip yüklemediğini belirten Boolean değer.
- `on-authorized-authapfs-volume`: Operating system'in executable'ı yetkilendirilmiş ve doğrulanmış bir APFS volume'ünden yükleyip yüklemediğini belirten Boolean değer.
- Cryptexes volume
- `on-system-volume:` Operating system'in executable'ı o anda boot edilmiş system volume'ünden yükleyip yüklemediğini belirten Boolean değer.
- /System içinde...
- ...

Bir Apple binary'si sign edildiğinde, **trust cache** içinde onu bir LC kategorisine **atar**.

- **iOS 16 LC kategorileri** [**burada reverse edilip belgelenmiştir**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Güncel **LC kategorileri (macOS 14** - Somona) reverse edilmiştir ve [**açıklamalarına buradan ulaşılabilir**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Örneğin Category 1 şöyledir:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: System veya Cryptexes volume içinde olmalıdır.
- `launch-type == 1`: Bir system service olmalıdır (LaunchDaemons içindeki plist).
- `validation-category == 1`: Bir operating system executable olmalıdır.
- `is-init-proc`: Launchd

### LC Categories'i Tersine Mühendislik

[**Burada bunun hakkında**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints) daha fazla bilgi bulabilirsiniz; ancak temelde bunlar **AMFI (AppleMobileFileIntegrity)** içinde tanımlanır. Bu nedenle **KEXT**'i edinmek için Kernel Development Kit'i indirmeniz gerekir. **`kConstraintCategory`** ile başlayan semboller **ilgi çekici** olanlardır. Bunları çıkardığınızda, [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) veya python-asn1 kütüphanesi ve daha anlaşılır bir string sağlayacak `dump.py` script'i ile decode etmeniz gereken DER (ASN.1) encoded bir stream elde edersiniz; [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master).<sup>[[3]](#references)</sup>

## Environment Constraints

Bunlar **third party applications** içinde yapılandırılmış Launch Constraints'tır. Developer, kendi application'ına erişimi kısıtlamak için application'ında kullanılacak **facts** ve **logical operands**'ı seçebilir.

Bir application'ın Environment Constraints'larını şu şekilde enumerate etmek mümkündür:
```bash
codesign -d -vvvv app.app
```
## Trust Cache'leri

**macOS** içinde birkaç trust cache bulunur:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

iOS'ta ise bunun **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** içinde olduğu görülüyor.

> [!WARNING]
> Apple Silicon cihazlarda çalışan macOS'ta, Apple tarafından imzalanmış bir binary trust cache içinde değilse AMFI onu yüklemeyi reddeder.

### Trust Cache'leri Listeleme

Önceki trust cache dosyaları **IMG4** ve **IM4P** formatındadır; IM4P, IMG4 formatının payload bölümüdür.

Veritabanlarının payload bölümünü çıkarmak için [**pyimg4**](https://github.com/m1stadev/PyIMG4) kullanabilirsiniz:
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(Başka bir seçenek de [**img4tool**](https://github.com/tihmstar/img4tool) aracını kullanmaktır; sürüm eski olsa bile M1 üzerinde, x86_64 için ise uygun konumlara yüklediğinizde çalışır).

Artık bilgileri okunabilir bir formatta almak için [**trustcache**](https://github.com/CRKatri/trustcache) aracını kullanabilirsiniz:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Trust cache aşağıdaki yapıyı izler; dolayısıyla **LC kategorisi 4. sütundur**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Ardından, verileri çıkarmak için [**bu script**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) gibi bir script kullanabilirsiniz.

Bu verilerden **`0` launch constraints değerine sahip** App'leri kontrol edebilirsiniz; bunlar kısıtlanmamış olanlardır (her değerin ne anlama geldiğini görmek için [**buraya bakın**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)).<sup>[[6]](#references)</sup>

## Saldırı Azaltmaları

Launch Constraints, eski saldırıların birkaçını **process'in beklenmeyen koşullarda çalıştırılmayacağından emin olarak** azaltabilirdi: Örneğin beklenmeyen konumlardan veya beklenmeyen bir parent process tarafından çağrıldığında (onu yalnızca launchd başlatabiliyorsa).

Ayrıca Launch Constraints, **downgrade attacks** riskini de azaltır.

Ancak bunlar yaygın **XPC** abuse'larını, **Electron** code injection'larını veya library validation olmadan gerçekleştirilen **dylib injection**'larını azaltmaz (library yükleyebilecek team ID'leri biliniyor olsa bile).<sup>[[3]](#references)</sup>

### XPC Daemon Protection

Sonoma sürümünde dikkat çeken bir nokta, daemon XPC service'in **responsibility configuration** ayarıdır. XPC service'ten connecting client sorumlu olmak yerine, XPC service kendisinden sorumludur. Bu durum, feedback report FB13206884'te belgelenmiştir. Bu yapı kusurlu görünebilir, çünkü XPC service ile belirli etkileşimlere izin verir:

- **XPC Service'i başlatma**: Bunun bir bug olduğu varsayılsa bile bu yapı, attacker code aracılığıyla XPC service'in başlatılmasına izin vermez.
- **Aktif bir Service'e bağlanma**: XPC service zaten çalışıyorsa (muhtemelen kendi original application'ı tarafından etkinleştirilmiştir), ona bağlanmanın önünde herhangi bir engel yoktur.

XPC service üzerinde constraints uygulamak **olası saldırılar için pencereyi daraltarak** faydalı olabilir; ancak temel sorunu çözmez. XPC service'in güvenliğini sağlamak, temelde **connecting client'ı etkili biçimde validate etmeyi** gerektirir. Service'in güvenliğini güçlendirmenin tek yöntemi budur. Ayrıca, bahsedilen responsibility configuration'ın şu anda çalışır durumda olduğunu ve bunun amaçlanan tasarımla örtüşmeyebileceğini belirtmek gerekir.<sup>[[3]](#references)</sup>

### Electron Protection

Application'ın **LaunchService tarafından açılması** zorunlu olsa bile (parents constraints içinde), bu işlem **`open`** kullanılarak (env variable'lar ayarlanabilir) veya **Launch Services API** kullanılarak (env variable'lar burada belirtilebilir) gerçekleştirilebilir.<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Spawn time'da yerleşik constraints'lerin override edilmesi

Launch constraints (resmî olarak **lightweight code requirements**, *LWCR*), **AMFI MAC policy** tarafından uygulanır. `posix_spawn`, bir caller'ın **`posix_spawnattr_setmacpolicyinfo_np()`** aracılığıyla bir MAC policy'ye rastgele bir blob iletmesine izin verir ve AMFI, bu yol üzerinden caller tarafından sağlanan bir LWCR dictionary'yi kabul ediyordu. Bug'ın nedeni, **attacker tarafından sağlanan constraints'lerin binary'nin yerleşik constraints'lerini ek olarak kontrol edilmek yerine değiştirmesiydi**:

- Minimal (hatta boş) bir launch-constraints dictionary oluşturun.
- **Constraint category'yi `127` olarak ayarlayın**; bu değer AMFI'nin spawn attributes içinde izin verdiği ancak **uygulamadığı** bir değerdir — çalıştırmayı engellemek yerine yalnızca `Launch Constraint Violation (not enforcing)` log'lar.
- Bunu spawn attributes üzerinden iletin; böylece process, gerçek self/parent constraints'lerinin yasaklayacağı bir context içinde başlatılır.

Fix sonrasında hem yerleşik hem de sağlanan constraints validate edilir; dolayısıyla sağlanan dictionary artık yerleşik constraint'i zayıflatamaz.<sup>[[2]](#references)</sup>

> [!TIP]
> Constraints enforcement'ı audit ederken aranacak genel yapı şudur: Untrusted input'un bir policy *sağlamasına* izin veren bir API, policy engine sağlanan değeri ek bir gereksinim yerine replacement olarak ele aldığında genellikle ilgi çekicidir.

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: macOS'ta Launch Constraints'leri Bypass Etme (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch ve Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Bir system app veya command tool neden çalışmaz? Launch constraints ve trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Mac app'inizi environment constraints ile koruyun - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [iOS 16'da tanıtılan Launch Constraints açıklaması (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
