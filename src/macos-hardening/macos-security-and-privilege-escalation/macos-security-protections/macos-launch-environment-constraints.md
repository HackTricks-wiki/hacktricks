# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS'taki launch constraints, **bir process'in nasıl, kim tarafından ve nereden başlatılabileceğini düzenleyerek** güvenliği artırmak amacıyla kullanıma sunulmuştur. macOS Ventura'da kullanıma sunulan bu constraints, **her system binary'sini farklı constraint kategorilerine** ayıran bir framework sağlar. Bu kategoriler, system binary'lerini ve bunlara ait hash'leri içeren bir liste olan **trust cache** içinde tanımlanır. Bu constraints, system içindeki her executable binary için geçerlidir ve **belirli bir binary'yi başlatmak** için gereken koşulları tanımlayan bir dizi **kural** içerir. Kurallar, binary'nin karşılaması gereken self constraints'i, parent process'in karşılaması gereken parent constraints'i ve diğer ilgili entity'lerin uyması gereken responsible constraints'i kapsar.

Bu mekanizma, macOS Sonoma'dan itibaren **Environment Constraints** aracılığıyla üçüncü taraf uygulamalara da uygulanır ve developer'ların **environment constraints için bir dizi key ve value belirleyerek** uygulamalarını korumasına olanak tanır.

**Launch environment ve library constraints**'i, constraint dictionary'lerinde tanımlarsınız. Bu dictionary'leri **`launchd` property list dosyalarına** veya code signing sırasında kullandığınız **ayrı property list** dosyalarına kaydedebilirsiniz.

4 tür constraint vardır:

- **Self Constraints**: **Çalışan** binary'ye uygulanan constraints.
- **Parent Process**: **Process'in parent'ına** uygulanan constraints (örneğin bir XP service'i çalıştıran **`launchd`**)
- **Responsible Constraints**: Bir XPC iletişiminde **service'i çağıran process'e** uygulanan constraints
- **Library load constraints**: Yüklenebilecek code'u seçici bir şekilde tanımlamak için library load constraints'i kullanın

Dolayısıyla bir process, `execve(_:_:_:)` veya `posix_spawn(_:_:_:_:_:)` çağrısı yaparak başka bir process'i başlatmaya çalıştığında işletim sistemi, **executable** dosyanın kendi **self constraint**'ini karşılayıp karşılamadığını kontrol eder. Ayrıca **parent** **process'in** executable'ının, executable'ın **parent constraint**'ini karşılayıp karşılamadığını ve **responsible** **process'in** executable'ının executable'ın **responsible process constraint**'ini karşılayıp karşılamadığını da kontrol eder. Bu launch constraint'lerinden herhangi biri karşılanmazsa işletim sistemi programı çalıştırmaz.

Bir library yüklenirken **library constraint'in herhangi bir bölümü doğru değilse**, process'iniz library'yi **yüklemez**.

## LC Kategorileri

Bir LC, fact'lerden ve bu fact'leri birleştiren **mantıksal işlemlerden** (and, or..) oluşur.

Bir LC'nin kullanabileceği [**fact'ler belgelenmiştir**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Örneğin:

- is-init-proc: Executable'ın işletim sisteminin initialization process'i (`launchd`) olması gerekip gerekmediğini belirten bir Boolean value.
- is-sip-protected: Executable'ın System Integrity Protection (SIP) tarafından korunan bir file olması gerekip gerekmediğini belirten bir Boolean value.
- `on-authorized-authapfs-volume:` İşletim sisteminin executable'ı yetkili ve doğrulanmış bir APFS volume'ünden yükleyip yüklemediğini belirten bir Boolean value.
- `on-authorized-authapfs-volume`: İşletim sisteminin executable'ı yetkili ve doğrulanmış bir APFS volume'ünden yükleyip yüklemediğini belirten bir Boolean value.
- Cryptexes volume
- `on-system-volume:` İşletim sisteminin executable'ı o anda boot edilmiş system volume'ünden yükleyip yüklemediğini belirten bir Boolean value.
- /System içinde...
- ...

Bir Apple binary'si imzalandığında, **trust cache** içindeki bir LC kategorisine **atanır**.

- **iOS 16 LC kategorileri** [**burada reverse edilmiş ve belgelenmiştir**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[6]</sup>
- Güncel **LC kategorileri (macOS 14** - Somona) reverse edilmiştir ve [**açıklamaları burada bulunabilir**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[7]</sup>

Örneğin Category 1:<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: System veya Cryptexes volume içinde olmalıdır.
- `launch-type == 1`: Bir system service olmalıdır (LaunchDaemons içinde plist).
- `validation-category == 1`: Bir operating system executable.
- `is-init-proc`: Launchd

### LC Categories Reversing

Bu konu hakkında daha fazla bilgiyi [**burada bulabilirsiniz**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ancak temel olarak bunlar **AMFI (AppleMobileFileIntegrity)** içinde tanımlanmıştır; bu nedenle **KEXT** dosyasını edinmek için Kernel Development Kit'i indirmeniz gerekir. **`kConstraintCategory`** ile başlayan semboller **ilginç** olanlardır. Bunları çıkardığınızda, [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) veya python-asn1 library ve onun `dump.py` script'i ile decode etmeniz gereken DER (ASN.1) encoded bir stream elde edersiniz. [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) size daha anlaşılır bir string verecektir.<sup>[3]</sup>

## Environment Constraints

Bunlar **third party applications** içinde yapılandırılmış Launch Constraints'tır. Developer, kendisine erişimi kısıtlamak için uygulamasında kullanılacak **facts** ve **logical operands** öğelerini seçebilir.

Bir uygulamanın Environment Constraints öğelerini şu şekilde enumerate etmek mümkündür:
```bash
codesign -d -vvvv app.app
```
## Trust Cache'leri

**macOS** içinde birkaç trust cache bulunur:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

iOS'ta ise bunun **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** içinde bulunduğu görülüyor.

> [!WARNING]
> Apple Silicon cihazlarda çalışan macOS'ta, Apple tarafından imzalanmış bir binary trust cache içinde değilse AMFI yüklenmesini reddeder.

### Trust Cache'leri Listeleme

Önceki trust cache dosyaları **IMG4** ve **IM4P** formatındadır; IM4P, IMG4 formatının payload bölümüdür.

Veritabanlarının payload'unu çıkarmak için [**pyimg4**](https://github.com/m1stadev/PyIMG4) kullanabilirsiniz:
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
(Başka bir seçenek de [**img4tool**](https://github.com/tihmstar/img4tool) aracını kullanmaktır; sürüm eski olsa ve x86_64 için olsa bile, uygun konumlara yüklediğinizde M1 üzerinde dahi çalışır).

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
Trust cache aşağıdaki yapıyı izler; dolayısıyla **LC kategorisi 4. sütundur**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Ardından, veri çıkarmak için [**bu script**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) gibi bir script kullanabilirsiniz.

Bu verilerden, **`0` launch constraints değerine sahip** Apps'leri kontrol edebilirsiniz; bunlar kısıtlanmamış olanlardır (her bir değerin ne anlama geldiğini görmek için [**buraya bakın**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)).<sup>[6]</sup>

## Attack Mitigations

Launch Constraints, **process'in beklenmeyen koşullarda çalıştırılmamasını sağlayarak** eski birçok attack'i mitigate edebilirdi: Örneğin beklenmeyen konumlardan veya beklenmeyen bir parent process tarafından çağrıldığında (eğer onu yalnızca launchd başlatmalıysa).

Ayrıca Launch Constraints, **downgrade attack'lerini de mitigate eder.**

Ancak library validation olmadan gerçekleştirilen yaygın **XPC** abuse'larını, **Electron** code injection'larını veya **dylib injection**'larını mitigate etmezler (library'leri yükleyebilecek team ID'leri bilinmediği sürece).<sup>[3]</sup>

### XPC Daemon Protection

Sonoma sürümünde dikkat çeken bir nokta, daemon XPC service'in **responsibility configuration**'ıdır. XPC service, bağlantı kuran client'ın sorumlu olmasının aksine kendisinden sorumludur. Bu durum, FB13206884 feedback report'unda belgelenmiştir. Bu yapı kusurlu görünebilir; çünkü XPC service ile belirli etkileşimlere izin verir:

- **XPC Service'i başlatma**: Bunun bir bug olduğu varsayılırsa, bu yapı attacker code aracılığıyla XPC service'in başlatılmasına izin vermez.
- **Active Service'e bağlanma**: XPC service zaten çalışıyorsa (muhtemelen kendi original application'ı tarafından etkinleştirilmiştir), ona bağlanmanın önünde hiçbir engel yoktur.

XPC service üzerinde constraints uygulamak **potansiyel attack'ler için pencereyi daraltarak** faydalı olabilir; ancak temel endişeyi ele almaz. XPC service'in security'sini sağlamak, temelde **bağlanan client'ı etkili bir şekilde validate etmeyi** gerektirir. Service'in security'sini güçlendirmenin tek yöntemi budur. Ayrıca belirtilen responsibility configuration'ın şu anda operational olduğunu ve bunun amaçlanan design ile örtüşmeyebileceğini belirtmek gerekir.<sup>[3]</sup>

### Electron Protection

Application'ın **LaunchService tarafından açılmasının** zorunlu olduğu durumda bile (parents constraints içinde), bu işlem environment variable'ları ayarlayabilen **`open`** kullanılarak veya environment variable'ların belirtilebildiği **Launch Services API** kullanılarak gerçekleştirilebilir.<sup>[3]</sup>

### CVE-2025-43253 - Spawn time'da built-in constraints'ı override etme

Launch constraints (resmi olarak **lightweight code requirements**, *LWCR*), **AMFI MAC policy** tarafından enforce edilir. `posix_spawn`, bir caller'ın **`posix_spawnattr_setmacpolicyinfo_np()`** aracılığıyla bir MAC policy'ye arbitrary bir blob göndermesine izin verir ve AMFI bu yol üzerinden caller-supplied bir LWCR dictionary'yi kabul ediyordu. Bug, **attacker-supplied constraints'ın binary'nin built-in constraints'ının yerine geçmesi**, bunlara ek olarak kontrol edilmemesiydi:

- Minimal (hatta boş) bir launch-constraints dictionary oluşturun.
- **Constraint category'yi `127` olarak ayarlayın**; bu değer AMFI'nin spawn attributes içinde izin verdiği ancak **enforce etmediği** bir değerdir — execution'ı engellemek yerine yalnızca `Launch Constraint Violation (not enforcing)` log'lar.
- Bunu spawn attributes aracılığıyla gönderin; process, gerçek self/parent constraints'ının yasaklayacağı bir context'te launch edilir.

Fix sonrasında **hem** built-in hem de supplied constraints validate edilir; böylece supplied dictionary artık built-in constraint'ı zayıflatamaz.<sup>[2]</sup>

> [!TIP]
> Constraint enforcement'ı audit ederken aranacak genel yapı şudur: Güvenilmeyen input'un bir policy *supply etmesine* izin veren bir API, policy engine supplied değeri ek bir requirement yerine replacement olarak ele aldığında genellikle ilgi çekicidir.

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
