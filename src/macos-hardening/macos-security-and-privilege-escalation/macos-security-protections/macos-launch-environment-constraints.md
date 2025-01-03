# macOS Başlatma/Ortam Kısıtlamaları & Güven Cache'i

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS'taki başlatma kısıtlamaları, **bir sürecin nasıl, kim tarafından ve nereden başlatılacağını düzenleyerek** güvenliği artırmak için tanıtılmıştır. macOS Ventura ile başlatılan bu kısıtlamalar, **her sistem ikili dosyasını belirli kısıtlama kategorilerine** ayıran bir çerçeve sağlar; bu kategoriler **güven cache'inde** tanımlanmıştır ve sistem ikili dosyalarını ve bunların ilgili hash'lerini içerir. Bu kısıtlamalar, sistemdeki her yürütülebilir ikili dosyayı kapsar ve **belirli bir ikili dosyanın başlatılması için gereksinimleri** belirleyen bir dizi **kural** içerir. Kurallar, bir ikilinin karşılaması gereken kendi kısıtlamalarını, ebeveyn sürecinin karşılaması gereken ebeveyn kısıtlamalarını ve diğer ilgili varlıkların uyması gereken sorumlu kısıtlamaları kapsar.

Mekanizma, macOS Sonoma'dan itibaren **Ortam Kısıtlamaları** aracılığıyla üçüncü taraf uygulamalara da uzanır ve geliştiricilerin uygulamalarını korumalarına olanak tanır; bu, bir **dizi anahtar ve değer belirleyerek** yapılır.

**Başlatma ortamı ve kütüphane kısıtlamalarını** ya **`launchd` özellik listesi dosyalarında** ya da kod imzalamada kullandığınız **ayrı özellik listesi** dosyalarında tanımlarsınız.

4 tür kısıtlama vardır:

- **Kendi Kısıtlamaları**: **çalışan** ikiliye uygulanan kısıtlamalar.
- **Ebeveyn Süreci**: **sürecin ebeveynine** uygulanan kısıtlamalar (örneğin **`launchd`** bir XP hizmetini çalıştırıyorsa)
- **Sorumlu Kısıtlamalar**: **hizmeti çağıran sürece** uygulanan kısıtlamalar bir XPC iletişimi içinde
- **Kütüphane yükleme kısıtlamaları**: Yüklenebilecek kodu seçici olarak tanımlamak için kütüphane yükleme kısıtlamalarını kullanın

Bir süreç başka bir süreci başlatmaya çalıştığında — `execve(_:_:_:)` veya `posix_spawn(_:_:_:_:_:_:)` çağrısı yaparak — işletim sistemi, **yürütülebilir** dosyanın **kendi kısıtlamasını** **karşılayıp karşılamadığını** kontrol eder. Ayrıca, **ebeveyn** **sürecinin** yürütülebilirinin **yürütülebilirin ebeveyn kısıtlamasını** **karşılayıp karşılamadığını** ve **sorumlu** **sürecin** yürütülebilirinin **yürütülebilirin sorumlu süreç kısıtlamasını** **karşılayıp karşılamadığını** kontrol eder. Bu başlatma kısıtlamalarından herhangi biri karşılanmazsa, işletim sistemi programı çalıştırmaz.

Bir kütüphane yüklenirken **kütüphane kısıtlamasının** herhangi bir kısmı doğru değilse, süreciniz **kütüphaneyi yüklemez**.

## LC Kategorileri

Bir LC, **gerçekler** ve **mantıksal işlemler** (ve, veya..) ile oluşturulmuştur ve gerçekleri birleştirir.

[**Bir LC'nin kullanabileceği gerçekler belgelenmiştir**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Örneğin:

- is-init-proc: Yürütülebilir dosyanın işletim sisteminin başlatma süreci (`launchd`) olup olmadığını belirten bir Boolean değeri.
- is-sip-protected: Yürütülebilir dosyanın Sistem Bütünlüğü Koruması (SIP) tarafından korunan bir dosya olup olmadığını belirten bir Boolean değeri.
- `on-authorized-authapfs-volume:` İşletim sisteminin yürütülebilir dosyayı yetkilendirilmiş, kimlik doğrulanmış bir APFS hacminden yükleyip yüklemediğini belirten bir Boolean değeri.
- `on-authorized-authapfs-volume`: İşletim sisteminin yürütülebilir dosyayı yetkilendirilmiş, kimlik doğrulanmış bir APFS hacminden yükleyip yüklemediğini belirten bir Boolean değeri.
- Cryptexes hacmi
- `on-system-volume:` İşletim sisteminin yürütülebilir dosyayı şu anda önyüklenmiş sistem hacminden yükleyip yüklemediğini belirten bir Boolean değeri.
- İçinde /System...
- ...

Bir Apple ikilisi imzalandığında, **onu bir LC kategorisine atar** **güven cache'inde**.

- **iOS 16 LC kategorileri** [**tersine çevrildi ve burada belgelenmiştir**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
- Mevcut **LC kategorileri (macOS 14 - Somona)** tersine çevrildi ve [**açıklamaları burada bulunabilir**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Örneğin Kategori 1 şudur:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Sistem veya Cryptexes hacminde olmalıdır.
- `launch-type == 1`: Bir sistem servisi olmalıdır (LaunchDaemons'da plist).
- `validation-category == 1`: Bir işletim sistemi yürütülebilir dosyası.
- `is-init-proc`: Launchd

### LC Kategorilerini Tersine Çevirme

Bununla ilgili daha fazla bilgiye [**buradan ulaşabilirsiniz**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ama temelde, **AMFI (AppleMobileFileIntegrity)** içinde tanımlanmışlardır, bu yüzden **KEXT**'i almak için Kernel Geliştirme Kitini indirmeniz gerekir. **`kConstraintCategory`** ile başlayan semboller **ilginç** olanlardır. Bunları çıkardığınızda, [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) veya python-asn1 kütüphanesi ve `dump.py` scripti ile çözmeniz gereken DER (ASN.1) kodlu bir akış elde edeceksiniz, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) daha anlaşılır bir dize verecektir.

## Ortam Kısıtlamaları

Bunlar **üçüncü taraf uygulamalarda** yapılandırılan Başlatma Kısıtlamalarıdır. Geliştirici, uygulamasında kendisine erişimi kısıtlamak için kullanacağı **gerçekleri** ve **mantıksal operatörleri** seçebilir.

Bir uygulamanın Ortam Kısıtlamalarını şu şekilde listelemek mümkündür:
```bash
codesign -d -vvvv app.app
```
## Güven Cache'leri

**macOS**'ta birkaç güven cache'i bulunmaktadır:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Ve iOS'ta **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** içinde olduğu görünmektedir.

> [!WARNING]
> Apple Silicon cihazlarda çalışan macOS'ta, eğer bir Apple imzalı ikili güven cache'inde yoksa, AMFI bunu yüklemeyi reddedecektir.

### Güven Cache'lerini Sıralama

Önceki güven cache dosyaları **IMG4** ve **IM4P** formatındadır, IM4P IMG4 formatının yükleme bölümüdür.

Veritabanlarının yükleme bölümünü çıkarmak için [**pyimg4**](https://github.com/m1stadev/PyIMG4) kullanabilirsiniz:
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
(Başka bir seçenek, [**img4tool**](https://github.com/tihmstar/img4tool) aracını kullanmak olabilir; bu araç, eski bir sürüm olsa bile M1'de çalışacak ve x86_64 için uygun konumlara kurarsanız çalışacaktır).

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
Güven cache'i aşağıdaki yapıyı takip eder, bu nedenle **LC kategorisi 4. sütundur**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Sonra, verileri çıkarmak için [**bu scripti**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) kullanabilirsiniz.

Bu verilerden, **`0`** değerine sahip **launch constraints** olan Uygulamaları kontrol edebilirsiniz; bunlar kısıtlanmamış olanlardır ([**burada kontrol edin**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) her değerin ne olduğunu görmek için).

## Saldırı Azaltmaları

Launch Constraints, **sürecin beklenmedik koşullarda çalıştırılmayacağından emin olarak** birkaç eski saldırıyı azaltmış olur: Örneğin, beklenmedik yerlerden veya beklenmedik bir ana süreç tarafından çağrılmaktan (sadece launchd'nin başlatması gerekiyorsa).

Ayrıca, Launch Constraints **downgrade saldırılarını da azaltır.**

Ancak, **yaygın XPC** kötüye kullanımlarını, **Electron** kod enjeksiyonlarını veya **dylib enjeksiyonlarını** kütüphane doğrulaması olmadan azaltmaz (yükleyebilecek takım kimlikleri bilinmiyorsa).

### XPC Daemon Koruması

Sonoma sürümünde, dikkat çekici bir nokta, daemon XPC hizmetinin **sorumluluk yapılandırmasıdır**. XPC hizmeti kendisinden sorumludur, bağlanan istemcinin sorumlu olmasının aksine. Bu, geri bildirim raporu FB13206884'te belgelenmiştir. Bu yapılandırma hatalı görünebilir, çünkü XPC hizmeti ile belirli etkileşimlere izin verir:

- **XPC Hizmetini Başlatma**: Bir hata olarak varsayılırsa, bu yapılandırma, XPC hizmetini saldırgan kod aracılığıyla başlatmaya izin vermez.
- **Aktif Bir Hizmete Bağlanma**: Eğer XPC hizmeti zaten çalışıyorsa (muhtemelen orijinal uygulaması tarafından etkinleştirilmişse), ona bağlanmak için hiçbir engel yoktur.

XPC hizmetinde kısıtlamalar uygulamak, **potansiyel saldırılar için pencereyi daraltarak** faydalı olabilir, ancak temel endişeyi ele almaz. XPC hizmetinin güvenliğini sağlamak, esasen **bağlanan istemcinin etkili bir şekilde doğrulanmasını** gerektirir. Bu, hizmetin güvenliğini güçlendirmenin tek yoludur. Ayrıca, bahsedilen sorumluluk yapılandırmasının şu anda çalıştığını belirtmek gerekir; bu, tasarlanan amaçla uyumlu olmayabilir.

### Electron Koruması

Uygulamanın **LaunchService tarafından açılması gerektiği** gereksinimi olsa bile (ebeveyn kısıtlamalarında). Bu, **`open`** kullanılarak (çevre değişkenlerini ayarlayabilen) veya **Launch Services API** kullanılarak (çevre değişkenlerinin belirtilebileceği) gerçekleştirilebilir.

## Referanslar

- [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [https://theevilbit.github.io/posts/launch_constraints_deep_dive/](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

{{#include ../../../banners/hacktricks-training.md}}
