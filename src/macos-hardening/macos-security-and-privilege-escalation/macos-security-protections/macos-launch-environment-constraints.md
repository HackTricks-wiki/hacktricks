# macOS Başlatma/Ortam Kısıtlamaları ve Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS'taki başlatma kısıtlamaları, **bir sürecin nasıl, kim tarafından ve nereden başlatılabileceğini düzenleyerek** güvenliği artırmak amacıyla kullanıma sunuldu. macOS Ventura ile başlayan bu kısıtlamalar, **her sistem ikilisini ayrı kısıtlama kategorilerine** ayıran bir çerçeve sağlar. Bu kategoriler, sistem ikililerini ve bunların karşılık gelen hash'lerini içeren bir liste olan **trust cache** içinde tanımlanır. Bu kısıtlamalar sistemdeki her çalıştırılabilir ikiliyi kapsar ve **belirli bir ikilinin başlatılması** için gereken koşulları tanımlayan bir dizi **kural** içerir. Kurallar, ikilinin karşılaması gereken kendi kısıtlamalarını, üst sürecinin karşılaması gereken üst süreç kısıtlamalarını ve ilgili diğer varlıkların uyması gereken sorumlu süreç kısıtlamalarını kapsar.<sup>[[1]](#references)[[4]](#references)</sup>

macOS Sonoma'dan itibaren bu mekanizma, geliştiricilerin **ortam kısıtlamaları için bir anahtar ve değer kümesi** belirleyerek uygulamalarını korumasına olanak tanır ve üçüncü taraf uygulamaları da kapsar.<sup>[[5]](#references)</sup>

**Başlatma ortamı ve kütüphane kısıtlamalarını**, kısıtlama sözlüklerinde tanımlarsınız. Bu sözlükleri **`launchd` property list dosyalarına** ya da code signing'de kullandığınız **ayrı property list** dosyalarına kaydedebilirsiniz.<sup>[[5]](#references)</sup>

4 tür kısıtlama vardır:

- **Kendi Kısıtlamaları**: **Çalışan** ikiliye uygulanan kısıtlamalar.
- **Üst Süreç**: Sürecin **üst sürecine** uygulanan kısıtlamalar (örneğin, bir XP hizmetini çalıştıran **`launchd`**)
- **Sorumlu Süreç Kısıtlamaları**: XPC iletişiminde hizmeti **çağıran sürece** uygulanan kısıtlamalar
- **Kütüphane yükleme kısıtlamaları**: Yüklenebilecek kodu seçici olarak tanımlamak için kütüphane yükleme kısıtlamalarını kullanın

Bir süreç, `execve(_:_:_:)` veya `posix_spawn(_:_:_:_:_:_:)` çağrısı yaparak başka bir süreci başlatmaya çalıştığında işletim sistemi, **çalıştırılabilir** dosyanın **kendi kısıtlamasını karşıladığını** denetler. Ayrıca **üst** **sürecin** çalıştırılabilir dosyasının, çalıştırılabilir dosyanın **üst süreç kısıtlamasını** karşıladığını ve **sorumlu** **sürecin** çalıştırılabilir dosyasının, çalıştırılabilir dosyanın **sorumlu süreç kısıtlamasını** karşıladığını denetler. Bu başlatma kısıtlamalarından herhangi biri karşılanmazsa işletim sistemi programı çalıştırmaz.

Bir kütüphane yüklenirken **kütüphane kısıtlamasının herhangi bir bölümü karşılanmıyorsa** süreciniz kütüphaneyi **yüklemez**.

## LC Kategorileri

Bir LC, olguların ve bu olguları birleştiren mantıksal işlemlerin (and, or vb.) oluşturduğu bir yapıdır.

Bir LC'nin kullanabileceği [**olgular belgelenmiştir**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Örneğin:

- is-init-proc: Çalıştırılabilir dosyanın işletim sisteminin başlatma süreci (`launchd`) olması gerekip gerekmediğini belirten bir Boolean değer.
- is-sip-protected: Çalıştırılabilir dosyanın System Integrity Protection (SIP) tarafından korunan bir dosya olması gerekip gerekmediğini belirten bir Boolean değer.
- `on-authorized-authapfs-volume:` İşletim sisteminin çalıştırılabilir dosyayı yetkilendirilmiş, kimliği doğrulanmış bir APFS biriminden yükleyip yüklemediğini belirten bir Boolean değer.
- `on-authorized-authapfs-volume`: İşletim sisteminin çalıştırılabilir dosyayı yetkilendirilmiş, kimliği doğrulanmış bir APFS biriminden yükleyip yüklemediğini belirten bir Boolean değer.
  - Cryptexes birimi
- `on-system-volume:`İşletim sisteminin çalıştırılabilir dosyayı şu anda önyüklenmiş sistem biriminden yükleyip yüklemediğini belirten bir Boolean değer.
  - /System içinde...
- ...

Bir Apple ikilisi imzalandığında, **trust cache** içinde onu bir **LC kategorisine** atar.

- **iOS 16 LC kategorileri** [**burada tersine mühendislikle çözümlenip belgelenmiştir**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Mevcut **LC kategorileri (macOS 14 - Somona)** tersine mühendislikle çözümlenmiştir ve [**açıklamalarına buradan ulaşılabilir**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Örneğin, Kategori 1 şöyledir:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: System veya Cryptexes volume içinde olmalıdır.
- `launch-type == 1`: Bir system service olmalıdır (LaunchDaemons içindeki plist).
- `validation-category == 1`: Bir operating system executable olmalıdır.
- `is-init-proc`: Launchd

### LC Kategorilerinin Tersine Mühendislikle İncelenmesi

Daha fazla bilgiye [**buradan ulaşabilirsiniz**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ancak temel olarak bunlar **AMFI (AppleMobileFileIntegrity)** içinde tanımlanmıştır; bu nedenle **KEXT** dosyasını edinmek için Kernel Development Kit'i indirmeniz gerekir. **`kConstraintCategory`** ile başlayan semboller **ilgi çekici** olanlardır. Bunları çıkardığınızda, [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) veya python-asn1 kütüphanesindeki `dump.py` betiğiyle çözmeniz gereken DER (ASN.1) kodlu bir akış elde edersiniz. [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) bu akışı daha anlaşılır bir metne dönüştürür.<sup>[[3]](#references)[[8]](#references)</sup>

## Ortam Kısıtlamaları

Bunlar, **üçüncü taraf uygulamalarda** yapılandırılan Launch Constraints'tir. Geliştirici, uygulamanın kendisine erişimi kısıtlamak için uygulamasında kullanılacak **olguları** ve **mantıksal işleçleri** seçebilir.

Bir uygulamanın Environment Constraints'lerini şu şekilde sıralamak mümkündür:

```bash
codesign -d -vvvv app.app
```

## Trust Caches

**macOS**’te birkaç trust cache bulunur:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

iOS’ta ise **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** konumunda olduğu anlaşılıyor.

> [!WARNING]
> Apple Silicon cihazlarda çalışan macOS’te, Apple tarafından imzalanmış bir binary trust cache’te yer almıyorsa AMFI yüklenmesini reddeder.

### Trust Caches’i Listeleme

Önceki trust cache dosyaları **IMG4** biçimindedir. **IM4P**, IMG4 biçiminin payload bölümüdür.

Veritabanlarının payload’ını çıkarmak için [**pyimg4**](https://github.com/m1stadev/PyIMG4) kullanabilirsiniz:

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

(Başka bir seçenek de [**img4tool**](https://github.com/tihmstar/img4tool) aracını kullanmak olabilir. Sürüm eski olsa bile M1'de çalışır; x86_64'te ise doğru konumlara yüklerseniz çalışır.)

Artık bilgileri okunabilir bir biçimde almak için [**trustcache**](https://github.com/CRKatri/trustcache) aracını kullanabilirsiniz:

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

Güven önbelleği aşağıdaki yapıyı izler; bu nedenle **LC kategorisi 4. sütundur**

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

Then verileri çıkarmak için [**bu**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) gibi bir script kullanabilirsiniz.

Bu verilerden **launch constraints değeri `0` olan** Apps'leri kontrol edebilirsiniz; bunlar kısıtlanmamış olanlardır (her değerin ne anlama geldiğini öğrenmek için [**buraya bakın**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)).<sup>[[6]](#references)</sup>

## Saldırı Azaltımları

Launch Constraints, **process'in beklenmedik koşullarda yürütülmesini önleyerek** eski saldırıların birçoğunu engelleyebilirdi: Örneğin beklenmedik konumlardan veya beklenmedik bir parent process tarafından başlatılması (onu yalnızca launchd başlatmalıysa).

Ayrıca Launch Constraints, **downgrade saldırılarını da azaltır.**

Ancak, **yaygın XPC** kötüye kullanımlarını, **Electron** kod enjeksiyonlarını veya library validation olmadan **dylib enjeksiyonlarını** engellemezler (library yükleyebilecek team ID'leri biliniyorsa bu durum hariç).<sup>[[3]](#references)</sup>

### XPC Daemon Koruması

Sonoma sürümündeki dikkat çekici bir nokta, daemon XPC service'in **sorumluluk yapılandırmasıdır**. Bağlanan client yerine XPC service'in kendisi sorumludur. Bu, FB13206884 feedback raporunda belgelenmiştir. Bu yapı kusurlu görünebilir; çünkü XPC service ile belirli etkileşimlere izin verir:

- **XPC Service'i Başlatma**: Bunun bir bug olduğu varsayılsa bile, bu yapı attacker kodunun XPC service'i başlatmasına izin vermez.
- **Çalışır Durumdaki Bir Service'e Bağlanma**: XPC service zaten çalışıyorsa (muhtemelen özgün uygulaması tarafından etkinleştirilmiştir), ona bağlanmanın önünde hiçbir engel yoktur.

XPC service'e constraints uygulamak, **potansiyel saldırılar için fırsat aralığını daraltarak** fayda sağlayabilir; ancak temel sorunu çözmez. XPC service'in güvenliğini sağlamak için **bağlanan client'ı etkili biçimde doğrulamak** gerekir. Service'in güvenliğini güçlendirmenin tek yolu budur. Ayrıca, söz konusu sorumluluk yapılandırmasının şu anda çalışır durumda olduğunu ve bunun amaçlanan tasarımla örtüşmeyebileceğini belirtmek gerekir.<sup>[[3]](#references)</sup>

### Electron Koruması

Uygulamanın **LaunchService tarafından açılması** zorunlu olsa bile (parents constraints içinde), bu işlem **`open`** (env variables ayarlayabilir) veya **Launch Services API** (env variables belirtilebilir) kullanılarak gerçekleştirilebilir.<sup>[[3]](#references)</sup>

Policy'ye özgü spawn attributes'ın arkasındaki genel MACF mekanizması için bkz. [MACF policy-specific spawn attributes](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Yerleşik constraints'leri spawn anında geçersiz kılma

Launch constraints (resmî adıyla **lightweight code requirements**, *LWCR*), **AMFI MAC policy** tarafından uygulanır. `posix_spawn`, çağıranın **`posix_spawnattr_setmacpolicyinfo_np()`** aracılığıyla bir MAC policy'ye keyfi bir blob iletmesine izin verir ve AMFI bu yol üzerinden çağıranın sağladığı bir LWCR sözlüğünü kabul ediyordu. Bug, **attacker tarafından sağlanan constraints'lerin binary'nin yerleşik constraints'lerinin yerine geçmesi**, bunlara ek olarak denetlenmemesiydi:

- Minimal (hatta boş) bir launch-constraints sözlüğü oluşturun.
- **Constraint kategorisini `127`** olarak ayarlayın. Bu değere AMFI spawn attributes içinde izin verir ancak **uygulamaz**; yürütmeyi engellemek yerine yalnızca `Launch Constraint Violation (not enforcing)` kaydı tutar.
- Bunu spawn attributes üzerinden iletin; process, gerçek self/parent constraints'lerinin yasaklayacağı bir bağlamda başlatılır.

Düzeltmeden sonra hem yerleşik hem de sağlanan constraints doğrulanır; dolayısıyla sağlanan sözlük artık yerleşik constraints'leri zayıflatamaz.<sup>[[2]](#references)</sup>

> [!TIP]
> Constraint uygulamasını denetlerken aranması gereken genel kalıp şudur: Güvenilmeyen girdilerin bir policy *sağlamasına* izin veren bir API, policy engine bu sağlanan değeri ek bir gereklilik yerine ikame olarak ele alıyorsa ilgi çekicidir.



## References

- [1] [Objective by the Sea #OBTS v6.0 2. Gün (Canlı Yayın)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: macOS'ta Launch Constraints'i Atlatma (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch ve Environment Constraints Derinlemesine İnceleme - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Bir sistem uygulaması veya komut aracı neden çalışmaz? Launch constraints ve trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Environment constraints ile Mac uygulamanızı koruyun - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [iOS 16'da kullanıma sunulan Launch Constraints'in açıklaması (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Eski güzel LaunchAgents'ın ötesi - konuyla ilgili yazı](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
