# Android Adli İncelemesi

{{#include ../../banners/hacktricks-training.md}}

## Kilitli Cihaz

Cihazın durumunu koruyan edinim yöntemlerini tercih edin ve her işlemi belgeleyin. Cihaz kilitliyse kullanılabilecek seçenekler modele, Android sürümüne, yama düzeyine ve el koymadan önce erişimin yapılandırılmış olup olmadığına bağlıdır. NIST, inceleme için cihaz ve yetki kapsamına uygun bir yöntem seçilmesini önerir.<sup>[[1]](#references)</sup>

- USB debugging'in etkin olup olmadığını ve edinim iş istasyonunun önceden yetkilendirilip yetkilendirilmediğini kontrol edin. ADB erişimi normalde kullanıcının cihazın kilidini açmasını ve iş istasyonunun RSA anahtarını onaylamasını gerektirir.<sup>[[3]](#references)</sup>
- Geçerli yasal ve prosedürel kurallar kapsamında biyometrik erişimin hâlâ kullanılabilir olup olmadığını değerlendirin.
- Ekrandaki kalıntılar, **smudge attack** yoluyla grafik kilit desenini ortaya çıkarabilir; ancak sonradan yapılan dokunuşlar ve temizlik bu yöntemin güvenilirliğini azaltır.<sup>[[2]](#references)</sup>
- Yetkili araçlar tam olarak ilgili cihazı ve yazılım derlemesini destekliyorsa PIN, parola veya desen kurtarma ya da brute force girişiminde bulunabilir. Donanım destekli kimlik bilgisi doğrulaması, yeniden deneme gecikmeleri ve silme politikaları nedeniyle bu durum büyük ölçüde cihaza özgüdür; bu nedenle Android cihazın desteklendiğine dair kanıt olmadan iPhone tekniğini veya sonucunu kullanmayın.<sup>[[1]](#references)</sup>

## Veri edinimi

Eski cihazlarda, eski bir [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) `.backup` dosyası oluşturabilir; bu dosya Android Backup Extractor ile açılabilir:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Her uygulamanın bu şekilde yakalandığını varsaymayın. ADB, komutu kullanımdan kaldırılmış olarak işaretler ve Android 12, uygulama debuggable değilse API düzeyi 31 veya üzerini hedefleyen uygulamaların verilerini hariç tutar.<sup>[[4]](#references)</sup>

### Root veya fiziksel debug erişimi

Canlı bir cihazda root erişiminiz varsa önce bölümleri ve mount noktalarını envanterleyin; aşağıdaki komutlar fiziksel JTAG edinimi için doğrudan geçerli değildir. Doğru blok aygıtı donanıma bağlıdır, bu nedenle her zaman `mmcblk0` olduğunu varsaymayın. Yalnızca doğrulanmış kaynağın imajını ayrı bir depolama alanına alın:<sup>[[1]](#references)</sup>

JTAG ediniminde ise erişilebilir belleği okumak için cihazın donanımsal test erişim arayüzü ve uyumlu edinim ekipmanı kullanılır. Pin dizilimi, yonga seti desteği, cihazın durumu ve uçucu bellek ile kalıcı bellek hedefleri arasındaki ayrım cihaza özeldir; donanım yolunu belgeleyin ve ilgili model için doğrulanmış bir prosedür kullanın.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Örneğin, bölüm envanteri `/dev/block/mmcblk0`'ın tüm flash aygıtı olduğunu ve hedefte yeterli alan bulunduğunu doğrularsa, özgün edinim komutu şu hâle gelir:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Burada `df /data`, `/data` dizinini bağlı olduğu dosya sistemiyle ilişkilendirmeye yardımcı olur; `mmcblk0` aygıtının doğru tüm aygıt kaynağı olduğunu veya `4096` değerinin geçerli tek `dd` blok boyutu olduğunu kanıtlamaz.

Sonucun hash'ini alın ve kullanılan komutu, aygıt tanımlayıcılarını, zamanı ve edinim sırasında yapılan değişiklikleri kaydedin.<sup>[[1]](#references)</sup>

### Bellek

LiME, Linux ve bazı Android aygıtlarından fiziksel bellek edinebilir; ancak kernel modülünün hedef kernel için derlenmesi ve yeterli ayrıcalıklarla yüklenmesi gerekir. Modül imzalama, kernel lockdown ve modern Android güvenlik önlemleri modülün yüklenmesini engelleyebilir.<sup>[[5]](#references)</sup>

Projenin Android iş akışı, eşleşen modülü ADB ile gönderir, bir TCP portunu yönlendirir, modülü bir root shell üzerinden yükler ve akışı inceleme ana bilgisayarında yakalar:<sup>[[5]](#references)</sup>

```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```

LiME bunun yerine `path=/sdcard/ram.lime` kullanarak cihazın depolama alanına yazabilir; ancak bu, cihazın depolama alanını değiştirir ve yeterli boş alan gerektirir. Bu yan etkiyi kaydedin ve elde edilen imajın hash'ini alın.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Mobil Cihaz Adli İncelemesi için Yönergeler](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Akıllı Telefon Dokunmatik Ekranlarında Smudge Saldırıları](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB yedekleme kısıtlaması](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
