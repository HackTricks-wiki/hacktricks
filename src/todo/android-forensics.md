# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Kilitli Cihaz

Cihazın durumunu koruyan acquisition yöntemlerini tercih edin ve her işlemi belgeleyin. Cihaz kilitliyse mevcut seçenekler modele, Android sürümüne, patch level'a ve erişimin el koyma işleminden önce yapılandırılıp yapılandırılmadığına bağlıdır. NIST, yöntemin cihaza ve inceleme yetkisine göre seçilmesini önerir.<sup>[[1]](#references)</sup>

- USB debugging'in etkin olup olmadığını ve acquisition workstation'ın zaten yetkilendirilip yetkilendirilmediğini kontrol edin. ADB erişimi normalde kullanıcının cihazın kilidini açmasını ve workstation'ın RSA key'ini onaylamasını gerektirir.<sup>[[3]](#references)</sup>
- Uygulanabilir yasal ve prosedürel kurallar kapsamında biometric access'in hâlâ kullanılabilir olup olmadığını değerlendirin.
- Ekrandaki kalıntılardan grafik unlock pattern'ini ortaya çıkarmak için bir **smudge attack** kullanılabilir; ancak sonraki dokunuşlar ve temizlik güvenilirliğini azaltır.<sup>[[2]](#references)</sup>
- Yetkili tooling tam olarak ilgili cihazı ve software build'ini destekliyorsa PIN, password veya pattern recovery ya da brute force denemesi yapabilir. Hardware-backed credential verification, retry delays ve wipe policies bu işlemi büyük ölçüde cihaza özgü hâle getirir; bu nedenle bir iPhone tekniğini veya sonucunu Android cihazın desteklendiğine dair kanıt olarak kullanmayın.<sup>[[1]](#references)</sup>

## Data acquisition

Daha eski cihazlarda, legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup), Android Backup Extractor'ın unpack edebileceği bir `.backup` dosyası üretebilir:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Bunun her uygulamayı kapsadığını varsaymayın. ADB bu komutu deprecated olarak etiketler ve Android 12, uygulama debuggable olmadığı sürece API level 31 veya sonraki sürümleri hedefleyen uygulamalardan gelen verileri hariç tutar.<sup>[[4]](#references)</sup>

### Root veya fiziksel debug erişimi

Canlı bir cihazda root erişimiyle önce partition'ların ve mount'ların envanterini çıkarın; aşağıdaki komutlar fiziksel bir JTAG acquisition için doğrudan geçerli değildir. Doğru block device donanıma bağlıdır; bu nedenle her zaman `mmcblk0` olduğunu varsaymayın. Yalnızca doğrulanmış kaynağın imajını ayrı bir depolamaya alın:<sup>[[1]](#references)</sup>

JTAG acquisition bunun yerine cihazın hardware test-access interface'ini ve uyumlu acquisition equipment'i kullanarak erişilebilir belleği okur. Pinout, chipset desteği, cihaz durumu ve volatile ile non-volatile hedefler arasındaki ayrım cihaza özgüdür; donanım yolunu belgeleyin ve ilgili model için doğrulanmış bir prosedür kullanın.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Örneğin, partition inventory `/dev/block/mmcblk0`'ın tüm flash device olduğunu ve hedefte yeterli alan bulunduğunu doğrularsa, orijinal acquisition command şu hale gelir:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Burada, `df /data`, `/data` yolunun bağlı dosya sistemiyle ilişkilendirilmesine yardımcı olur; `mmcblk0` değerinin doğru tüm-cihaz kaynağı veya `4096` değerinin geçerli tek `dd` blok boyutu olduğunun kanıtı olarak değerlendirilmemelidir.

Sonucun Hash'ini alın ve tam komutu, cihaz tanımlayıcılarını, zamanı ve acquisition sırasında yapılan tüm değişiklikleri kaydedin.<sup>[[1]](#references)</sup>

### Bellek

LiME, Linux ve bazı Android cihazlardan fiziksel belleği alabilir, ancak kernel module hedef kernel için derlenmeli ve yeterli privileges ile yüklenmelidir. Module signing, kernel lockdown ve modern Android hardening, modülün yüklenmesini engelleyebilir.<sup>[[5]](#references)</sup>

Projenin Android workflow'u, eşleşen modülü ADB ile gönderir, bir TCP portunu forward eder, modülü bir root shell'den yükler ve stream'i inceleme host'unda yakalar:<sup>[[5]](#references)</sup>
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
LiME bunun yerine `path=/sdcard/ram.lime` ile cihazın depolama alanına yazabilir, ancak bu işlem cihazın depolama alanını değiştirir ve yeterli boş alan gerektirir. Bu yan etkiyi kaydedin ve elde edilen imajın hash değerini hesaplayın.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Mobil Cihaz Adli Bilişimi Kılavuzları](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Akıllı Telefon Dokunmatik Ekranlarında Smudge Saldırıları](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Geliştiricileri - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Geliştiricileri - Android 12 ADB yedekleme kısıtlaması](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
