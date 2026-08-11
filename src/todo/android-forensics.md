# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Kilitli Cihaz

Cihazın durumunu koruyan edinim yöntemlerini tercih edin ve gerçekleştirilen her işlemi belgeleyin. Cihaz kilitliyse kullanılabilecek seçenekler modele, Android sürümüne, yama düzeyine ve el koymadan önce erişimin yapılandırılıp yapılandırılmadığına bağlıdır. NIST, inceleme için yöntemin cihaza ve inceleme yetkisine göre seçilmesini önerir.<sup>[[1]](#references)</sup>

- USB debugging özelliğinin etkin olup olmadığını ve edinim workstation'ının zaten yetkilendirilip yetkilendirilmediğini kontrol edin. ADB erişimi normalde kullanıcının cihazın kilidini açmasını ve workstation'ın RSA key'ini onaylamasını gerektirir.<sup>[[3]](#references)</sup>
- Geçerli yasal ve prosedürel kurallar kapsamında biometric access'in kullanılabilir durumda olup olmadığını değerlendirin.
- Bir **smudge attack**, ekrandaki kalıntılardan grafik kilit açma desenini ortaya çıkarabilir; ancak sonraki dokunuşlar ve temizlik işlemleri güvenilirliğini azaltır.<sup>[[2]](#references)</sup>
- Commercial veya research lock-bypass tooling'i yalnızca tam olarak ilgili cihazı ve software build'i desteklediği açıkça belirtiliyorsa kullanın.

## Veri edinimi

Daha eski cihazlarda, eski bir [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup), Android Backup Extractor'ın açabileceği bir `.backup` dosyası oluşturabilir:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Bunun her uygulamayı kapsadığını varsaymayın. ADB, komutu kullanımdan kaldırılmış olarak işaretler ve Android 12, uygulama debuggable olmadığı sürece API level 31 veya sonraki sürümleri hedefleyen uygulamalardan gelen verileri hariç tutar.<sup>[[4]](#references)</sup>

### Root veya fiziksel debug erişimi

Canlı bir cihazda root erişimiyle önce bölümleri ve mount'ları envanterleyin; aşağıdaki komutlar fiziksel bir JTAG acquisition için doğrudan geçerli değildir. Doğru blok aygıtı donanıma bağlıdır; bu nedenle her zaman `mmcblk0` olduğunu varsaymayın. Yalnızca doğrulanmış kaynağın imajını ayrı bir depolama alanına alın:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Sonucu Hash'leyin ve edinim sırasında kullanılan exact command'ı, device identifier'larını, zamanı ve yapılan tüm değişiklikleri kaydedin.<sup>[[1]](#references)</sup>

### Bellek

LiME, Linux ve bazı Android cihazlardan fiziksel belleği alabilir; ancak kernel module hedef kernel için derlenmeli ve yeterli privileges ile yüklenmelidir. Module signing, kernel lockdown ve modern Android hardening, modülün yüklenmesini engelleyebilir.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Mobil Device Forensics için Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smartphone Touch Screens üzerinde Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
