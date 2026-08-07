# Android Adli İncelemesi

{{#include ../banners/hacktricks-training.md}}

## Kilitli Cihaz

Bir Android cihazdan veri çıkarmaya başlamak için cihazın kilidinin açılmış olması gerekir. Kilitliyse şunları yapabilirsiniz:

- Cihazda USB üzerinden debugging özelliğinin etkin olup olmadığını kontrol edin.
- Olası bir [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup> olup olmadığını kontrol edin.
- [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup> deneyin.

## Veri Edinme

Bir [android backup using adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) oluşturun ve [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) kullanarak çıkarın: `java -jar abe.jar unpack file.backup file.tar`

### Root erişimi veya JTAG interface ile fiziksel bağlantı varsa

- `cat /proc/partitions` (flash memory yolunu arayın; genellikle ilk giriş _mmcblk0_ olur ve flash memory'nin tamamına karşılık gelir).
- `df /data` (sistemin block size değerini öğrenin).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (block size bilgisinden elde edilen verilerle çalıştırın).

### Memory

RAM bilgilerini çıkarmak için Linux Memory Extractor (LiME) kullanın. Bu, adb üzerinden yüklenmesi gereken bir kernel extension'dır.

## References

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
