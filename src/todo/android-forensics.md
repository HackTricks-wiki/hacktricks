# Android Adli Tahlili

{{#include ../banners/hacktricks-training.md}}

## Kilitli Cihaz

Bir Android cihazdan veri çıkarmaya başlamak için cihazın kilidinin açılması gerekir. Eğer kilitliyse şunları yapabilirsiniz:

- Cihazın USB üzerinden hata ayıklamanın etkin olup olmadığını kontrol edin.
- Olası bir [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf) kontrol edin.
- [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) ile deneyin.

## Veri Edinimi

Bir [android yedeği oluşturun](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ve bunu [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) kullanarak çıkarın: `java -jar abe.jar unpack file.backup file.tar`

### Eğer root erişimi veya JTAG arayüzüne fiziksel bağlantı varsa

- `cat /proc/partitions` (flash belleğin yolunu arayın, genellikle ilk giriş _mmcblk0_ olup tüm flash belleği temsil eder).
- `df /data` (sistemin blok boyutunu keşfedin).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (blok boyutundan elde edilen bilgilerle çalıştırın).

### Bellek

RAM bilgilerini çıkarmak için Linux Memory Extractor (LiME) kullanın. Bu, adb üzerinden yüklenmesi gereken bir çekirdek uzantısıdır.

{{#include ../banners/hacktricks-training.md}}
