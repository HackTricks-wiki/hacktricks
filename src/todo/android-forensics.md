# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Заблокований пристрій

Щоб почати вилучення даних з Android-пристрою, його потрібно розблокувати. Якщо він заблокований, можна:

- Перевірити, чи активовано налагодження через USB.
- Перевірити можливість [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Спробувати [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Отримання даних

Створіть [резервну копію Android за допомогою adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) та розпакуйте її за допомогою [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Якщо є root-доступ або фізичне підключення до інтерфейсу JTAG

- `cat /proc/partitions` (знайдіть шлях до flash-пам'яті; зазвичай першим записом є _mmcblk0_, який відповідає всій flash-пам'яті).
- `df /data` (визначте розмір блоку системи).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (виконайте команду, використовуючи отриману інформацію про розмір блоку).

### Пам'ять

Використовуйте Linux Memory Extractor (LiME) для вилучення даних з RAM. Це розширення kernel, яке потрібно завантажити через adb.

## References

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
