# Android Forensics

{{#include ./banners/hacktricks-training.md}}

## Zablokowane urządzenie

Aby rozpocząć ekstrakcję danych z urządzenia z Androidem, musi być odblokowane. Jeśli jest zablokowane, możesz:

- Sprawdzić, czy urządzenie ma włączone debugowanie przez USB.
- Sprawdzić możliwy [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- Spróbować z [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Pozyskiwanie danych

Utwórz [kopię zapasową androida za pomocą adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) i wyodrębnij ją za pomocą [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Jeśli masz dostęp do roota lub fizyczne połączenie z interfejsem JTAG

- `cat /proc/partitions` (znajdź ścieżkę do pamięci flash, zazwyczaj pierwsza pozycja to _mmcblk0_ i odpowiada całej pamięci flash).
- `df /data` (Odkryj rozmiar bloku systemu).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (wykonaj to z informacjami zebranymi z rozmiaru bloku).

### Pamięć

Użyj Linux Memory Extractor (LiME), aby wyodrębnić informacje z RAM. To rozszerzenie jądra, które powinno być załadowane za pomocą adb.

{{#include ./banners/hacktricks-training.md}}
