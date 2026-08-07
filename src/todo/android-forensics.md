# Analiza kryminalistyczna Androida

{{#include ../banners/hacktricks-training.md}}

## Zablokowane urządzenie

Aby rozpocząć ekstrakcję danych z urządzenia Android, musi ono zostać odblokowane. Jeśli jest zablokowane, możesz:

- Sprawdzić, czy w urządzeniu aktywowano debugging przez USB.
- Sprawdzić możliwość przeprowadzenia [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Spróbować użyć [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Pozyskiwanie danych

Utwórz [kopię zapasową Androida za pomocą adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) i wyodrębnij ją za pomocą [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Jeśli dostępny jest root lub fizyczne połączenie z interfejsem JTAG

- `cat /proc/partitions` (wyszukaj ścieżkę do pamięci flash; zazwyczaj pierwszy wpis to _mmcblk0_ i odpowiada całej pamięci flash).
- `df /data` (ustal rozmiar bloku systemu).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (wykonaj polecenie, korzystając z informacji uzyskanych na temat rozmiaru bloku).

### Pamięć

Użyj Linux Memory Extractor (LiME), aby wyodrębnić informacje z pamięci RAM. Jest to rozszerzenie jądra, które należy załadować za pomocą adb.

## Referencje

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
