# Android Forensics

{{#include ./banners/hacktricks-training.md}}

## Zaključan uređaj

Da biste započeli ekstrakciju podataka sa Android uređaja, mora biti otključan. Ako je zaključan, možete:

- Proveriti da li je uređaj aktivirao debagovanje putem USB-a.
- Proveriti za mogući [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- Pokušati sa [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Akvizicija podataka

Kreirajte [android backup koristeći adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) i ekstraktujte ga koristeći [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Ako postoji root pristup ili fizička veza sa JTAG interfejsom

- `cat /proc/partitions` (pronađite putanju do flash memorije, obično je prvi unos _mmcblk0_ i odgovara celoj flash memoriji).
- `df /data` (otkrijte veličinu bloka sistema).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (izvršite to sa informacijama prikupljenim o veličini bloka).

### Memorija

Koristite Linux Memory Extractor (LiME) za ekstrakciju RAM informacija. To je kernel ekstenzija koja treba da se učita putem adb.

{{#include ./banners/hacktricks-training.md}}
