# Android forenzika

{{#include ../banners/hacktricks-training.md}}

## Otključan uređaj

Da biste započeli ekstrakciju podataka sa Android uređaja, on mora biti otključan. Ako je zaključan, možete:

- Proveriti da li je debugging putem USB-a aktiviran.
- Proveriti mogućnost [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Pokušati sa [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Akvizicija podataka

Napravite [android backup using adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) i ekstraktujte ga pomoću [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Ako postoji root pristup ili fizička veza sa JTAG interfejsom

- `cat /proc/partitions` (potražite putanju do flash memorije; uglavnom je prvi unos _mmcblk0_ i odgovara celoj flash memoriji).
- `df /data` (otkrijte veličinu bloka sistema).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (izvršite komandu koristeći informacije dobijene o veličini bloka).

### Memorija

Koristite Linux Memory Extractor (LiME) za ekstrakciju informacija iz RAM-a. To je kernel ekstenzija koja treba da bude učitana putem adb-a.

## Reference

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
