# Android-Forensik

{{#include ../banners/hacktricks-training.md}}

## Gesperrtes Gerät

Um mit dem Extrahieren von Daten von einem Android-Gerät zu beginnen, muss es entsperrt sein. Wenn es gesperrt ist, kannst du:

- Überprüfen, ob debugging via USB aktiviert ist.
- Nach einem möglichen [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup> suchen.
- [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup> versuchen.

## Datenerfassung

Erstelle ein [Android-Backup mit adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) und extrahiere es mit [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Bei Root-Zugriff oder physischer Verbindung zur JTAG-Schnittstelle

- `cat /proc/partitions` (Suche nach dem Pfad zum Flash-Speicher. Im Allgemeinen ist der erste Eintrag _mmcblk0_ und entspricht dem gesamten Flash-Speicher.)
- `df /data` (Ermittle die Blockgröße des Systems.)
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (Führe den Befehl mit den anhand der Blockgröße ermittelten Informationen aus.)

### Speicher

Verwende Linux Memory Extractor (LiME), um die RAM-Informationen zu extrahieren. Es handelt sich um eine Kernel-Erweiterung, die über adb geladen werden sollte.

## Referenzen

- [1] [Smudge-Angriffe auf Smartphone-Touchscreens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [Dieses Brute-Force-Gerät kann den PIN-Code jedes iPhones knacken](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
