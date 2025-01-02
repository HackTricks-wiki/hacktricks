# Android Forensik

{{#include ./banners/hacktricks-training.md}}

## Gesperrtes Gerät

Um mit der Datenextraktion von einem Android-Gerät zu beginnen, muss es entsperrt sein. Wenn es gesperrt ist, können Sie:

- Überprüfen, ob das Gerät das Debugging über USB aktiviert hat.
- Nach einem möglichen [Smudge-Angriff](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf) suchen.
- Es mit [Brute-Force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) versuchen.

## Datenerfassung

Erstellen Sie ein [Android-Backup mit adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) und extrahieren Sie es mit dem [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Wenn Root-Zugriff oder physische Verbindung zur JTAG-Schnittstelle

- `cat /proc/partitions` (suchen Sie den Pfad zum Flash-Speicher, in der Regel ist der erste Eintrag _mmcblk0_ und entspricht dem gesamten Flash-Speicher).
- `df /data` (Entdecken Sie die Blockgröße des Systems).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (führen Sie es mit den gesammelten Informationen zur Blockgröße aus).

### Speicher

Verwenden Sie den Linux Memory Extractor (LiME), um die RAM-Informationen zu extrahieren. Es ist eine Kernel-Erweiterung, die über adb geladen werden sollte.

{{#include ./banners/hacktricks-training.md}}
