# Android Forensics

{{#include ./banners/hacktricks-training.md}}

## Dispositivo Bloccato

Per iniziare a estrarre dati da un dispositivo Android, deve essere sbloccato. Se è bloccato puoi:

- Controllare se il dispositivo ha attivato il debug via USB.
- Controllare un possibile [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- Provare con [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Acquisizione Dati

Crea un [backup android usando adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ed estrailo usando [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Se accesso root o connessione fisica all'interfaccia JTAG

- `cat /proc/partitions` (cerca il percorso della memoria flash, generalmente la prima voce è _mmcblk0_ e corrisponde all'intera memoria flash).
- `df /data` (Scopri la dimensione del blocco del sistema).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (eseguilo con le informazioni raccolte dalla dimensione del blocco).

### Memoria

Usa Linux Memory Extractor (LiME) per estrarre le informazioni della RAM. È un'estensione del kernel che deve essere caricata tramite adb.

{{#include ./banners/hacktricks-training.md}}
