# Computer Forensics Android

{{#include ../banners/hacktricks-training.md}}

## Dispositivo bloccato

Per iniziare a estrarre dati da un dispositivo Android, questo deve essere sbloccato. Se è bloccato, puoi:

- Verificare se il debugging tramite USB è attivato.
- Verificare la possibile presenza di uno [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Provare con il [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Acquisizione dei dati

Crea un [backup Android usando adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ed estrailo usando [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Se hai accesso root o una connessione fisica all'interfaccia JTAG

- `cat /proc/partitions` (cerca il percorso della memoria flash; generalmente la prima voce è _mmcblk0_ e corrisponde all'intera memoria flash).
- `df /data` (determina la dimensione dei blocchi del sistema).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (eseguilo usando le informazioni raccolte sulla dimensione dei blocchi).

### Memoria

Usa Linux Memory Extractor (LiME) per estrarre le informazioni dalla RAM. È un'estensione del kernel che dovrebbe essere caricata tramite adb.

## Riferimenti

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [Questo dispositivo brute force può violare il codice PIN di qualsiasi iPhone](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
