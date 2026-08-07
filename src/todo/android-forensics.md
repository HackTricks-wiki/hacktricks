# Forensics de Android

{{#include ../banners/hacktricks-training.md}}

## Dispositivo bloqueado

Para comenzar a extraer datos de un dispositivo Android, debe estar desbloqueado. Si está bloqueado, puedes:

- Comprobar si el dispositivo tiene activada la depuración mediante USB.
- Comprobar si es posible realizar un [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Intentar un [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Adquisición de datos

Crea un [backup de Android usando adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) y extráelo usando [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Si tienes acceso root o conexión física a la interfaz JTAG

- `cat /proc/partitions` (busca la ruta a la memoria flash; generalmente, la primera entrada es _mmcblk0_ y corresponde a toda la memoria flash).
- `df /data` (descubre el tamaño de bloque del sistema).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (ejecútalo con la información obtenida sobre el tamaño de bloque).

### Memoria

Usa Linux Memory Extractor (LiME) para extraer la información de la RAM. Es una extensión del kernel que debe cargarse mediante adb.

## Referencias

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
