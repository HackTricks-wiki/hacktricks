# Android Forensics

{{#include ./banners/hacktricks-training.md}}

## Dispositivo Bloqueado

Para comenzar a extraer datos de un dispositivo Android, debe estar desbloqueado. Si está bloqueado, puedes:

- Verificar si el dispositivo tiene la depuración por USB activada.
- Comprobar un posible [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- Intentar con [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Adquisición de Datos

Crea un [android backup usando adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) y extráelo usando [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Si hay acceso root o conexión física a la interfaz JTAG

- `cat /proc/partitions` (busca la ruta a la memoria flash, generalmente la primera entrada es _mmcblk0_ y corresponde a toda la memoria flash).
- `df /data` (Descubre el tamaño del bloque del sistema).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (ejecuta esto con la información recopilada del tamaño del bloque).

### Memoria

Usa Linux Memory Extractor (LiME) para extraer la información de la RAM. Es una extensión del kernel que debe ser cargada a través de adb.

{{#include ./banners/hacktricks-training.md}}
