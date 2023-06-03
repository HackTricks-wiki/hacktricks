# Forense de Android

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Dispositivo bloqueado

Para empezar a extraer datos de un dispositivo Android, éste tiene que estar desbloqueado. Si está bloqueado, puedes:

* Comprobar si el dispositivo tiene activada la depuración a través de USB.
* Comprobar si hay un posible [ataque de huellas dactilares](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf).
* Intentar con [fuerza bruta](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/).

## Adquisición de datos

Crea una copia de seguridad de Android usando adb y extrae los datos usando [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Si se tiene acceso root o conexión física a la interfaz JTAG

* `cat /proc/partitions` (busca la ruta a la memoria flash, generalmente la primera entrada es _mmcblk0_ y corresponde a toda la memoria flash).
* `df /data` (descubre el tamaño de bloque del sistema).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (ejecútalo con la información recopilada del tamaño de bloque).

### Memoria

Usa Linux Memory Extractor (LiME) para extraer la información de la RAM. Es una extensión del kernel que debe cargarse a través de adb.
