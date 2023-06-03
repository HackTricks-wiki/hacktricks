<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Timestamps

Un atacante puede estar interesado en **cambiar los timestamps de los archivos** para evitar ser detectado.\
Es posible encontrar los timestamps dentro del MFT en los atributos `$STANDARD_INFORMATION` y `$FILE_NAME`.

Ambos atributos tienen 4 timestamps: **Modificación**, **acceso**, **creación** y **modificación del registro MFT** (MACE o MACB).

El **explorador de Windows** y otras herramientas muestran la información de **`$STANDARD_INFORMATION`**.

## TimeStomp - Herramienta anti-forense

Esta herramienta **modifica** la información de los timestamps dentro de **`$STANDARD_INFORMATION`** **pero no** la información dentro de **`$FILE_NAME`**. Por lo tanto, es posible **identificar** **actividad sospechosa**.

## Usnjrnl

El **USN Journal** (Update Sequence Number Journal), o Change Journal, es una característica del sistema de archivos de Windows NT (NTFS) que **mantiene un registro de los cambios realizados en el volumen**.\
Es posible utilizar la herramienta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) para buscar modificaciones en este registro.

![](<../../.gitbook/assets/image (449).png>)

La imagen anterior es la **salida** mostrada por la **herramienta** donde se puede observar que se realizaron algunos **cambios al archivo**.

## $LogFile

Todos los cambios de metadatos en un sistema de archivos se registran para garantizar la recuperación consistente de las estructuras críticas del sistema de archivos después de un fallo del sistema. Esto se llama [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead\_logging).\
Los metadatos registrados se almacenan en un archivo llamado "**$LogFile**", que se encuentra en un directorio raíz de
