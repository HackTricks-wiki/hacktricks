# NTFS

## NTFS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **NTFS**

**NTFS** (**New Technology File System**) es un sistema de archivos de registro propietario desarrollado por Microsoft.

El clúster es la unidad de tamaño más pequeña en NTFS y el tamaño del clúster depende del tamaño de una partición.

| Tamaño de la partición | Sectores por clúster | Tamaño del clúster |
| ------------------------ | ------------------- | ------------ |
| 512MB o menos            | 1                   | 512 bytes    |
| 513MB-1024MB (1GB)       | 2                   | 1KB          |
| 1025MB-2048MB (2GB)      | 4                   | 2KB          |
| 2049MB-4096MB (4GB)      | 8                   | 4KB          |
| 4097MB-8192MB (8GB)      | 16                  | 8KB          |
| 8193MB-16,384MB (16GB)
### Marcas de tiempo de NTFS

![](<../../../.gitbook/assets/image (512).png>)

Otra herramienta útil para analizar el MFT es [**MFT2csv**](https://github.com/jschicht/Mft2Csv) (selecciona el archivo MFT o la imagen y presiona "dump all and extract" para extraer todos los objetos).\
Este programa extraerá todos los datos del MFT y los presentará en formato CSV. También se puede utilizar para volcar archivos.

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

El archivo **`$LOGFILE`** contiene **registros** sobre las **acciones** que se han **realizado** **en** **archivos**. También **guarda** la **acción** que necesitaría realizar en caso de un **reintento** y la acción necesaria para **volver** al **estado** **anterior**.\
Estos registros son útiles para que el MFT reconstruya el sistema de archivos en caso de que ocurra algún tipo de error. El tamaño máximo de este archivo es de **65536KB**.

Para inspeccionar el `$LOGFILE`, es necesario extraerlo e inspeccionar el `$MFT` previamente con [**MFT2csv**](https://github.com/jschicht/Mft2Csv).\
Luego, ejecute [**LogFileParser**](https://github.com/jschicht/LogFileParser) contra este archivo y seleccione el archivo `$LOGFILE` exportado y el CVS de la inspección del `$MFT`. Obtendrá un archivo CSV con los registros de la actividad del sistema de archivos registrados por el registro `$LOGFILE`.

![](<../../../.gitbook/assets/image (515).png>)

Filtrando por nombres de archivo, se pueden ver **todas las acciones realizadas contra un archivo**:

![](<../../../.gitbook/assets/image (514).png>)

### $USNJnrl

El archivo `$EXTEND/$USNJnrl/$J` es un flujo de datos alternativo del archivo `$EXTEND$USNJnrl`. Este artefacto contiene un **registro de cambios producidos dentro del volumen NTFS con más detalle que `$LOGFILE`**.

Para inspeccionar este archivo, se puede utilizar la herramienta [**UsnJrnl2csv**](https://github.com/jschicht/UsnJrnl2Csv).

Filtrando por el nombre de archivo, es posible ver **todas las acciones realizadas contra un archivo**. Además, se puede encontrar la `MFTReference` en la carpeta principal. Luego, al mirar esa `MFTReference`, se puede encontrar **información de la carpeta principal**.

![](<../../../.gitbook/assets/image (516).png>)

### $I30

Cada **directorio** en el sistema de archivos contiene un **atributo `$I30`** que debe mantenerse siempre que haya cambios en el contenido del directorio. Cuando se eliminan archivos o carpetas del directorio, los registros del índice **`$I30`** se reorganizan en consecuencia. Sin embargo, **la reorganización de los registros del índice puede dejar restos de la entrada de archivo/carpeta eliminada dentro del espacio de holgura**. Esto puede ser útil en el análisis forense para identificar archivos que pueden haber existido en la unidad.

Se puede obtener el archivo `$I30` de un directorio desde el **FTK Imager** e inspeccionarlo con la herramienta [Indx2Csv](https://github.com/jschicht/Indx2Csv).

![](<../../../.gitbook/assets/image (519).png>)

Con estos datos, se puede encontrar **información sobre los cambios de archivo realizados dentro de la carpeta**, pero tenga en cuenta que el tiempo de eliminación de un archivo no se guarda dentro de este registro. Sin embargo, se puede ver que la **última fecha de modificación** del archivo **`$I30`**, y si la **última acción realizada** sobre el directorio es la **eliminación** de un archivo, los tiempos pueden ser los mismos.

### $Bitmap

El **`$BitMap`** es un archivo especial dentro del sistema de archivos NTFS. Este archivo mantiene **un registro de todos los clústeres utilizados y no utilizados** en un volumen NTFS. Cuando un archivo ocupa espacio en el volumen NTFS, la ubicación utilizada se marca en el `$BitMap`.

![](<../../../.gitbook/assets/image (523).png>)

### ADS (Flujo de datos alternativo)

Los flujos de datos alternativos permiten que los archivos contengan más de un flujo de datos. Cada archivo tiene al menos un flujo de datos. En Windows, este flujo de datos predeterminado se llama `:$DATA`.\
En esta [página se pueden ver diferentes formas de crear/acceder/descubrir flujos de datos alternativos](../../../windows-hardening/basic-cmd-for-pentesters.md#alternate-data-streams-cheatsheet-ads-alternate-data-stream) desde la consola. En el pasado, esto causó una vulnerabilidad en IIS, ya que las personas podían acceder al código fuente de una página accediendo al flujo `:$DATA` como `http://www.alternate-data-streams.com/default.asp::$DATA`.

Usando la herramienta [**AlternateStreamView**](https://www.nirsoft.net/utils/alternate\_data\_streams.html), se pueden buscar y exportar todos los archivos con algún ADS.

![](<../../../.gitbook/assets/image (518).png>)

Usando el FTK Imager y haciendo doble clic en un archivo con ADS, se puede **acceder a los datos ADS**:

![](<../../../.gitbook/assets/image (517).png>)

Si encuentra un ADS llamado **`Zone.Identifier`** (ver la imagen anterior), esto generalmente contiene **información sobre cómo se descargó el archivo**. Habría un campo "ZoneId" con la siguiente información:

* Zone ID = 0 -> Mi equipo
* Zone ID = 1 -> Intranet
* Zone ID = 2 -> Confiable
* Zone ID = 3 -> Internet
* Zone ID = 4 -> No confiable

Además, diferentes software pueden almacenar información adicional:

| Software                                                            | Información                                                                 |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Google Chrome, Opera, Vivaldi,                                      | ZoneId=3, ReferrerUrl, HostUrl                                               |
| Microsoft Edge                                                      | ZoneId=3, LastWriterPackageFamilyName=Microsoft.MicrosoftEdge\_8wekyb3d8bbwe |
| Firefox, Tor browser, Outlook2016, Thunderbird, Windows Mail, Skype | ZoneId=3                                                                     |
| μTorrent                                                            | ZoneId=3, HostUrl=about:internet                                             |

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Consigue el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
