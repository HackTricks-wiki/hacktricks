# Particiones/Sistemas de archivos/Carving

## Particiones

Un disco duro o un **SSD puede contener diferentes particiones** con el objetivo de separar físicamente los datos.\
La **unidad mínima** de un disco es el **sector** (normalmente compuesto por 512B). Por lo tanto, el tamaño de cada partición debe ser múltiplo de ese tamaño.

### MBR (Registro de arranque principal)

Se encuentra en el **primer sector del disco después de los 446B del código de arranque**. Este sector es esencial para indicar a la PC qué y desde dónde se debe montar una partición.\
Permite hasta **4 particiones** (como máximo **solo 1** puede estar activa/**arrancable**). Sin embargo, si necesita más particiones, puede usar **particiones extendidas**. El **último byte** de este primer sector es la firma del registro de arranque **0x55AA**. Solo se puede marcar una partición como activa.\
MBR permite **máximo 2.2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Desde los **bytes 440 a 443** del MBR, se puede encontrar la **Firma de disco de Windows** (si se usa Windows). La letra de unidad lógica del disco duro depende de la Firma de disco de Windows. Cambiar esta firma podría evitar que Windows se inicie (herramienta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Formato**

| Offset      | Longitud   | Elemento             |
| ----------- | ---------- | -------------------- |
| 0 (0x00)    | 446(0x1BE) | Código de arranque   |
| 446 (0x1BE) | 16 (0x10)  | Primera partición     |
| 462 (0x1CE) | 16 (0x10)  | Segunda partición    |
| 478 (0x1DE) | 16 (0x10)  | Tercera partición     |
| 494 (0x1EE) | 16 (0x10)  | Cuarta partición    |
| 510 (0x1FE) | 2 (0x2)    | Firma 0x55 0xAA |

**Formato de registro de partición**

| Offset    | Longitud | Elemento                                                  |
| --------- | -------- | --------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Bandera activa (0x80 = arrancable)                        |
| 1 (0x01)  | 1 (0x01) | Cabeza de inicio                                         |
| 2 (0x02)  | 1 (0x01) | Sector de inicio (bits 0-5); bits superiores del cilindro (6-7) |
| 3 (0x03)  | 1 (0x01) | Bits más bajos del cilindro de inicio                      |
| 4 (0x04)  | 1 (0x01) | Código de tipo de partición (0x83 = Linux)                |
| 5 (0x05)  | 1 (0x01) | Cabeza final                                             |
| 6 (0x06)  | 1 (0x01) | Sector final (bits 0-5); bits superiores del cilindro (6-7) |
| 7 (0x07)  | 1 (0x01) | Bits más bajos del cilindro final                         |
| 8 (0x08)  | 4 (0x04) | Sectores anteriores a la partición (poco endian)           |
| 12 (0x0C) | 4 (0x04) | Sectores en la partición                                  |

Para montar un MBR en Linux, primero debe obtener el desplazamiento de inicio (puede usar `fdisk` y el comando `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

Y luego use el siguiente código
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Dirección lógica de bloques)**

La **dirección lógica de bloques** (**LBA**) es un esquema común utilizado para **especificar la ubicación de bloques** de datos almacenados en dispositivos de almacenamiento informático, generalmente sistemas de almacenamiento secundario como discos duros. LBA es un esquema de direccionamiento lineal particularmente simple; **los bloques se ubican mediante un índice entero**, siendo el primer bloque LBA 0, el segundo LBA 1, y así sucesivamente.

### GPT (Tabla de particiones GUID)

Se llama Tabla de Particiones GUID porque cada partición en su disco tiene un **identificador único global**.

Al igual que MBR, comienza en el **sector 0**. El MBR ocupa 32 bits mientras que **GPT** utiliza **64 bits**.\
GPT **permite hasta 128 particiones** en Windows y hasta **9,4ZB**.\
Además, las particiones pueden tener un nombre Unicode de 36 caracteres.

En un disco MBR, la partición y los datos de arranque se almacenan en un solo lugar. Si estos datos se sobrescriben o se corrompen, estás en problemas. En contraste, **GPT almacena múltiples copias de estos datos en todo el disco**, por lo que es mucho más robusto y puede recuperarse si los datos están corruptos.

GPT también almacena valores de **verificación de redundancia cíclica (CRC)** para comprobar que sus datos están intactos. Si los datos están corruptos, GPT puede detectar el problema e **intentar recuperar los datos dañados** desde otra ubicación en el disco.

**MBR protector (LBA0)**

Para una compatibilidad limitada hacia atrás, el espacio del MBR heredado todavía se reserva en la especificación GPT, pero ahora se usa de una **manera que evita que las utilidades de disco basadas en MBR reconozcan erróneamente y posiblemente sobrescriban los discos GPT**. Esto se conoce como un MBR protector.

![](<../../../.gitbook/assets/image (491).png>)

**MBR híbrido (LBA 0 + GPT)**

En los sistemas operativos que admiten el **arranque basado en GPT a través de los servicios BIOS** en lugar de EFI, el primer sector también puede seguir utilizándose para almacenar la primera etapa del código del **cargador de arranque**, pero **modificado** para reconocer **particiones GPT**. El cargador de arranque en el MBR no debe asumir un tamaño de sector de 512 bytes.

**Encabezado de tabla de particiones (LBA 1)**

El encabezado de la tabla de particiones define los bloques utilizables en el disco. También define el número y el tamaño de las entradas de partición que conforman la tabla de particiones (desplazamientos 80 y 84 en la tabla).

| Desplazamiento | Longitud | Contenido                                                                                                                                                                        |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)       | 8 bytes  | Firma ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h o 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)en máquinas little-endian) |
| 8 (0x08)       | 4 bytes  | Revisión 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                     |
| 12 (0x0C)      | 4 bytes  | Tamaño del encabezado en little-endian (en bytes, generalmente 5Ch 00h 00h 00h o 92 bytes)                                                                                        |
| 16 (0x10)      | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) del encabezado (desplazamiento +0 hasta el tamaño del encabezado) en little-endian, con este campo en cero durante el cálculo |
| 20 (0x14)      | 4 bytes  | Reservado; debe ser cero                                                                                                                                                        |
| 24 (0x18)      | 8 bytes  | LBA actual (ubicación de esta copia de encabezado)                                                                                                                               |
| 32 (0x20)      | 8 bytes  | LBA de respaldo (ubicación de la otra copia de encabezado)                                                                                                                       |
| 40 (0x28)      | 8 bytes  | Primer LBA utilizable para particiones (último LBA de la tabla de particiones primaria + 1)                                                                                        |
| 48 (0x30)      | 8 bytes  | Último LBA utilizable (primer LBA de la tabla de particiones secundaria - 1)                                                                                                      |
| 56 (0x38)      | 16 bytes | GUID del disco en mixed-endian                                                                                                                                                  |
| 72 (0x48)      | 8 bytes  | LBA de inicio de una matriz de entradas de partición (siempre 2 en la copia primaria)                                                                                             |
| 80 (0x50)      | 4 bytes  | Número de entradas de partición en la matriz                                                                                                                                     |
| 84 (0x54)      | 4 bytes  | Tamaño de una sola entrada de partición (generalmente 80h o 128)                                                                                                                |
| 88 (0x58)      | 4 bytes  | CRC32 de la matriz de entradas de partición en little-endian                                                                                                                     |
| 92 (0x5C)      | \*       | Reservado; debe ser cero para el resto del bloque (420 bytes para un tamaño de sector de 512 bytes; pero puede ser más con tamaños de sector mayores)                         |

**Entradas de partición (LBA 2-33)**

| Formato de entrada de partición GUID |          |                                                                                                                   |
| ----------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Desplazamiento
### **Tallado de archivos**

El **tallado de archivos** es una técnica que intenta **encontrar archivos en un gran volumen de datos**. Hay 3 formas principales en que funcionan las herramientas como esta: **basadas en encabezados y pies de página de tipos de archivo**, basadas en **estructuras de tipos de archivo** y basadas en el **contenido** en sí.

Tenga en cuenta que esta técnica **no funciona para recuperar archivos fragmentados**. Si un archivo **no se almacena en sectores contiguos**, entonces esta técnica no podrá encontrarlo o al menos parte de él.

Hay varias herramientas que puede utilizar para el tallado de archivos indicando los tipos de archivo que desea buscar.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Tallado de flujos de datos

El tallado de flujos de datos es similar al tallado de archivos, pero **en lugar de buscar archivos completos, busca fragmentos interesantes** de información. Por ejemplo, en lugar de buscar un archivo completo que contenga URL registradas, esta técnica buscará URL.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Eliminación segura

Obviamente, hay formas de **eliminar "seguramente" archivos y parte de los registros sobre ellos**. Por ejemplo, es posible **sobrescribir el contenido** de un archivo con datos basura varias veces, y luego **eliminar** los **registros** del **$MFT** y **$LOGFILE** sobre el archivo, y **eliminar las copias de sombra del volumen**.\
Puede notar que incluso al realizar esa acción, puede haber **otras partes donde todavía se registra la existencia del archivo**, y eso es cierto y parte del trabajo profesional de la informática forense es encontrarlos.

## Referencias

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparta sus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
