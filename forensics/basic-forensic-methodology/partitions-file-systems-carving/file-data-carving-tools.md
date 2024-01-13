<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue**me en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Herramientas de Carving

## Autopsy

La herramienta más común utilizada en forense para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárgala, instálala y haz que procese el archivo para encontrar archivos "ocultos". Ten en cuenta que Autopsy está diseñado para soportar imágenes de disco y otros tipos de imágenes, pero no archivos simples.

## Binwalk <a id="binwalk"></a>

**Binwalk** es una herramienta para buscar en archivos binarios como imágenes y archivos de audio para encontrar archivos y datos incrustados.
Se puede instalar con `apt`, sin embargo, el [código fuente](https://github.com/ReFirmLabs/binwalk) se encuentra en github.
**Comandos útiles**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo quieres buscar algunos archivos específicos, descoméntalos. Si no descomentas nada, foremost buscará los tipos de archivos configurados por defecto.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** es otra herramienta que se puede usar para encontrar y extraer **archivos incrustados en un archivo**. En este caso, necesitarás descomentar del archivo de configuración \(_/etc/scalpel/scalpel.conf_\) los tipos de archivos que quieres que extraiga.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta herramienta viene incluida en kali, pero puedes encontrarla aquí: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Esta herramienta puede escanear una imagen y **extraerá pcaps** dentro de ella, **información de red \(URLs, dominios, IPs, MACs, correos\)** y más **archivos**. Solo tienes que hacer:
```text
bulk_extractor memory.img -o out_folder
```
Navegue a través de **toda la información** que la herramienta ha recopilado \(¿contraseñas?\), **analice** los **paquetes** \(lea [**Análisis de Pcaps**](../pcap-inspection/)\), busque **dominios extraños** \(dominios relacionados con **malware** o **inexistentes**\).

## PhotoRec

Puede encontrarlo en [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Viene con versión GUI y CLI. Puede seleccionar los **tipos de archivo** que desea que PhotoRec busque.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Herramientas Específicas para Carving de Datos

## FindAES

Busca claves AES buscando sus horarios de clave. Capaz de encontrar claves de 128, 192 y 256 bits, como las utilizadas por TrueCrypt y BitLocker.

Descargar [aquí](https://sourceforge.net/projects/findaes/).

# Herramientas Complementarias

Puede usar [**viu**](https://github.com/atanunq/viu) para ver imágenes desde la terminal.
Puede usar la herramienta de línea de comandos de Linux **pdftotext** para transformar un pdf en texto y leerlo.



<details>

<summary><strong>Aprenda hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si desea ver su **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtenga el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únase al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparta sus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
