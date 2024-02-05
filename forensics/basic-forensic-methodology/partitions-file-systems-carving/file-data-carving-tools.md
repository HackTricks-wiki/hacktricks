<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# Herramientas de Carving

## Autopsy

La herramienta más común utilizada en forense para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárgala, instálala y haz que ingiera el archivo para encontrar archivos "ocultos". Ten en cuenta que Autopsy está diseñado para admitir imágenes de disco y otros tipos de imágenes, pero no archivos simples.

## Binwalk <a id="binwalk"></a>

**Binwalk** es una herramienta para buscar archivos binarios como imágenes y archivos de audio en busca de archivos y datos incrustados.
Puede ser instalado con `apt`, sin embargo, la [fuente](https://github.com/ReFirmLabs/binwalk) se puede encontrar en github.
**Comandos útiles**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo deseas buscar archivos específicos, descoméntalos. Si no descomentas nada, foremost buscará los tipos de archivo configurados por defecto.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** es otra herramienta que se puede utilizar para encontrar y extraer **archivos incrustados en un archivo**. En este caso, deberá descomentar en el archivo de configuración \(_/etc/scalpel/scalpel.conf_\) los tipos de archivo que desea extraer.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta herramienta viene incluida en Kali pero puedes encontrarla aquí: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Esta herramienta puede escanear una imagen y **extraer pcaps** en su interior, **información de red \(URLs, dominios, IPs, MACs, correos electrónicos\)** y más **archivos**. Solo tienes que hacer:
```text
bulk_extractor memory.img -o out_folder
```
## PhotoRec

Puedes encontrarlo en [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Viene con versión GUI y CLI. Puedes seleccionar los **tipos de archivos** que deseas que PhotoRec busque.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Herramientas Específicas de Carving de Datos

## FindAES

Busca claves AES buscando sus programaciones de claves. Capaz de encontrar claves de 128, 192 y 256 bits, como las utilizadas por TrueCrypt y BitLocker.

Descarga [aquí](https://sourceforge.net/projects/findaes/).

# Herramientas Complementarias

Puedes usar [**viu** ](https://github.com/atanunq/viu)para ver imágenes desde la terminal.
Puedes usar la herramienta de línea de comandos de Linux **pdftotext** para transformar un pdf en texto y leerlo.
