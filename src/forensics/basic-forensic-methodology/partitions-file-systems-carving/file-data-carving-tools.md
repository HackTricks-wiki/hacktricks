{{#include ../../../banners/hacktricks-training.md}}

# Herramientas de carving

## Autopsy

La herramienta más común utilizada en forense para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárgala, instálala y haz que ingiera el archivo para encontrar archivos "ocultos". Ten en cuenta que Autopsy está diseñada para soportar imágenes de disco y otros tipos de imágenes, pero no archivos simples.

## Binwalk <a id="binwalk"></a>

**Binwalk** es una herramienta para buscar archivos binarios como imágenes y archivos de audio en busca de archivos y datos incrustados.  
Se puede instalar con `apt`, sin embargo, la [fuente](https://github.com/ReFirmLabs/binwalk) se puede encontrar en github.  
**Comandos útiles**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo deseas buscar algunos archivos específicos, descomenta esos. Si no descomentas nada, foremost buscará los tipos de archivos configurados por defecto.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** es otra herramienta que se puede usar para encontrar y extraer **archivos incrustados en un archivo**. En este caso, necesitarás descomentar del archivo de configuración \(_/etc/scalpel/scalpel.conf_\) los tipos de archivos que deseas que extraiga.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta herramienta viene incluida en Kali, pero puedes encontrarla aquí: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Esta herramienta puede escanear una imagen y **extraer pcaps** dentro de ella, **información de red (URLs, dominios, IPs, MACs, correos)** y más **archivos**. Solo tienes que hacer:
```text
bulk_extractor memory.img -o out_folder
```
Navega a través de **toda la información** que la herramienta ha recopilado \(¿contraseñas?\), **analiza** los **paquetes** \(lee [**análisis de Pcaps**](../pcap-inspection/index.html)\), busca **dominios extraños** \(dominios relacionados con **malware** o **inexistentes**\).

## PhotoRec

Puedes encontrarlo en [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Viene con versión GUI y CLI. Puedes seleccionar los **tipos de archivo** que deseas que PhotoRec busque.

![](../../../images/image%20%28524%29.png)

# Herramientas específicas de carving de datos

## FindAES

Busca claves AES buscando sus horarios de clave. Capaz de encontrar claves de 128, 192 y 256 bits, como las utilizadas por TrueCrypt y BitLocker.

Descarga [aquí](https://sourceforge.net/projects/findaes/).

# Herramientas complementarias

Puedes usar [**viu** ](https://github.com/atanunq/viu) para ver imágenes desde la terminal.  
Puedes usar la herramienta de línea de comandos de linux **pdftotext** para transformar un pdf en texto y leerlo.

{{#include ../../../banners/hacktricks-training.md}}
