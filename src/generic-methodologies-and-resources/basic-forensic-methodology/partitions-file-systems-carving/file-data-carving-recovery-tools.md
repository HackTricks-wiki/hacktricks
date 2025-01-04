# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Herramientas de Carving y Recuperación

Más herramientas en [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

La herramienta más común utilizada en forenses para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárgala, instálala y haz que ingiera el archivo para encontrar archivos "ocultos". Ten en cuenta que Autopsy está diseñada para soportar imágenes de disco y otros tipos de imágenes, pero no archivos simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** es una herramienta para analizar archivos binarios y encontrar contenido incrustado. Se puede instalar a través de `apt` y su código fuente está en [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandos útiles**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo deseas buscar algunos archivos específicos, descoméntalos. Si no descomentas nada, foremost buscará sus tipos de archivo configurados por defecto.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** es otra herramienta que se puede utilizar para encontrar y extraer **archivos incrustados en un archivo**. En este caso, necesitarás descomentar del archivo de configuración (_/etc/scalpel/scalpel.conf_) los tipos de archivo que deseas que extraiga.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Esta herramienta viene dentro de kali, pero puedes encontrarla aquí: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Esta herramienta puede escanear una imagen y **extraer pcaps** dentro de ella, **información de red (URLs, dominios, IPs, MACs, correos)** y más **archivos**. Solo tienes que hacer:
```
bulk_extractor memory.img -o out_folder
```
Navega a través de **toda la información** que la herramienta ha recopilado (¿contraseñas?), **analiza** los **paquetes** (lee [**análisis de Pcaps**](../pcap-inspection/index.html)), busca **dominios extraños** (dominios relacionados con **malware** o **inexistentes**).

### PhotoRec

Puedes encontrarlo en [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Viene con versiones GUI y CLI. Puedes seleccionar los **tipos de archivo** que deseas que PhotoRec busque.

![](<../../../images/image (242).png>)

### binvis

Revisa el [código](https://code.google.com/archive/p/binvis/) y la [página web de la herramienta](https://binvis.io/#/).

#### Características de BinVis

- Visualizador de **estructura** visual y activa
- Múltiples gráficos para diferentes puntos de enfoque
- Enfocándose en porciones de una muestra
- **Viendo cadenas y recursos**, en ejecutables PE o ELF, por ejemplo.
- Obteniendo **patrones** para criptoanálisis en archivos
- **Detectando** algoritmos de empaquetado o codificación
- **Identificar** esteganografía por patrones
- **Diferenciación** binaria visual

BinVis es un gran **punto de partida para familiarizarse con un objetivo desconocido** en un escenario de caja negra.

## Herramientas específicas de recuperación de datos

### FindAES

Busca claves AES buscando sus horarios de clave. Capaz de encontrar claves de 128, 192 y 256 bits, como las utilizadas por TrueCrypt y BitLocker.

Descarga [aquí](https://sourceforge.net/projects/findaes/).

## Herramientas complementarias

Puedes usar [**viu**](https://github.com/atanunq/viu) para ver imágenes desde la terminal.\
Puedes usar la herramienta de línea de comandos de linux **pdftotext** para transformar un pdf en texto y leerlo.

{{#include ../../../banners/hacktricks-training.md}}
