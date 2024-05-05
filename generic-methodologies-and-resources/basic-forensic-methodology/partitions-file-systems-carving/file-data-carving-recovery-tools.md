# Herramientas de Carving y Recuperación de Datos

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red de HackTricks AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Grupo de Seguridad Try Hard**

<figure><img src="../../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Herramientas de Carving y Recuperación

Más herramientas en [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

La herramienta más comúnmente utilizada en forense para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárgala, instálala y haz que ingiera el archivo para encontrar archivos "ocultos". Ten en cuenta que Autopsy está diseñado para admitir imágenes de disco y otros tipos de imágenes, pero no archivos simples.

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

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo deseas buscar archivos específicos, descoméntalos. Si no descomentas nada, foremost buscará por defecto los tipos de archivos configurados.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** es otra herramienta que se puede utilizar para encontrar y extraer **archivos incrustados en un archivo**. En este caso, deberás descomentar del archivo de configuración (_/etc/scalpel/scalpel.conf_) los tipos de archivo que deseas extraer.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Esta herramienta viene incluida en kali pero puedes encontrarla aquí: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Esta herramienta puede escanear una imagen y **extraer pcaps** en su interior, **información de red (URLs, dominios, IPs, MACs, correos electrónicos)** y más **archivos**. Solo tienes que hacer:
```
bulk_extractor memory.img -o out_folder
```
### PhotoRec

Puedes encontrarlo en [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Viene con versiones de GUI y CLI. Puedes seleccionar los **tipos de archivos** que deseas que PhotoRec busque.

![](<../../../.gitbook/assets/image (242).png>)

### binvis

Verifica el [código](https://code.google.com/archive/p/binvis/) y la [herramienta de la página web](https://binvis.io/#/).

#### Características de BinVis

* Visualizador de **estructuras** visual y activo
* Múltiples gráficos para diferentes puntos de enfoque
* Enfoque en porciones de una muestra
* **Ver cadenas y recursos**, en ejecutables PE o ELF, por ejemplo
* Obtener **patrones** para criptoanálisis en archivos
* **Detectar** algoritmos de empaquetado o codificación
* **Identificar** Esteganografía por patrones
* **Diferenciación** binaria visual

BinVis es un excelente **punto de partida para familiarizarse con un objetivo desconocido** en un escenario de caja negra.

## Herramientas Específicas de Recuperación de Datos

### FindAES

Busca claves AES buscando sus programaciones de claves. Capaz de encontrar claves de 128, 192 y 256 bits, como las utilizadas por TrueCrypt y BitLocker.

Descarga [aquí](https://sourceforge.net/projects/findaes/).

## Herramientas Complementarias

Puedes usar [**viu**](https://github.com/atanunq/viu) para ver imágenes desde la terminal.\
Puedes usar la herramienta de línea de comandos de Linux **pdftotext** para transformar un PDF en texto y leerlo.

**Try Hard Security Group**

<figure><img src="../../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
