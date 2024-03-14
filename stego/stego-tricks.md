# Trucos de Estego

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de GitHub.

</details>

**Grupo de Seguridad Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## **Extrayendo Datos de Archivos**

### **Binwalk**

Una herramienta para buscar archivos binarios en busca de archivos y datos ocultos incrustados. Se instala a través de `apt` y su código fuente está disponible en [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Recupera archivos basados en sus encabezados y pies de página, útil para imágenes png. Instalado a través de `apt` con su fuente en [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Ayuda a ver los metadatos del archivo, disponible [aquí](https://www.sno.phy.queensu.ca/\~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Similar to exiftool, for viewing metadata. Instalable via `apt`, fuente en [GitHub](https://github.com/Exiv2/exiv2), y tiene un [sitio web oficial](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Archivo**

Identifica el tipo de archivo con el que estás tratando.

### **Cadenas**

Extrae cadenas legibles de archivos, utilizando varios ajustes de codificación para filtrar la salida.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Comparación (cmp)**

Útil para comparar un archivo modificado con su versión original encontrada en línea.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Extracción de Datos Ocultos en Texto**

### **Datos Ocultos en Espacios**

Los caracteres invisibles en espacios aparentemente vacíos pueden ocultar información. Para extraer estos datos, visita [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Extracción de Datos de Imágenes**

### **Identificación de Detalles de Imágenes con GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) sirve para determinar tipos de archivos de imagen e identificar posibles corrupciones. Ejecuta el siguiente comando para inspeccionar una imagen:
```bash
./magick identify -verbose stego.jpg
```
Para intentar reparar una imagen dañada, agregar un comentario de metadatos podría ser útil:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Esteganografía para Ocultar Datos**

Steghide facilita ocultar datos dentro de archivos `JPEG, BMP, WAV y AU`, capaz de incrustar y extraer datos encriptados. La instalación es sencilla utilizando `apt`, y su [código fuente está disponible en GitHub](https://github.com/StefanoDeVuono/steghide).

**Comandos:**

* `steghide info archivo` revela si un archivo contiene datos ocultos.
* `steghide extract -sf archivo [--contraseña contraseña]` extrae los datos ocultos, la contraseña es opcional.

Para extracción basada en web, visita [este sitio web](https://futureboy.us/stegano/decinput.html).

**Ataque de Fuerza Bruta con Stegcracker:**

* Para intentar la craqueo de contraseñas en Steghide, utiliza [stegcracker](https://github.com/Paradoxis/StegCracker.git) de la siguiente manera:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg para archivos PNG y BMP**

zsteg se especializa en descubrir datos ocultos en archivos PNG y BMP. La instalación se realiza a través de `gem install zsteg`, con su [fuente en GitHub](https://github.com/zed-0xff/zsteg).

**Comandos:**

* `zsteg -a archivo` aplica todos los métodos de detección en un archivo.
* `zsteg -E archivo` especifica un payload para la extracción de datos.

### **StegoVeritas y Stegsolve**

**stegoVeritas** verifica metadatos, realiza transformaciones de imagen y aplica fuerza bruta LSB, entre otras características. Utiliza `stegoveritas.py -h` para obtener una lista completa de opciones y `stegoveritas.py stego.jpg` para ejecutar todas las verificaciones.

**Stegsolve** aplica varios filtros de color para revelar textos ocultos o mensajes dentro de imágenes. Está disponible en [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT para la detección de contenido oculto**

Las técnicas de Transformada Rápida de Fourier (FFT) pueden revelar contenido oculto en imágenes. Recursos útiles incluyen:

* [Demo de EPFL](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [FFTStegPic en GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy para archivos de audio e imagen**

Stegpy permite incrustar información en archivos de imagen y audio, admitiendo formatos como PNG, BMP, GIF, WebP y WAV. Está disponible en [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck para análisis de archivos PNG**

Para analizar archivos PNG o validar su autenticidad, utiliza:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Herramientas adicionales para análisis de imágenes**

Para una exploración más detallada, considera visitar:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Análisis de Nivel de Error de Imagen](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **Extracción de datos de archivos de audio**

La **esteganografía de audio** ofrece un método único para ocultar información dentro de archivos de sonido. Se utilizan diferentes herramientas para incrustar o recuperar contenido oculto.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide es una herramienta versátil diseñada para ocultar datos en archivos JPEG, BMP, WAV y AU. Se proporcionan instrucciones detalladas en la [documentación de trucos de estego](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Esta herramienta es compatible con una variedad de formatos, incluidos PNG, BMP, GIF, WebP y WAV. Para obtener más información, consulta la [sección de Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg es crucial para evaluar la integridad de archivos de audio, resaltando información detallada y señalando cualquier discrepancia.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg destaca en ocultar y extraer datos dentro de archivos WAV utilizando la estrategia del bit menos significativo. Es accesible en [GitHub](https://github.com/ragibson/Steganography#WavSteg). Los comandos incluyen:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound permite el cifrado y la detección de información dentro de archivos de sonido utilizando AES-256. Puede descargarse desde [la página oficial](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Una herramienta invaluable para la inspección visual y analítica de archivos de audio, Sonic Visualizer puede revelar elementos ocultos indetectables por otros medios. Visita el [sitio web oficial](https://www.sonicvisualiser.org/) para más información.

### **Tonos DTMF - Tonos de marcación**

La detección de tonos DTMF en archivos de audio se puede lograr a través de herramientas en línea como [este detector de DTMF](https://unframework.github.io/dtmf-detect/) y [DialABC](http://dialabc.com/sound/detect/index.html).

## **Otras Técnicas**

### **Longitud Binaria SQRT - Código QR**

Los datos binarios que al cuadrar dan un número entero podrían representar un código QR. Utiliza este fragmento para verificar:
```python
import math
math.sqrt(2500) #50
```
### **Traducción de Braille**

Para traducir Braille, el [Traductor de Braille de Branah](https://www.branah.com/braille-translator) es un excelente recurso.

## **Referencias**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

**Grupo de Seguridad Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
