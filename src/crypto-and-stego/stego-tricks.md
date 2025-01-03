# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Extracción de Datos de Archivos**

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

Ayuda a ver los metadatos del archivo, disponible [aquí](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Similar a exiftool, para la visualización de metadatos. Instalado a través de `apt`, código fuente en [GitHub](https://github.com/Exiv2/exiv2), y tiene un [sitio web oficial](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Archivo**

Identifica el tipo de archivo con el que estás tratando.

### **Cadenas**

Extrae cadenas legibles de archivos, utilizando varias configuraciones de codificación para filtrar la salida.
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

[GraphicMagick](https://imagemagick.org/script/download.php) sirve para determinar los tipos de archivos de imagen e identificar posibles corrupciones. Ejecuta el siguiente comando para inspeccionar una imagen:
```bash
./magick identify -verbose stego.jpg
```
Para intentar reparar una imagen dañada, agregar un comentario de metadatos podría ayudar:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide para la Ocultación de Datos**

Steghide facilita ocultar datos dentro de archivos `JPEG, BMP, WAV y AU`, capaz de incrustar y extraer datos encriptados. La instalación es sencilla usando `apt`, y su [código fuente está disponible en GitHub](https://github.com/StefanoDeVuono/steghide).

**Comandos:**

- `steghide info file` revela si un archivo contiene datos ocultos.
- `steghide extract -sf file [--passphrase password]` extrae los datos ocultos, la contraseña es opcional.

Para la extracción basada en la web, visita [este sitio web](https://futureboy.us/stegano/decinput.html).

**Ataque de Fuerza Bruta con Stegcracker:**

- Para intentar romper la contraseña en Steghide, usa [stegcracker](https://github.com/Paradoxis/StegCracker.git) de la siguiente manera:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg para archivos PNG y BMP**

zsteg se especializa en descubrir datos ocultos en archivos PNG y BMP. La instalación se realiza a través de `gem install zsteg`, con su [código fuente en GitHub](https://github.com/zed-0xff/zsteg).

**Comandos:**

- `zsteg -a file` aplica todos los métodos de detección en un archivo.
- `zsteg -E file` especifica una carga útil para la extracción de datos.

### **StegoVeritas y Stegsolve**

**stegoVeritas** verifica los metadatos, realiza transformaciones de imagen y aplica fuerza bruta LSB, entre otras características. Usa `stegoveritas.py -h` para una lista completa de opciones y `stegoveritas.py stego.jpg` para ejecutar todas las verificaciones.

**Stegsolve** aplica varios filtros de color para revelar textos o mensajes ocultos dentro de las imágenes. Está disponible en [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT para detección de contenido oculto**

Las técnicas de Transformada Rápida de Fourier (FFT) pueden revelar contenido oculto en imágenes. Los recursos útiles incluyen:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic en GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy para archivos de audio e imagen**

Stegpy permite incrustar información en archivos de imagen y audio, soportando formatos como PNG, BMP, GIF, WebP y WAV. Está disponible en [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck para análisis de archivos PNG**

Para analizar archivos PNG o validar su autenticidad, usa:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Herramientas Adicionales para Análisis de Imágenes**

Para una exploración adicional, considera visitar:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Extracción de Datos de Audios**

**La esteganografía de audio** ofrece un método único para ocultar información dentro de archivos de sonido. Se utilizan diferentes herramientas para incrustar o recuperar contenido oculto.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide es una herramienta versátil diseñada para ocultar datos en archivos JPEG, BMP, WAV y AU. Se proporcionan instrucciones detalladas en la [documentación de trucos de esteganografía](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Esta herramienta es compatible con una variedad de formatos, incluyendo PNG, BMP, GIF, WebP y WAV. Para más información, consulta la [sección de Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg es crucial para evaluar la integridad de los archivos de audio, destacando información detallada y señalando cualquier discrepancia.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg se destaca en ocultar y extraer datos dentro de archivos WAV utilizando la estrategia del bit menos significativo. Está disponible en [GitHub](https://github.com/ragibson/Steganography#WavSteg). Los comandos incluyen:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound permite la encriptación y detección de información dentro de archivos de sonido utilizando AES-256. Se puede descargar desde [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Una herramienta invaluable para la inspección visual y analítica de archivos de audio, Sonic Visualizer puede revelar elementos ocultos indetectables por otros medios. Visita el [official website](https://www.sonicvisualiser.org/) para más información.

### **DTMF Tones - Dial Tones**

Detectar tonos DTMF en archivos de audio se puede lograr a través de herramientas en línea como [this DTMF detector](https://unframework.github.io/dtmf-detect/) y [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Los datos binarios que se elevan al cuadrado para dar un número entero podrían representar un código QR. Usa este fragmento para verificar:
```python
import math
math.sqrt(2500) #50
```
Para la conversión de binario a imagen, consulta [dcode](https://www.dcode.fr/binary-image). Para leer códigos QR, utiliza [este lector de códigos de barras en línea](https://online-barcode-reader.inliteresearch.com/).

### **Traducción de Braille**

Para traducir Braille, el [Branah Braille Translator](https://www.branah.com/braille-translator) es un excelente recurso.

## **Referencias**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
