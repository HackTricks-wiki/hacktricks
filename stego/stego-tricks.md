# Técnicas de Estego

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repos de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para poder arreglarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Extracción de datos de todos los archivos

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalk es una herramienta para buscar en archivos binarios, como imágenes y archivos de audio, archivos y datos ocultos incrustados.\
Se puede instalar con `apt`, y el [código fuente](https://github.com/ReFirmLabs/binwalk) se puede encontrar en Github.\
**Comandos útiles**:\
`binwalk file` : Muestra los datos incrustados en el archivo dado\
`binwalk -e file` : Muestra y extrae los datos del archivo dado\
`binwalk --dd ".*" file` : Muestra y extrae los datos del archivo dado

### Foremost <a href="#foremost" id="foremost"></a>

Foremost es un programa que recupera archivos basándose en sus cabeceras, pies de página y estructuras de datos internas. Lo encuentro especialmente útil al tratar con imágenes png. Puedes seleccionar los archivos que Foremost extraerá cambiando el archivo de configuración en **/etc/foremost.conf.**\
Se puede instalar con `apt`, y el [código fuente](https://github.com/korczis/foremost) se puede encontrar en Github.\
**Comandos útiles:**\
`foremost -i file` : extrae datos del archivo dado.

### Exiftool <a href="#exiftool" id="exiftool"></a>

A veces, cosas importantes están ocultas en los metadatos de una imagen o archivo; exiftool puede ser muy útil para ver los metadatos de un archivo.\
Puedes obtenerlo [aquí](https://www.sno.phy.queensu.ca/\~phil/exiftool/)\
**Comandos útiles:**\
`exiftool file` : muestra los metadatos del archivo dado

### Exiv2 <a href="#exiv2" id="exiv2"></a>

Una herramienta similar a exiftool.\
Se puede instalar con `apt`, y el [código fuente](https://github.com/Exiv2/exiv2) se puede encontrar en Github.\
[Sitio web oficial](http://www.exiv2.org/)\
**Comandos útiles:**\
`exiv2 file` : muestra los metadatos del archivo dado

### File

Comprueba qué tipo de archivo tienes

### Strings

Extrae cadenas del archivo.\
Comandos útiles:\
`strings -n 6 file`: Extrae las cadenas con una longitud mínima de 6\
`strings -n 6 file | head -n 20`: Extrae las primeras 20 cadenas con una longitud mínima de 6\
`strings -n 6 file | tail -n 20`: Extrae las últimas 20 cadenas con una longitud mínima de 6\
`strings -e s -n 6 file`: Extrae cadenas de 7 bits\
`strings -e S -n 6 file`: Extrae cadenas de 8 bits\
`strings -e l -n 6 file`: Extrae cadenas de 16 bits (little-endian)\
`strings -e b -n 6 file`: Extrae cadenas de 16 bits (big-endian)\
`strings -e L -n 6 file`: Extrae cadenas de 32 bits (little-endian)\
`strings -e B -n 6 file`: Extrae cadenas de 32 bits (big-endian)

### cmp - Comparación

Si tienes alguna imagen/audio/video **modificado**, verifica si puedes **encontrar el original exacto** en internet, luego **compara ambos** archivos con:
```
cmp original.jpg stego.jpg -b -l
```
## Extracción de datos ocultos en texto

### Datos ocultos en espacios

Si encuentras que una **línea de texto** es **más grande** de lo que debería ser, entonces podría haber **información oculta** dentro de los **espacios** usando caracteres invisibles. Para **extraer** los **datos**, puedes usar: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Extracción de datos de imágenes

### identify

Herramienta [GraphicMagick](https://imagemagick.org/script/download.php) para verificar qué tipo de imagen es un archivo. También comprueba si la imagen está corrupta.
```
./magick identify -verbose stego.jpg
```
Si la imagen está dañada, podrías ser capaz de restaurarla simplemente añadiendo un comentario de metadatos a la misma (si está muy mal dañada esto no funcionará):
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghide es un programa de esteganografía que oculta datos en varios tipos de archivos de imagen y audio. Soporta los siguientes formatos de archivo: `JPEG, BMP, WAV y AU`. También es útil para extraer datos incrustados y encriptados de otros archivos.\
Se puede instalar con `apt`, y el [código fuente](https://github.com/StefanoDeVuono/steghide) se encuentra en Github.\
**Comandos útiles:**\
`steghide info file` : muestra información sobre si un archivo tiene datos incrustados o no.\
`steghide extract -sf file [--passphrase password]` : extrae datos incrustados de un archivo \[usando una contraseña]

También puedes extraer contenido de steghide usando la web: [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Fuerza bruta** en Steghide: [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zsteg es una herramienta que puede detectar datos ocultos en archivos png y bmp.\
Para instalarlo: `gem install zsteg`. El código fuente también se encuentra en [Github](https://github.com/zed-0xff/zsteg)\
**Comandos útiles:**\
`zsteg -a file` : Ejecuta todos los métodos de detección en el archivo dado\
`zsteg -E file` : Extrae datos con la carga útil dada (ejemplo: zsteg -E b4,bgr,msb,xy name.png)

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

Capaz de una amplia variedad de trucos simples y avanzados, esta herramienta puede verificar metadatos de archivos, crear imágenes transformadas, fuerza bruta en LSB y más. Consulta `stegoveritas.py -h` para leer sobre sus capacidades completas. Ejecuta `stegoveritas.py stego.jpg` para realizar todas las comprobaciones.

### Stegsolve

A veces hay un mensaje o un texto oculto en la imagen misma que, para verlo, debe tener aplicados filtros de color o algunos niveles de color cambiados. Aunque puedes hacer eso con algo como GIMP o Photoshop, Stegsolve lo facilita. Es una pequeña herramienta Java que aplica muchos filtros de color útiles en imágenes; en desafíos CTF, Stegsolve a menudo ahorra mucho tiempo.\
Puedes obtenerlo de [Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)\
Para usarlo, simplemente abre la imagen y haz clic en los botones `<` `>`.

### FFT

Para encontrar contenido oculto usando Transformada Rápida de Fourier:

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

Un programa para codificar información en archivos de imagen y audio a través de la esteganografía. Puede almacenar los datos como texto plano o encriptado.\
Encuéntralo en [Github](https://github.com/dhsdshdhk/stegpy).

### Pngcheck

Obtén detalles sobre un archivo PNG (¡o incluso averigua si en realidad es algo más!).\
`apt-get install pngcheck`: Instala la herramienta\
`pngcheck stego.png` : Obtén información sobre el PNG

### Algunas otras herramientas de imagen que vale la pena mencionar

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [https://github.com/resurrecting-open-source-projects/outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [https://www.openstego.com/](https://www.openstego.com/)
* [https://diit.sourceforge.net/](https://diit.sourceforge.net/)

## Extracción de datos de audios

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpeg se puede usar para verificar la integridad de archivos de audio, informando varias informaciones sobre el archivo, así como cualquier error que encuentre.\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavSteg es una herramienta Python3 que puede ocultar datos, usando el bit menos significativo, en archivos wav. También puede buscar y extraer datos de archivos wav.\
Puedes obtenerlo de [Github](https://github.com/ragibson/Steganography#WavSteg)\
Comandos útiles:\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile` : Extrae a un archivo de salida (tomando solo 1 lsb)\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile` : Extrae a un archivo de salida (tomando solo 2 lsb)

### Deepsound

Oculta y verifica información encriptada con AES-265 en archivos de sonido. Descarga desde [la página oficial](http://jpinsoft.net/deepsound/download.aspx).\
Para buscar información oculta, simplemente ejecuta el programa y abre el archivo de sonido. Si DeepSound encuentra datos ocultos, necesitarás proporcionar la contraseña para desbloquearlos.

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizer es una herramienta para ver y analizar los contenidos de archivos de audio. Puede ser muy útil cuando te enfrentas a desafíos de esteganografía de audio; puedes revelar formas ocultas en archivos de audio que muchas otras herramientas no detectarán.\
Si estás atascado, siempre verifica el espectrograma del audio. [Sitio Web Oficial](https://www.sonicvisualiser.org/)

### Tonos DTMF - Tonos de marcado

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Otros trucos

### Longitud binaria SQRT - Código QR

Si recibes datos binarios con una longitud SQRT de un número entero, podría ser algún tipo de código QR:
```
import math
math.sqrt(2500) #50
```
Para convertir "1"s y "0"s binarios en una imagen adecuada: [https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
Para leer un código QR: [https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### Braile

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **Referencias**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
