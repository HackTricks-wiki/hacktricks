# Trucos de Stego

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Usa [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Extrayendo datos de todos los archivos

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalk es una herramienta para buscar archivos binarios, como imágenes y archivos de audio, para encontrar archivos y datos ocultos incrustados.\
Se puede instalar con `apt`, y la [fuente](https://github.com/ReFirmLabs/binwalk) se puede encontrar en Github.\
**Comandos útiles**:\
`binwalk file` : Muestra los datos incrustados en el archivo dado\
`binwalk -e file` : Muestra y extrae los datos del archivo dado\
`binwalk --dd ".*" file` : Muestra y extrae los datos del archivo dado

### Foremost <a href="#foremost" id="foremost"></a>

Foremost es un programa que recupera archivos basados en sus encabezados, pies de página y estructuras de datos internas. Lo encuentro especialmente útil al tratar con imágenes png. Puedes seleccionar los archivos que Foremost extraerá cambiando el archivo de configuración en **/etc/foremost.conf.**\
Se puede instalar con `apt`, y la [fuente](https://github.com/korczis/foremost) se puede encontrar en Github.\
**Comandos útiles:**\
`foremost -i file` : extrae datos del archivo dado.

### Exiftool <a href="#exiftool" id="exiftool"></a>

A veces, cosas importantes están ocultas en los metadatos de una imagen o archivo; exiftool puede ser muy útil para ver los metadatos del archivo.\
Puedes obtenerlo [aquí](https://www.sno.phy.queensu.ca/\~phil/exiftool/)\
**Comandos útiles:**\
`exiftool file` : muestra los metadatos del archivo dado

### Exiv2 <a href="#exiv2" id="exiv2"></a>

Una herramienta similar a exiftool.\
Se puede instalar con `apt`, y la [fuente](https://github.com/Exiv2/exiv2) se puede encontrar en Github.\
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
`strings -e l -n 6 file`: Extrae cadenas de 16 bits (poco-endian)\
`strings -e b -n 6 file`: Extrae cadenas de 16 bits (big-endian)\
`strings -e L -n 6 file`: Extrae cadenas de 32 bits (poco-endian)\
`strings -e B -n 6 file`: Extrae cadenas de 32 bits (big-endian)

### cmp - Comparación

Si tienes alguna imagen/audio/video **modificado**, comprueba si puedes **encontrar el original exacto** en internet, luego **compara ambos** archivos con:
```
cmp original.jpg stego.jpg -b -l
```
## Extrayendo datos ocultos en texto

### Datos ocultos en espacios

Si encuentras que una **línea de texto** es **más grande** de lo que debería ser, entonces es posible que se haya incluido alguna **información oculta** dentro de los **espacios** utilizando caracteres invisibles. 󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
Para **extraer** los **datos**, puedes usar: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Usa [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Extrayendo datos de imágenes

### identify

Herramienta [GraphicMagick](https://imagemagick.org/script/download.php) para verificar qué tipo de imagen es un archivo. También verifica si la imagen está corrupta.
```
./magick identify -verbose stego.jpg
```
Si la imagen está dañada, es posible que pueda restaurarse simplemente agregando un comentario de metadatos (si está muy dañada, esto no funcionará):
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghide es un programa de esteganografía que oculta datos en varios tipos de archivos de imagen y audio. Admite los siguientes formatos de archivo: `JPEG, BMP, WAV y AU`. También es útil para extraer datos incrustados y cifrados de otros archivos.\
Se puede instalar con `apt`, y la [fuente](https://github.com/StefanoDeVuono/steghide) se puede encontrar en Github.\
**Comandos útiles:**\
`steghide info archivo` : muestra información sobre si un archivo tiene datos incrustados o no.\
`steghide extract -sf archivo [--passphrase contraseña]` : extrae datos incrustados de un archivo \[usando una contraseña]

También se puede extraer contenido de steghide usando la web: [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Fuerza bruta** en Steghide: [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <archivo> [<lista de palabras>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zsteg es una herramienta que puede detectar datos ocultos en archivos png y bmp.\
Para instalarlo: `gem install zsteg`. La fuente también se puede encontrar en [Github](https://github.com/zed-0xff/zsteg)\
**Comandos útiles:**\
`zsteg -a archivo` : Ejecuta todos los métodos de detección en el archivo dado\
`zsteg -E archivo` : Extrae datos con la carga útil dada (ejemplo: zsteg -E b4,bgr,msb,xy nombre.png)

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

Capaz de una amplia variedad de trucos simples y avanzados, esta herramienta puede verificar los metadatos del archivo, crear imágenes transformadas, forzar LSB y más. Consulte `stegoveritas.py -h` para leer sobre todas sus capacidades. Ejecute `stegoveritas.py stego.jpg` para ejecutar todas las comprobaciones.

### Stegsolve

A veces hay un mensaje o un texto oculto en la imagen misma que, para verlo, debe aplicar filtros de color o cambiar algunos niveles de color. Aunque se puede hacer eso con algo como GIMP o Photoshop, Stegsolve lo hace más fácil. Es una pequeña herramienta de Java que aplica muchos filtros de color útiles en imágenes; En los desafíos CTF, Stegsolve a menudo es un verdadero ahorro de tiempo.\
Se puede obtener de [Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)\
Para usarlo, simplemente abra la imagen y haga clic en los botones `<` `>`.

### FFT

Para encontrar contenido oculto usando Fast Fourier T:

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

Un programa para codificar información en archivos de imagen y audio a través de la esteganografía. Puede almacenar los datos como texto sin formato o cifrado.\
Encuéntralo en [Github](https://github.com/dhsdshdhk/stegpy).

### Pngcheck

Obtenga detalles sobre un archivo PNG (¡o incluso descubra que en realidad es algo más!).\
`apt-get install pngcheck`: Instale la herramienta\
`pngcheck stego.png` : Obtenga información sobre el PNG

### Otras herramientas de imagen que vale la pena mencionar

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Extracción de datos de audios

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpeg se puede utilizar para verificar la integridad de los archivos de audio, informando varios detalles sobre el archivo, así como cualquier error que encuentre.\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavSteg es una herramienta de Python3 que puede ocultar datos, utilizando el bit menos significativo, en archivos wav. También puede buscar y extraer datos de archivos wav.\
Se puede obtener de [Github](https://github.com/ragibson/Steganography#WavSteg)\
Comandos útiles:\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile` : Extrae a un archivo de salida (tomando solo 1 lsb)\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile` : Extrae a un archivo de salida (tomando solo 2 lsb)

### Deepsound

Oculta y verifica información cifrada con AES-265 en archivos de sonido. Descarga desde [la página oficial](http://jpinsoft.net/deepsound/download.aspx).\
Para buscar información oculta, simplemente ejecute el programa y abra el archivo de sonido. Si DeepSound encuentra algún dato oculto, deberá proporcionar la contraseña para desbloquearlo.

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizer es una herramienta para ver y analizar el contenido de archivos de audio. Puede ser muy útil cuando se enfrenta a desafíos de esteganografía de audio; puede revelar formas ocultas en archivos de audio que muchas otras herramientas no detectarán.\
Si está atascado, siempre verifique el espectrograma del audio. [Sitio web oficial](https://www.sonicvisualiser.org/)

### Tonos DTMF - Tonos de marcación

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Otros trucos

### Longitud binaria SQRT - Código QR

Si recibe datos binarios con una longitud SQRT de un número entero, podría ser algún tipo de código QR:
```
import math
math.sqrt(2500) #50
```
Para convertir los "1"s y "0"s binarios en una imagen adecuada: [https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
Para leer un código QR: [https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### Braille

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **Referencias**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Usa [**Trickest**](https://trickest.io/) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
