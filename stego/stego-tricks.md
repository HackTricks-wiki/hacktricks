# Stego Tricks

**Some info was taken from** [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/) **and from** [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)\*\*\*\*

## Extracting data from all files

### Binwalk <a id="binwalk"></a>

Binwalk is a tool for searching binary files like images and audio files for embedded files and data.  
It can be installed with `apt` however the [source](https://github.com/ReFirmLabs/binwalk) can be found on github.  
**Useful commands**:  
`binwalk file` : Displays the embedded data in the given file  
`binwalk -e file` : Displays and extracts the data from the given file  
`binwalk --dd ".*" file` : Displays and extracts the data from the given file

### Foremost <a id="foremost"></a>

Foremost is a program that recovers files based on their headers , footers and internal data structures , I find it useful when dealing with png images. You can select the files that foremost extract by changing the config file in **/etc/foremost.conf.**  
It can be installed with `apt` however the [source](https://github.com/korczis/foremost) can be found on github.  
**Useful commands:**  
 `foremost -i file` : extracts data from the given file.

### Exiftool <a id="exiftool"></a>

Sometimes important stuff is hidden in the metadata of the image or the file , exiftool can be very helpful to view the metadata of the files.  
You can get it from [here](https://www.sno.phy.queensu.ca/~phil/exiftool/)  
**Useful commands:**  
`exiftool file` : shows the metadata of the given file

### Exiv2 <a id="exiv2"></a>

A tool similar to exiftool.  
It can be installed with `apt` however the [source](https://github.com/Exiv2/exiv2) can be found on github.  
[Official website](http://www.exiv2.org/)  
**Useful commands:**  
 `exiv2 file` : shows the metadata of the given file

### File

Check out what kind of file you have

### Strings

Extract strings from the file.  
Useful commands:  
`strings -n 6 file`: Extact the strings with min length of 6  
`strings -n 6 file | head -n 20`: Extact first 20 strings with min length of 6  
`strings -n 6 file | tail -n 20`: Extact last 20 strings with min length of 6  
`strings -e s -n 6 file`: Extact 7bit strings  
`strings -e S -n 6 file`: Extact 8bit strings   
`strings -e l -n 6 file`: Extact 16bit strings \(little-endian\)  
`strings -e b -n 6 file`: Extact 16bit strings \(big-endian\)  
`strings -e L -n 6 file`: Extact 32bit strings \(little-endian\)  
`strings -e B -n 6 file`: Extact 32bit strings \(big-endian\)

### cmp - Comparison

If you have some **modified** image/audio/video, check if you can **find the exact original one** from the internet and **compare both** files:

```text
cmp original.jpg stego.jpg -b -l
```

## Extracting hidden data in text

### Hidden data in spaces

If you find that a **text line** is **bigger** than it should, then some **hidden information** could by included inside the **spaces** using invisible characters.󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨  
To **extract** the **data** you can use: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

## Extracting data from images

### identify

 [GraphicMagick](https://imagemagick.org/script/download.php) tool to check what kind of image a file is. Checks also if image is corrupted.

```text
./magick identify -verbose stego.jpg
```

If the image is damage, you may be able to restore it just adding a metadata comment to it \(it's badly damaged this won't work\): 

```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```

### Steghide \[JPEG, BMP, WAV, AU\] <a id="steghide"></a>

Steghide is a steganography program that hides data in various kinds of image and audio files , only supports these file formats : `JPEG, BMP, WAV and AU`. but it’s also useful for extracting embedded and encrypted data from other files.  
 It can be installed with `apt` however the [source](https://github.com/StefanoDeVuono/steghide) can be found on github.  
**Useful commands:**  
`steghide info file` : displays info about a file whether it has embedded data or not.  
`steghide extract -sf file [--passphrase password]` : extracts embedded data from a file \[using a password\]

You can also extract content from steghide using the web: [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Bruteforcing** Steghide: [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP\] <a id="zsteg"></a>

zsteg is a tool that can detect hidden data in png and bmp files.  
Install it : `gem install zsteg` , The source can be found on [github](https://github.com/zed-0xff/zsteg)  
**Useful commands:**  
 `zsteg -a file` : Runs all the methods on the given file  
 `zsteg -E file` : Extracts data from the given payload \(example : zsteg -E b4,bgr,msb,xy name.png\)

### stegoVeritas JPG, PNG, GIF, TIFF, BMP 

A wide variety of simple and advanced checks. Check out `stegoveritas.py -h`. Checks metadata, creates many transformed images and saves them to a directory, Brute forces LSB, ...  
 `stegoveritas.py stego.jpg` to run all checks

### Stegsolve

Sometimes there is a message or a text hidden in the image itself and in order to view it you need to apply some color filters or play with the color levels. You can do it with GIMP or Photoshop or any other image editing software but stegsolve made it easier. it’s a small java tool that applies many color filters on images. Personally I find it very useful.  
You can get it from [github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)  
Just open the image with this tool and clinck on the  `<`  `>` buttons.

### FFT

Find hidden content using Fast Fourier T  
Check it in:

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic) `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV\]

A program for encoding information in image and audio files through steganography. It can store it in plain and encrypted.  
Find it in [github](https://github.com/dhsdshdhk/stegpy).

### Pngcheck

Get details on a PNG file \(or find out is is actually something else\).  
`apt-get isntall pngcheck`: Install the tool  
`pngcheck stego.png` : Obtain info

### Other tools

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Extracting data from audios

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpeg can be used to check integrity of audio files and let it report infos and errors.  
 `ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV\] <a id="wavsteg"></a>

WavSteg is a python3 tool that can hide data \(using least significant bit\) in wav files and can also extract data from wav files.  
You can get it from [github](https://github.com/ragibson/Steganography#WavSteg)  
Useful commands:  
 `python3 WavSteg.py -r -b 1 -s soundfile -o outputfile` : Extracts to output \(taking only 1 lsb\)  
 `python3 WavSteg.py -r -b 2 -s soundfile -o outputfile` : Extracts to output \(taking only 2 lsb\)

### Deepsound

Hide information encrypted using AES-265  
Download from [the oficial page](http://jpinsoft.net/deepsound/download.aspx).  
Run it and open the file and check if DeepSound finds any data hidden, in that case you will need to provide the password.

### Sonic visualizer <a id="sonic-visualizer"></a>

Sonic visualizer is a tool for viewing and analyzing the contents of audio files, however it can be helpful when dealing with audio steganography. You can reveal hidden shapes in audio files.   
You should always check the spectrogram of the audio.  
 [Offical Website](https://www.sonicvisualiser.org/)

### DTMF Tones - Dial tones

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Other tricks

### Binary length SQRT - QR Code

If you receibe a length of a binary data whose SQRT is an entire number, think that it can be some kind of QR code:

```text
import math
math.sqrt(2500) #50
```

From "1"s and "0"s to image: [ https://www.dcode.fr/binary-image](%20https://www.dcode.fr/binary-image)  
Read a QR code: [https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### Braile

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator%29)





