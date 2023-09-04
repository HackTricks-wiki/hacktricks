# Stego Tricks

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Extracting data from all files

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalk is a tool for searching binary files, like images and audio files, for embedded hidden files and data.\
It can be installed with `apt`, and the [source](https://github.com/ReFirmLabs/binwalk) can be found on Github.\
**Useful commands**:\
`binwalk file` : Displays the embedded data in the given file\
`binwalk -e file` : Displays and extracts the data from the given file\
`binwalk --dd ".*" file` : Displays and extracts the data from the given file

### Foremost <a href="#foremost" id="foremost"></a>

Foremost is a program that recovers files based on their headers, footers, and internal data structures. I find it especially useful when dealing with png images. You can select the files that Foremost will extract by changing the config file in **/etc/foremost.conf.**\
It can be installed with `apt`, and the [source](https://github.com/korczis/foremost) can be found on Github.\
**Useful commands:**\
`foremost -i file` : extracts data from the given file.

### Exiftool <a href="#exiftool" id="exiftool"></a>

Sometimes, important stuff is hidden in the metadata of an image or file; exiftool can be very helpful to view file metadata.\
You can get it from [here](https://www.sno.phy.queensu.ca/\~phil/exiftool/)\
**Useful commands:**\
`exiftool file` : shows the metadata of the given file

### Exiv2 <a href="#exiv2" id="exiv2"></a>

A tool similar to exiftool.\
It can be installed with `apt`, and the [source](https://github.com/Exiv2/exiv2) can be found on Github.\
[Official website](http://www.exiv2.org/)\
**Useful commands:**\
`exiv2 file` : shows the metadata of the given file

### File

Check out what kind of file you have

### Strings

Extract strings from the file.\
Useful commands:\
`strings -n 6 file`: Extract the strings with min length of 6\
`strings -n 6 file | head -n 20`: Extract first 20 strings with min length of 6\
`strings -n 6 file | tail -n 20`: Extract last 20 strings with min length of 6\
`strings -e s -n 6 file`: Extract 7bit strings\
`strings -e S -n 6 file`: Extract 8bit strings\
`strings -e l -n 6 file`: Extract 16bit strings (little-endian)\
`strings -e b -n 6 file`: Extract 16bit strings (big-endian)\
`strings -e L -n 6 file`: Extract 32bit strings (little-endian)\
`strings -e B -n 6 file`: Extract 32bit strings (big-endian)

### cmp - Comparison

If you have some **modified** image/audio/video, check if you can **find the exact original one** on the internet, then **compare both** files with:

```
cmp original.jpg stego.jpg -b -l
```

## Extracting hidden data in text

### Hidden data in spaces

If you find that a **text line** is **bigger** than it should be, then some **hidden information** could be included inside the **spaces** using invisible characters.󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
To **extract** the **data**, you can use: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Extracting data from images

### identify

[GraphicMagick](https://imagemagick.org/script/download.php) tool to check what kind of image a file is. Also checks if the image is corrupted.

```
./magick identify -verbose stego.jpg
```

If the image is damaged, you may be able to restore it by simply adding a metadata comment to it (if it's very badly damaged this won't work):

```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```

### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghide is a steganography program that hides data in various kinds of image and audio files. It supports the following file formats : `JPEG, BMP, WAV and AU`. It’s also useful for extracting embedded and encrypted data from other files.\
It can be installed with `apt`, and the [source](https://github.com/StefanoDeVuono/steghide) can be found on Github.\
**Useful commands:**\
`steghide info file` : displays info about whether a file has embedded data or not.\
`steghide extract -sf file [--passphrase password]` : extracts embedded data from a file \[using a password]

You can also extract content from steghide using the web: [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Bruteforcing** Steghide: [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zsteg is a tool that can detect hidden data in png and bmp files.\
To install it : `gem install zsteg`. The source can also be found on [Github](https://github.com/zed-0xff/zsteg)\
**Useful commands:**\
`zsteg -a file` : Runs every detection method on the given file\
`zsteg -E file` : Extracts data with the given payload (example : zsteg -E b4,bgr,msb,xy name.png)

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

Capable of a wide variety of simple and advanced tricks, this tool can check file metadata, create transformed images, brute force LSB, and more. Check out `stegoveritas.py -h` to read about its full capabilities. Execute `stegoveritas.py stego.jpg` to run all checks.

### Stegsolve

Sometimes there is a message or a text hidden in the image itself that, in order to view it, must have color filters applied, or some color levels changed. Although you can do that with something like GIMP or Photoshop, Stegsolve makes it easier. It's a small Java tool that applies many useful color filters on images; In CTF challenges, Stegsolve is often a real timesaver.\
You can get it from [Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)\
To use it, just open the image and click on the `<` `>` buttons.

### FFT

To find hidden content using Fast Fourier T:

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

A program for encoding information in image and audio files through steganography. It can store the data as either plaintext or encrypted.\
Find it on [Github](https://github.com/dhsdshdhk/stegpy).

### Pngcheck

Get details on a PNG file (or even find out it's actually something else!).\
`apt-get install pngcheck`: Install the tool\
`pngcheck stego.png` : Obtain info about the PNG

### Some other image tools worth mentioning

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Extracting data from audios

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpeg can be used to check the integrity of audio files, reporting various information about the file, as well as any errors it finds.\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavSteg is a Python3 tool that can hide data, using least significant bit, in wav files. It can also search for, and extract, data from wav files.\
You can get it from [Github](https://github.com/ragibson/Steganography#WavSteg)\
Useful commands:\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile` : Extracts to an output file (taking only 1 lsb)\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile` : Extracts to an output file (taking only 2 lsb)

### Deepsound

Hide, and check for, information encrypted with AES-265 in sound files. Download from [the oficial page](http://jpinsoft.net/deepsound/download.aspx).\
To search for hidden info, simply run the program and open the sound file. If DeepSound finds any data hidden, you'll need to provide the password to unlock it.

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizer is a tool for viewing and analyzing the contents of audio files. It can be very helpful when facing audio steganography challenges; you can reveal hidden shapes in audio files that many other tools won't detect.\
If you're stuck, always check the spectrogram of the audio. [Offical Website](https://www.sonicvisualiser.org/)

### DTMF Tones - Dial tones

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Other tricks

### Binary length SQRT - QR Code

If you receive binary data with an SQRT length of an entire number, it could be some kind of QR code:

```
import math
math.sqrt(2500) #50
```

To convert binary "1"s and "0"s to a proper image: [https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
To read a QR code: [https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### Braile

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **References**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
