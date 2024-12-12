# Stego Tricks

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Extracting Data from Files**

### **Binwalk**

A tool for searching binary files for embedded hidden files and data. It's installed via `apt` and its source is available on [GitHub](https://github.com/ReFirmLabs/binwalk).

```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```

### **Foremost**

Recovers files based on their headers and footers, useful for png images. Installed via `apt` with its source on [GitHub](https://github.com/korczis/foremost).

```bash
foremost -i file # Extracts data
```

### **Exiftool**

Helps to view file metadata, available [here](https://www.sno.phy.queensu.ca/\~phil/exiftool/).

```bash
exiftool file # Shows the metadata
```

### **Exiv2**

Similar to exiftool, for metadata viewing. Installable via `apt`, source on [GitHub](https://github.com/Exiv2/exiv2), and has an [official website](http://www.exiv2.org/).

```bash
exiv2 file # Shows the metadata
```

### **File**

Identify the type of file you're dealing with.

### **Strings**

Extracts readable strings from files, using various encoding settings to filter the output.

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

Useful for comparing a modified file with its original version found online.

```bash
cmp original.jpg stego.jpg -b -l
```

## **Extracting Hidden Data in Text**

### **Hidden Data in Spaces**

Invisible characters in seemingly empty spaces may hide information. To extract this data, visit [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Extracting Data from Images**

### **Identifying Image Details with GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) serves to determine image file types and identify potential corruption. Execute the command below to inspect an image:

```bash
./magick identify -verbose stego.jpg
```

To attempt repair on a damaged image, adding a metadata comment might help:

```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```

### **Steghide for Data Concealment**

Steghide facilitates hiding data within `JPEG, BMP, WAV, and AU` files, capable of embedding and extracting encrypted data. Installation is straightforward using `apt`, and its [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Commands:**

* `steghide info file` reveals if a file contains hidden data.
* `steghide extract -sf file [--passphrase password]` extracts the hidden data, password optional.

For web-based extraction, visit [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

* To attempt password cracking on Steghide, use [stegcracker](https://github.com/Paradoxis/StegCracker.git) as follows:

```bash
stegcracker <file> [<wordlist>]
```

### **zsteg for PNG and BMP Files**

zsteg specializes in uncovering hidden data in PNG and BMP files. Installation is done via `gem install zsteg`, with its [source on GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

* `zsteg -a file` applies all detection methods on a file.
* `zsteg -E file` specifies a payload for data extraction.

### **StegoVeritas and Stegsolve**

**stegoVeritas** checks metadata, performs image transformations, and applies LSB brute forcing among other features. Use `stegoveritas.py -h` for a full list of options and `stegoveritas.py stego.jpg` to execute all checks.

**Stegsolve** applies various color filters to reveal hidden texts or messages within images. It's available on [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) techniques can unveil concealed content in images. Useful resources include:

* [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy allows embedding information into image and audio files, supporting formats like PNG, BMP, GIF, WebP, and WAV. It's available on [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck for PNG File Analysis**

To analyze PNG files or to validate their authenticity, use:

```bash
apt-get install pngcheck
pngcheck stego.png
```

### **Additional Tools for Image Analysis**

For further exploration, consider visiting:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **Extracting Data from Audios**

**Audio steganography** offers a unique method to conceal information within sound files. Different tools are utilized for embedding or retrieving hidden content.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide is a versatile tool designed for hiding data in JPEG, BMP, WAV, and AU files. Detailed instructions are provided in the [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

This tool is compatible with a variety of formats including PNG, BMP, GIF, WebP, and WAV. For more information, refer to [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg is crucial for assessing the integrity of audio files, highlighting detailed information and pinpointing any discrepancies.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

### **WavSteg (WAV)**

WavSteg excels in concealing and extracting data within WAV files using the least significant bit strategy. It is accessible on [GitHub](https://github.com/ragibson/Steganography#WavSteg). Commands include:

```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```

### **Deepsound**

Deepsound allows for the encryption and detection of information within sound files using AES-256. It can be downloaded from [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

An invaluable tool for visual and analytical inspection of audio files, Sonic Visualizer can unveil hidden elements undetectable by other means. Visit the [official website](https://www.sonicvisualiser.org/) for more.

### **DTMF Tones - Dial Tones**

Detecting DTMF tones in audio files can be achieved through online tools such as [this DTMF detector](https://unframework.github.io/dtmf-detect/) and [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Binary data that squares to a whole number might represent a QR code. Use this snippet to check:

```python
import math
math.sqrt(2500) #50
```

For binary to image conversion, check [dcode](https://www.dcode.fr/binary-image). To read QR codes, use [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Braille Translation**

For translating Braille, the [Branah Braille Translator](https://www.branah.com/braille-translator) is an excellent resource.

## **References**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
