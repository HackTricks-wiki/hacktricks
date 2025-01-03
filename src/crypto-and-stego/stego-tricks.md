# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **从文件中提取数据**

### **Binwalk**

一个用于搜索二进制文件中嵌入的隐藏文件和数据的工具。它通过 `apt` 安装，源代码可在 [GitHub](https://github.com/ReFirmLabs/binwalk) 上获取。
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

根据文件的头部和尾部恢复文件，对 png 图像非常有用。通过 `apt` 安装，源代码在 [GitHub](https://github.com/korczis/foremost) 上。
```bash
foremost -i file # Extracts data
```
### **Exiftool**

帮助查看文件元数据，访问 [这里](https://www.sno.phy.queensu.ca/~phil/exiftool/)。
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

类似于 exiftool，用于查看元数据。可以通过 `apt` 安装，源代码在 [GitHub](https://github.com/Exiv2/exiv2)，并且有一个 [官方网站](http://www.exiv2.org/)。
```bash
exiv2 file # Shows the metadata
```
### **文件**

识别您正在处理的文件类型。

### **字符串**

从文件中提取可读字符串，使用各种编码设置来过滤输出。
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
### **比较 (cmp)**

用于将修改过的文件与在线找到的原始版本进行比较。
```bash
cmp original.jpg stego.jpg -b -l
```
## **提取文本中的隐藏数据**

### **空格中的隐藏数据**

看似空白的空间中的不可见字符可能隐藏着信息。要提取这些数据，请访问 [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)。

## **从图像中提取数据**

### **使用 GraphicMagick 识别图像细节**

[GraphicMagick](https://imagemagick.org/script/download.php) 用于确定图像文件类型并识别潜在的损坏。执行以下命令以检查图像：
```bash
./magick identify -verbose stego.jpg
```
要尝试修复损坏的图像，添加元数据注释可能会有所帮助：
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide用于数据隐藏**

Steghide 方便地在 `JPEG, BMP, WAV, 和 AU` 文件中隐藏数据，能够嵌入和提取加密数据。使用 `apt` 安装非常简单，其 [源代码可在 GitHub 上获取](https://github.com/StefanoDeVuono/steghide)。

**命令：**

- `steghide info file` 显示文件是否包含隐藏数据。
- `steghide extract -sf file [--passphrase password]` 提取隐藏数据，密码可选。

要进行基于网页的提取，请访问 [此网站](https://futureboy.us/stegano/decinput.html)。

**使用 Stegcracker 进行暴力破解攻击：**

- 要尝试对 Steghide 进行密码破解，请使用 [stegcracker](https://github.com/Paradoxis/StegCracker.git) 如下：
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg用于PNG和BMP文件**

zsteg专注于揭示PNG和BMP文件中的隐藏数据。安装通过`gem install zsteg`完成，其[源代码在GitHub上](https://github.com/zed-0xff/zsteg)。

**命令：**

- `zsteg -a file`对文件应用所有检测方法。
- `zsteg -E file`指定用于数据提取的有效载荷。

### **StegoVeritas和Stegsolve**

**stegoVeritas**检查元数据，执行图像转换，并应用LSB暴力破解等功能。使用`stegoveritas.py -h`获取完整选项列表，使用`stegoveritas.py stego.jpg`执行所有检查。

**Stegsolve**应用各种颜色滤镜以揭示图像中的隐藏文本或消息。它可在[GitHub上](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)获取。

### **FFT用于隐藏内容检测**

快速傅里叶变换（FFT）技术可以揭示图像中的隐蔽内容。实用资源包括：

- [EPFL演示](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [GitHub上的FFTStegPic](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy用于音频和图像文件**

Stegpy允许将信息嵌入图像和音频文件，支持PNG、BMP、GIF、WebP和WAV等格式。它可在[GitHub上](https://github.com/dhsdshdhk/stegpy)获取。

### **Pngcheck用于PNG文件分析**

要分析PNG文件或验证其真实性，请使用：
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **图像分析的附加工具**

要进一步探索，请考虑访问：

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **从音频中提取数据**

**音频隐写术**提供了一种独特的方法，将信息隐藏在声音文件中。使用不同的工具来嵌入或检索隐藏的内容。

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide是一个多功能工具，旨在将数据隐藏在JPEG、BMP、WAV和AU文件中。详细说明请参见[stego tricks documentation](stego-tricks.md#steghide)。

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

该工具兼容多种格式，包括PNG、BMP、GIF、WebP和WAV。有关更多信息，请参阅[Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)。

### **ffmpeg**

ffmpeg对于评估音频文件的完整性至关重要，突出详细信息并指出任何差异。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg 擅长使用最低有效位策略在 WAV 文件中隐藏和提取数据。它可以在 [GitHub](https://github.com/ragibson/Steganography#WavSteg) 上获取。命令包括：
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound 允许使用 AES-256 对声音文件中的信息进行加密和检测。可以从 [the official page](http://jpinsoft.net/deepsound/download.aspx) 下载。

### **Sonic Visualizer**

Sonic Visualizer 是一个用于音频文件的视觉和分析检查的宝贵工具，可以揭示其他方法无法检测到的隐藏元素。访问 [official website](https://www.sonicvisualiser.org/) 了解更多信息。

### **DTMF Tones - Dial Tones**

通过在线工具可以检测音频文件中的 DTMF 音调，例如 [this DTMF detector](https://unframework.github.io/dtmf-detect/) 和 [DialABC](http://dialabc.com/sound/detect/index.html)。

## **Other Techniques**

### **Binary Length SQRT - QR Code**

平方为整数的二进制数据可能表示 QR 码。使用此代码片段进行检查：
```python
import math
math.sqrt(2500) #50
```
对于二进制到图像的转换，请查看 [dcode](https://www.dcode.fr/binary-image)。要读取二维码，请使用 [this online barcode reader](https://online-barcode-reader.inliteresearch.com/)。

### **盲文翻译**

对于盲文翻译，[Branah Braille Translator](https://www.branah.com/braille-translator) 是一个很好的资源。

## **参考文献**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
