# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Dosyalardan Veri Çıkarma**

### **Binwalk**

Gömülü gizli dosyaları ve verileri aramak için kullanılan bir araçtır. `apt` ile kurulur ve kaynak kodu [GitHub](https://github.com/ReFirmLabs/binwalk) üzerinde mevcuttur.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Başlıkları ve alt başlıkları temel alarak dosyaları kurtarır, png görüntüleri için faydalıdır. `apt` ile kurulur, kaynağı [GitHub](https://github.com/korczis/foremost) üzerindedir.
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Dosya meta verilerini görüntülemeye yardımcı olur, [burada](https://www.sno.phy.queensu.ca/~phil/exiftool/) mevcuttur.
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Exiftool'e benzer, metadata görüntüleme için. `apt` ile kurulabilir, kaynağı [GitHub](https://github.com/Exiv2/exiv2)'da ve bir [resmi web sitesi](http://www.exiv2.org/) vardır.
```bash
exiv2 file # Shows the metadata
```
### **Dosya**

İşlemekte olduğunuz dosya türünü belirleyin.

### **Dizeler**

Çıktıyı filtrelemek için çeşitli kodlama ayarları kullanarak dosyalardan okunabilir dizeleri çıkarır.
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
### **Karşılaştırma (cmp)**

Çevrimiçi bulunan orijinal versiyonuyla değiştirilmiş bir dosyayı karşılaştırmak için yararlıdır.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Metin İçindeki Gizli Verilerin Çıkarılması**

### **Boşluklardaki Gizli Veriler**

Görünüşte boş olan alanlardaki görünmez karakterler bilgi saklayabilir. Bu verileri çıkarmak için [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder) adresini ziyaret edin.

## **Görüntülerden Veri Çıkarılması**

### **GraphicMagick ile Görüntü Ayrıntılarını Belirleme**

[GraphicMagick](https://imagemagick.org/script/download.php), görüntü dosyası türlerini belirlemek ve olası bozulmaları tanımlamak için kullanılır. Bir görüntüyü incelemek için aşağıdaki komutu çalıştırın:
```bash
./magick identify -verbose stego.jpg
```
Hasarlı bir görüntüyü onarmaya çalışmak için, bir meta veri yorumu eklemek yardımcı olabilir:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Veri Gizleme için Steghide**

Steghide, `JPEG, BMP, WAV ve AU` dosyaları içinde veri gizlemeyi kolaylaştırır, şifreli verileri gömme ve çıkarma yeteneğine sahiptir. Kurulum `apt` kullanarak basittir ve [kaynak kodu GitHub'da mevcuttur](https://github.com/StefanoDeVuono/steghide).

**Komutlar:**

- `steghide info file` bir dosyanın gizli veri içerip içermediğini gösterir.
- `steghide extract -sf file [--passphrase password]` gizli veriyi çıkarır, şifre isteğe bağlıdır.

Web tabanlı çıkarım için [bu web sitesini](https://futureboy.us/stegano/decinput.html) ziyaret edin.

**Stegcracker ile Bruteforce Saldırısı:**

- Steghide üzerinde şifre kırma denemesi yapmak için [stegcracker](https://github.com/Paradoxis/StegCracker.git) kullanın:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg PNG ve BMP Dosyaları için**

zsteg, PNG ve BMP dosyalarında gizli verileri ortaya çıkarmada uzmanlaşmıştır. Kurulum `gem install zsteg` ile yapılır, [kaynağı GitHub'da](https://github.com/zed-0xff/zsteg).

**Komutlar:**

- `zsteg -a file` bir dosya üzerinde tüm tespit yöntemlerini uygular.
- `zsteg -E file` veri çıkarımı için bir yük belirtir.

### **StegoVeritas ve Stegsolve**

**stegoVeritas**, meta verileri kontrol eder, görüntü dönüşümleri gerçekleştirir ve diğer özelliklerin yanı sıra LSB brute forcing uygular. Tüm seçeneklerin tam listesi için `stegoveritas.py -h` kullanın ve tüm kontrolleri gerçekleştirmek için `stegoveritas.py stego.jpg` komutunu çalıştırın.

**Stegsolve**, görüntülerde gizli metinleri veya mesajları ortaya çıkarmak için çeşitli renk filtreleri uygular. [GitHub'da](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) mevcuttur.

### **Gizli İçerik Tespiti için FFT**

Hızlı Fourier Dönüşümü (FFT) teknikleri, görüntülerde gizli içeriği açığa çıkarabilir. Yararlı kaynaklar şunlardır:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [GitHub'da FFTStegPic](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy Ses ve Görüntü Dosyaları için**

Stegpy, PNG, BMP, GIF, WebP ve WAV gibi formatları destekleyerek bilgi gömülmesine olanak tanır. [GitHub'da](https://github.com/dhsdshdhk/stegpy) mevcuttur.

### **PNG Dosyası Analizi için Pngcheck**

PNG dosyalarını analiz etmek veya doğruluklarını kontrol etmek için:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Görüntü Analizi için Ek Araçlar**

Daha fazla keşif için ziyaret etmeyi düşünün:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Seslerden Veri Çıkartma**

**Ses steganografisi**, bilgi gizlemek için ses dosyaları içinde benzersiz bir yöntem sunar. Gizli içeriği gömmek veya geri almak için farklı araçlar kullanılır.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide, JPEG, BMP, WAV ve AU dosyalarında veri gizlemek için tasarlanmış çok yönlü bir araçtır. Ayrıntılı talimatlar [stego tricks documentation](stego-tricks.md#steghide) içinde sağlanmıştır.

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Bu araç, PNG, BMP, GIF, WebP ve WAV dahil olmak üzere çeşitli formatlarla uyumludur. Daha fazla bilgi için [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav) bölümüne bakın.

### **ffmpeg**

ffmpeg, ses dosyalarının bütünlüğünü değerlendirmek için kritik öneme sahiptir, ayrıntılı bilgileri vurgular ve herhangi bir tutarsızlığı belirler.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg, en az anlamlı bit stratejisini kullanarak WAV dosyaları içinde verileri gizleme ve çıkarma konusunda mükemmeldir. [GitHub](https://github.com/ragibson/Steganography#WavSteg) üzerinde erişilebilir. Komutlar şunlardır:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound, AES-256 kullanarak ses dosyaları içindeki bilgilerin şifrelenmesi ve tespit edilmesini sağlar. [resmi sayfadan](http://jpinsoft.net/deepsound/download.aspx) indirilebilir.

### **Sonic Visualizer**

Ses dosyalarının görsel ve analitik incelemesi için paha biçilmez bir araç olan Sonic Visualizer, diğer yöntemlerle tespit edilemeyen gizli unsurları ortaya çıkarabilir. Daha fazla bilgi için [resmi web sitesini](https://www.sonicvisualiser.org/) ziyaret edin.

### **DTMF Tones - Dial Tones**

Ses dosyalarında DTMF tonlarını tespit etmek, [bu DTMF dedektörü](https://unframework.github.io/dtmf-detect/) ve [DialABC](http://dialabc.com/sound/detect/index.html) gibi çevrimiçi araçlar aracılığıyla gerçekleştirilebilir.

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Tam sayıya kare olan ikili veriler bir QR kodunu temsil edebilir. Kontrol etmek için bu kod parçasını kullanın:
```python
import math
math.sqrt(2500) #50
```
Binary'den görüntüye dönüşüm için [dcode](https://www.dcode.fr/binary-image)'u kontrol edin. QR kodları okumak için [bu çevrimiçi barkod okuyucusunu](https://online-barcode-reader.inliteresearch.com/) kullanın.

### **Braille Çevirisi**

Braille çevirisi için [Branah Braille Translator](https://www.branah.com/braille-translator) mükemmel bir kaynaktır.

## **Referanslar**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
