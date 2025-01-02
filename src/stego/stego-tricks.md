# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Витягування даних з файлів**

### **Binwalk**

Інструмент для пошуку бінарних файлів на наявність вбудованих прихованих файлів та даних. Він встановлюється через `apt`, а його вихідний код доступний на [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Відновлює файли на основі їх заголовків і футерів, корисно для png зображень. Встановлюється через `apt` з його джерелом на [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Допомагає переглядати метадані файлів, доступний [тут](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Схоже на exiftool, для перегляду метаданих. Встановлюється через `apt`, вихідний код на [GitHub](https://github.com/Exiv2/exiv2), і має [офіційний вебсайт](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Файл**

Визначте тип файлу, з яким ви маєте справу.

### **Рядки**

Витягує читабельні рядки з файлів, використовуючи різні налаштування кодування для фільтрації виходу.
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

Корисно для порівняння зміненого файлу з його оригінальною версією, знайденою в Інтернеті.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Витягування прихованих даних у тексті**

### **Приховані дані в пробілах**

Невидимі символи в, здавалося б, порожніх пробілах можуть приховувати інформацію. Щоб витягти ці дані, відвідайте [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Витягування даних з зображень**

### **Визначення деталей зображення за допомогою GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) служить для визначення типів файлів зображень та виявлення потенційних пошкоджень. Виконайте команду нижче, щоб перевірити зображення:
```bash
./magick identify -verbose stego.jpg
```
Щоб спробувати відновити пошкоджене зображення, додавання коментаря до метаданих може допомогти:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide для приховування даних**

Steghide дозволяє приховувати дані в файлах `JPEG, BMP, WAV та AU`, здатний вбудовувати та витягувати зашифровані дані. Встановлення є простим за допомогою `apt`, а його [джерельний код доступний на GitHub](https://github.com/StefanoDeVuono/steghide).

**Команди:**

- `steghide info file` показує, чи містить файл приховані дані.
- `steghide extract -sf file [--passphrase password]` витягує приховані дані, пароль є необов'язковим.

Для веб-витягування відвідайте [цей вебсайт](https://futureboy.us/stegano/decinput.html).

**Атака методом перебору з Stegcracker:**

- Щоб спробувати зламати пароль на Steghide, використовуйте [stegcracker](https://github.com/Paradoxis/StegCracker.git) наступним чином:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg для PNG та BMP файлів**

zsteg спеціалізується на виявленні прихованих даних у файлах PNG та BMP. Встановлення виконується через `gem install zsteg`, з його [джерелом на GitHub](https://github.com/zed-0xff/zsteg).

**Команди:**

- `zsteg -a file` застосовує всі методи виявлення до файлу.
- `zsteg -E file` вказує корисне навантаження для витягування даних.

### **StegoVeritas та Stegsolve**

**stegoVeritas** перевіряє метадані, виконує трансформації зображень та застосовує брутфорс LSB серед інших функцій. Використовуйте `stegoveritas.py -h` для повного списку опцій та `stegoveritas.py stego.jpg` для виконання всіх перевірок.

**Stegsolve** застосовує різні кольорові фільтри для виявлення прихованих текстів або повідомлень у зображеннях. Він доступний на [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT для виявлення прихованого контенту**

Техніки швидкого перетворення Фур'є (FFT) можуть виявити прихований контент у зображеннях. Корисні ресурси включають:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic на GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy для аудіо та зображень**

Stegpy дозволяє вбудовувати інформацію в зображення та аудіофайли, підтримуючи формати, такі як PNG, BMP, GIF, WebP та WAV. Він доступний на [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck для аналізу PNG файлів**

Для аналізу PNG файлів або для перевірки їх автентичності використовуйте:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Додаткові інструменти для аналізу зображень**

Для подальшого дослідження, розгляньте можливість відвідати:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Витягування даних з аудіо**

**Аудіо стеганографія** пропонує унікальний метод приховування інформації в звукових файлах. Використовуються різні інструменти для вбудовування або отримання прихованого контенту.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide - це універсальний інструмент, призначений для приховування даних у файлах JPEG, BMP, WAV та AU. Докладні інструкції наведені в [документації стего трюків](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Цей інструмент сумісний з різними форматами, включаючи PNG, BMP, GIF, WebP та WAV. Для отримання додаткової інформації зверніться до [розділу Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg є важливим для оцінки цілісності аудіофайлів, підкреслюючи детальну інформацію та вказуючи на будь-які розбіжності.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg відзначається в приховуванні та витягуванні даних у WAV файлах, використовуючи стратегію найменш значущого біта. Він доступний на [GitHub](https://github.com/ragibson/Steganography#WavSteg). Команди включають:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound дозволяє шифрувати та виявляти інформацію в звукових файлах за допомогою AES-256. Його можна завантажити з [офіційної сторінки](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Безцінний інструмент для візуальної та аналітичної перевірки аудіофайлів, Sonic Visualizer може виявити приховані елементи, які не піддаються виявленню іншими засобами. Відвідайте [офіційний вебсайт](https://www.sonicvisualiser.org/) для отримання додаткової інформації.

### **DTMF Tones - Dial Tones**

Виявлення DTMF тонів в аудіофайлах можна здійснити за допомогою онлайн-інструментів, таких як [цей DTMF детектор](https://unframework.github.io/dtmf-detect/) та [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Бінарні дані, які квадратуються до цілого числа, можуть представляти QR-код. Використовуйте цей фрагмент коду для перевірки:
```python
import math
math.sqrt(2500) #50
```
Для перетворення двійкових даних в зображення, перевірте [dcode](https://www.dcode.fr/binary-image). Щоб прочитати QR-коди, використовуйте [цей онлайн-сканер штрих-кодів](https://online-barcode-reader.inliteresearch.com/).

### **Переклад Брайля**

Для перекладу Брайля [Branah Braille Translator](https://www.branah.com/braille-translator) є відмінним ресурсом.

## **Посилання**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
