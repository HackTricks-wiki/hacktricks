# Stego Tricks

<details>

<summary><strong>Вивчайте методи зламу AWS з нуля та станьте експертом з курсом</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **компанії з кібербезпеки**? Хочете бачити **рекламу своєї компанії на HackTricks**? чи хочете отримати доступ до **останньої версії PEASS або завантажити HackTricks у форматі PDF**? Ознайомтеся з [**ПЛАНАМИ ПЕРЕДПЛАТИ**](https://github.com/sponsors/carlospolop)!
* Відкрийте для себе ексклюзивні [NFT](https://opensea.io/collection/the-peass-family) з нашої колекції [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* Отримайте офіційний [**PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Приєднуйтеся до [**💬**](https://emojipedia.org/speech-balloon/) [**Discord групи**](https://discord.gg/hRep4RUj7f) або [**telegram каналу**](https://t.me/peass) чи **підписуйтесь** на мене в **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.
* **Поділіться вашими хакерськими фішками, надіславши Pull Request до репозиторію [hacktricks](https://github.com/carlospolop/hacktricks) або [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Знаходьте найсерйозніші вразливості, щоб виправити їх якомога швидше. Intruder досліджує вашу область потенційних загроз, проводить проактивні сканування на вразливості, знаходить проблеми по всьому вашому технічному стеку, від API до веб-додатків та хмарних систем. [**Спробуйте безкоштовно**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) сьогодні.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Експорт даних з файлів**

### **Binwalk**
Інструмент для пошуку вбудованих прихованих файлів та даних в бінарниках. Встановлюється через `apt`, а його код доступний на [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```

### **Foremost**
Відновлює файли на основі їхніх хедерів та футерів, корисний для роботи з png зображеннями. Встановлюється через `apt`, а його код доступний на [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```

### **Exiftool**
Допомагає переглядати метадані файлів, доступний [тут](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```

### **Exiv2**
Схожий на exiftool, для перегляду метаданих. Встановлюється через `apt`, код на [GitHub](https://github.com/Exiv2/exiv2), а тут є [офіційний сайт](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```

### **File**
Дозволяє ідентифікувати тип файлу, з яким ви працюєте.
```bash
file file # Shows the file type
```

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

### **Порівняння або сomparison (cmp)**
Корисний для порівняння модифікованого файлу з його оригінальною версією, знайденою в інтернеті.
```bash
cmp original.jpg stego.jpg -b -l
```

## **Витягування прихованих даних з тексту**

### **Приховані дані у пробілах**
Невидимі символи в здавалося б, порожніх пробілах можуть приховувати інформацію. Для витягування цих даних ознайомтеся з [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) для легкого створення та **автоматизації робочих процесів**, які працюють на **найкращих** open-source інструментах.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **Витягування даних з зображень**

### **Визначення деталей зображення за допомогою GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) використовується для визначення типів файлів зображень та ідентифікації потенційних пошкоджень. Виконайте наведену нижче команду для перевірки зображення:

```bash
./magick identify -verbose stego.jpg
```

Для спроби відновлення пошкодженого зображення, може допомогти додавання коментаря до метаданих:

```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```

### **Steghide для приховування даних**

Steghide дозволяє приховувати дані в файлах `JPEG, BMP, WAV, AU`, здатний вбудовувати та витягувати зашифровані дані. Встановлення є простим за допомогою `apt`, а вихідний код доступний на [GitHub](https://github.com/StefanoDeVuono/steghide).

**Команди:**
- `steghide info file` виявляє, чи файл містить приховані дані.
- `steghide extract -sf file [--passphrase password]` витягує приховані дані, пароль вказувати не обов'язково.

Відвідайте [цей сайт](https://futureboy.us/stegano/decinput.html), щоб дізнатись про витягування даних з вебу.

**Bruteforce атака за допомогою Stegcracker:**
- Для спроби зламу пароля з Steghide використовуйте [stegcracker](https://github.com/Paradoxis/StegCracker.git) таким чином:

```bash
stegcracker <file> [<wordlist>]
```

### **zsteg для PNG та BMP файлів**

zsteg спеціалізується на виявленні прихованих даних у файлах PNG та BMP. Встановлення здійснюється через `gem install zsteg`, з кодом на [GitHub](https://github.com/zed-0xff/zsteg).

**Команди:**
- `zsteg -a file` застосовує всі методи виявлення до файлу.
- `zsteg -E file` вказує поле для витягування даних.

### **StegoVeritas і Stegsolve**

**stegoVeritas** перевіряє метадані, виконує трансформації зображення, застосовує перебір LSB та має інші фічі. Використовуйте  `stegoveritas.py -h` для повного списку доступних опцій та `stegoveritas.py stego.jpg` для виконання одразу всіх перевірок.

**Stegsolve** застосовує різні кольорові фільтри для виявлення прихованих текстів чи повідомлень у зображеннях. Доступний на [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **Швидке перетворення Фур'є (Fast Fourier Transform) для виявлення прихованого вмісту**

Техніки швидкого перетворення Фур'є можуть розкрити прихований вміст у зображеннях. Корисні ресурси:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy для аудіо та зображень**

Stegpy дозволяє вбудовувати інформацію у файли зображень та аудіо, підтримуючи формати PNG, BMP, GIF, WebP та WAV. Доступний на [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck для аналізу PNG файлів**

Для аналізу PNG файлів або перевірки їх автентичності, використовуйте:

```bash
apt-get install pngcheck
pngcheck stego.png
```

### **Додаткові інструменти для аналізу зображень**

Для отримання додаткових деталей, перегляньте лінки:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Витягування даних з аудіо**

**Аудіо стеганографія** пропонує унікальний метод приховування інформації всередині звукових файлів. Різні інструменти використовуються для вбудовування або отримання прихованого вмісту.

### **Steghide (JPEG, BMP, WAV, AU)**
Steghide - це універсальний інструмент, призначений для приховування даних у файлах JPEG, BMP, WAV та AU. Детальні інструкції надані в [розділі Steghide](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**
Цей інструмент сумісний з різними форматами, включаючи PNG, BMP, GIF, WebP та WAV. Для додаткової інформації, дивіться [розділ Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**
ffmpeg - це основний інструмент для оцінки цілісності аудіо файлів, виділяючи детальну інформацію та виявляючи будь-які невідповідності.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```

### **WavSteg (WAV)**
WavSteg відзначається здатністю приховувати та вилучати дані в WAV файлах, використовуючи стратегію найменш значущих бітів. Доступний на [GitHub](https://github.com/ragibson/Steganography#WavSteg). Команди:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```

### **Deepsound**
Deepsound дозволяє шифрувати та виявляти інформацію всередині звукових файлів, використовуючи AES-256. Можна завантажити з [офіційної сторінки](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**
Незамінний інструмент для візуального та аналітичного дослідження аудіо файлів, Sonic Visualizer може розкрити приховані елементи, непомітні іншими способами. Відвідайте [офіційний вебсайт](https://www.sonicvisualiser.org/) для ознайомлення з деталями.

### **Тони DTMF - Сигнальні тони**
Виявлення тонів DTMF у аудіофайлах можливе за допомогою онлайн-інструментів, таких як [цей DTMF детектор](https://unframework.github.io/dtmf-detect/) чи [DialABC](http://dialabc.com/sound/detect/index.html).

## **Інші техніки**

### **Довжина бінарних даних квадратного кореню (SQRT) - QR Code**
Бінарні дані, квадратний корінь яких є цілим числом, можуть представляти QR-код. Використовуйте цей фрагмент для перевірки:
```python
import math
math.sqrt(2500) #50
```
Для конвертації бінарних даних у зображення перегляньте [dcode](https://www.dcode.fr/binary-image). Для читання QR-кодів скористайтеся [цим онлайн-читачем штрих-кодів.](https://online-barcode-reader.inliteresearch.com/).

### **Переклад Брайля**
Для перекладу шрифту Брайля [перекладач Брайля Branah](https://www.branah.com/braille-translator) є чудовим ресурсом.





## **Джерела**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Знаходьте найсерйозніші вразливості, щоб виправити їх якомога швидше. Intruder досліджує вашу область потенційних загроз, проводить проактивні сканування на вразливості, знаходить проблеми по всьому вашому технічному стеку, від API до веб-додатків та хмарних систем. [**Спробуйте безкоштовно**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) сьогодні.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Вивчайте методи зламу AWS з нуля та станьте експертом з курсом</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **компанії з кібербезпеки**? Хочете бачити **рекламу своєї компанії на HackTricks**? чи хочете отримати доступ до **останньої версії PEASS або завантажити HackTricks у форматі PDF**? Ознайомтеся з [**ПЛАНАМИ ПЕРЕДПЛАТИ**](https://github.com/sponsors/carlospolop)!
* Відкрийте для себе ексклюзивні [NFT](https://opensea.io/collection/the-peass-family) з нашої колекції [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* Отримайте офіційний [**PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Приєднуйтеся до [**💬**](https://emojipedia.org/speech-balloon/) [**Discord групи**](https://discord.gg/hRep4RUj7f) або [**telegram каналу**](https://t.me/peass) чи **підписуйтесь** на мене в **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.
* **Поділіться вашими хакерськими фішками, надіславши Pull Request до репозиторію [hacktricks](https://github.com/carlospolop/hacktricks) або [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
