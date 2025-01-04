# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Більше інструментів на [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Найбільш поширений інструмент, що використовується в судовій експертизі для витягування файлів з образів, це [**Autopsy**](https://www.autopsy.com/download/). Завантажте його, встановіть і дайте йому обробити файл, щоб знайти "приховані" файли. Зверніть увагу, що Autopsy створено для підтримки образів дисків та інших видів образів, але не простих файлів.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** - це інструмент для аналізу бінарних файлів з метою виявлення вбудованого контенту. Його можна встановити через `apt`, а його вихідний код знаходиться на [GitHub](https://github.com/ReFirmLabs/binwalk).

**Корисні команди**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Ще один поширений інструмент для знаходження прихованих файлів - це **foremost**. Ви можете знайти файл конфігурації foremost у `/etc/foremost.conf`. Якщо ви хочете шукати лише деякі конкретні файли, зніміть коментар з них. Якщо ви нічого не знімете, foremost буде шукати файли за замовчуванням.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** - це ще один інструмент, який можна використовувати для знаходження та вилучення **файлів, вбудованих у файл**. У цьому випадку вам потрібно буде зняти коментарі з файлів типів у конфігураційному файлі (_/etc/scalpel/scalpel.conf_), які ви хочете, щоб він вилучив.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Цей інструмент входить до складу kali, але ви можете знайти його тут: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Цей інструмент може сканувати зображення і **витягувати pcaps** всередині нього, **мережеву інформацію (URL, домени, IP, MAC, електронні листи)** та інші **файли**. Вам потрібно лише:
```
bulk_extractor memory.img -o out_folder
```
Перегляньте **всю інформацію**, яку зібрав інструмент (паролі?), **проаналізуйте** **пакети** (читайте [**аналіз Pcaps**](../pcap-inspection/index.html)), шукайте **дивні домени** (домени, пов'язані з **шкідливим ПЗ** або **неіснуючі**).

### PhotoRec

Ви можете знайти його на [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Він постачається з версіями GUI та CLI. Ви можете вибрати **типи файлів**, які хочете, щоб PhotoRec шукав.

![](<../../../images/image (524).png>)

### binvis

Перевірте [код](https://code.google.com/archive/p/binvis/) та [веб-сторінку інструмента](https://binvis.io/#/).

#### Особливості BinVis

- Візуальний та активний **переглядач структури**
- Кілька графіків для різних фокусних точок
- Фокусування на частинах зразка
- **Перегляд рядків та ресурсів** у PE або ELF виконуваних файлах, наприклад
- Отримання **шаблонів** для криптоаналізу файлів
- **Виявлення** алгоритмів пакування або кодування
- **Ідентифікація** стеганографії за шаблонами
- **Візуальне** бінарне порівняння

BinVis є чудовою **відправною точкою для ознайомлення з невідомою ціллю** в сценарії чорного ящика.

## Специфічні інструменти для карвінгу даних

### FindAES

Шукає ключі AES, досліджуючи їх графіки ключів. Може знаходити 128, 192 та 256 бітні ключі, такі як ті, що використовуються TrueCrypt та BitLocker.

Завантажте [тут](https://sourceforge.net/projects/findaes/).

## Додаткові інструменти

Ви можете використовувати [**viu**](https://github.com/atanunq/viu), щоб переглядати зображення з терміналу.\
Ви можете використовувати командний рядок linux **pdftotext**, щоб перетворити pdf у текст і прочитати його.

{{#include ../../../banners/hacktricks-training.md}}
