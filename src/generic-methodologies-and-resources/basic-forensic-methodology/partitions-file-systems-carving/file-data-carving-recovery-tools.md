# Інструменти карвінгу та відновлення файлів/даних

## Інструменти карвінгу та відновлення

Більше інструментів у [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Найпоширенішим інструментом, який використовується у forensic для вилучення файлів з образів, є [**Autopsy**](https://www.autopsy.com/download/). Завантажте його, встановіть і передайте йому файл для пошуку «прихованих» файлів. Зверніть увагу, що Autopsy розроблено для підтримки дискових образів та інших типів образів, але не звичайних файлів.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** — це інструмент для аналізу бінарних файлів з метою пошуку вбудованого вмісту. Його можна встановити через `apt`, а його вихідний код доступний на [GitHub](https://github.com/ReFirmLabs/binwalk).

**Корисні команди**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Примітка з безпеки** – Версії **2.1.2b до 2.3.3** уражені вразливістю **Path Traversal** (CVE-2022-4510); в advisory не вказано жодної виправленої версії pip. Уникайте розпакування ненадійних зразків за допомогою уражених релізів або ізолюйте інструмент за допомогою контейнера/непривілейованого UID.<sup>[[4]](#references)</sup>

### Foremost

Ще одним поширеним інструментом для пошуку прихованих файлів є **foremost**. Конфігураційний файл foremost можна знайти в `/etc/foremost.conf`. Якщо ви хочете шукати лише певні файли, розкоментуйте їх. Якщо нічого не розкоментувати, foremost шукатиме файли типів, налаштованих за замовчуванням.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** — ще один інструмент, який можна використовувати для пошуку та вилучення **файлів, вбудованих у файл**. У цьому випадку потрібно розкоментувати у файлі конфігурації (_/etc/scalpel/scalpel.conf_) типи файлів, які потрібно вилучити.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Цей інструмент входить до складу kali, але його можна знайти тут: <https://github.com/simsong/bulk_extractor>

Bulk Extractor може сканувати образ доказів і виконувати carving **фрагментів pcap**, **мережевих артефактів (URL, доменів, IP-адрес, MAC-адрес, електронних адрес)** та багатьох інших об’єктів **паралельно за допомогою кількох сканерів**.

У релізі v2.1.1 задокументовано збирання за допомогою Autotools і параметр `-S jpeg_carve_mode=2` для carving усіх суміжних JPEG-файлів.<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
The bundled `bulk_diff.py` порівнює два результати запуску bulk_extractor, тоді як `bulk_extractor_reader.py` читає звіт і feature-файли.<sup>[[3]](#references)</sup>

### PhotoRec

Його можна знайти за адресою <https://www.cgsecurity.org/wiki/TestDisk_Download>

Він постачається у версіях із GUI та CLI. Ви можете вибрати **file-types**, які потрібно шукати за допомогою PhotoRec.

![Запустіть усі сканери, агресивно виконуйте carving JPEG і генеруйте bodyfile - PhotoRec: Він постачається у версіях із GUI та CLI. Ви можете вибрати file-types, які потрібно шукати за допомогою PhotoRec](<../../../images/image (242).png>)

### ddrescue + ddrescueview (створення образу нестабільних дисків)

Коли фізичний диск працює нестабільно, найкращою практикою є **спочатку створити його образ**, а вже потім запускати carving tools для цього образу. `ddrescue` (проєкт GNU) зосереджений на надійному копіюванні пошкоджених дисків із веденням журналу секторів, які неможливо прочитати.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Опція **`--cluster-size`** визначає, скільки секторів копіюється за один раз; менші значення можуть допомогти під час роботи з повільними дисками.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Якщо вихідна файлова система є Linux EXT-based, ви можете відновити нещодавно видалені файли **без повного carving**; ці journal-based tools працюють із відмонтованою файловою системою або образом, доступним лише для читання.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Примітка щодо сумісності** – ext4magic покинутий; на сторінці проєкту попереджається, що сучасні файлові системи більше з ним несумісні.<sup>[[10]](#references)</sup>

> 🛈 Якщо файлову систему було змонтовано після видалення, блоки даних могли вже бути повторно використані – у такому разі все ще потрібне належне carving (Foremost/Scalpel).

### binvis

Перегляньте [код](https://code.google.com/archive/p/binvis/) і [вебінструмент](https://binvis.io/#/).

#### Можливості BinVis

- Візуальний та інтерактивний **переглядач структури**
- Кілька графіків для різних точок фокусування
- Фокусування на частинах зразка
- **Перегляд рядків і ресурсів**, наприклад у виконуваних файлах PE або ELF
- Отримання **патернів** для криптоаналізу файлів
- **Виявлення** алгоритмів пакування або кодування
- **Ідентифікація** Steganography за патернами
- **Візуальне** порівняння бінарних файлів

BinVis є чудовою **відправною точкою для ознайомлення з невідомою ціллю** у сценарії black-boxing.

## Спеціалізовані інструменти Data Carving

### FindAES

Шукає ключі AES шляхом пошуку їхніх розкладів ключів. Здатний знаходити ключі довжиною 128, 192 і 256 бітів, наприклад ті, що використовуються TrueCrypt і BitLocker.

Завантажити [тут](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) — це переписана на Rust версія YARA, представлена у 2024 році; VirusTotal повідомляє, що деякі правила з регулярними виразами та складними циклами можуть виконуватися значно швидше.<sup>[[5]](#references)</sup> Її CLI називається `yr`, а команда `scan` підтримує рекурсивне сканування, кількість потоків і виведення метаданих.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Додаткові інструменти

Ви можете використовувати [**viu** ](https://github.com/atanunq/viu), щоб переглядати зображення з термінала.  \
Ви можете використовувати інструмент командного рядка Linux **pdftotext**, щоб перетворювати PDF на текст і читати його.



## References

- [1] [Примітки до випуску Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README Python-інструментів bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Обхід шляху в binwalk (CVE-2022-4510) - база даних рекомендацій GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA мертва, хай живе YARA-X - блог VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Команди CLI YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Посібник GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Посібник ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Стан проєкту ext4magic](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
