# Інструменти для carving і відновлення файлів/даних

{{#include ../../../banners/hacktricks-training.md}}

## Інструменти для carving і відновлення

Більше інструментів у [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Найпоширенішим інструментом, який використовується у forensic для вилучення файлів із образів, є [**Autopsy**](https://www.autopsy.com/download/). Завантажте його, встановіть і доручіть йому обробити файл, щоб знайти «приховані» файли. Зверніть увагу, що Autopsy створено для підтримки дискових образів та інших типів образів, але не простих файлів.

> **Оновлення за 2024–2025 роки** – Версія **4.21** (випущена в лютому 2025 року) отримала перебудований **carving module на основі SleuthKit v4.13**, який помітно швидше працює з образами розміром у кілька терабайтів і підтримує паралельне вилучення в системах із кількома ядрами. Також було представлено невелику CLI-обгортку (`autopsycli ingest <case> <image>`), що дає змогу автоматизувати carving у CI/CD або великомасштабних лабораторних середовищах.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** — це інструмент для аналізу бінарних файлів з метою пошуку вбудованого вмісту. Його можна встановити через `apt`, а його вихідний код доступний на [GitHub](https://github.com/ReFirmLabs/binwalk).

**Корисні команди**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Примітка щодо безпеки** – Версії **≤2.3.3** уразливі до **Path Traversal** (CVE-2022-4510). Оновіть програму (або ізолюйте її за допомогою контейнера/непривілейованого UID), перш ніж виконувати carving ненадійних зразків.<sup>[[2]](#references)</sup>

### Foremost

Ще одним поширеним інструментом для пошуку прихованих файлів є **foremost**. Файл конфігурації foremost можна знайти в `/etc/foremost.conf`. Якщо потрібно виконати пошук лише певних файлів, розкоментуйте їх. Якщо нічого не розкоментувати, foremost шукатиме файли типів, налаштованих за замовчуванням.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** — це ще один tool, який можна використовувати для пошуку та вилучення **файлів, вбудованих у файл**. У цьому випадку вам потрібно розкоментувати у файлі конфігурації (_/etc/scalpel/scalpel.conf_) типи файлів, які потрібно вилучити.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Цей інструмент входить до складу kali, але його можна знайти тут: <https://github.com/simsong/bulk_extractor>

Bulk Extractor може сканувати образ доказів і виконувати carving **фрагментів pcap**, **мережевих артефактів (URL, доменів, IP-адрес, MAC-адрес, електронних адрес)** та багатьох інших об’єктів **паралельно, використовуючи кілька сканерів**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Корисні скрипти постобробки (`bulk_diff`, `bulk_extractor_reader.py`) можуть усувати дублікати артефактів між двома образами або перетворювати результати на JSON для імпорту в SIEM.

### PhotoRec

Його можна знайти на <https://www.cgsecurity.org/wiki/TestDisk_Download>

Він має версії з GUI та CLI. Ви можете вибрати **типи файлів**, які PhotoRec має шукати.

![Запустити кожен сканер, агресивно виконати carving JPEG і створити bodyfile - PhotoRec: Він має версії з GUI та CLI. Ви можете вибрати типи файлів, які PhotoRec має шукати](<../../../images/image (242).png>)

### ddrescue + ddrescueview (створення образу несправного диска)

Коли фізичний диск нестабільний, найкращою практикою є **спочатку створити його образ**, а вже потім запускати carving tools для цього образу. `ddrescue` (проєкт GNU) зосереджений на надійному копіюванні пошкоджених дисків зі збереженням журналу непрочитаних секторів.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Версія **1.28** (грудень 2024 року) представила **`--cluster-size`**, що може пришвидшити створення образів SSD великої ємності, де традиційні розміри секторів більше не відповідають блокам flash-пам'яті.

### Extundelete / Ext4magic (відновлення EXT 3/4)

Якщо вихідна файлова система є Linux EXT-based, ви можете відновити нещодавно видалені файли **без повного carving**. Обидва інструменти працюють безпосередньо з образом, доступним лише для читання:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Якщо файлову систему було змонтовано після видалення, блоки даних могли вже бути повторно використані — у такому разі все одно потрібен належний carving (Foremost/Scalpel).

### binvis

Перегляньте [code](https://code.google.com/archive/p/binvis/) і [web page tool](https://binvis.io/#/).

#### Features of BinVis

- Візуальний та активний **переглядач структури**
- Кілька графіків для різних точок фокусування
- Фокусування на частинах зразка
- **Перегляд рядків і ресурсів**, наприклад у виконуваних файлах PE або ELF
- Отримання **патернів** для cryptanalysis у файлах
- **Виявлення** алгоритмів packer або encoder
- **Ідентифікація** Steganography за патернами
- **Візуальне** binary-diffing

BinVis — чудова **відправна точка для ознайомлення з невідомою ціллю** у сценарії black-boxing.

## Specific Data Carving Tools

### FindAES

Шукає AES-ключі, знаходячи їхні key schedules. Здатен знаходити ключі довжиною 128, 192 і 256 бітів, наприклад ті, що використовуються TrueCrypt і BitLocker.

Завантажити [тут](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) — це переписана на Rust версія YARA, випущена у 2024 році. Вона **у 10–30 разів швидша** за класичну YARA і може дуже швидко класифікувати тисячі carved objects:<sup>[[3]](#references)</sup>.
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Швидкодія робить реалістичним **автоматично позначати** всі carved-файли під час великомасштабних розслідувань.

## Додаткові інструменти

Ви можете використовувати [**viu** ](https://github.com/atanunq/viu), щоб переглядати зображення з термінала.  \
Ви можете використовувати інструмент командного рядка Linux **pdftotext**, щоб перетворити PDF на текст і прочитати його.



## Посилання

- [1] [Примітки до випуску Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal у binwalk (CVE-2022-4510) — GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA is dead, long live YARA-X — VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
