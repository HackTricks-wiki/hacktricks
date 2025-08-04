# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Більше інструментів на [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Найбільш поширений інструмент, що використовується в судовій експертизі для витягування файлів з образів, це [**Autopsy**](https://www.autopsy.com/download/). Завантажте його, встановіть і дайте йому обробити файл, щоб знайти "сховані" файли. Зверніть увагу, що Autopsy створено для підтримки образів дисків та інших видів образів, але не простих файлів.

> **2024-2025 оновлення** – Версія **4.21** (випущена в лютому 2025 року) додала перероблений **модуль карвінгу на основі SleuthKit v4.13**, який помітно швидший при обробці багатотерабайтних образів і підтримує паралельне витягування на багатоядерних системах.¹ Також був представлений невеликий CLI-обгортка (`autopsycli ingest <case> <image>`), що дозволяє скриптувати карвінг у середовищах CI/CD або великих лабораторіях.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** - це інструмент для аналізу бінарних файлів з метою виявлення вбудованого контенту. Його можна встановити через `apt`, а його вихідний код доступний на [GitHub](https://github.com/ReFirmLabs/binwalk).

**Корисні команди**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Примітка безпеки** – Версії **≤2.3.3** підлягають впливу вразливості **Path Traversal** (CVE-2022-4510). Оновіть (або ізолюйте за допомогою контейнера/непривілейованого UID) перед карвінгом ненадійних зразків.

### Foremost

Ще один поширений інструмент для знаходження прихованих файлів – це **foremost**. Ви можете знайти файл конфігурації foremost у `/etc/foremost.conf`. Якщо ви хочете шукати деякі конкретні файли, зніміть коментарі з них. Якщо ви нічого не прокоментуєте, foremost буде шукати за типовими файлами, які налаштовані за замовчуванням.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** - це ще один інструмент, який можна використовувати для знаходження та вилучення **файлів, вбудованих у файл**. У цьому випадку вам потрібно буде зняти коментарі з конфігураційного файлу (_/etc/scalpel/scalpel.conf_) для типів файлів, які ви хочете, щоб він вилучив.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Цей інструмент входить до складу kali, але ви можете знайти його тут: <https://github.com/simsong/bulk_extractor>

Bulk Extractor може сканувати зображення доказів і вирізати **фрагменти pcap**, **мережеві артефакти (URL, домени, IP, MAC, електронні листи)** та багато інших об'єктів **паралельно, використовуючи кілька сканерів**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Корисні скрипти пост-обробки (`bulk_diff`, `bulk_extractor_reader.py`) можуть видаляти дублікат артефактів між двома образами або конвертувати результати в JSON для споживання SIEM.

### PhotoRec

Ви можете знайти його на <https://www.cgsecurity.org/wiki/TestDisk_Download>

Він постачається з версіями GUI та CLI. Ви можете вибрати **типи файлів**, які ви хочете, щоб PhotoRec шукав.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (іміджування несправних дисків)

Коли фізичний диск нестабільний, найкраща практика - спочатку **зробити його образ** і лише потім запускати інструменти карвінгу проти образу. `ddrescue` (проект GNU) зосереджується на надійному копіюванні несправних дисків, зберігаючи журнал нечитаємих секторів.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Версія **1.28** (грудень 2024) представила **`--cluster-size`**, що може прискорити створення образів високоякісних SSD, де традиційні розміри секторів більше не відповідають блокам флеш-пам'яті.

### Extundelete / Ext4magic (EXT 3/4 undelete)

Якщо вихідна файлова система базується на Linux EXT, ви можете відновити нещодавно видалені файли **без повного карвінгу**. Обидва інструменти працюють безпосередньо з образами тільки для читання:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Якщо файлова система була змонтована після видалення, блоки даних могли вже бути повторно використані – в такому випадку потрібне правильне карвінг (Foremost/Scalpel).

### binvis

Перевірте [код](https://code.google.com/archive/p/binvis/) та [веб-інструмент](https://binvis.io/#/).

#### Особливості BinVis

- Візуальний та активний **переглядач структури**
- Кілька графіків для різних фокусних точок
- Фокусування на частинах зразка
- **Перегляд рядків та ресурсів**, у PE або ELF виконуваних файлах, наприклад
- Отримання **шаблонів** для криптоаналізу файлів
- **Виявлення** алгоритмів пакування або кодування
- **Ідентифікація** стеганографії за шаблонами
- **Візуальне** бінарне порівняння

BinVis є чудовою **відправною точкою для ознайомлення з невідомою ціллю** в сценарії чорного ящика.

## Специфічні інструменти для карвінгу даних

### FindAES

Шукає ключі AES, досліджуючи їх графіки ключів. Може знаходити 128, 192 та 256 бітні ключі, такі як ті, що використовуються TrueCrypt та BitLocker.

Завантажити [тут](https://sourceforge.net/projects/findaes/).

### YARA-X (тріаж вирізаних артефактів)

[YARA-X](https://github.com/VirusTotal/yara-x) є переписаною на Rust версією YARA, випущеною у 2024 році. Вона **10-30× швидша** за класичну YARA і може бути використана для класифікації тисяч вирізаних об'єктів дуже швидко:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Прискорення робить реалістичним **автоматичне тегування** всіх вирізаних файлів у масштабних розслідуваннях.

## Додаткові інструменти

Ви можете використовувати [**viu** ](https://github.com/atanunq/viu), щоб переглядати зображення з терміналу.  \
Ви можете використовувати командний рядок linux **pdftotext**, щоб перетворити pdf у текст і прочитати його.

## Посилання

1. Примітки до випуску Autopsy 4.21 – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
