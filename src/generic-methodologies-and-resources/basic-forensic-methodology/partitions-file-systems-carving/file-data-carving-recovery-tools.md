# Інструменти Carving і відновлення даних

{{#include ../../../banners/hacktricks-training.md}}

## Інструменти Carving і відновлення

Завжди виконуйте carving **перевіреної копії**, а не оригінального пристрою. Див. [Image Acquisition & Mount](../image-acquisition-and-mount.md), щоб ознайомитися з робочими процесами отримання даних у режимі лише для читання та хешування.

Більше інструментів у [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Найпоширеніший інструмент, який використовується у forensic для вилучення файлів з образів, — [**Autopsy**](https://www.autopsy.com/download/). Завантажте його, встановіть і додайте файл для обробки, щоб знайти "приховані" файли. Зверніть увагу, що Autopsy призначений для роботи з дисковими та іншими типами образів, але не зі звичайними файлами.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** — це інструмент для аналізу бінарних файлів з метою пошуку вбудованого вмісту. **Binwalk v3** — це переписана на Rust версія з автоматичним вилученням (`-e`), raw carving відомих і невідомих об'єктів (`-c`), рекурсивним/Matryoshka-скануванням (`-M`) і налаштовуваною кількістю worker threads. Проєкт рекомендує Docker build, якщо потрібні всі зовнішні extractors; `cargo install binwalk` встановлює Rust CLI, але не ці зовнішні залежності.<sup>[[11]](#references)</sup>

**Корисні команди v3**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
The legacy v2 `--dd='.*'` recipe is **not the v3 equivalent of `-c`**; first check `binwalk --version` when following old CTF/write-up commands.<sup>[[11]](#references)</sup>

⚠️  **Примітка щодо безпеки** – Версії **2.1.2b–2.3.3** уражені вразливістю **Path Traversal** (CVE-2022-4510); advisory не містить жодної виправленої версії pip. Уникайте вилучення недовірених зразків за допомогою уражених версій або ізолюйте tool за допомогою container/non-privileged UID.<sup>[[4]](#references)</sup>

### Foremost

Іншим поширеним tool для пошуку прихованих файлів є **foremost**. Configuration file foremost можна знайти в `/etc/foremost.conf`. Якщо ви хочете шукати лише певні файли, розкоментуйте їх. Якщо нічого не розкоментувати, foremost шукатиме стандартні налаштовані типи файлів.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** — це ще один інструмент, який можна використовувати для пошуку та вилучення **файлів, вбудованих у файл**. У цьому випадку потрібно розкоментувати у конфігураційному файлі (_/etc/scalpel/scalpel.conf_) типи файлів, які потрібно вилучити.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Цей інструмент входить до складу kali, але його можна знайти тут: <https://github.com/simsong/bulk_extractor>

Bulk Extractor може сканувати образ доказів і виконувати carving **фрагментів pcap**, **мережевих артефактів (URL-адрес, доменів, IP-адрес, MAC-адрес, e-mail)** та багатьох інших об’єктів **паралельно за допомогою кількох сканерів**.

У релізі v2.1.1 задокументовано збірку Autotools і параметр `-S jpeg_carve_mode=2` для carving усіх суміжних JPEG.<sup>[[2]](#references)</sup>
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
Вбудований `bulk_diff.py` порівнює два запуски bulk_extractor, тоді як `bulk_extractor_reader.py` читає звіт і файли ознак.<sup>[[3]](#references)</sup>

### PhotoRec

Його можна знайти тут: <https://www.cgsecurity.org/wiki/TestDisk_Download>

Він постачається у версіях із GUI та CLI. Ви можете вибрати **типи файлів**, які потрібно шукати за допомогою PhotoRec.

![Запуск усіх сканерів, агресивне вилучення JPEG і створення bodyfile - PhotoRec: він постачається у версіях із GUI та CLI. Ви можете вибрати типи файлів, які потрібно шукати за допомогою PhotoRec](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (спочатку метадані)

Перед carving за сирими сигнатурами спробуйте відновлення з урахуванням файлової системи, якщо метадані тому все ще можна розібрати. `tsk_recover` за замовчуванням експортує лише неallocated-файли; `-a` вибирає allocated-файли, а `-e` експортує обидва типи. Для образу всього диска передайте **початковий сектор** розділу з `mmls` до `-o` (не перетворюйте його на байти). Якщо вхідні дані вже є образом розділу, не використовуйте `-o`.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Цей підхід може зберігати назви та шляхи, отримані з файлової системи, чого не може header/footer carving; після цього запустіть Foremost, Scalpel або PhotoRec для записів, метадані яких відсутні або непридатні для використання.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (створення образу нестабільних дисків)

Коли фізичний диск нестабільний, найкращою практикою є **спочатку створити його образ**, а вже потім запускати інструменти carving для цього образу. `ddrescue` (проєкт GNU) зосереджений на надійному копіюванні пошкоджених дисків із веденням журналу непрочитаних секторів.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Опція **`--cluster-size`** визначає, скільки секторів копіюється за один раз; менші значення можуть допомогти під час роботи з повільними накопичувачами.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Якщо вихідна файлова система базується на Linux EXT, можливо, вам вдасться відновити нещодавно видалені файли **без повного carving**; ці журнальні інструменти працюють із демонтованою файловою системою або образом, доступним лише для читання.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Примітка щодо сумісності** – ext4magic закинуто; на сторінці проєкту попереджають, що сучасні файлові системи більше з ним несумісні.<sup>[[10]](#references)</sup>

> 🛈 Якщо файлову систему було змонтовано після видалення, блоки даних могли вже бути повторно використані – у такому разі все ще потрібен належний carving (Foremost/Scalpel).

### binvis

Перегляньте [code](https://code.google.com/archive/p/binvis/) і [web page tool](https://binvis.io/#/).

#### Можливості BinVis

- Візуальний та інтерактивний **переглядач структури**
- Кілька графіків для різних точок фокусування
- Фокусування на частинах зразка
- **Перегляд strings і ресурсів**, наприклад у виконуваних файлах PE або ELF
- Отримання **patterns** для cryptanalysis файлів
- **Виявлення** packer або encoder алгоритмів
- **Виявлення** Steganography за patterns
- **Візуальне** binary-diffing

BinVis — чудова **відправна точка для ознайомлення з невідомою ціллю** у сценарії black-boxing.

## Спеціалізовані інструменти Data Carving

### FindAES

Шукає AES-ключі, знаходячи їхні key schedules. Уміє знаходити ключі довжиною 128, 192 і 256 бітів, зокрема ті, що використовуються TrueCrypt і BitLocker.

Завантажити [тут](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) — це переписана на Rust версія YARA, представлена у 2024 році; VirusTotal повідомляє, що деякі правила з regular-expression і складними циклами можуть виконуватися значно швидше.<sup>[[5]](#references)</sup> Її CLI називається `yr`, а команда `scan` підтримує рекурсивне сканування, задання кількості потоків і виведення metadata.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Додаткові інструменти

Ви можете використовувати [**viu** ](https://github.com/atanunq/viu), щоб переглядати зображення з термінала.  \
Ви можете використовувати інструмент командного рядка Linux **pdftotext**, щоб перетворити pdf на текст і прочитати його.





## References

- [1] [Примітки до випуску Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README Python-інструментів bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal у binwalk (CVE-2022-4510) — база даних рекомендацій GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA is dead, long live YARA-X — блог VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Команди CLI YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Посібник GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Посібник ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Стан проєкту ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [Посібник The Sleuth Kit: tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
