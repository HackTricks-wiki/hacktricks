# Карвінг файлів/даних і засоби відновлення

{{#include ../../../banners/hacktricks-training.md}}

## Засоби карвінгу та відновлення

Завжди виконуйте карвінг **перевіреної копії**, а не оригінального пристрою. Див. [Отримання образу та монтування](../image-acquisition-and-mount.md), щоб ознайомитися з робочими процесами отримання даних лише для читання та хешування.

Більше інструментів: [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Найпоширеніший інструмент для вилучення файлів з образів у комп’ютерній криміналістиці — [**Autopsy**](https://www.autopsy.com/download/). Завантажте його, встановіть і передайте йому файл для пошуку «прихованих» файлів. Зверніть увагу: Autopsy підтримує образи дисків та інші типи образів, але не окремі файли.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** — це інструмент для аналізу бінарних файлів і пошуку вбудованого вмісту. **Binwalk v3** — переписана на Rust версія з автоматичним витягуванням (`-e`), карвінгом відомих і невідомих об’єктів із сирих даних (`-c`), рекурсивним скануванням (Matryoshka) (`-M`) і налаштовуваною кількістю робочих потоків. Проєкт рекомендує збірку Docker, якщо потрібні всі зовнішні засоби витягування; `cargo install binwalk` встановлює Rust CLI, але не ці зовнішні залежності.<sup>[[11]](#references)</sup>

**Корисні команди v3**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Застарілий рецепт v2 `--dd='.*'` — це **не** еквівалент v3 для `-c`; перш ніж виконувати старі команди з CTF/write-up, перевірте `binwalk --version`.<sup>[[11]](#references)</sup>

⚠️  **Примітка з безпеки** — Версії **від 2.1.2b до 2.3.3** вразливі до **Path Traversal** (CVE-2022-4510); в advisory не вказано виправленої версії pip. Не витягуйте ненадійні зразки за допомогою вразливих версій або ізолюйте інструмент у контейнері чи під непривілейованим UID.<sup>[[4]](#references)</sup>

### Foremost

Ще один поширений інструмент для пошуку прихованих файлів — **foremost**. Файл конфігурації foremost розташований у `/etc/foremost.conf`. Якщо потрібно шукати лише певні файли, розкоментуйте відповідні рядки. Якщо нічого не розкоментувати, foremost шукатиме типи файлів, налаштовані за замовчуванням.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** — це ще один інструмент, який можна використовувати для пошуку й вилучення **файлів, вбудованих у файл**. У цьому випадку потрібно розкоментувати у файлі конфігурації (_/etc/scalpel/scalpel.conf_) типи файлів, які потрібно вилучити.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Фрагментований карвінг за допомогою Scalpel3

Якщо відновлення спочатку за метаданими та карвери суміжних даних не можуть повністю відновити розділені файли, **Scalpel3** може зібрати підтримувані формати за допомогою валідаторів файлів і блоків. Це окрема кодова база, не пов’язана зі застарілою командою `scalpel`, згаданою вище. Спочатку створіть необхідну для нього blockmap із **тим самим розміром блока**, який використовуватиметься під час карвінгу; якщо розмір кластера файлової системи відомий, використайте значення з `fsstat`, а якщо ні — обґрунтовано визначте його перед скануванням образу розділу. Працюйте лише з перевіреною копією, а результати зберігайте на окремому томі.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Замініть `4096` на вибраний розмір блока. Параметр `-w` зберігає як перевірені кандидати, так і кандидатів зі статусом **PROMISING**, а `-b` записує блок-вектори, щоб допомогти перевірити реконструйовані структури. Файл зі статусом PROMISING або файл зі знайомим розширенням не є доказом повного відновлення; перш ніж використовувати його, перевірте вміст.<sup>[[13]](#references)[[14]](#references)</sup> Щоб знайти видалені розділи або проміжки перед карвінгом, див. [Пошук даних поза переліченими розділами](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Цей інструмент входить до Kali, але знайти його можна тут: <https://github.com/simsong/bulk_extractor>

Bulk Extractor може сканувати образ доказів і карвити **фрагменти pcap**, **мережеві артефакти (URL-адреси, домени, IP-адреси, MAC-адреси, електронні адреси)** та багато інших об’єктів **паралельно, використовуючи кілька сканерів**.

У документації до випуску v2.1.1 описано збирання за допомогою Autotools і параметр `-S jpeg_carve_mode=2` для карвінгу всіх суміжних JPEG-файлів.<sup>[[2]](#references)</sup>

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

The bundled `bulk_diff.py` порівнює результати двох запусків bulk_extractor, а `bulk_extractor_reader.py` читає файли звітів і ознак.<sup>[[3]](#references)</sup>

### PhotoRec

Його можна знайти тут: <https://www.cgsecurity.org/wiki/TestDisk_Download>

Він має версії з GUI та CLI. Ви можете вибрати **типи файлів**, які PhotoRec має шукати.

![Запустити всі сканери, агресивно відновлювати JPEG-файли та згенерувати bodyfile — PhotoRec: Він має версії з GUI та CLI. Ви можете вибрати типи файлів, які PhotoRec має шукати](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (спочатку метадані)

Перш ніж відновлювати дані за сигнатурами у сирому образі, спробуйте відновлення з урахуванням файлової системи, якщо метадані тому ще можна розібрати. За замовчуванням `tsk_recover` експортує лише неалоковані файли; `-a` вибирає алоковані файли, а `-e` експортує обидва типи. Для образу всього диска передайте до `-o` **початковий сектор** розділу з `mmls` (не переводьте його в байти). Якщо вхідний файл уже є образом розділу, не вказуйте `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Цей етап може зберегти імена та шляхи, отримані з файлової системи, чого не може карвінг за заголовками й нижніми колонтитулами; після цього запустіть Foremost, Scalpel або PhotoRec для записів, метадані яких відсутні або непридатні для використання.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (створення образів несправних дисків)

Якщо фізичний диск нестабільний, найкраще спершу **створити його образ** і запускати інструменти карвінгу лише для цього образу. `ddrescue` (проєкт GNU) призначений для надійного копіювання несправних дисків зі збереженням журналу секторів, які неможливо прочитати.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

Опція **`--cluster-size`** визначає, скільки секторів копіюється за раз; менші значення можуть допомогти з повільними дисками.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (відновлення видалених файлів EXT 3/4)

Якщо вихідна файлова система — на базі Linux EXT, можливо, вам вдасться відновити нещодавно видалені файли **без повного carving**; ці інструменти на основі журналу працюють із відмонтованою файловою системою або образом лише для читання.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Примітка щодо сумісності** – ext4magic закинуто; на сторінці проєкту зазначено, що сучасні файлові системи з ним уже несумісні.<sup>[[10]](#references)</sup>

> 🛈 Якщо файлову систему було змонтовано після видалення, блоки даних могли вже бути повторно використані — у такому разі все ще потрібен належний carving (Foremost/Scalpel).

### binvis

Перегляньте [код](https://code.google.com/archive/p/binvis/) і [вебінструмент](https://binvis.io/#/).

#### Можливості BinVis

- Візуальний інтерактивний **переглядач структур**
- Кілька графіків для різних точок фокусування
- Фокусування на частинах зразка
- **Перегляд рядків і ресурсів**, наприклад, у виконуваних файлах PE або ELF
- Пошук **патернів** у файлах для криптоаналізу
- **Виявлення** алгоритмів пакування або кодування
- **Виявлення** стеганографії за патернами
- **Візуальне** порівняння бінарних файлів

BinVis — чудова **відправна точка для знайомства з невідомою ціллю** в сценарії black-box тестування.

## Спеціалізовані інструменти для carving даних

### FindAES

Шукає ключі AES за їхніми розкладами ключів. Може знаходити ключі довжиною 128, 192 і 256 біт, зокрема ті, що використовуються TrueCrypt і BitLocker.

Завантажити [тут](https://sourceforge.net/projects/findaes/).

### YARA-X (первинний аналіз відновлених артефактів)

[YARA-X](https://github.com/VirusTotal/yara-x) — переписана мовою Rust версія YARA, представлена у 2024 році; VirusTotal повідомляє, що деякі правила з регулярними виразами та складними циклами можуть виконуватися значно швидше.<sup>[[5]](#references)</sup> Її CLI називається `yr`, а команда `scan` підтримує рекурсивне сканування, задання кількості потоків і виведення метаданих.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Додаткові інструменти

Ви можете використовувати [**viu** ](https://github.com/atanunq/viu), щоб переглядати зображення в терміналі.  \
Ви можете використовувати інструмент командного рядка Linux **pdftotext**, щоб перетворити PDF на текст і прочитати його.







## References

- [1] [Примітки до випуску Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README інструментів bulk_extractor для Python](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal у binwalk (CVE-2022-4510) — база даних рекомендацій GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA померла, хай живе YARA-X — блог VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Команди CLI YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Посібник GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Посібник ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Стан проєкту ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: посібник tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [README Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Посібник Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Тестовий workflow Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
