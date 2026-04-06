# Трюки з ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Інструменти командного рядка** для роботи з **zip-файлами** необхідні для діагностики, відновлення та злому zip-архівів. Ось ключові утиліти:

- **`unzip`**: Пояснює, чому zip-файл може не розпаковуватись.
- **`zipdetails -v`**: Надає детальний аналіз полів формату zip.
- **`zipinfo`**: Перелічує вміст zip-файлу без його розпакування.
- **`zip -F input.zip --out output.zip`** і **`zip -FF input.zip --out output.zip`**: Пробують відремонтувати пошкоджені zip-файли.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Інструмент для брутфорс-розгадування паролів zip, ефективний для паролів приблизно до 7 символів.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

Важливо зазначити, що захищені паролем zip-файли **не шифрують імена файлів або розміри файлів** всередині — це недолік безпеки, який не стосується RAR чи 7z, що шифрують цю інформацію. Додатково, zip-файли, зашифровані старішим методом ZipCrypto, вразливі до plaintext attack, якщо доступна незашифрована копія стисненого файлу. Ця атака використовує відомий вміст для підбору пароля архіву — її описано в [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) та докладніше пояснено в [цьому науковому папері](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Проте zip-файли, захищені за допомогою **AES-256**, стійкі до цієї plaintext attack, що підкреслює важливість вибору надійних методів шифрування для конфіденційних даних.

---

## Антиреверс-методи в APK із зміненими заголовками ZIP

Сучасні Android malware droppers використовують пошкоджені метадані ZIP, щоб зламати статичні інструменти (jadx/apktool/unzip), водночас залишаючи APK інсталюваним на пристрої. Найпоширеніші трюки:

- Фальшиве шифрування шляхом встановлення біта 0 у ZIP General Purpose Bit Flag (GPBF)
- Зловживання великими/власними полями Extra для плутанини парсерів
- Колізії імен файлів/папок для приховування реальних артефактів (наприклад, директорія з назвою `classes.dex/` поруч із реальним `classes.dex`)

### 1) Фальшиве шифрування (GPBF bit 0 встановлений) без реальної криптографії

Симптоми:
- `jadx-gui` падає з помилками типу:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` запитує пароль для основних файлів APK, хоча валідний APK не може мати зашифровані `classes*.dex`, `resources.arsc`, або `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Виявлення за допомогою zipdetails:
```bash
zipdetails -v sample.apk | less
```
Подивіться на General Purpose Bit Flag для local і central headers. Показовим значенням є встановлений біт 0 (Encryption) навіть для core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Евристика: Якщо APK встановлюється і запускається на пристрої, але основні записи виглядають "зашифрованими" для інструментів, GPBF був змінений.

Виправлення: очистіть біт 0 GPBF як у Local File Headers (LFH), так і у записах Central Directory (CD). Мінімальний byte-patcher:

<details>
<summary>Мінімальний GPBF bit-clear patcher</summary>
```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
out = bytearray(buf)
i = 0
patched = 0
while True:
i = out.find(sig, i)
if i == -1:
break
flags, = struct.unpack_from('<H', out, i + flag_off)
if flags & 1:  # encryption bit set
struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
patched += 1
i += 4  # move past signature to continue search
return bytes(out), patched

if __name__ == '__main__':
inp, outp = sys.argv[1], sys.argv[2]
data = open(inp, 'rb').read()
data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
open(outp, 'wb').write(data)
print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```
</details>

Використання:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Тепер ви повинні бачити `General Purpose Flag  0000` у основних записах, і інструменти знову розберуть APK.

### 2) Великі/кастомні Extra fields, щоб вивести parsers з ладу

Зловмисники вставляють у headers надмірно великі Extra fields та дивні IDs, щоб збити з пантелику decompilers. У реальних випадках ви можете побачити кастомні маркери (наприклад, рядки на кшталт `JADXBLOCK`), вставлені туди.

Перевірка:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Приклади спостережень: невідомі ID, такі як `0xCAFE` ("Java Executable") або `0x414A` ("JA:"), що містять великі payloads.

DFIR евристики:
- Сповіщати, коли поля Extra надзвичайно великі в основних записах (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Розцінювати невідомі Extra ID у таких записах як підозрілі.

Практичне рішення: перебудова архіву (наприклад, повторне zip-ування витягнутих файлів) видаляє шкідливі поля Extra. Якщо інструменти відмовляються розпаковувати через фейкове шифрування, спочатку обнуліть біт 0 GPBF як описано вище, а потім упакуйте знову:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Колізії імен файлів/каталогів (приховування реальних артефактів)

ZIP може містити одночасно файл `X` і каталог `X/`. Деякі програми для розпаковки та декомпілятори плутаються і можуть накрити або приховати реальний файл записом каталогу. Таке спостерігалось при колізіях з базовими іменами APK, такими як `classes.dex`.

Тріаж та безпечна розпаковка:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Програмне виявлення постфікса:
```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
names = z.namelist()

collisions = defaultdict(list)
for n in names:
base = n[:-1] if n.endswith('/') else n
collisions[base].append(n)

for base, variants in collisions.items():
if len(variants) > 1:
print('COLLISION', base, '->', variants)
```
Ідеї виявлення для Blue-team:
- Позначати APKs, чиї локальні заголовки маркують шифрування (GPBF bit 0 = 1), але які все ж install/run.
- Позначати великі/невідомі Extra fields у core entries (шукати маркери на кшталт `JADXBLOCK`).
- Позначати колізії шляхів (`X` and `X/`) особливо для `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Інші зловмисні трюки з ZIP (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Останні фішингові кампанії доставляють один blob, який насправді є **двома ZIP файлими, склеєними разом**. Кожен має свій власний End of Central Directory (EOCD) + central directory. Різні екстрактори парсять різні каталоги (7zip читає перший, WinRAR — останній), що дозволяє нападникам приховувати payloads, які видно лише деяким інструментам. Це також обходить базовий mail gateway AV, який інспектує лише перший каталог.

**Команди тріажу**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Якщо з'являється більше одного EOCD або є попередження "data after payload", розділіть blob і перевірте кожну частину:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Сучасна реалізація "better zip bomb" створює невеликий **kernel** (дуже стиснений DEFLATE block) і повторно використовує його через перекривні локальні заголовки. Кожен запис центрального каталогу вказує на ті самі стиснені дані, досягаючи співвідношень >28M:1 без вкладення архівів. Бібліотеки, які довіряють розмірам центрального каталогу (Python `zipfile`, Java `java.util.zip`, Info-ZIP до випусків із підвищеною безпекою), можуть бути змушені виділити петабайти.

**Швидке виявлення (дублікати зсувів LFH)**
```python
# detect overlapping entries by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
i = buf.find(b'PK\x01\x02', off)
if i<0: break
rel = struct.unpack_from('<I', buf, i+42)[0]
if rel in seen:
print('OVERLAP at offset', rel)
break
seen.add(rel); off = i+4
```
**Обробка**
- Виконайте dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` і переконайтеся, що зсуви строго зростають і є унікальними.
- Обмежте загальний прийнятний розмір після розпакування та кількість записів перед екстракцією (`zipdetails -t` або власний парсер).
- Якщо потрібно екстрагувати — робіть це всередині cgroup/VM з обмеженнями CPU і диска (щоб уникнути краху через необмежене роздування).

---

### Плутанина парсерів: Local-header vs central-directory

Останні дослідження differential-parser показали, що неоднозначність ZIP досі експлуатується в сучасних тулчейнах. Суть проста: деяке ПЗ довіряє **Local File Header (LFH)**, тоді як інше — **Central Directory (CD)**, тому один архів може показувати різним інструментам різні імена файлів, шляхи, коментарі, зсуви або набори записів.

Практичні атакувальні сценарії:
- Змусити upload filter, AV pre-scan або package validator бачити безпечний файл у CD, тоді як екстрактор шанує інше ім'я/шлях у LFH.
- Зловживати дубльованими іменами, записами, які присутні тільки в одній структурі, або неоднозначними метаданими Unicode шляху (наприклад, Info-ZIP Unicode Path Extra Field `0x7075`), щоб різні парсери реконструювали різні дерева.
- Поєднати це з path traversal, щоб перетворити "harmless" вигляд архіву на write-primitive під час екстракції. For the extraction side, see [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR: первинна оцінка:
```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
n, e = struct.unpack_from('<HH', b, i + 26)
lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
n = struct.unpack_from('<H', b, i + 28)[0]
off = struct.unpack_from('<I', b, i + 42)[0]
cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
if off in lfh and cd != lfh[off]:
print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
i += 4
```
You didn’t provide the file content to translate or the text to “complement”. Please either:

- Paste the full contents of src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md you want translated, or
- Describe exactly what additional content you want me to add (and in which language), and paste any material to be merged.

I’ll then translate the English parts to Ukrainian following your formatting and tag rules.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Евристики:
- Відхиляйте або ізольовуйте архіви з невідповідними іменами LFH/CD, дубльованими іменами файлів, кількома записами EOCD або з зайвими байтами після фінального EOCD.
- Вважайте ZIPs підозрілими, якщо вони використовують незвичні Unicode-path extra fields або мають неконсистентні коментарі, і різні інструменти не сходяться щодо extracted tree.
- Якщо для аналізу важливіше отримати коректну картину, ніж зберегти оригінальні байти, перепакуйте архів за допомогою strict parser після витягання в sandbox і порівняйте отриманий список файлів зі справжніми метаданими.

Це має значення поза межами package ecosystems: той самий клас неоднозначностей може приховувати payloads від mail gateways, static scanners і custom ingestion pipelines, які "peek" у вміст ZIP перед тим, як інший extractor обробить архів.

---



## Посилання

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
