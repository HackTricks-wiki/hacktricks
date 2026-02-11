# ZIPs трюки

{{#include ../../../banners/hacktricks-training.md}}

**Інструменти командного рядка** для роботи з **zip files** необхідні для діагностики, ремонту та злому zip-файлів. Ось ключові утиліти:

- **`unzip`**: Показує, чому zip-файл може не розпаковуватись.
- **`zipdetails -v`**: Надає детальний аналіз полів формату zip.
- **`zipinfo`**: Перелічує вміст zip-файлу без його розпакування.
- **`zip -F input.zip --out output.zip`** та **`zip -FF input.zip --out output.zip`**: Спроби відновлення пошкоджених zip-файлів.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Інструмент для brute-force злому паролів zip, ефективний для паролів приблизно до 7 символів.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) надає вичерпні деталі щодо структури та стандартів zip-файлів.

Важливо зазначити, що password-protected zip files **не шифрують імена файлів чи розміри файлів** всередині — недолік безпеки, якого немає у RAR або 7z, які шифрують цю інформацію. Крім того, zip-файли, зашифровані старішим методом ZipCrypto, вразливі до **plaintext attack**, якщо доступна незашифрована копія стисненого файлу. Ця атака використовує відомий вміст для злому пароля zip-файлу, про що йдеться в [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) і детальніше пояснюється в [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Однак zip-файли, захищені **AES-256**, стійкі до цієї plaintext attack, що підкреслює важливість вибору надійних методів шифрування для чутливих даних.

---

## Anti-reversing трюки в APKs з модифікованими заголовками ZIP

Сучасні Android malware droppers використовують некоректні метадані ZIP, щоб зламати статичні інструменти (jadx/apktool/unzip), одночасно зберігаючи можливість встановлення APK на пристрої. Найпоширеніші трюки:

- Fake encryption, встановлення біту 0 в ZIP General Purpose Bit Flag (GPBF)
- Зловживання великими/кастомними Extra fields, щоб заплутати парсери
- Колізії імен файлів/каталогів для приховування реальних артефактів (наприклад, каталог з ім'ям `classes.dex/` поруч із реальним `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) без реального шифрування

Симптоми:
- `jadx-gui` видає помилки на кшталт:

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
Подивіться на General Purpose Bit Flag для local і central headers. Характерна ознака — встановлений bit 0 (Encryption) навіть для core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Евристика: Якщо APK встановлюється й запускається на пристрої, але основні записи здаються "encrypted" для інструментів, GPBF було змінено.

Виправляється очищенням біта 0 GPBF у записах як Local File Headers (LFH), так і Central Directory (CD). Мінімальний байт-патчер:

<details>
<summary>Мінімальний патчер очищення біта GPBF</summary>
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
Тепер ви повинні бачити `General Purpose Flag  0000` на core записах і інструменти знову проаналізують APK.

### 2) Large/custom Extra fields to break parsers

Зловмисники вставляють надмірно великі поля Extra та нестандартні ID у заголовки, щоб збити з пантелику decompilers. У природі ви можете побачити кастомні маркери (наприклад, рядки на кшталт `JADXBLOCK`) вбудовані там.

Перевірка:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Спостережувані приклади: невідомі ID, такі як `0xCAFE` ("Java Executable") або `0x414A` ("JA:"), які містять великі payloads.

DFIR евристики:
- Попереджати, коли поля Extra неприродно великі в ключових записах (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Вважати невідомі Extra ID в цих записах підозрілими.

Практичне пом'якшення: перебудова архіву (наприклад, повторне zip-упакування вилучених файлів) видаляє шкідливі поля Extra. Якщо інструменти відмовляються витягувати через фальшиве шифрування, спочатку очистіть GPBF bit 0, як описано вище, потім повторно запакуйте:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Колізії імен файлів/каталогів (приховування реальних артефактів)

ZIP може містити як файл `X`, так і каталог `X/`. Деякі екстрактори та декомпілятори плутаються й можуть накладати або приховувати реальний файл за записом каталогу. Це спостерігалося при колізіях записів з основними іменами APK, такими як `classes.dex`.

Тріаж і безпечне витягання:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Постфікс для програмного виявлення:
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
Blue-team detection ideas:
- Позначати APKs, чиї локальні заголовки вказують на шифрування (GPBF bit 0 = 1), але вони все одно інсталюються/запускаються.
- Позначати великі/невідомі Extra fields у основних записах (шукати маркери на кшталт `JADXBLOCK`).
- Позначати path-collisions (`X` and `X/`) особливо для `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Інші шкідливі ZIP трюки (2024–2025)

### Конкатеновані центральні каталоги (multi-EOCD evasion)

Останні phishing кампанії доставляють один blob, який насправді є **два конкатеновані ZIP файли**. Кожен має свій власний End of Central Directory (EOCD) + central directory. Різні екстрактори розбирають різні каталоги (7zip читає перший, WinRAR — останній), що дозволяє атакам приховувати payloadи, які показують лише деякі інструменти. Це також обходить базовий mail gateway AV, який інспектує лише перший каталог.

**Команди для триажу**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Якщо з'являється більше одного EOCD або виникають попередження "data after payload", розділіть blob і перевірте кожну частину:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Сучасна "better zip bomb" створює крихітне **kernel** (дуже стиснутий DEFLATE блок) і повторно використовує його через перекриваючіся локальні заголовки. Кожен запис центрального каталогу вказує на ті ж стиснені дані, досягаючи співвідношень >28M:1 без вкладених архівів. Бібліотеки, які покладаються на розміри записів у центральному каталозі (Python `zipfile`, Java `java.util.zip`, Info-ZIP до жорсткіших збірок), можна змусити виділяти петабайти.

**Швидке виявлення (повторні зсуви LFH)**
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
- Виконайте dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` і переконайтеся, що зсуви (offsets) строго зростають і є унікальними.
- Обмежте прийнятний загальний розмір у розпакованому вигляді та кількість записів перед вилученням (`zipdetails -t` або власний парсер).
- Якщо потрібно розпаковувати, робіть це всередині cgroup/VM з лімітами CPU та диска (щоб уникнути аварій через необмежене роздування даних).

---

## Посилання

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
