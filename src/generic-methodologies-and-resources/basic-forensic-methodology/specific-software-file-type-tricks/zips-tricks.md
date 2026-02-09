# Трюки з ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Інструменти командного рядка** для керування **zip files** необхідні для діагностики, відновлення та злому zip files. Ось основні утиліти:

- **`unzip`**: Показує, чому zip file може не розпаковуватися.
- **`zipdetails -v`**: Надає детальний аналіз полів формату zip file.
- **`zipinfo`**: Перелічує вміст zip file без витягнення.
- **`zip -F input.zip --out output.zip`** і **`zip -FF input.zip --out output.zip`**: Спроби відновити пошкоджені zip файли.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Інструмент для брутфорс-розблокування паролів zip, ефективний для паролів приблизно до 7 символів.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

Важливо пам'ятати, що password-protected zip files **не шифрують імена файлів або їхні розміри** всередині архіву — це вразливість, якої немає у RAR або 7z, які шифрують цю інформацію. Крім того, zip files, зашифровані застарілим методом ZipCrypto, вразливі до **plaintext attack**, якщо доступна незашифрована копія стисненого файлу. Ця атака використовує відомий вміст для злома пароля zip — уразливість детально описана в [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) і детальніше пояснена в [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Проте zip files, захищені шифруванням **AES-256**, не піддаються цій plaintext attack, що демонструє важливість вибору надійних методів шифрування для чутливих даних.

---

## Антиреверсинг трюки в APKs, що використовують модифіковані заголовки ZIP

Сучасні Android malware droppers використовують пошкоджені метадані ZIP, щоб зламати статичні інструменти (jadx/apktool/unzip), при цьому APK залишається встановлюваним на пристрої. Найпоширеніші трюки:

- Фейкове шифрування шляхом встановлення біту 0 ZIP General Purpose Bit Flag (GPBF)
- Використання великих/кастомних Extra fields для плутання парсерів
- Колізії імен файлів/каталогів для приховування реальних артефактів (наприклад, каталог з ім'ям `classes.dex/` поруч із реальним `classes.dex`)

### 1) Фейкове шифрування (GPBF біт 0 встановлений) без реального шифрування

Симптоми:
- `jadx-gui` падає з помилками, наприклад:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` запитує пароль для основних файлів APK, хоча дійсний APK не може мати зашифровані `classes*.dex`, `resources.arsc` або `AndroidManifest.xml`:

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
Перегляньте General Purpose Bit Flag для local та central headers. Показовим значенням є встановлений біт 0 (Encryption) навіть для core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Евристика: Якщо APK встановлюється і запускається на пристрої, але основні записи для інструментів виглядають як "зашифровані", GPBF було змінено.

Виправлення: очистити біт 0 GPBF як у Local File Headers (LFH), так і в записах Central Directory (CD). Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit-clear patcher</summary>
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
Тепер ви повинні бачити `General Purpose Flag  0000` на основних записах, і інструменти знову зможуть розпарсити APK.

### 2) Великі/кастомні Extra fields, що ламають парсери

Зловмисники вставляють надмірно великі Extra-поля та дивні ID в заголовки, щоб збити декомпілятори. На практиці ви можете бачити кастомні маркери (наприклад, рядки типу `JADXBLOCK`), вбудовані там.

Перевірка:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Спостережені приклади: невідомі ID, такі як `0xCAFE` ("Java Executable") або `0x414A` ("JA:"), які несуть великі payloads.

DFIR heuristics:
- Попереджати, коли Extra fields неприродно великі у основних записах (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Розглядати невідомі Extra IDs у цих записах як підозрілі.

Practical mitigation: перебудова архіву (наприклад, повторне збирання у zip витягнутих файлів) видаляє шкідливі поля Extra. Якщо інструменти відмовляються витягати через фейкове шифрування, спочатку очистіть GPBF bit 0 як зазначено вище, потім запакуйте заново:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Колізії імен файлів/каталогів (приховування реальних артефактів)

Архів ZIP може містити як файл `X`, так і каталог `X/`. Деякі екстрактори та декомпілятори плутаються і можуть перекрити або приховати реальний файл записом каталогу. Таке спостерігалося для записів, що конфліктують із ключовими іменами в APK, наприклад `classes.dex`.

Тріаж та безпечне вилучення:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Програмна детекція постфікса:
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
- Позначати APKs, у яких локальні заголовки вказують на шифрування (`GPBF bit 0 = 1`), але вони все ще встановлюються/запускаються.
- Позначати великі/невідомі Extra fields на core entries (шукати маркери на кшталт `JADXBLOCK`).
- Позначати колізії шляхів (`X` і `X/`), особливо для `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Інші шкідливі ZIP хитрощі (2024–2025)

### Конкатеновані центральні каталоги (multi-EOCD evasion)

Нещодавні фішингові кампанії доставляють один blob, який насправді є **двома конкатенованими ZIP-файлами**. Кожен має власний End of Central Directory (EOCD) + центральний каталог. Різні розпакувальники парсять різні каталоги (7zip читає перший, WinRAR — останній), що дозволяє зловмисникам приховувати payloads, які видно лише в деяких інструментах. Це також обходить базовий mail gateway AV, який інспектує лише перший каталог.

**Команди для тріажу**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Якщо з'являється більше ніж один EOCD або є попередження "data after payload", розділіть blob і перевірте кожну частину:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Сучасна "better zip bomb" створює крихітне **ядро** (сильно стиснутий DEFLATE-блок) і повторно використовує його через перекриття локальних заголовків. Кожен запис центрального каталогу вказує на ті самі стиснені дані, досягаючи співвідношень >28M:1 без вкладених архівів. Бібліотеки, які довіряють розмірам центрального каталогу (Python `zipfile`, Java `java.util.zip`, Info-ZIP до випусків із підвищеною безпекою), можуть бути змушені виділяти петабайти.

**Швидке виявлення (повторні зміщення LFH)**
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
- Виконайте dry-run перевірку: `zipdetails -v file.zip | grep -n "Rel Off"` і переконайтеся, що офсети строго зростають та є унікальними.
- Обмежте допустимий загальний розмір після розпакування та кількість записів перед витягуванням (`zipdetails -t` or custom parser).
- Якщо потрібно розпаковувати, робіть це в cgroup/VM з обмеженнями CPU і диска (щоб уникнути крашів через необмежене роздування).

---

## Джерела

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
