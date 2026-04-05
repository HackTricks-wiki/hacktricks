# Трюки з ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Інструменти командного рядка** для роботи з **zip files** необхідні для діагностики, відновлення та злому zip-файлів. Ось кілька ключових утиліт:

- **`unzip`**: Показує, чому zip-файл може не розархівовуватися.
- **`zipdetails -v`**: Надає детальний аналіз полів формату zip-файлу.
- **`zipinfo`**: Перелічує вміст zip-файлу без його розпакування.
- **`zip -F input.zip --out output.zip`** and **`zip -FF input.zip --out output.zip`**: Намагаються відновити пошкоджені zip-файли.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Інструмент для брутфорс-атаки паролів zip, ефективний для паролів приблизно до 7 символів.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

Важливо зауважити, що password-protected zip files **не шифрують імена файлів або розміри файлів** всередині, — це уразливість, якої нема у RAR або 7z, які шифрують цю інформацію. Крім того, zip-файли, зашифровані старішим методом ZipCrypto, вразливі до **plaintext attack**, якщо доступна незашифрована копія стисненого файлу. Ця атака використовує відомий вміст для зламу пароля zip, уразливість детально описана в статті [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) і докладніше пояснена в [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Однак zip-файли, захищені шифруванням **AES-256**, стійкі до цієї plaintext attack, що підкреслює важливість вибору надійних методів шифрування для конфіденційних даних.

---

## Антиреверсинг-трюки в APK за допомогою модифікованих заголовків ZIP

Сучасні Android malware droppers використовують пошкоджені ZIP metadata, щоб зламати статичні інструменти (jadx/apktool/unzip), одночасно залишаючи APK інсталюваним на пристрої. Найпоширеніші трюки:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Зловживання великими/кастомними Extra полями, щоб заплутати парсери
- Колізії імен файлів/директорій для приховування реальних артефактів (наприклад, директорія з іменем `classes.dex/` поруч із реальним `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Симптоми:
- `jadx-gui` fails with errors like:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` prompts for a password for core APK files even though a valid APK cannot have encrypted `classes*.dex`, `resources.arsc`, or `AndroidManifest.xml`:

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
Подивіться на General Purpose Bit Flag для локальних і центральних заголовків. Характерне значення — встановлений біт 0 (Encryption) навіть для основних записів:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Евристика: Якщо APK інсталюється і запускається на пристрої, але основні записи виглядають «зашифрованими» для інструментів, GPBF було підмінено.

Виправити це можна, очистивши bit 0 GPBF у записах і в Local File Headers (LFH), і в Central Directory (CD). Мінімальний byte-patcher:

<details>
<summary>Мінімальний патчер для очищення біта GPBF</summary>
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
Тепер ви повинні бачити `General Purpose Flag  0000` на основних записах, і інструменти знову зможуть парсити APK.

### 2) Великі/користувацькі додаткові поля для порушення роботи парсерів

Зловмисники вштовхують надмірно великі додаткові поля та дивні ідентифікатори в заголовки, щоб збити з пантелику декомпілятори. У реальних зразках можна натрапити на користувацькі маркери (наприклад, рядки на кшталт `JADXBLOCK`), вбудовані там.

Перевірка:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Приклади спостережень: невідомі ID, такі як `0xCAFE` ("Java Executable") або `0x414A` ("JA:") що несуть великі payloads.

DFIR heuristics:
- Сповіщати, коли Extra fields неприродно великі в основних записах (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Розглядати невідомі Extra IDs у цих записах як підозрілі.

Практичне вирішення: перевпакування архіву (наприклад, повторне zip-упакування витягнутих файлів) видаляє шкідливі Extra fields. Якщо інструменти відмовляються розпаковувати через фейкове шифрування, спочатку очистіть GPBF bit 0, як описано вище, потім знову упакуйте:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Колізії імен файлу/каталогу (приховання реальних артефактів)

У ZIP-архіві може бути одночасно файл `X` та каталог `X/`. Деякі утиліти для розпаковування та декомпілятори плутаються і можуть перекривати або приховувати реальний файл записом каталогу. Таке спостерігалося при конфлікті записів з основними іменами APK, такими як `classes.dex`.

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
Blue-team ідеї для виявлення:
- Позначати APK, у яких локальні заголовки вказують на шифрування (GPBF bit 0 = 1), але які все ж встановлюються/запускаються.
- Позначати великі/невідомі Extra fields в основних записах (див. маркери типу `JADXBLOCK`).
- Позначати колізії шляхів (`X` і `X/`) особливо для `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Інші шкідливі ZIP-трюки (2024–2026)

### Конкатенація центральних каталогів (multi-EOCD evasion)

Останні фішингові кампанії доставляють один blob, який фактично є **двома ZIP-файлами, склеєними разом**. Кожен має свій End of Central Directory (EOCD) + central directory. Різні екстрактори парсять різні каталоги (7zip читає перший, WinRAR — останній), що дозволяє атакуючим приховувати payload-и, які видно лише деяким інструментам. Це також обходить базовий mail gateway AV, який інспектує лише перший каталог.

**Команди для триажу**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Якщо з'являється більше одного EOCD або є попередження "data after payload", розбийте blob і перевірте кожну частину:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Сучасна "better zip bomb" створює крихітне **ядро** (дуже стиснений блок DEFLATE) і повторно використовує його через перекриті локальні заголовки. Кожен запис у центральному каталозі вказує на ті самі стиснені дані, досягаючи коефіцієнтів >28M:1 без вкладення архівів. Бібліотеки, які покладаються на розміри центрального каталогу (Python `zipfile`, Java `java.util.zip`, Info-ZIP до впровадження захищених збірок), можуть бути змушені виділяти петабайти.

**Швидке виявлення (duplicate LFH offsets)**
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
- Виконайте пробний прогін: `zipdetails -v file.zip | grep -n "Rel Off"` і переконайтеся, що offsetи строго зростають і є унікальними.
- Обмежте прийнятний загальний розмір після розпакування та кількість записів перед витяганням (`zipdetails -t` or custom parser).
- Коли потрібно витягати, робіть це всередині cgroup/VM з обмеженнями CPU і диска (щоб уникнути аварій через необмежене збільшення).

---

### Плутанина парсерів: Local-header vs central-directory

Нещодавні дослідження диференційних парсерів показали, що неоднозначність ZIP все ще експлуатується в сучасних тулчейнах. Основна ідея проста: деяке програмне забезпечення довіряє **Local File Header (LFH)**, тоді як інше — **Central Directory (CD)**, тому один архів може показувати різні імена файлів, шляхи, коментарі, offsets або набори записів різним інструментам.

Практичні наступальні сценарії:
- Змусьте фільтр завантаження, AV pre-scan, або package validator бачити безпечний файл у CD, тоді як екстрактор шанує інше ім'я/шлях з LFH.
- Зловживайте дублікатами імен, записами, присутніми лише в одній структурі, або неоднозначними Unicode-метаданими шляху (наприклад, Info-ZIP Unicode Path Extra Field `0x7075`), щоб різні парсери реконструювали різні дерева.
- Поєднайте це з path traversal, щоб перетворити "невинний" вигляд архіву на write-primitive під час витягання. Для сторони розпакування див. [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR первинна оцінка:
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
Будь ласка, надайте текст або фрагмент, який потрібно «complement» (доповнити) — без цього я не можу виконати переклад і вставлення. Вкажіть також, куди саме його додати (якщо потрібно), або просто вставте додатковий контент у повідомленні.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Евристика:
- Відхиляйте або ізолюйте архіви з невідповідними іменами LFH/CD, дубльованими іменами файлів, кількома записами EOCD або з байтами, що йдуть після кінцевого EOCD.
- Розглядайте ZIPs, які використовують незвичні Unicode-path extra fields або мають неконсистентні коментарі, як підозрілі, якщо різні інструменти дають різну витягнуту структуру.
- Якщо для аналізу важливіше зберегти інформацію, ніж оригінальні байти, перепакуйте архів за допомогою строгого parser після витягання в sandbox і порівняйте отриманий список файлів з оригінальними метаданими.

Це важливо не тільки для пакетних екосистем: той самий клас неоднозначностей може приховувати payloads від mail gateways, static scanners та кастомних ingestion pipelines, які "peek" вміст ZIP перед тим, як інший extractor обробить архів.

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
