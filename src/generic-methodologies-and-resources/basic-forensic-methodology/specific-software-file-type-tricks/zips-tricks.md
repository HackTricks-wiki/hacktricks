# Трюки з ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Інструменти командного рядка** для роботи з **zip-файлами** необхідні для діагностики, відновлення та злому zip-файлів. Ось кілька ключових утиліт:<sup>[[1]](#references)</sup>

- **`unzip`**: показує, чому zip-файл може не розпаковуватися.
- **`zipdetails -v`**: надає детальний аналіз полів формату zip-файлів.<sup>[[3]](#references)</sup>
- **`zipinfo`**: перелічує вміст zip-файлу без його розпакування.
- **`zip -F input.zip --out output.zip`** та **`zip -FF input.zip --out output.zip`**: намагаються відновити пошкоджені zip-файли.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: інструмент для brute-force злому паролів zip-файлів, ефективний для паролів довжиною приблизно до 7 символів.

[Специфікація формату Zip-файлів](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) містить вичерпні відомості про структуру та стандарти zip-файлів.<sup>[[4]](#references)</sup>

Важливо зазначити, що захищені паролем zip-файли **не шифрують імена файлів або розміри файлів**, що є недоліком безпеки, якого немає у RAR- або 7z-файлах, які шифрують цю інформацію. Крім того, zip-файли, зашифровані за допомогою старішого методу ZipCrypto, вразливі до **атаки з відомим відкритим текстом**, якщо доступна незашифрована копія стисненого файлу.<sup>[[1]](#references)</sup> Ця атака використовує відомий вміст для злому пароля zip-файлу; детально цю вразливість описано у [статті HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) та додатково пояснено у [цій академічній статті](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Однак zip-файли, захищені шифруванням **AES-256**, не вразливі до цієї атаки з відомим відкритим текстом, що демонструє важливість вибору безпечних методів шифрування для конфіденційних даних.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks в APK із використанням маніпуляцій із ZIP-заголовками

Сучасні Android malware droppers використовують некоректні ZIP-метадані, щоб вивести з ладу статичні інструменти (jadx/apktool/unzip), водночас зберігаючи можливість встановлення APK на пристрій. Найпоширеніші трюки:<sup>[[2]](#references)</sup>

- Fake encryption через встановлення біта 0 ZIP General Purpose Bit Flag (GPBF)
- Зловживання великими/нестандартними Extra-полями для введення парсерів в оману
- Конфлікти імен файлів/каталогів для приховування реальних артефактів (наприклад, каталог із назвою `classes.dex/` поруч зі справжнім `classes.dex`)

### 1) Fake encryption (встановлено GPBF bit 0) без справжньої криптографії

Ознаки:
- `jadx-gui` завершує роботу з помилками на кшталт:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` запитує пароль для основних файлів APK, хоча коректний APK не може містити зашифровані `classes*.dex`, `resources.arsc` або `AndroidManifest.xml`:

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
Зверніть увагу на General Purpose Bit Flag для локальних і центральних заголовків. Показовою ознакою є встановлений біт 0 (Encryption) навіть для основних записів:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Евристика: Якщо APK встановлюється та запускається на пристрої, але основні записи відображаються інструментами як «зашифровані», GPBF було змінено.

Виправлення: очистіть біт 0 GPBF як у Local File Headers (LFH), так і в записах Central Directory (CD). Мінімальний byte-patcher:

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
Тепер у записах core має відображатися `General Purpose Flag  0000`, і tools знову зможуть аналізувати APK.

### 2) Великі/кастомні Extra fields для порушення роботи parser-ів

Атакувальники додають до заголовків надмірно великі Extra fields і нестандартні ID, щоб вивести decompiler-и з ладу. У реальних зразках там можуть траплятися кастомні маркери, наприклад рядки на кшталт `JADXBLOCK`.

Перевірка:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Приклади: невідомі ID, як-от `0xCAFE` ("Java Executable") або `0x414A` ("JA:"), що містять великі payload.

Евристики DFIR:
- Створюйте alert, коли Extra fields мають нетипово великий розмір у core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Вважайте невідомі Extra IDs у цих entries підозрілими.

Практичне mitigation: перебудова archive (наприклад, повторне пакування розпакованих файлів у zip) видаляє malicious Extra fields. Якщо tools відмовляються виконувати extract через fake encryption, спочатку очистіть GPBF bit 0, як зазначено вище, а потім виконайте repackage:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Конфлікти імен файлів/каталогів (приховування справжніх артефактів)

ZIP може містити як файл `X`, так і каталог `X/`. Деякі extractors і decompilers можуть заплутатися та накласти або приховати справжній файл записом каталогу. Це спостерігалося, коли записи конфліктували з основними іменами APK, такими як `classes.dex`.

Тріаж і безпечне розпакування:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Програмне виявлення після виправлення:
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
Ідеї для виявлення Blue-team:
- Позначати APK, локальні заголовки яких вказують на шифрування (GPBF bit 0 = 1), але які встановлюються/запускаються.
- Позначати великі/невідомі Extra fields у ключових записах (шукати маркери на кшталт `JADXBLOCK`).
- Позначати колізії шляхів (`X` і `X/`) саме для `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Інші шкідливі трюки ZIP (2024–2026)

### Конкатеновані central directories (обхід виявлення через multi-EOCD)

Нещодавні фішингові кампанії поширюють один blob, який фактично є **двома ZIP-файлами, об’єднаними послідовно**. Кожен із них має власний End of Central Directory (EOCD) і central directory. Різні extractors аналізують різні directories (7zip читає перший, WinRAR — останній), що дає змогу зловмисникам приховувати payloads, які відображаються лише в деяких інструментах. Це також обходить базовий mail gateway AV, який перевіряє лише першу directory.<sup>[[5]](#references)[[6]](#references)</sup>

**Команди для первинного аналізу**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Якщо з’являється більше одного EOCD або виникають попередження «data after payload», розділіть blob і перевірте кожну його частину:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (нерекурсивні)

Сучасні збірки **better zip bomb** створюють крихітне **ядро** (сильно стиснений блок DEFLATE) і повторно використовують його через перекривні локальні заголовки. Кожен запис центрального каталогу вказує на одні й ті самі стиснені дані, забезпечуючи коефіцієнти стиснення понад 28M:1 без вкладення архівів. Бібліотеки, які довіряють розмірам центрального каталогу (`zipfile` у Python, `java.util.zip` у Java, Info-ZIP до появи hardened builds), можна змусити виділити петабайти пам’яті.<sup>[[7]](#references)[[8]](#references)</sup>

**Швидке виявлення (дублікати зміщень LFH)**
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
- Виконайте dry-run-перевірку: `zipdetails -v file.zip | grep -n "Rel Off"` і переконайтеся, що offsets суворо зростають і є унікальними.
- Обмежте допустимий загальний uncompressed size і кількість entry до extraction (`zipdetails -t` або custom parser).
- Якщо extraction необхідне, виконуйте його всередині cgroup/VM з обмеженнями CPU та disk (щоб уникнути crash через необмежене розгортання).

---

### Плутанина між Local-header і central-directory parser

Нещодавні дослідження differential-parser показали, що ZIP-неоднозначність усе ще експлуатується в сучасних toolchain. Основна ідея проста: деяке software довіряє **Local File Header (LFH)**, тоді як інше довіряє **Central Directory (CD)**, тому один archive може надавати різним tools різні filenames, paths, comments, offsets або entry sets.<sup>[[9]](#references)</sup>

Практичні offensive-застосування:
- Змусити upload filter, AV pre-scan або package validator побачити benign file у CD, тоді як extractor використає інше LFH name/path.
- Зловживати duplicate names, entries, наявними лише в одній structure, або неоднозначними Unicode path metadata (наприклад, Info-ZIP Unicode Path Extra Field `0x7075`), щоб різні parsers відновили різні trees.
- Поєднати це з path traversal, щоб перетворити "harmless" archive view на write-primitive під час extraction. Щодо extraction side див. [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR-тріаж:
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
Надайте текст, який потрібно перекласти.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Евристики:
- Відхиляйте або ізолюйте архіви з невідповідними іменами LFH/CD, дубльованими іменами файлів, кількома записами EOCD або байтами після фінального EOCD.<sup>[[10]](#references)</sup>
- Вважайте ZIP, що використовують незвичайні додаткові поля Unicode-шляхів або несумісні коментарі, підозрілими, якщо різні інструменти не узгоджуються щодо розпакованого дерева.<sup>[[9]](#references)</sup>
- Якщо аналіз важливіший за збереження оригінальних байтів, перепакуйте архів за допомогою strict parser після розпакування в sandbox і порівняйте отриманий список файлів з оригінальними метаданими.

Це важливо не лише для package ecosystems: той самий клас неоднозначностей може приховувати payloads від mail gateways, static scanners і custom ingestion pipelines, які "заглядають" у ZIP-вміст перед тим, як інший extractor обробить архів.

---



## References

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
