# Трюки з ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Інструменти командного рядка** для керування **zip-файлами** необхідні для діагностики, відновлення та злому zip-файлів. Ось кілька основних утиліт:<sup>[[1]](#references)</sup>

- **`unzip`**: показує, чому zip-файл може не розпаковуватися.
- **`zipdetails -v`**: надає детальний аналіз полів формату zip-файлів.<sup>[[3]](#references)</sup>
- **`zipinfo`**: перелічує вміст zip-файлу без його розпакування.
- **`zip -F input.zip --out output.zip`** та **`zip -FF input.zip --out output.zip`**: намагаються відновити пошкоджені zip-файли.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: інструмент для brute-force злому паролів zip-файлів, ефективний для паролів довжиною приблизно до 7 символів.

[Специфікація формату Zip-файлів](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) містить вичерпні відомості про структуру та стандарти zip-файлів.<sup>[[4]](#references)</sup>

Важливо зазначити, що традиційні ZIP-файли, захищені паролем, зазвичай залишають видимими імена файлів та їхні розміри, на відміну від режимів шифрування заголовків, які підтримують RAR і 7z. Крім того, ZIP-файли, зашифровані за допомогою старішого методу ZipCrypto, уразливі до **plaintext attack**, якщо доступна незашифрована копія стисненого файлу.<sup>[[1]](#references)</sup> Ця атака використовує відомий вміст для злому пароля ZIP, як описано в [цій академічній статті](https://math.ucr.edu/~mike/zipattacks.pdf) та показано в [цьому покроковому керівництві Hack This Site](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Однак ZipCrypto known-plaintext attack не застосовується до записів, захищених шифруванням **AES-256**.<sup>[[1]](#references)</sup>

---

## Anti-reversing tricks в APK із використанням змінених ZIP-заголовків

Сучасні Android malware droppers використовують некоректні ZIP-метадані, щоб вивести з ладу статичні інструменти (jadx/apktool/unzip), водночас залишаючи APK придатним для встановлення на пристрої. Найпоширеніші трюки:<sup>[[2]](#references)</sup>

- Імітація шифрування шляхом встановлення біта 0 ZIP General Purpose Bit Flag (GPBF)
- Зловживання великими/нестандартними Extra-полями для введення парсерів в оману
- Колізії імен файлів/каталогів для приховування реальних артефактів (наприклад, каталог із назвою `classes.dex/` поруч зі справжнім `classes.dex`)

### 1) Fake encryption (встановлений біт 0 GPBF) без справжньої криптографії

Ознаки:
- `jadx-gui` завершує роботу з помилками на кшталт:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` запитує пароль для основних APK-файлів, хоча коректний APK не може містити зашифровані `classes*.dex`, `resources.arsc` або `AndroidManifest.xml`:

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
Перевірте General Purpose Bit Flag для локальних і центральних заголовків. Показовим значенням є встановлений біт 0 (Encryption) навіть для основних записів:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Евристика: Якщо APK встановлюється та запускається на пристрої, але основні записи виглядають для інструментів як «зашифровані», GPBF було змінено.

Виправлення: очистіть біт 0 GPBF у записах Local File Headers (LFH) і Central Directory (CD). Мінімальний патчер байтів:

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
Тепер у записах core ви маєте побачити `General Purpose Flag  0000`, і tools знову зможуть розібрати APK.

### 2) Великі/нестандартні Extra fields для злому парсерів

Attackers додають до заголовків надмірно великі Extra fields і нетипові ID, щоб вивести decompilers з ладу. У wild ви можете побачити custom markers (наприклад, рядки на кшталт `JADXBLOCK`), вбудовані туди.

Перевірка:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Приклади, що спостерігалися: невідомі ID, як-от `0xCAFE` ("Java Executable") або `0x414A` ("JA:"), що містять великі payload.<sup>[[2]](#references)</sup>

Евристики DFIR:
- Створюйте сповіщення, коли Extra fields мають нетипово великий розмір у ключових записах (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Вважайте невідомі Extra IDs у цих записах підозрілими.

Практичний захід протидії: перебудова архіву (наприклад, повторне пакування розпакованих файлів у ZIP) видаляє шкідливі Extra fields. Якщо інструменти відмовляються розпаковувати архів через фальшиве шифрування, спочатку очистіть біт 0 GPBF, як описано вище, а потім повторно запакуйте:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Колізії назв файлів/каталогів (приховування реальних артефактів)

ZIP може містити одночасно файл `X` і каталог `X/`. Деякі extractors і decompilers плутаються та можуть накладати каталог або приховувати реальний файл записом каталогу. Це спостерігалося для записів, що конфліктують із ключовими назвами APK, як-от `classes.dex`.

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
Ідеї для виявлення blue-team:
- Позначати APK, локальні заголовки яких вказують на шифрування (GPBF bit 0 = 1), але які встановлюються/запускаються.
- Позначати великі/невідомі Extra fields у core entries (шукати маркери на кшталт `JADXBLOCK`).
- Виявляти path-collisions (`X` і `X/`) саме для `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Інші шкідливі ZIP-трюки (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

У phishing-кампанії 2024 року зловмисники поширювали один blob, який насправді складався з **двох ZIP-файлів, об’єднаних послідовно**. Кожен із них мав власний запис End of Central Directory (EOCD) і central directory. Різні extractors обробляли різні directories (7-Zip читав першу, а WinRAR — останню), що давало зловмисникам змогу приховувати payloads, які відображалися лише деякими інструментами; scanners, що перевіряють лише одну directory, можуть пропустити інший archive.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Якщо з’являється більше одного EOCD або виникають попередження «data after payload», розділіть blob і перевірте кожну його частину:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs створюють крихітне **ядро** (сильно стиснений блок DEFLATE) і повторно використовують його в overlapping entries. Варіанти з повним перекриттям спрямовують кілька записів центрального каталогу на один local header, тоді як варіанти з quoted-overlap цитують local headers усередині потоків DEFLATE; опублікована конструкція досягає співвідношення понад 28M:1 без вкладених архівів.<sup>[[7]](#references)</sup>

**Quick detection (duplicate LFH offsets)**
```python
# detect full-overlap variants by identical relative offsets
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
- Виконайте dry-run перевірку: `zipdetails -v file.zip | grep -n "Local Header Offset"` і порівняйте вказані offsets локальних заголовків та діапазони стиснених даних; дубльовані offsets вказують на варіанти з повним перекриттям.<sup>[[7]](#references)[[8]](#references)</sup>
- До розпакування обмежте parser-ом прийнятний загальний розмір нестиснених даних і кількість entries; `zipinfo -t file.zip` повідомляє підсумкові значення, але не застосовує обмеження безпеки.<sup>[[8]](#references)</sup>
- Якщо розпакування необхідне, виконуйте його всередині cgroup/VM з обмеженнями CPU і дискового простору (щоб уникнути crash-ів через необмежене розпакування).<sup>[[8]](#references)</sup>

---

### Плутанина між parser-ами локальних заголовків і central directory

Нещодавнє дослідження differential-parser-ів показало, що неоднозначність ZIP досі можна експлуатувати в сучасних toolchain-ах. Основна ідея проста: одне ПЗ довіряє **Local File Header (LFH)**, тоді як інше — **Central Directory (CD)**, тому один archive може надавати різним інструментам різні filenames, paths, comments, offsets або набори entries.<sup>[[9]](#references)</sup>

Практичне offensive-застосування:
- Зробіть так, щоб upload filter, AV pre-scan або package validator бачив benign file у CD, тоді як extractor використовував інше ім’я/path із LFH.
- Використовуйте duplicate names, entries, наявні лише в одній структурі, або неоднозначні Unicode path metadata (наприклад, Info-ZIP Unicode Path Extra Field `0x7075`), щоб різні parsers відновлювали різні дерева.
- Поєднайте це з path traversal, щоб перетворити "нешкідливе" представлення archive на write-primitive під час extraction. Щодо боку extraction див. [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR triage:
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
Доповніть це:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Евристики:
- Для security-sensitive ingestion відхиляйте або ізолюйте архіви з невідповідними іменами LFH/CD, дубльованими іменами файлів, кількома записами EOCD або байтами після фінального EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Вважайте ZIP-архіви з нетиповими extra fields Unicode-шляхів або неузгодженими коментарями підозрілими, якщо різні інструменти по-різному визначають дерево розпакованих файлів.<sup>[[4]](#references)[[9]](#references)</sup>
- Якщо аналіз важливіший за збереження оригінальних байтів, перепакуйте архів за допомогою strict parser після розпакування в sandbox і порівняйте отриманий список файлів з оригінальними метаданими.

Це важливо не лише для package ecosystems: той самий клас неоднозначностей може приховувати payloads від mail gateways, static scanners і custom ingestion pipelines, які «заглядають» у вміст ZIP до того, як інший extractor обробить архів.<sup>[[9]](#references)</sup>

---



## References

- [1] [Довідник із CTF Forensics (блог Mike, категорія CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Частина 1 – Багатоетапний dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (скрипт IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Специфікація формату ZIP-файлів (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Гнучка структура ZIP-архівів, використана для непомітного приховування malware (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers ховають malware у новій атаці через ZIP-файли — об’єднані центральні каталоги ZIP](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Краща zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Розуміння Zip Bombs: побудова ядра з overlapping/quoted-overlap](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Мій ZIP — не ваш ZIP: виявлення та експлуатація семантичних розбіжностей між ZIP-парсерами (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Запобігання атакам через плутанину ZIP-парсерів на інсталяторах Python-пакетів](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP-атаки зі зменшеним обсягом відомого відкритого тексту (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Реалістична вебмісія, рівень 15 (ZIP-атака з відомим відкритим текстом)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
