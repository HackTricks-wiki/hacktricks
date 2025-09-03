# Трюки з ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Інструменти командного рядка** для роботи з **zip-файлами** необхідні для діагностики, відновлення та злому zip-файлів. Ось кілька ключових утиліт:

- **`unzip`**: Показує, чому zip-файл може не розпаковуватись.
- **`zipdetails -v`**: Надає детальний аналіз полів формату zip.
- **`zipinfo`**: Перелічує вміст zip-файлу без його розпакування.
- **`zip -F input.zip --out output.zip`** and **`zip -FF input.zip --out output.zip`**: Спроби відновити пошкоджені zip-файли.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Інструмент для брутфорс-атаки паролів zip, ефективний для паролів приблизно до 7 символів.

Специфікація формату файлу Zip: [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) містить вичерпні відомості про структуру та стандарти zip-файлів.

Важливо зазначити, що zip-файли з паролем **не шифрують імена файлів та розміри файлів** всередині архіву — це недолік безпеки, якого немає в RAR або 7z, які шифрують цю інформацію. Крім того, zip-файли, зашифровані старим методом ZipCrypto, вразливі до **plaintext attack**, якщо доступна незашифрована копія стисненого файлу. Ця атака використовує відомий вміст для злому пароля архіву, вразливість описана в статті [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) і докладно пояснена в [цьому академічному документі](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Однак zip-файли, захищені **AES-256**, стійкі до цієї plaintext attack, що підкреслює важливість вибору надійних методів шифрування для конфіденційних даних.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Сучасні Android malware droppers використовують пошкоджені метадані ZIP, щоб зламати статичні інструменти (jadx/apktool/unzip), при цьому APK залишається встановлюваним на пристрої. Найпоширеніші трюки:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Симптоми:
- `jadx-gui` падає з помилками на кшталт:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` запитує пароль для ключових файлів APK, хоча в дійсному APK не може бути зашифрованих `classes*.dex`, `resources.arsc`, або `AndroidManifest.xml`:

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
Подивіться на General Purpose Bit Flag для локальних та центральних заголовків. Характерне значення — встановлений bit 0 (Encryption) навіть для основних записів:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Евристика: Якщо APK встановлюється й запускається на пристрої, але основні записи інструментів виглядають як «зашифровані», то GPBF було змінено.

Виправлення: очистіть біт 0 GPBF як у Local File Headers (LFH), так і в записах Central Directory (CD). Мінімальний byte-patcher:
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
Використання:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Тепер ви повинні побачити `General Purpose Flag  0000` у основних записах, і інструменти знову зможуть parse APK.

### 2) Великі/нестандартні Extra fields, що ламають parsers

Зловмисники додають надто великі Extra fields і дивні ID у заголовки, щоб збити з пантелику decompilers. У реальних зразках ви можете побачити користувацькі маркери (наприклад, рядки на кшталт `JADXBLOCK`) вбудовані там.

Перевірка:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Спостерігалися приклади: невідомі ID, такі як `0xCAFE` ("Java Executable") або `0x414A` ("JA:") що містять великі payloads.

Евристики DFIR:
- Сповіщати, коли Extra fields ненормально великі в ключових записах (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Розглядати невідомі Extra ID у цих записах як підозрілі.

Практичне рішення: перебудова архіву (наприклад, повторне запакування витягнутих файлів) видаляє шкідливі Extra-поля. Якщо інструменти відмовляються витягувати через фейкове шифрування, спочатку очистіть GPBF bit 0, як зазначено вище, потім повторно запакуйте:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Файлові/директорні колізії імен (приховування реальних артефактів)

ZIP може містити одночасно файл `X` і директорію `X/`. Деякі утиліти розпаковування та декомпілятори плутаються і можуть накладати або приховувати реальний файл директорним записом. Це спостерігалося при колізіях записів з основними іменами APK, такими як `classes.dex`.

Тріаж і безпечне витягнення:
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
Blue-team виявлення ідеї:
- Позначати APK, у яких локальні заголовки вказують шифрування (GPBF bit 0 = 1), але вони встановлюються/запускаються.
- Позначати великі/невідомі Extra fields у core entries (шукати маркери на кшталт `JADXBLOCK`).
- Позначати колізії шляхів (`X` and `X/`) зокрема для `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Посилання

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
