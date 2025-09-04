# Трюки з ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** для роботи з **zip файлами** необхідні для діагностики, відновлення та злому zip-файлів. Ось ключові утиліти:

- **`unzip`**: Показує, чому zip-файл може не розпакуватись.
- **`zipdetails -v`**: Надає детальний аналіз полів формату zip-файлу.
- **`zipinfo`**: Перелічує вміст zip-файлу без його розпакування.
- **`zip -F input.zip --out output.zip`** і **`zip -FF input.zip --out output.zip`**: Працюють над відновленням пошкоджених zip-файлів.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Інструмент для брутфорс-розшифровки паролів zip, ефективний для паролів до ~7 символів.

Детальна інформація про структуру та стандарти zip-файлів доступна в [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).

Важливо зазначити, що password-protected zip files **не шифрують імена файлів або їх розміри** всередині архіву — недолік безпеки, якого немає у RAR або 7z, що шифрують цю інформацію. Крім того, zip-файли, зашифровані старішим методом ZipCrypto, вразливі до **plaintext attack**, якщо доступна незашифрована копія стисненого файлу. Ця атака використовує відомий вміст для підбору пароля архіву — вразливість описана в [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) і детальніше пояснена в [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Однак zip-файли, захищені **AES-256**, стійкі до цієї plaintext attack, що підкреслює важливість вибору надійних методів шифрування для конфіденційних даних.

---

## Антиреверс-трюки в APK, які використовують модифіковані заголовки ZIP

Сучасні Android malware droppers використовують пошкоджені метадані ZIP, щоб ламати статичні інструменти (jadx/apktool/unzip), при цьому APK залишається встановлюваним на пристрої. Найпоширеніші трюки:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Симптоми:
- `jadx-gui` завершує роботу з помилками на кшталт:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` запитує пароль для ключових файлів APK, хоча валідний APK не може мати зашифровані `classes*.dex`, `resources.arsc` або `AndroidManifest.xml`:

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
Подивіться на General Purpose Bit Flag для локальних і центральних заголовків. Показовим значенням є встановлений біт 0 (Encryption) навіть для core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Евристика: Якщо APK встановлюється і запускається на пристрої, але основні записи виглядають "зашифрованими" для інструментів, GPBF був змінений.

Виправлення: Очистіть біт 0 GPBF у записах Local File Headers (LFH) та Central Directory (CD). Мінімальний byte-patcher:
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
Тепер ви повинні бачити `General Purpose Flag  0000` на основних записах, і інструменти знову розберуть APK.

### 2) Великі/кастомні Extra поля, що ламають парсери

Атакуючі запихають у заголовки надвеликий Extra поля та дивні ID, щоб збити з пантелику декомпілятори. У реальному житті ви можете побачити там кастомні маркери (наприклад, рядки на кшталт `JADXBLOCK`) вкладені там.

Перевірка:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Приклади, що спостерігалися: невідомі ідентифікатори, такі як `0xCAFE` ("Java Executable") або `0x414A` ("JA:") з великими payload'ами.

DFIR евристики:
- Попереджати, коли Extra поля незвично великі в основних записах (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Розглядати невідомі Extra ID у цих записах як підозрілі.

Практичні заходи: перебудова архіву (наприклад, повторне zip-архівування вилучених файлів) видаляє шкідливі Extra поля. Якщо інструменти відмовляються витягувати через підроблене шифрування, спочатку очистіть GPBF біт 0, як зазначено вище, потім переупакуйте:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Колізії імен файлів/каталогів (приховування реальних артефактів)

ZIP архів може містити одночасно файл `X` і каталог `X/`. Деякі екстрактори та декомпілятори можуть заплутатися і перекрити або приховати реальний файл записом каталогу. Це спостерігалося при колізіях з основними іменами в APK, наприклад `classes.dex`.

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
Ідеї виявлення для Blue-team:
- Позначати APKs, чиї локальні заголовки вказують на шифрування (GPBF bit 0 = 1), але при цьому встановлюються/запускаються.
- Позначати великі/невідомі Extra поля в основних записах (шукати маркери на кшталт `JADXBLOCK`).
- Позначати колізії шляхів (`X` та `X/`) зокрема для `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Посилання

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
