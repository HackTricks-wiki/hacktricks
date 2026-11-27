# Трюки із ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Інструменти командного рядка** для роботи з **ZIP-файлами** необхідні для діагностики, відновлення та злому ZIP-файлів. Ось кілька важливих утиліт:<sup>[[1]](#references)</sup>

- **`unzip`**: показує, чому ZIP-файл може не розпаковуватися.
- **`zipdetails -v`**: надає детальний аналіз полів формату ZIP-файлу.<sup>[[3]](#references)</sup>
- **`zipinfo`**: перелічує вміст ZIP-файлу без розпакування.
- **`zip -F input.zip --out output.zip`** і **`zip -FF input.zip --out output.zip`**: намагаються відновити пошкоджені ZIP-файли.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: інструмент для словникових атак і brute-force атак на паролі ZIP; доцільність залежить від простору пошуку пароля.<sup>[[15]](#references)</sup>

[Специфікація формату файлів Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) містить докладну інформацію про структуру та стандарти ZIP-файлів.<sup>[[4]](#references)</sup>

У традиційних ZIP-файлах, захищених паролем, імена файлів і їхні розміри зазвичай залишаються видимими, на відміну від режимів шифрування заголовків, які підтримують RAR і 7z. Атака ZipCrypto з відомим відкритим текстом відновлює **внутрішні ключі шифрування**, але не обов’язково початковий пароль; цих ключів достатньо, щоб розшифрувати записи, зашифровані тим самим паролем.<sup>[[13]](#references)</sup> Для атаки потрібні відомі байти потоку **до шифрування**: для збереженого елемента це байти оригінального файлу, а для елемента DEFLATE — стиснуті байти, для отримання яких може знадобитися відтворити точний результат стиснення.<sup>[[13]](#references)[[14]](#references)</sup> Практичний процес описано в розділі [Атака на ZIP із відомим відкритим текстом](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack). Передумови криптоаналізу див. у [статті](https://math.ucr.edu/~mike/zipattacks.pdf) та [покроковому розборі](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Ця атака ZipCrypto не працює із записами ZIP, зашифрованими AES.<sup>[[13]](#references)</sup>

---

## Трюки Anti-reversing в APK із маніпульованими заголовками ZIP

Сучасні дропери шкідливого ПЗ для Android використовують некоректні метадані ZIP, щоб порушити роботу статичних інструментів (jadx/apktool/unzip), але водночас залишити APK придатним до встановлення на пристрої. Найпоширеніші трюки:<sup>[[2]](#references)</sup>

- Імітація шифрування через встановлення біта 0 у ZIP General Purpose Bit Flag (GPBF)
- Зловживання великими або користувацькими полями Extra, щоб заплутати парсери
- Конфлікти назв файлів і каталогів для приховування справжніх артефактів (наприклад, каталог із назвою `classes.dex/` поруч зі справжнім `classes.dex`)

### 1) Імітація шифрування (встановлений біт 0 GPBF) без справжньої криптографії

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

Перевірте прапорець бітів загального призначення в локальних і центральних заголовках. Характерна ознака — встановлений біт 0 (шифрування), навіть для основних записів:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Евристика: Якщо APK встановлюється та запускається на пристрої, але інструменти показують, що основні записи «зашифровані», значення GPBF було підмінено.

Виправлення: очистіть біт 0 GPBF у заголовках локальних файлів (LFH) і записах центрального каталогу (CD). Мінімальний патчер байтів:

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

Змінювати слід лише біт 0: наприклад, `0A09` стає `0A08`, а не `0000`. Цей мінімальний патчер шукає сигнатури заголовків у сирих байтах, тому байти, схожі на сигнатуру, усередині даних файлу можуть спричинити хибні збіги; працюйте з копією та перевірте список записів і заголовки результату, перш ніж використовувати його.<sup>[[4]](#references)</sup>

### 2) Великі/нестандартні поля Extra для збою парсерів

Зловмисники додають до заголовків надмірно великі поля Extra та незвичні ID, щоб вивести з ладу декомпілятори. У реальних зразках там можуть траплятися власні маркери (наприклад, рядки на кшталт `JADXBLOCK`).

Перевірка:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Спостерігалися приклади: невідомі ID, як-от `0xCAFE` («Java Executable») або `0x414A` («JA:»), що містять великі payload.<sup>[[2]](#references)</sup>

Евристики DFIR:
- Створюйте сповіщення, якщо поля Extra незвично великі у ключових записах (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Вважайте невідомі ID Extra у цих записах підозрілими.

Практичний захід протидії: перебудова архіву (наприклад, повторне пакування розпакованих файлів у ZIP) видаляє шкідливі поля Extra. Якщо інструменти відмовляються розпаковувати архів через фальшиве шифрування, спершу очистьте біт 0 GPBF, як описано вище, а потім запакуйте файли знову:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Колізії імен файлів/каталогів (приховування реальних артефактів)

ZIP може містити і файл `X`, і каталог `X/`. Деякі засоби розпакування та декомпілятори плутаються й можуть накладати запис каталогу на реальний файл або приховувати його. Таке спостерігали, коли записи конфліктували з назвами основних файлів APK, як-от `classes.dex`.

Перевірка та безпечне розпакування:

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

Ідеї для виявлення синьою командою:
- Позначайте APK, локальні заголовки яких указують на шифрування (GPBF bit 0 = 1), але які встановлюються/запускаються.
- Позначайте великі/невідомі поля Extra у ключових записах (шукайте маркери на кшталт `JADXBLOCK`).
- Позначайте колізії шляхів (`X` і `X/`) саме для `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Інші шкідливі прийоми з ZIP (2024–2026)

### Конкатеновані центральні каталоги (обхід за допомогою кількох EOCD)

У фішинговій кампанії 2024 року зловмисники розповсюджували один файл, який насправді складався з **двох об’єднаних ZIP-файлів**. Кожен мав власний запис End of Central Directory (EOCD) і центральний каталог. Різні екстрактори аналізували різні каталоги (7-Zip читав перший, а WinRAR — останній), що давало змогу зловмисникам приховувати payload-и, які показували лише деякі інструменти; сканери, що перевіряють лише один каталог, можуть не виявити інший архів.<sup>[[5]](#references)[[6]](#references)</sup>

**Команди первинного аналізу**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Якщо виявлено кілька EOCD або попередження «data after payload», розділіть blob і перевірте кожну частину:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs створюють крихітне **ядро** (блок DEFLATE із високим ступенем стиснення) і повторно використовують його в перекривних записах. Варіанти Full-overlap вказують кількома записами центрального каталогу на один локальний заголовок, тоді як варіанти quoted-overlap цитують локальні заголовки всередині потоків DEFLATE; опублікована конструкція забезпечує співвідношення понад 28M:1 без вкладених архівів.<sup>[[7]](#references)</sup>

**Швидке виявлення (дублікати зміщень LFH)**

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
- Виконайте пробний перегляд: `zipdetails -v file.zip | grep -n "Local Header Offset"` і порівняйте зазначені зміщення локальних заголовків та діапазони стиснених даних; дубльовані зміщення вказують на варіанти з повним перекриттям.<sup>[[7]](#references)[[8]](#references)</sup>
- За допомогою парсера обмежте максимальний загальний розмір розпакованих даних і кількість записів до розпакування; `zipinfo -t file.zip` виводить підсумкові значення, але не встановлює безпечні обмеження.<sup>[[8]](#references)</sup>
- Якщо розпакування неминуче, виконуйте його в cgroup/VM з обмеженнями CPU і дискового простору (щоб уникнути збоїв через неконтрольоване розпакування).<sup>[[8]](#references)</sup>

---

### Плутанина парсерів через локальний заголовок і центральний каталог

Нещодавні дослідження диференційного парсингу показали, що неоднозначності ZIP досі можна експлуатувати в сучасних ланцюжках інструментів. Основна ідея проста: одне програмне забезпечення довіряє **Local File Header (LFH)**, а інше — **Central Directory (CD)**, тож один архів може показувати різним інструментам різні імена файлів, шляхи, коментарі, зміщення або набори записів.<sup>[[9]](#references)</sup>

Практичне застосування в атаках:
- Змусити фільтр завантажень, попереднє сканування AV або валідатор пакетів побачити нешкідливий файл у CD, тоді як екстрактор використовує інше ім’я/шлях із LFH.
- Скористатися дубльованими іменами, записами, наявними лише в одній структурі, або неоднозначними метаданими Unicode-шляхів (наприклад, Info-ZIP Unicode Path Extra Field `0x7075`), щоб різні парсери відтворювали різні дерева файлів.
- Поєднати це з path traversal, щоб перетворити «нешкідливий» вигляд архіву на примітив запису під час розпакування. Про бік розпакування див. [Обхід шляхів під час розпакування архівів](../../../generic-hacking/archive-extraction-path-traversal.md).

Первинне сортування DFIR:

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
- Для критично важливого з погляду безпеки приймання відхиляйте або ізолюйте архіви з невідповідністю імен у LFH/CD, повторюваними іменами файлів, кількома записами EOCD або кінцевими байтами після останнього EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Вважайте ZIP-архіви з незвичними додатковими полями Unicode-шляхів або непослідовними коментарями підозрілими, якщо різні інструменти по-різному обробляють дерево розпакованих файлів.<sup>[[4]](#references)[[9]](#references)</sup>
- Якщо аналіз важливіший за збереження вихідних байтів, перепакуйте архів за допомогою суворого парсера після розпакування в sandbox і порівняйте отриманий список файлів з вихідними метаданими.

Це важливо не лише для екосистем пакетів: той самий клас неоднозначності може приховувати payload-и від поштових шлюзів, статичних сканерів і власних конвеєрів приймання, які «зазиряють» у вміст ZIP до того, як інший розпаковувач обробить архів.<sup>[[9]](#references)</sup>

---





## References

- [1] [Посібник із комп'ютерної криміналістики для CTF (блог Майка, категорія CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather — частина 1 — багатоступеневий дропер (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (скрипт IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Специфікація формату файлів ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Гнучка структура ZIP-архівів використовується для приховування шкідливого ПЗ від виявлення (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Хакери ховають шкідливе ПЗ у новій атаці з ZIP-файлами — з'єднані центральні каталоги ZIP](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Краща ZIP-бомба (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Розуміння ZIP-бомб: побудова ядра з перекриттям/цитованим перекриттям](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Мій ZIP — не ваш ZIP: виявлення та використання семантичних розбіжностей між ZIP-парсерами (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Запобігання атакам зі спричиненням плутанини ZIP-парсерів в інсталяторі пакетів Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Атаки на ZIP зі скороченим відомим відкритим текстом (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: реалістична вебмісія, рівень 15 (атака на ZIP із відомим відкритим текстом)](https://www.hackthissite.org/articles/read/793)
- [13] [Використання bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [Навчальний посібник bkcrack із відомим відкритим текстом](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [Репозиторій fcrackzip](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
