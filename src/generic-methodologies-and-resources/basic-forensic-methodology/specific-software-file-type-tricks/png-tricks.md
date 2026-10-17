# Трюки з PNG

{{#include ../../../banners/hacktricks-training.md}}

**PNG-файли** дуже поширені в **CTF**, під час **реагування на інциденти** та **підготовки malware до доставки**, оскільки вони **не втрачають дані**, мають **структуру на основі чанків**, а багато інструментів без проблем відображають їх, навіть якщо вони містять **додаткові метадані**, **дописані payload-и** або **частково пошкоджені чанки**.

Розглядайте PNG як **контейнер**, а не просто як зображення.

## Швидке сортування

Перш ніж переходити до стеганографії LSB, перевірте контейнер. Щоб ознайомитися з робочим процесом для бітових площин/LSB, дивіться [спеціальну сторінку про стеганографію зображень](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Корисні речі, на які варто звернути увагу:

- **Неочікувані допоміжні чанки**, як-от `tEXt`, `zTXt`, `iTXt`, `eXIf` або `iCCP`
- **Помилки CRC** або некоректна довжина чанків
- **Додаткові дані після `IEND`**
- **Кілька маркерів `IEND`** або фрагменти `IDAT`, які можна відновити, після формального кінця файлу
- Файл, який є коректним PNG **і** під час carving також схожий на ZIP/PDF/скрипт

Пам’ятайте, що мінімальна коректна структура зазвичай така:

- `IHDR` (має бути першим)
- `IDAT` (один або кілька послідовних чанків)
- `IEND` (має бути останнім)

## Хвостові дані після `IEND`

Один із найвиразніших артефактів PNG — це **дані, дописані після останнього чанка `IEND`**. Багато декодерів ігнорують їх, що робить їх корисними для:

- **Простого стегано / прихованих payload-ів**
- **PNG polyglots**
- **Підготовки malware**
- **Відновлення старіших даних зображення** з редакторів із помилками

Швидке виявлення:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Пошук байтів `IEND` — лише підказка: ті самі байти можуть траплятися в даних chunk або підробленому трейлері. Щоб надійно витягнути дані, пройдіть чанки з префіксом довжини від сигнатури PNG і зупиніться на першому структурному `IEND`; [наведений нижче обхідник чанків](#extract-ancillary-chunk-payloads) також зберігає трейлер.<sup>[[6]](#references)</sup>

Також спробуйте безпосередньо застосувати універсальні парсери архівів до PNG або витягнутого трейлера:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Відновлення обрізаних/заретушованих знімків екрана у стилі aCropalypse

Дуже практичний і відносно новий PNG-форензичний трюк — перевірити, чи редактор знімків екрана **перезаписав** PNG, не **обрізавши** спочатку старий файл. У таких випадках байти з **попереднього зображення** можуть залишитися після `IEND`, а іноді вдається частково відновити додаткові дані `IDAT`.

Цей прийом став широко відомим завдяки **aCropalypse** (Google Pixel Markup) і пов’язаній з ним проблемі **Windows Snipping Tool**.<sup>[[3]](#references)</sup> На практиці, якщо в «обрізаному» або «заретушованому» PNG досі є старі дані наприкінці файла, іноді можна відновити частину оригінального знімка екрана.<sup>[[1]](#references)</sup>

Практичний порядок дій:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Ознаки, які є вагомою підставою для глибшого аналізу:

- `pngcheck` повідомляє про **додаткові дані після `IEND`**
- Ви знаходите **більше одного `IEND`**
- Ви знаходите **додаткові чанки `IDAT`** після видимого кінця зображення
- Знімок екрана зроблено на пристрої або в редакторі, які, як відомо, зазнали впливу цієї вразливості

Якщо це сталося, пропустіть файл через інструмент відновлення **aCropalypse**, перш ніж вважати редагування надійним.

## Зловживання чанками, важливе на практиці

Найцікавіші для розслідувань чанки PNG зазвичай не є очевидними чанками зображення, а можуть містити **текст**, **метадані** або **байти корисного навантаження**:

- `tEXt` / `zTXt` / `iTXt` – текстові метадані та стиснений текст
- `eXIf` – дані EXIF усередині PNG
- `iCCP` – вбудований профіль ICC
- `PLTE` – дані палітри в індексованих зображеннях, але також корисні в сценаріях приховування корисного навантаження.<sup>[[2]](#references)</sup>

Виведіть їх за допомогою:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Для збереження offensive payload у PNG-фрагментах (наприклад, за допомогою трюків із **PLTE**, **IDAT** або **tEXt**, які працюють після деяких перетворень зображень у PHP) дивіться докладніші нотатки про завантаження файлів тут:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Витягування payload із допоміжних фрагментів

Зловмисник може розмістити довільні байти в **невідомому допоміжному фрагменті перед `IEND`**. Звичайні декодери PNG можуть ігнорувати невідомий допоміжний фрагмент, тоді як скрипт, що отримує зображення як байти, може прочитати й використати payload; саме відкриття PNG його не виконує.<sup>[[4]](#references)[[6]](#references)</sup> В оригінальному дослідженні було показано стиснений і зашифрований користувацький фрагмент.<sup>[[4]](#references)</sup> У пізнішому прикладі для браузера витягнуті байти використовувалися для передачі HTML або файлу для завантаження.<sup>[[5]](#references)</sup>

Регістр першої літери типу фрагмента вказує на те, що він *допоміжний*; мала друга літера означає, що він *приватний*. Наприклад, `paMP` є приватним, тоді як `pAMP` використовує публічний простір імен, хоча останній було вигадано для демонстрації.<sup>[[4]](#references)[[6]](#references)</sup> Фрагмент має структуру `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`; CRC охоплює тип і дані. Розбирайте цю структуру, а не шукайте назву типу всередині стиснених даних `IDAT`. Наведений нижче обхідник перевіряє межі та CRC, експортує payload допоміжних фрагментів як сирі байти й записує байти після структурного `IEND` у файл `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Витягування допоміжних фрагментів і трейлера PNG</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Перевірте вирізані байти за допомогою `file`, `strings` або `binwalk`; розпаковуйте лише тоді, коли дані-носій справді стиснуті.<sup>[[4]](#references)</sup> Повторне кодування може видалити дані-носій, тому порівняйте байти завантаженого й отриманого файлів, перш ніж покладатися на них.<sup>[[2]](#references)[[6]](#references)</sup>

## Відновлення пошкоджених PNG

Для перевірки цілісності й точного визначення пошкодженої ділянки **pngcheck** і досі залишається одним із найкращих інструментів для початкової перевірки:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Якщо файл пошкоджений, а не навмисно зловмисний, **PCRT** може стати в пригоді в CTF і лабораторних роботах для виправлення поширених проблем, як-от неправильні заголовки, хибні значення IHDR, проблеми з CRC або некоректна структура чанків.

Якщо ваша мета — **очистити** PNG із підозрілими кінцевими даними, зберігши видиме зображення, ExifTool дає змогу явно видалити кінцеві дані:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Для роботи з конфіденційними доказами завжди використовуйте **копію** та зберігайте хеші оригіналу перед спробами відновлення.



## References

- [1] [Експлуатація aCropalypse: відновлення обрізаних PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Постійні PHP-пейлоади в PNG: як впровадити PHP-код у зображення — і зберегти його там](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD — CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Допоміжні чанки — ідеальне місце для зберігання конфіденційної інформації](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Використання валідних допоміжних чанків для прихованого передавання даних до кінцевої точки](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Специфікація Portable Network Graphics (PNG), третє видання](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
