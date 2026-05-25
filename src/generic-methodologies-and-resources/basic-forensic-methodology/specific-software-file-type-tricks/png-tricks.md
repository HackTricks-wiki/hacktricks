# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Pliki PNG** są bardzo częste w **CTFs**, **incident response** i **malware staging**, ponieważ są **bezstratne**, **chunk-based**, a wiele narzędzi chętnie je renderuje nawet wtedy, gdy zawierają **extra metadata**, **appended payloads** lub **partially corrupted chunks**.

Traktuj PNG jako **container**, a nie tylko jako obraz.

## Quick triage

Zacznij od sprawdzeń na poziomie kontenera, zanim przejdziesz do LSB stego. W przypadku workflow bit-plane/LSB sprawdź [the dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Przydatne rzeczy do sprawdzenia:

- **Unexpected ancillary chunks** takie jak `tEXt`, `zTXt`, `iTXt`, `eXIf` lub `iCCP`
- **CRC errors** lub nieprawidłowe długości chunków
- **Dodatkowe dane po `IEND`**
- **Multiple `IEND` markers** lub możliwe do odzyskania fragmenty `IDAT` po formalnym końcu pliku
- Plik, który jest poprawnym PNG **i** jednocześnie wygląda jak ZIP/PDF/skrypt po carvingu

Pamiętaj, że minimalna poprawna struktura zwykle jest taka:

- `IHDR` (musi być pierwsze)
- `IDAT` (jeden lub więcej kolejnych chunków)
- `IEND` (musi być ostatnie)

## Trailing data after `IEND`

Jednym z artefaktów PNG o najwyższej wartości sygnału są **dane dołączone po końcowym chunku `IEND`**. Wiele dekoderów je ignoruje, co czyni to użytecznym do:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Odzyskiwania starszych danych obrazu** z wadliwych edytorów

Szybka detekcja:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Jeśli chcesz wyciąć wszystko po końcowym `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Spróbuj także bezpośrednio użyć ogólnych parserów archiwów na PNG lub na wydobytym trailerze:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Odzyskiwanie w stylu Acropalypse z przyciętych/zanonimizowanych zrzutów ekranu

Bardzo praktyczny, niedawny trik forensic dla PNG polega na sprawdzeniu, czy edytor zrzutów ekranu **nadpisał** PNG bez wcześniejszego **ucięcia** starego pliku. W takich przypadkach bajty z **poprzedniego obrazu** mogą pozostać za `IEND`, a czasem dodatkowe dane `IDAT` da się częściowo odtworzyć.

Stało się to szeroko znane dzięki **aCropalypse** (Google Pixel Markup) oraz powiązanemu problemowi z **Windows Snipping Tool**. W praktyce, jeśli „przycięty” lub „zanonimizowany” PNG nadal zawiera stare końcowe dane, możesz odzyskać część oryginalnego zrzutu ekranu.

Praktyczny workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Znaki, które silnie uzasadniają głębszą analizę:

- `pngcheck` zgłasza **dodatkowe dane po `IEND`**
- znajdujesz **więcej niż jedno `IEND`**
- znajdujesz **dodatkowe chunki `IDAT`** po pozornym końcu obrazu
- zrzut ekranu pochodził z urządzenia/edytora, o którym wiadomo, że był dotknięty

Jeśli tak się stanie, przepuść plik przez **aCropalypse recovery tool** zanim uznasz redaction za wiarygodne.

## Chunk abuse that matters in practice

Najciekawsze chunki PNG do analiz zwykle nie są tymi oczywistymi obrazowymi, tylko chunki, które mogą przenosić **text**, **metadata** albo **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – metadane tekstowe i skompresowany text
- `eXIf` – dane EXIF wewnątrz PNG
- `iCCP` – osadzony profil ICC
- `PLTE` – dane palety w obrazach indeksowanych, ale też przydatne w scenariuszach payload-smuggling

Zrzuć je przy pomocy:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
For offensive payload persistence inside PNG chunks (for example **PLTE**, **IDAT**, or **tEXt** tricks that survive some PHP image transformations), check the more detailed upload-focused notes here:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

For checking integrity and locating the exact broken area, **pngcheck** remains one of the best first tools:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

If the file is damaged rather than intentionally malicious, **PCRT** can be useful in CTFs and lab work for fixing common issues such as bad headers, wrong IHDR values, CRC problems, or malformed chunk layouts.

If your goal is to **sanitize** a PNG that contains suspicious trailer data while preserving the visible image, ExifTool can explicitly remove the trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
W przypadku wrażliwych dowodów zawsze pracuj na **kopii** i zachowaj hashe oryginału przed próbą napraw.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
