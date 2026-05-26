# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** są bardzo częste w **CTFs**, **incident response** i **malware staging**, ponieważ są **lossless**, **chunk-based** i wiele narzędzi bez problemu je renderuje nawet wtedy, gdy zawierają **extra metadata**, **appended payloads** lub **partially corrupted chunks**.

Traktuj PNG jako **container**, a nie tylko jako obraz.

## Quick triage

Zacznij od sprawdzeń na poziomie kontenera, zanim przejdziesz do LSB stego. W przypadku workflow dla bit-plane/LSB sprawdź [dedicated image stego page](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Przydatne rzeczy do sprawdzenia:

- **Nieoczekiwane dodatkowe chunki pomocnicze** takie jak `tEXt`, `zTXt`, `iTXt`, `eXIf` lub `iCCP`
- **Błędy CRC** lub nieprawidłowe długości chunków
- **Dodatkowe dane po `IEND`**
- **Wiele znaczników `IEND`** lub możliwe do odzyskania fragmenty `IDAT` po formalnym końcu pliku
- Plik, który jest poprawnym PNG **i** jednocześnie wygląda jak ZIP/PDF/skrypt po wyodrębnieniu

Pamiętaj, że minimalna poprawna struktura to zwykle:

- `IHDR` (musi być pierwszy)
- `IDAT` (jeden lub więcej kolejnych chunków)
- `IEND` (musi być ostatni)

## Dodatkowe dane po `IEND`

Jednym z artefaktów PNG o najwyższej wartości sygnału są **dane dopisane po końcowym chunku `IEND`**. Wiele dekoderów je ignoruje, co czyni je przydatnymi do:

- **Prostego stego / ukrytego payloadu**
- **PNG polyglots**
- **Malware staging**
- **Odzyskiwania starszych danych obrazu** z wadliwych edytorów

Szybkie wykrywanie:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Jeśli chcesz wyciąć wszystko po ostatnim `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Spróbuj także bezpośrednio ogólnych parserów archiwów na PNG lub na wyciętym trailerze:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Odzyskiwanie przyciętych/zredagowanych zrzutów ekranu w stylu Acropalypse

Bardzo praktyczny, ostatnio odkryty trik forensic PNG to sprawdzanie, czy edytor zrzutów ekranu **nadpisał** PNG bez wcześniejszego **obcięcia** starego pliku. W takich przypadkach bajty z **poprzedniego obrazu** mogą pozostać za `IEND`, a czasem dodatkowe dane `IDAT` można częściowo zrekonstruować.

Stało się to szeroko znane dzięki **aCropalypse** (Google Pixel Markup) oraz powiązanemu problemowi **Windows Snipping Tool**. W praktyce, jeśli „przycięty” lub „zredagowany” PNG nadal zawiera stare końcowe dane, możesz być w stanie odzyskać część oryginalnego zrzutu ekranu.

Praktyczny workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Oznaki, które silnie uzasadniają głębszą analizę:

- `pngcheck` zgłasza **dodatkowe dane po `IEND`**
- Znajdujesz **więcej niż jedno `IEND`**
- Znajdujesz **dodatkowe chunki `IDAT`** po pozornym końcu obrazu
- Zrzut ekranu pochodzi z urządzenia/edytora, o którym wiadomo, że był dotknięty

Jeśli tak się stanie, przekaż plik do narzędzia **aCropalypse recovery tool** zanim uznasz redakcję za wiarygodną.

## Nadużycie chunków, które ma znaczenie w praktyce

Najciekawsze chunki PNG do analiz to zwykle nie oczywiste chunki obrazu, lecz chunki, które mogą przenosić **text**, **metadata** lub **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata i skompresowany text
- `eXIf` – dane EXIF wewnątrz PNG
- `iCCP` – osadzony profil ICC
- `PLTE` – dane palety w obrazach indeksowanych, ale też przydatne w scenariuszach payload-smuggling

Zrzuć je za pomocą:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
W przypadku persistence ofensywnego payloadu wewnątrz chunków PNG (na przykład **PLTE**, **IDAT** lub **tEXt** tricks, które przetrwają niektóre transformacje obrazów w PHP), sprawdź bardziej szczegółowe notatki dotyczące uploadu tutaj:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Naprawa uszkodzonego PNG

Do sprawdzania integralności i lokalizowania dokładnie uszkodzonego obszaru, **pngcheck** nadal pozostaje jednym z najlepszych pierwszych narzędzi:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Jeśli plik jest uszkodzony, a nie celowo złośliwy, **PCRT** może być przydatny w CTFs i pracy laboratoryjnej do naprawiania typowych problemów, takich jak złe nagłówki, nieprawidłowe wartości IHDR, problemy z CRC lub źle sformatowane układy chunków.

Jeśli twoim celem jest **sanitize** PNG zawierającego podejrzane dane trailer przy jednoczesnym zachowaniu widocznego obrazu, ExifTool może jawnie usunąć trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
W przypadku wrażliwych dowodów zawsze pracuj na **kopii** i zachowuj hashe oryginału przed próbą naprawy.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
