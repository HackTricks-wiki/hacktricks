# Sztuczki PNG

**Pliki PNG** są bardzo powszechne w **CTF-ach**, **analizie incydentów** i **malware staging**, ponieważ są **bezstratne**, **oparte na chunkach**, a wiele narzędzi bez problemu je renderuje, nawet gdy zawierają **dodatkowe metadane**, **dołączone payloady** lub **częściowo uszkodzone chunki**.

Traktuj PNG jako **kontener**, a nie tylko obraz.

## Szybki triage

Przed przejściem do stego LSB rozpocznij od kontroli na poziomie kontenera. W przypadku workflow bit-plane/LSB sprawdź [dedykowaną stronę dotyczącą image stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Przydatne rzeczy, których warto szukać:

- **Nieoczekiwane dodatkowe chunki**, takie jak `tEXt`, `zTXt`, `iTXt`, `eXIf` lub `iCCP`
- **Błędy CRC** lub nieprawidłowe długości chunków
- **Dodatkowe dane po `IEND`**
- **Wiele znaczników `IEND`** lub możliwe do odzyskania fragmenty `IDAT` po formalnym końcu pliku
- Plik, który jest poprawnym PNG, **a jednocześnie po wycięciu wygląda jak ZIP/PDF/skrypt**

Pamiętaj, że minimalna poprawna struktura zwykle wygląda tak:

- `IHDR` (musi być pierwszy)
- `IDAT` (jeden lub więcej kolejnych chunków)
- `IEND` (musi być ostatni)

## Dane po `IEND`

Jednym z artefaktów PNG o najwyższej wartości sygnałowej są **dane dołączone po końcowym chunku `IEND`**. Wiele dekoderów je ignoruje, dzięki czemu można je wykorzystać do:

- **Prostego stego / ukrytych payloadów**
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
Jeśli chcesz wyodrębnić wszystko po końcowym `IEND`:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Spróbuj także bezpośrednio użyć ogólnych parserów archiwów na pliku PNG lub wyodrębnionym końcowym fragmencie:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Odzyskiwanie w stylu Acropalypse przyciętych/zanonimizowanych zrzutów ekranu

Bardzo praktyczną, stosunkowo nową sztuczką w analizie forensycznej PNG jest sprawdzenie, czy edytor zrzutów ekranu **nadpisał** plik PNG bez wcześniejszego **skrócenia** starego pliku. W takich przypadkach bajty z **poprzedniego obrazu** mogą pozostać za `IEND`, a czasami można częściowo odtworzyć dodatkowe dane `IDAT`.

Stało się to szerzej znane dzięki **aCropalypse** (Google Pixel Markup) oraz powiązanemu problemowi w **Windows Snipping Tool**.<sup>[[3]](#references)</sup> W praktyce, jeśli „przycięty” lub „zanonimizowany” plik PNG nadal zawiera stare dane na końcu, może być możliwe odzyskanie części oryginalnego zrzutu ekranu.<sup>[[1]](#references)</sup>

Praktyczny przebieg:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Oznaki, które zdecydowanie uzasadniają dokładniejszą analizę:

- `pngcheck` zgłasza **dodatkowe dane po `IEND`**
- Znajdujesz **więcej niż jeden `IEND`**
- Znajdujesz **dodatkowe chunki `IDAT`** po pozornym końcu obrazu
- Zrzut ekranu pochodzi z urządzenia/edytora, o którym wiadomo, że był podatny na ten problem

Jeśli tak się stanie, przekaż plik do **aCropalypse recovery tool** przed uznaniem redakcji za wiarygodną.

## Nadużycia chunków istotne w praktyce

Najciekawsze chunki PNG w kontekście dochodzeń to zwykle nie oczywiste chunki obrazu, lecz chunki, które mogą przenosić **tekst**, **metadata** lub **bajty payloadu**:

- `tEXt` / `zTXt` / `iTXt` – metadata tekstowe i skompresowany tekst
- `eXIf` – dane EXIF wewnątrz PNG
- `iCCP` – osadzony profil ICC
- `PLTE` – dane palety w obrazach indeksowanych, ale także przydatne w scenariuszach przemycania payloadu.<sup>[[2]](#references)</sup>

Zrzuć je za pomocą:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
W przypadku persistence offensive payload wewnątrz chunków PNG (na przykład trików z **PLTE**, **IDAT** lub **tEXt**, które przetrwają niektóre transformacje obrazów PHP) sprawdź bardziej szczegółowe notatki dotyczące uploadu tutaj:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Do sprawdzania integralności i lokalizowania dokładnego uszkodzonego obszaru **pngcheck** pozostaje jednym z najlepszych narzędzi pierwszego wyboru:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Jeśli plik jest uszkodzony, a nie celowo złośliwy, **PCRT** może być przydatny w CTF-ach i pracy laboratoryjnej do naprawiania typowych problemów, takich jak nieprawidłowe nagłówki, błędne wartości IHDR, problemy z CRC lub niepoprawne układy chunków.

Jeśli celem jest **sanityzacja** pliku PNG zawierającego podejrzane dane trailer przy zachowaniu widocznego obrazu, ExifTool może jawnie usunąć trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
W przypadku wrażliwych danych dowodowych zawsze pracuj na **kopii** i zachowaj hashes oryginału przed próbą naprawy.

## References

- [1] [Exploiting aCropalypse: Odzyskiwanie obciętych plików PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: Jak wstrzyknąć kod PHP do obrazu i zachować go w pliku](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
