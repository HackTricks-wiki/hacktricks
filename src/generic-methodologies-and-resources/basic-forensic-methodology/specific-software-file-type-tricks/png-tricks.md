# Sztuczki PNG

{{#include ../../../banners/hacktricks-training.md}}

**Pliki PNG** są bardzo powszechne w **CTF-ach**, **incident response** i **malware staging**, ponieważ są **bezstratne**, **oparte na chunkach**, a wiele narzędzi bez problemu je renderuje, nawet gdy zawierają **dodatkowe metadane**, **dołączone payloady** lub **częściowo uszkodzone chunki**.

Traktuj PNG jako **kontener**, a nie tylko jako obraz.

## Szybki triage

Zacznij od kontroli na poziomie kontenera, zanim przejdziesz do LSB stego. W przypadku workflow bit-plane/LSB sprawdź [dedykowaną stronę dotyczącą image stego](../../../stego/images/README.md).
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
- Plik, który jest prawidłowym PNG, **a jednocześnie po wyodrębnieniu wygląda jak ZIP/PDF/skrypt**

Pamiętaj, że minimalna prawidłowa struktura zwykle wygląda tak:

- `IHDR` (musi być pierwszy)
- `IDAT` (jeden lub więcej kolejnych chunków)
- `IEND` (musi być ostatni)

## Dane końcowe po `IEND`

Jednym z artefaktów PNG o najwyższej wartości sygnałowej są **dane dołączone po końcowym chunku `IEND`**. Wiele dekoderów je ignoruje, co czyni je przydatnymi do:

- **Prostego stego / ukrytych payloadów**
- **Polyglotów PNG**
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
Spróbuj również bezpośrednio zastosować ogólne parsery archiwów do pliku PNG lub wyodrębnionego końcowego fragmentu:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Odzyskiwanie w stylu Acropalypse przyciętych/ocenzurowanych screenshotów

Bardzo praktycznym, niedawnym trickiem forensycznym dotyczącym PNG jest sprawdzenie, czy edytor screenshotów **nadpisał** plik PNG bez wcześniejszego **skrócenia** starego pliku. W takich przypadkach bajty z **poprzedniego obrazu** mogą pozostać za `IEND`, a czasami można częściowo odtworzyć dodatkowe dane `IDAT`.

Stało się to powszechnie znane dzięki **aCropalypse** (Google Pixel Markup) oraz powiązanemu problemowi **Windows Snipping Tool**.<sup>[[3]](#references)</sup> W praktyce, jeśli „przycięty” lub „ocenzurowany” PNG nadal zawiera stare dane na końcu pliku, może być możliwe odzyskanie części oryginalnego screenshota.<sup>[[1]](#references)</sup>

Praktyczny workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Oznaki, które wyraźnie uzasadniają dokładniejszą analizę:

- `pngcheck` zgłasza **dodatkowe dane po `IEND`**
- Znajdujesz **więcej niż jeden `IEND`**
- Znajdujesz **dodatkowe fragmenty `IDAT`** po pozornym końcu obrazu
- Zrzut ekranu pochodzi z urządzenia/edytora, o którym wiadomo, że dotyczył go ten problem

Jeśli tak się stanie, przekaż plik do **aCropalypse recovery tool** przed uznaniem zakrycia za wiarygodne.

## Nadużycia fragmentów istotne w praktyce

Najciekawsze fragmenty PNG do celów analizy to zazwyczaj nie oczywiste fragmenty obrazu, lecz te, które mogą zawierać **tekst**, **metadane** lub **bajty payloadu**:

- `tEXt` / `zTXt` / `iTXt` – metadane tekstowe i skompresowany tekst
- `eXIf` – dane EXIF wewnątrz PNG
- `iCCP` – osadzony profil ICC
- `PLTE` – dane palety w obrazach indeksowanych, ale także przydatne w scenariuszach przemycania payloadu.<sup>[[2]](#references)</sup>

Wypisz je za pomocą:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
W przypadku utrzymywania persistence dla offensive payloads wewnątrz chunków PNG (na przykład trików **PLTE**, **IDAT** lub **tEXt**, które przetrwają niektóre transformacje obrazów PHP) sprawdź bardziej szczegółowe notatki dotyczące uploadów tutaj:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Naprawa uszkodzonych plików PNG

Do sprawdzania integralności i lokalizowania dokładnego uszkodzonego obszaru **pngcheck** pozostaje jednym z najlepszych narzędzi pierwszego wyboru:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Jeśli plik jest uszkodzony, a nie celowo złośliwy, **PCRT** może być przydatny w CTF-ach i pracy laboratoryjnej do naprawiania typowych problemów, takich jak nieprawidłowe nagłówki, błędne wartości IHDR, problemy z CRC lub nieprawidłowe układy chunków.

Jeśli Twoim celem jest **oczyszczenie** pliku PNG zawierającego podejrzane dane końcowe przy zachowaniu widocznego obrazu, ExifTool może jawnie usunąć dane końcowe:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
W przypadku wrażliwych dowodów zawsze pracuj na **kopii** i zachowaj sumy kontrolne oryginału przed podjęciem prób naprawy.

## References

- [1] [Wykorzystanie aCropalypse: odzyskiwanie obciętych plików PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Trwałe payloady PHP w plikach PNG: jak wstrzyknąć kod PHP do obrazu i zachować go w nim](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
