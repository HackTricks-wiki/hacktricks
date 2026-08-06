# Sztuczki z plikami PNG

{{#include ../../../banners/hacktricks-training.md}}

**Pliki PNG** są bardzo powszechne w **CTF-ach**, **incident response** i **malware staging**, ponieważ są **bezstratne**, **oparte na chunkach**, a wiele narzędzi bez problemu je renderuje, nawet gdy zawierają **dodatkowe metadane**, **dołączone payloady** lub **częściowo uszkodzone chunki**.

Traktuj PNG jako **kontener**, a nie tylko jako obraz.

## Szybki triage

Przed przejściem do steganografii LSB zacznij od sprawdzenia poziomu kontenera. Informacje o workflow bit-plane/LSB znajdziesz na [dedykowanej stronie dotyczącej stego obrazów](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Przydatne rzeczy, których warto szukać:

- **Nieoczekiwane ancillary chunks**, takie jak `tEXt`, `zTXt`, `iTXt`, `eXIf` lub `iCCP`
- **Błędy CRC** lub nieprawidłowe długości chunków
- **Dodatkowe dane za `IEND`**
- **Wiele markerów `IEND`** lub możliwe do odzyskania fragmenty `IDAT` po formalnym końcu pliku
- Plik, który jest poprawnym PNG, **a jednocześnie po wycięciu wygląda jak ZIP/PDF/skrypt**

Pamiętaj, że minimalna poprawna struktura zwykle wygląda tak:

- `IHDR` (musi być pierwszy)
- `IDAT` (jeden lub więcej kolejnych chunków)
- `IEND` (musi być ostatni)

## Dane końcowe za `IEND`

Jednym z artefaktów PNG o najwyższej wartości sygnałowej są **dane dołączone za końcowym chunkiem `IEND`**. Wiele dekoderów je ignoruje, dzięki czemu można je wykorzystać do:

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
Spróbuj także bezpośrednio użyć ogólnych parserów archiwów na pliku PNG lub wyciętym trailerze:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Odzyskiwanie w stylu Acropalypse z przyciętych/zaczernionych zrzutów ekranu

Bardzo praktyczną, niedawną sztuczką w analizie kryminalistycznej plików PNG jest sprawdzenie, czy edytor zrzutów ekranu **nadpisał** plik PNG bez wcześniejszego **obcięcia** starego pliku. W takich przypadkach bajty z **poprzedniego obrazu** mogą pozostać za `IEND`, a czasami można częściowo odtworzyć dodatkowe dane `IDAT`.

Stało się to szerzej znane dzięki **aCropalypse** (Google Pixel Markup) oraz powiązanemu problemowi w **Windows Snipping Tool**. W praktyce, jeśli „przycięty” lub „zaczerniony” plik PNG nadal zawiera stare dane na końcu, może być możliwe odzyskanie części oryginalnego zrzutu ekranu.<sup>[[1]](#references)</sup>

Praktyczny przebieg:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Oznaki, które zdecydowanie uzasadniają dokładniejszą analizę:

- `pngcheck` zgłasza **additional data after `IEND`**
- Znajdujesz **więcej niż jeden `IEND`**
- Znajdujesz **dodatkowe chunki `IDAT`** po pozornym końcu obrazu
- Zrzut ekranu pochodzi z urządzenia/edytora, o którym wiadomo, że był podatny na ten problem

Jeśli tak się dzieje, przekaż plik do **aCropalypse recovery tool** przed uznaniem, że redakcja jest wiarygodna.

## Nadużycia chunków, które mają znaczenie w praktyce

Najciekawsze chunki PNG na potrzeby dochodzeń to zwykle nie oczywiste chunki obrazu, lecz chunki, które mogą przenosić **tekst**, **metadata** lub **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – metadata tekstowe i skompresowany tekst
- `eXIf` – dane EXIF wewnątrz PNG
- `iCCP` – osadzony profil ICC
- `PLTE` – dane palety w obrazach indeksowanych, ale także przydatne w scenariuszach przemycania payloadu<sup>[[2]](#references)</sup>

Zrzuć je za pomocą:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
W przypadku persistence offensive payloadów wewnątrz chunków PNG (na przykład trików z **PLTE**, **IDAT** lub **tEXt**, które przetrwają niektóre transformacje obrazów PHP) sprawdź bardziej szczegółowe, ukierunkowane na upload notatki tutaj<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Naprawa uszkodzonych plików PNG

Do sprawdzania integralności i lokalizowania dokładnego uszkodzonego obszaru **pngcheck** pozostaje jednym z najlepszych narzędzi na początek:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Jeśli plik jest uszkodzony, a nie celowo złośliwy, **PCRT** może być przydatny w CTF-ach i pracy laboratoryjnej do naprawiania typowych problemów, takich jak nieprawidłowe nagłówki, błędne wartości IHDR, problemy z CRC lub niepoprawne układy chunków.

Jeśli Twoim celem jest **sanityzacja** pliku PNG zawierającego podejrzane dane na końcu przy zachowaniu widocznego obrazu, ExifTool może jawnie usunąć te dane:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
W przypadku wrażliwych dowodów zawsze pracuj na **kopii** i zachowaj hashe oryginału przed próbą naprawy.

## Referencje

- [1] [Exploiting aCropalypse: Recovering Truncated PNGs](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Persistent PHP payloads in PNGs: How to inject PHP code in an image – and keep it there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
