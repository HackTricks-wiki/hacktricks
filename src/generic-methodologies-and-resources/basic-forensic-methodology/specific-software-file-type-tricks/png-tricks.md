# Sztuczki PNG

{{#include ../../../banners/hacktricks-training.md}}

**Pliki PNG** są bardzo często używane w **CTF-ach**, **reagowaniu na incydenty** i **przygotowywaniu malware do wdrożenia**, ponieważ są **bezstratne**, **oparte na chunkach**, a wiele narzędzi bez problemu je wyświetla, nawet gdy zawierają **dodatkowe metadane**, **dołączone payloady** lub **częściowo uszkodzone chunki**.

Traktuj PNG jako **kontener**, a nie tylko obraz.

## Szybka analiza wstępna

Zacznij od sprawdzenia kontenera, zanim przejdziesz do steganografii LSB. Informacje o przepływie pracy związanym z bit-plane/LSB znajdziesz na [dedykowanej stronie o steganografii obrazów](../../../stego/images/).

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
- **Dodatkowe dane za `IEND`**
- **Wiele znaczników `IEND`** lub możliwe do odzyskania fragmenty `IDAT` po formalnym końcu pliku
- Plik, który jest prawidłowym PNG, **a jednocześnie** po wyodrębnieniu wygląda jak ZIP/PDF/skrypt

Pamiętaj, że minimalna prawidłowa struktura zwykle obejmuje:

- `IHDR` (musi być pierwszy)
- `IDAT` (jeden lub więcej kolejnych chunków)
- `IEND` (musi być ostatni)

## Dane końcowe za `IEND`

Jednym z najbardziej charakterystycznych artefaktów PNG są **dane dołączone za ostatnim chunkiem `IEND`**. Wiele dekoderów je ignoruje, dzięki czemu mogą służyć do:

- **Prostego stego / ukrytych payloadów**
- **Polyglotów PNG**
- **Przygotowywania malware**
- **Odzyskiwania starszych danych obrazu** z wadliwie działających edytorów

Szybkie wykrywanie:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Wyszukiwanie bajtów `IEND` to tylko wskazówka: te same bajty mogą występować w danych chunku lub w sfałszowanym trailerze. Aby wyodrębnić dane niezawodnie, przechodź przez chunki z prefiksem długości, zaczynając od sygnatury PNG, i zatrzymaj się przy pierwszym strukturalnym `IEND`; [poniższy parser chunków](#extract-ancillary-chunk-payloads) zapisuje również trailer.<sup>[[6]](#references)</sup>

Wypróbuj też bezpośrednio ogólne parsery archiwów na pliku PNG lub wyodrębnionym trailerze:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Odzyskiwanie przyciętych/zredagowanych zrzutów ekranu w stylu Acropalypse

Bardzo praktyczną, stosunkowo nową sztuczką w analizie kryminalistycznej plików PNG jest sprawdzenie, czy edytor zrzutów ekranu **nadpisał** plik PNG, nie **obcinając** wcześniej jego starej zawartości. W takich przypadkach bajty z **poprzedniego obrazu** mogą pozostać za `IEND`, a czasami można częściowo odtworzyć dodatkowe dane `IDAT`.

Problem ten stał się powszechnie znany dzięki **aCropalypse** (Google Pixel Markup) oraz powiązanemu problemowi w **Narzędziu Wycinanie systemu Windows**.<sup>[[3]](#references)</sup> W praktyce, jeśli „przycięty” lub „zredagowany” plik PNG nadal zawiera stare dane na końcu, można odzyskać część oryginalnego zrzutu ekranu.<sup>[[1]](#references)</sup>

Praktyczny sposób postępowania:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Oznaki, które mocno uzasadniają dokładniejszą analizę:

- `pngcheck` zgłasza **dodatkowe dane po `IEND`**
- Znajdujesz **więcej niż jeden `IEND`**
- Znajdujesz **dodatkowe chunki `IDAT`** po widocznym końcu obrazu
- Zrzut ekranu pochodzi z urządzenia lub edytora, o którym wiadomo, że był podatny na tę podatność

W takim przypadku użyj narzędzia do odzyskiwania aCropalypse przed uznaniem, że zamazanie jest wiarygodne.

## Nadużywanie chunków, które ma znaczenie w praktyce

Najciekawsze chunki PNG na potrzeby analiz zwykle nie są oczywistymi chunkami obrazu, lecz tymi, które mogą zawierać **tekst**, **metadane** lub **bajty payloadu**:

- `tEXt` / `zTXt` / `iTXt` – metadane tekstowe i skompresowany tekst
- `eXIf` – dane EXIF w pliku PNG
- `iCCP` – osadzony profil ICC
- `PLTE` – dane palety w obrazach indeksowanych, ale także przydatne w scenariuszach przemycania payloadu.<sup>[[2]](#references)</sup>

Zrzuć je za pomocą:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

W przypadku utrwalania ofensywnych payloadów w chunkach PNG (na przykład sztuczek z **PLTE**, **IDAT** lub **tEXt**, które przetrwają niektóre transformacje obrazów w PHP) sprawdź bardziej szczegółowe notatki dotyczące uploadu tutaj:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Wyodrębnianie payloadów z chunków ancillary

Atakujący może umieścić dowolne bajty w **nieznanym chunku ancillary przed `IEND`**. Zwykłe dekodery PNG mogą zignorować nieznany chunk ancillary, a skrypt pobierający obraz jako bajty może odczytać payload i go użyć; samo otwarcie pliku PNG go nie uruchamia.<sup>[[4]](#references)[[6]](#references)</sup> Oryginalne badanie pokazało skompresowany i zaszyfrowany niestandardowy chunk.<sup>[[4]](#references)</sup> W późniejszym przykładzie dla przeglądarki wyodrębnione bajty posłużyły do dostarczenia HTML-a lub pliku do pobrania.<sup>[[5]](#references)</sup>

Mała litera w nazwie pierwszego chunku oznacza *ancillary*; mała litera w drugim znaku oznacza *private*. Na przykład `paMP` jest prywatny, podczas gdy `pAMP` korzysta z publicznej przestrzeni nazw, mimo że ten drugi typ wymyślono na potrzeby demonstracji.<sup>[[4]](#references)[[6]](#references)</sup> Chunk ma postać `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`; CRC obejmuje typ i dane. Analizuj tę strukturę zamiast wyszukiwać nazwę typu w skompresowanych danych `IDAT`. Poniższy parser sprawdza granice i sumy CRC, eksportuje payloady z chunków ancillary jako surowe bajty oraz zapisuje wszystkie bajty występujące po strukturalnym `IEND` do pliku `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Wyodrębnianie chunków ancillary i końcowych danych PNG</summary>

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

Sprawdź wyodrębnione bajty za pomocą `file`, `strings` lub `binwalk`; dekompresuj tylko wtedy, gdy nośnik jest rzeczywiście skompresowany.<sup>[[4]](#references)</sup> Ponowne kodowanie może usunąć nośnik, dlatego przed poleganiem na nim porównaj bajty przesłane z pobranymi.<sup>[[2]](#references)[[6]](#references)</sup>

## Naprawa uszkodzonych plików PNG

Do sprawdzania integralności i lokalizowania dokładnego uszkodzonego obszaru **pngcheck** pozostaje jednym z najlepszych narzędzi pierwszego wyboru:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Jeśli plik jest uszkodzony, a nie celowo złośliwy, **PCRT** może być przydatny w CTF-ach i pracy laboratoryjnej do naprawiania typowych problemów, takich jak nieprawidłowe nagłówki, błędne wartości IHDR, problemy z CRC lub niepoprawny układ chunków.

Jeśli chcesz **oczyścić** plik PNG zawierający podejrzane dane końcowe, zachowując widoczny obraz, ExifTool może jawnie usunąć te dane:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

W przypadku wrażliwych dowodów zawsze pracuj na **kopii** i zachowaj hashe oryginału przed próbą naprawy.



## References

- [1] [Wykorzystanie aCropalypse: odzyskiwanie obciętych plików PNG](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Trwałe payloady PHP w plikach PNG: jak wstrzyknąć kod PHP do obrazu i go tam zachować](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Dodatkowe chunki to idealne miejsce do przechowywania poufnych informacji](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Wykorzystanie prawidłowych dodatkowych chunków do przemycania danych do punktu końcowego](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Specyfikacja Portable Network Graphics (PNG) (wydanie trzecie)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
