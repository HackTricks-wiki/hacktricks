# Homograph / Homoglyph Attacks w phishingu

## Overview

Atak homograph (znany również jako homoglyph) wykorzystuje fakt, że wiele **punktów kodowych Unicode z niełacińskich skryptów jest wizualnie identycznych lub bardzo podobnych do znaków ASCII**. Zastępując jeden lub więcej znaków łacińskich ich wizualnymi odpowiednikami, atakujący może utworzyć:

* Nazwy wyświetlane, tematy lub treści wiadomości, które wyglądają wiarygodnie dla ludzkiego oka, ale omijają detekcję opartą na słowach kluczowych.
* Domeny, subdomeny lub ścieżki URL, które przekonują ofiary, że odwiedzają zaufaną stronę.<sup>[[1]](#references)</sup>

Ponieważ każdy glif jest wewnętrznie identyfikowany przez swój **punkt kodowy Unicode**, pojedynczy podstawiony znak wystarczy, aby pokonać naiwne porównania ciągów znaków (np. `"Παypal.com"` vs. `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Typowy przebieg phishingu

1. **Utworzenie treści wiadomości** – Zastąp określone litery łacińskie w podszywającej się marce / słowie kluczowym wizualnie nierozróżnialnymi znakami z innego skryptu (greckiego, cyrylicy, ormiańskiego, Cherokee itp.).
2. **Rejestracja infrastruktury pomocniczej** – Opcjonalnie zarejestruj domenę homoglyph i uzyskaj certyfikat TLS (większość CA nie sprawdza podobieństwa wizualnego).
3. **Wysłanie wiadomości e-mail / SMS** – Wiadomość zawiera znaki homoglyph w jednym lub kilku z następujących miejsc:
* Wyświetlana nazwa nadawcy (np. `Ηеlрdеѕk`)
* Temat wiadomości (`Urgеnt Аctіon Rеquіrеd`)
* Tekst hiperłącza lub w pełni kwalifikowana nazwa domeny
4. **Łańcuch przekierowań** – Ofiara jest przekierowywana przez pozornie nieszkodliwe strony internetowe lub usługi skracania URL, zanim trafi na złośliwy host, który wykrada dane uwierzytelniające / dostarcza malware.<sup>[[1]](#references)</sup>

## Często nadużywane zakresy Unicode

Poniższe przykłady przedstawiają bloki Unicode zawierające znaki często używane do tworzenia podobieństw między skryptami.<sup>[[2]](#references)[[3]](#references)</sup>

| Skrypt | Zakres | Przykładowy glif | Wygląda jak |
|--------|-------|---------------|------------|
| Grecki  | U+0370-03FF | `Η` (U+0397) | Łacińskie `H` |
| Grecki  | U+0370-03FF | `ρ` (U+03C1) | Łacińskie `p` |
| Cyrylica | U+0400-04FF | `а` (U+0430) | Łacińskie `a` |
| Cyrylica | U+0400-04FF | `е` (U+0435) | Łacińskie `e` |
| Ormiański | U+0530-058F | `օ` (U+0585) | Łacińskie `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Łacińskie `T` |

> Wskazówka: Użyj tablic kodów Unicode, aby sprawdzić bloki i punkty kodowe.

## Techniki detekcji

### 1. Inspekcja mieszanych skryptów

Phishingowe wiadomości e-mail kierowane do organizacji anglojęzycznej rzadko powinny zawierać znaki z wielu skryptów. Prostą, ale skuteczną heurystyką jest:

1. Iterowanie po każdym znaku analizowanego ciągu.
2. Zmapowanie punktu kodowego na nazwę skryptu lub blok Unicode.
3. Wygenerowanie alertu, jeśli obecny jest więcej niż jeden skrypt **lub** jeśli skrypty niełacińskie pojawiają się tam, gdzie nie powinny (wyświetlana nazwa, domena, temat, URL itp.).<sup>[[3]](#references)</sup>

Python proof-of-concept:
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Normalizacja Punycode (domeny)

Umiędzynarodowione nazwy domen (IDN) mają formę Unicode oraz zgodną z ASCII formę **Punycode**, poprzedzoną prefiksem `xn--`. Przed dodaniem nazw hostów do listy dozwolonych lub ich porównaniem konwertuj je do formatu IDNA/Punycode, zachowując formę Unicode do wyświetlania.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph Dictionaries / Algorithms

Narzędzia takie jak **dnstwist** (`--fuzzers homoglyph`) lub **urlcrazy` mogą wyliczać wizualnie podobne permutacje domen i są przydatne do proaktywnego usuwania oraz monitorowania.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* Wymuszaj rygorystyczne zasady DMARC/DKIM/SPF – zapobiegaj spoofingowi z nieautoryzowanych domen.
* Zaimplementuj powyższą logikę wykrywania w **Secure Email Gateways** oraz playbookach **SIEM/XSOAR**.
* Oznaczaj lub poddawaj kwarantannie wiadomości, w których domena z nazwy wyświetlanej ≠ domena nadawcy.
* Edukuj użytkowników: wklejaj podejrzany tekst do inspectora Unicode, sprawdzaj linki przez najechanie kursorem i nigdy nie ufaj skracaczom URL.

## Real-World Examples

* Nazwa wyświetlana: `Сonfidеntiаl Ꭲiꮯkеt` (cyrylickie `С`, `е`, `а`; Cherokee `Ꭲ`; łacińska mała kapitalika `ꮯ`).
* Łańcuch domen: `bestseoservices.com` ➜ katalog municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ fałszywa strona logowania Microsoft pod adresem `mlcorsftpsswddprotcct.approaches.it.com`, chroniona przez niestandardowy CAPTCHA OTP.
* Podszywanie się pod Spotify: nadawca `Sρօtifս` z linkiem ukrytym za `redirects.ca`.

Przykłady te pochodzą z badań Unit 42 (lipiec 2025) i pokazują, jak nadużycie homografów jest łączone z przekierowaniami URL oraz omijaniem CAPTCHA w celu obejścia automatycznej analizy.<sup>[[1]](#references)</sup>

## References

- [1] [Iluzja homografu: nie wszystko jest tym, czym się wydaje](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Tabele kodów znaków Unicode](https://www.unicode.org/charts/)
- [3] [Standard techniczny Unicode nr 39: mechanizmy bezpieczeństwa Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – silnik permutacji domen](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – generator literówek i wariantów domen](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Umiędzynarodowione nazwy domen dla aplikacji (IDNA): definicje i struktura dokumentu](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
