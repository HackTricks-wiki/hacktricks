# Homograph / Homoglyph Attacks w Phishingu

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

Atak homograph (znany również jako homoglyph) wykorzystuje fakt, że wiele **punktów kodowych Unicode z alfabetów innych niż łaciński jest wizualnie identycznych lub bardzo podobnych do znaków ASCII**. Zastępując jeden lub więcej znaków łacińskich ich odpowiednikami przypominającymi oryginały, atakujący może przygotować:

* Nazwy wyświetlane, tematy lub treści wiadomości, które wyglądają wiarygodnie dla człowieka, ale omijają detekcję opartą na słowach kluczowych.
* Domeny, subdomeny lub ścieżki URL, które sprawiają, że ofiary sądzą, iż odwiedzają zaufaną witrynę.<sup>[[1]](#references)</sup>

Ponieważ każdy glif jest wewnętrznie identyfikowany przez swój **punkt kodowy Unicode**, pojedynczy podmieniony znak wystarczy, aby pokonać naiwne porównania ciągów znaków (np. `"Παypal.com"` vs. `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Typowy przebieg Phishingu

1. **Przygotowanie treści wiadomości** – Zastąp konkretne litery łacińskie w podszywającej się marce / słowie kluczowym wizualnie nieodróżnialnymi znakami z innego alfabetu (greckiego, cyrylicy, ormiańskiego, czerokeskiego itd.).
2. **Rejestracja infrastruktury pomocniczej** – Opcjonalnie zarejestruj domenę homoglyph i uzyskaj certyfikat TLS (większość CA nie sprawdza podobieństwa wizualnego).
3. **Wysłanie wiadomości e-mail / SMS** – Wiadomość zawiera znaki homoglyph w co najmniej jednym z następujących miejsc:
* Nazwa nadawcy wyświetlana odbiorcy (np. `Ηеlрdеѕk`)
* Temat wiadomości (`Urgеnt Аctіon Rеquіrеd`)
* Tekst hiperłącza lub w pełni kwalifikowana nazwa domeny
4. **Łańcuch przekierowań** – Ofiara jest przekierowywana przez pozornie nieszkodliwe witryny lub skracacze URL, zanim trafi na złośliwy host, który wykrada dane uwierzytelniające / dostarcza malware.<sup>[[1]](#references)</sup>

## Często nadużywane zakresy Unicode

Poniższe przykłady przedstawiają bloki Unicode zawierające znaki często wykorzystywane do tworzenia podobieństw między alfabetami.<sup>[[2]](#references)[[3]](#references)</sup>

| Skrypt | Zakres | Przykładowy glif | Wygląda jak |
|--------|-------|---------------|------------|
| Grecki  | U+0370-03FF | `Η` (U+0397) | Łacińskie `H` |
| Grecki  | U+0370-03FF | `ρ` (U+03C1) | Łacińskie `p` |
| Cyrylica | U+0400-04FF | `а` (U+0430) | Łacińskie `a` |
| Cyrylica | U+0400-04FF | `е` (U+0435) | Łacińskie `e` |
| Ormiański | U+0530-058F | `օ` (U+0585) | Łacińskie `o` |
| Czerokeski | U+13A0-13FF | `Ꭲ` (U+13A2) | Łacińskie `T` |

> Wskazówka: Użyj tabel kodów Unicode, aby sprawdzić bloki i punkty kodowe.

## Techniki detekcji

### 1. Inspekcja mieszanych alfabetów

Wiadomości phishingowe skierowane do organizacji anglojęzycznej rzadko powinny mieszać znaki z wielu alfabetów. Prosta, ale skuteczna heurystyka polega na:

1. Iterowaniu po każdym znaku analizowanego ciągu.
2. Przypisaniu punktu kodowego do nazwy alfabetu lub bloku Unicode.
3. Wygenerowaniu alertu, jeśli obecny jest więcej niż jeden alfabet **lub** jeśli znaki z alfabetów innych niż łaciński pojawiają się w miejscach, w których nie są oczekiwane (nazwa wyświetlana odbiorcy, domena, temat, URL itd.).<sup>[[3]](#references)</sup>

Proof-of-concept w Pythonie:
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

Umiędzynarodowione nazwy domen (IDN) mają formę Unicode oraz zgodną z ASCII formę **Punycode** z prefiksem `xn--`. Konwertuj hostnames do formatu IDNA/Punycode przed umieszczeniem ich na allow-liście lub porównaniem, zachowując formę Unicode do wyświetlania.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Słowniki / algorytmy Homoglyph

Narzędzia takie jak **dnstwist** (`--fuzzers homoglyph`) lub **urlcrazy** mogą wyliczać wizualnie podobne permutacje domen i są przydatne do proaktywnego usuwania / monitorowania.<sup>[[4]](#references)[[5]](#references)</sup>

## Zapobieganie i ograniczanie skutków

* Wymuś ścisłe zasady DMARC/DKIM/SPF – zapobiegaj spoofingowi z nieautoryzowanych domen.
* Zaimplementuj powyższą logikę wykrywania w **Secure Email Gateways** oraz playbookach **SIEM/XSOAR**.
* Oznaczaj lub poddawaj kwarantannie wiadomości, w których domena w nazwie wyświetlanej ≠ domena nadawcy.
* Edukuj użytkowników: wklejaj podejrzany tekst do inspektora Unicode, sprawdzaj linki po najechaniu kursorem i nigdy nie ufaj skracaczom URL.

## Przykłady z rzeczywistego świata

* Nazwa wyświetlana: `Сonfidеntiаl Ꭲiꮯkеt` (cyrylickie `С`, `е`, `а`; czirokeski `Ꭲ`; łacińska mała kapitalika `ꮯ`).
* Łańcuch domen: `bestseoservices.com` ➜ katalog `/templates` należący do instytucji miejskiej ➜ `kig.skyvaulyt.ru` ➜ fałszywa strona logowania Microsoft pod adresem `mlcorsftpsswddprotcct.approaches.it.com`, chroniona przez niestandardowy CAPTCHA z OTP.
* Podszywanie się pod Spotify: nadawca `Sρօtifս` z linkiem ukrytym za `redirects.ca`.

Próbki te pochodzą z badań Unit 42 (lipiec 2025) i pokazują, jak nadużycie homografów jest łączone z przekierowaniami URL oraz obchodzeniem CAPTCHA w celu ominięcia automatycznej analizy.<sup>[[1]](#references)</sup>

## References

- [1] [Iluzja homografów: nie wszystko jest takie, jak się wydaje](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Tabele kodów znaków Unicode](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: mechanizmy bezpieczeństwa Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – silnik permutacji domen](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – generator literówek i wariantów domen](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: umiędzynarodowione nazwy domen dla aplikacji (IDNA): definicje i struktura dokumentu](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
