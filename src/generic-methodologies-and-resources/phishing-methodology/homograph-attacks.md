# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Atak homograph (znany również jako homoglyph) wykorzystuje fakt, że wiele **punktów kodowych Unicode z alfabetów innych niż łaciński wygląda identycznie lub bardzo podobnie do znaków ASCII**. Zastępując jeden lub więcej znaków łacińskich ich odpowiednikami o podobnym wyglądzie, attacker może utworzyć:

* Nazwy wyświetlane, tematy lub treści wiadomości, które dla ludzkiego oka wyglądają wiarygodnie, ale omijają detekcję opartą na słowach kluczowych.
* Domeny, subdomeny lub ścieżki URL, które sprawiają, że ofiary sądzą, iż odwiedzają zaufaną stronę.

Ponieważ każdy glif jest wewnętrznie identyfikowany przez swój **punkt kodowy Unicode**, pojedynczy podmieniony znak wystarczy, aby pokonać naiwne porównania ciągów znaków (np. `"Παypal.com"` vs. `"Paypal.com"`).

## Typowy przebieg Phishingu

1. **Utworzenie treści wiadomości** – Zastąpienie określonych liter łacińskich w podszywającej się marce / słowie kluczowym znakami z innego alfabetu, które są wizualnie nie do odróżnienia (greckiego, cyrylicy, ormiańskiego, czirokeskiego itd.).
2. **Rejestracja infrastruktury pomocniczej** – Opcjonalna rejestracja domeny homoglyph oraz uzyskanie certyfikatu TLS (większość CA nie przeprowadza kontroli podobieństwa wizualnego).
3. **Wysłanie emaila / SMS-a** – Wiadomość zawiera homoglyphs w jednym lub kilku z następujących miejsc:
* Nazwa wyświetlana nadawcy (np. `Ηеlрdеѕk`)
* Temat wiadomości (`Urgеnt Аctіon Rеquіrеd`)
* Tekst hyperlinku lub w pełni kwalifikowana nazwa domeny
4. **Łańcuch przekierowań** – Ofiara jest przekierowywana przez pozornie nieszkodliwe strony internetowe lub skracacze URL, zanim trafi na złośliwy host, który wykrada dane uwierzytelniające / dostarcza malware.

## Często nadużywane zakresy Unicode

| Skrypt | Zakres | Przykładowy glif | Wygląda jak |
|--------|-------|---------------|------------|
| Grecki  | U+0370-03FF | `Η` (U+0397) | Łacińskie `H` |
| Grecki  | U+0370-03FF | `ρ` (U+03C1) | Łacińskie `p` |
| Cyrylica | U+0400-04FF | `а` (U+0430) | Łacińskie `a` |
| Cyrylica | U+0400-04FF | `е` (U+0435) | Łacińskie `e` |
| Ormiański | U+0530-058F | `օ` (U+0585) | Łacińskie `o` |
| Czirokeski | U+13A0-13FF | `Ꭲ` (U+13A2) | Łacińskie `T` |

> Wskazówka: Pełne tablice Unicode są dostępne pod adresem [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Techniki wykrywania

### 1. Inspekcja mieszanych skryptów

Email phishingowy skierowany do organizacji anglojęzycznej rzadko powinien zawierać znaki z wielu skryptów. Prostą, ale skuteczną heurystyką jest:

1. Iterowanie po każdym znaku sprawdzanego ciągu.
2. Przypisanie punktu kodowego do jego bloku Unicode.
3. Wygenerowanie alertu, jeśli obecny jest więcej niż jeden skrypt **lub** jeśli skrypty inne niż łaciński pojawiają się w miejscach, w których nie są oczekiwane (nazwa wyświetlana, domena, temat, URL itd.).

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

Internationalised Domain Names (IDN) są kodowane za pomocą **punycode** (`xn--`). Konwersja każdej nazwy hosta do punycode, a następnie z powrotem do Unicode, umożliwia dopasowanie do whitelisty lub przeprowadzanie testów podobieństwa (np. odległości Levenshteina) **po** normalizacji ciągu.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Słowniki / algorytmy Homoglyph

Narzędzia takie jak **dnstwist** (`--homoglyph`) lub **urlcrazy** mogą wyliczać wizualnie podobne permutacje domen i są przydatne do proaktywnego zgłaszania do usunięcia / monitorowania.<sup>[[3]](#references)</sup>

## Zapobieganie i łagodzenie skutków

* Wymuś restrykcyjne zasady DMARC/DKIM/SPF – zapobiegaj spoofingowi z nieautoryzowanych domen.
* Zaimplementuj powyższą logikę wykrywania w **Secure Email Gateways** oraz playbookach **SIEM/XSOAR**.
* Oznaczaj lub poddawaj kwarantannie wiadomości, w których domena nazwy wyświetlanej ≠ domena nadawcy.
* Edukuj użytkowników: wklejaj podejrzany tekst do inspektora Unicode, najeżdżaj kursorem na linki i nigdy nie ufaj skracaczom URL.

## Przykłady z rzeczywistego świata

* Nazwa wyświetlana: `Сonfidеntiаl Ꭲiꮯkеt` (cyrylica `С`, `е`, `а`; Cherokee `Ꭲ`; łacińska mała kapitalika `ꮯ`).
* Łańcuch domen: `bestseoservices.com` ➜ katalog `/templates` należący do gminy ➜ `kig.skyvaulyt.ru` ➜ fałszywa strona logowania Microsoft pod adresem `mlcorsftpsswddprotcct.approaches.it.com`, zabezpieczona niestandardowym CAPTCHA OTP.
* Podszywanie się pod Spotify: nadawca `Sρօtifս` z linkiem ukrytym za `redirects.ca`.

Przykłady te pochodzą z badań Unit 42 (lipiec 2025) i ilustrują, jak nadużycie Homoglyph jest łączone z przekierowywaniem URL i obchodzeniem CAPTCHA w celu ominięcia automatycznej analizy.<sup>[[1]](#references)</sup>

## Odnośniki

- [1] [Iluzja Homoglyph: nie wszystko jest takie, na jakie wygląda](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Baza danych znaków Unicode](https://home.unicode.org/)
- [3] [dnstwist – silnik permutacji domen](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
