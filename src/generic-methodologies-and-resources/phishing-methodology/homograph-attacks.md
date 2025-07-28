# Ataki homograficzne / homoglifowe w phishingu

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Atak homograficzny (znany również jako atak homoglifowy) wykorzystuje fakt, że wiele **punktów kodowych Unicode z nielatynowych skryptów jest wizualnie identycznych lub bardzo podobnych do znaków ASCII**. Poprzez zastąpienie jednego lub więcej znaków łacińskich ich odpowiednikami, atakujący może stworzyć:

* Nazwy wyświetlane, tematy lub treści wiadomości, które wyglądają na legitymne dla ludzkiego oka, ale omijają detekcje oparte na słowach kluczowych.
* Domeny, subdomeny lub ścieżki URL, które oszukują ofiary, sprawiając, że wierzą, iż odwiedzają zaufaną stronę.

Ponieważ każdy glif jest identyfikowany wewnętrznie przez swój **punkt kodowy Unicode**, pojedynczy zastąpiony znak wystarczy, aby pokonać naiwne porównania ciągów (np. `"Παypal.com"` vs. `"Paypal.com"`).

## Typowy proces phishingowy

1. **Stwórz treść wiadomości** – Zastąp konkretne litery łacińskie w podszywającej się marce / słowie kluczowym wizualnie nieodróżnialnymi znakami z innego skryptu (greckiego, cyrylicy, ormiańskiego, cherokee itp.).
2. **Zarejestruj infrastrukturę wspierającą** – Opcjonalnie zarejestruj domenę homoglifową i uzyskaj certyfikat TLS (większość CA nie przeprowadza kontroli podobieństwa wizualnego).
3. **Wyślij e-mail / SMS** – Wiadomość zawiera homoglify w jednej lub więcej z następujących lokalizacji:
* Nazwa wyświetlana nadawcy (np. `Ηеlрdеѕk`)
* Temat (`Urgеnt Аctіon Rеquіrеd`)
* Tekst hiperlinku lub w pełni kwalifikowana nazwa domeny
4. **Łańcuch przekierowań** – Ofiara jest przekierowywana przez pozornie nieszkodliwe strony internetowe lub skracacze URL, zanim trafi na złośliwy host, który zbiera dane uwierzytelniające / dostarcza złośliwe oprogramowanie.

## Zakresy Unicode powszechnie nadużywane

| Skrypt | Zakres | Przykładowy glif | Wygląda jak |
|--------|-------|---------------|------------|
| Grecki  | U+0370-03FF | `Η` (U+0397) | Łacińskie `H` |
| Grecki  | U+0370-03FF | `ρ` (U+03C1) | Łacińskie `p` |
| Cyrylica | U+0400-04FF | `а` (U+0430) | Łacińskie `a` |
| Cyrylica | U+0400-04FF | `е` (U+0435) | Łacińskie `e` |
| Ormiański | U+0530-058F | `օ` (U+0585) | Łacińskie `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Łacińskie `T` |

> Wskazówka: Pełne wykresy Unicode są dostępne na [unicode.org](https://home.unicode.org/).

## Techniki detekcji

### 1. Inspekcja mieszanych skryptów

E-maile phishingowe skierowane do anglojęzycznej organizacji rzadko powinny mieszać znaki z wielu skryptów. Prosta, ale skuteczna heurystyka to:

1. Iterować przez każdy znak sprawdzanego ciągu.
2. Mapować punkt kodowy do jego bloku Unicode.
3. Wzbudzić alert, jeśli obecnych jest więcej niż jeden skrypt **lub** jeśli nielatynowe skrypty pojawiają się tam, gdzie nie są oczekiwane (nazwa wyświetlana, domena, temat, URL itp.).

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
### 2. Normalizacja Punycode (Domeny)

Zinternationalizowane Nazwy Domen (IDN) są kodowane za pomocą **punycode** (`xn--`). Konwersja każdej nazwy hosta na punycode, a następnie z powrotem na Unicode, umożliwia porównanie z białą listą lub przeprowadzenie kontroli podobieństwa (np. odległość Levenshteina) **po** normalizacji ciągu.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Słowniki / Algorytmy Homoglifów

Narzędzia takie jak **dnstwist** (`--homoglyph`) lub **urlcrazy** mogą enumerować wizualnie podobne permutacje domen i są przydatne do proaktywnego usuwania / monitorowania.

## Zapobieganie i Łagodzenie

* Wprowadź surowe polityki DMARC/DKIM/SPF – zapobiegaj podszywaniu się z nieautoryzowanych domen.
* Wdróż logikę detekcji powyżej w **Secure Email Gateways** i **SIEM/XSOAR** playbookach.
* Oznaczaj lub kwarantannuj wiadomości, w których domena wyświetlanej nazwy ≠ domena nadawcy.
* Edukuj użytkowników: kopiuj-wklej podejrzany tekst do inspektora Unicode, najeżdżaj na linki, nigdy nie ufaj skracaczom URL.

## Przykłady z Życia Wziętego

* Wyświetlana nazwa: `Сonfidеntiаl Ꭲiꮯkеt` (cyrylica `С`, `е`, `а`; cherokee `Ꭲ`; mała litera łacińska `ꮯ`).
* Łańcuch domen: `bestseoservices.com` ➜ katalog miejskich `/templates` ➜ `kig.skyvaulyt.ru` ➜ fałszywe logowanie do Microsoftu na `mlcorsftpsswddprotcct.approaches.it.com` chronione przez niestandardowy OTP CAPTCHA.
* Podszywanie się pod Spotify: nadawca `Sρօtifւ` z linkiem ukrytym za `redirects.ca`.

Te przykłady pochodzą z badań Unit 42 (lipiec 2025) i ilustrują, jak nadużycie homoglifów jest łączone z przekierowaniem URL i omijaniem CAPTCHA w celu obejścia analizy automatycznej.

## Źródła

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
