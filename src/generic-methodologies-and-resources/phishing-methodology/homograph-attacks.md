# Homograph / Homoglyph Attacks u Phishingu

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Homograph (poznat i kao homoglyph) napad zloupotrebljava činjenicu da su mnogi **Unicode code points iz nelatiničnih pisama vizuelno identični ili veoma slični ASCII karakterima**. Zamenom jednog ili više latiničnih karaktera njihovim vizuelno sličnim ekvivalentima, napadač može kreirati:

* Display names, subjects ili message bodies koji ljudskom oku izgledaju legitimno, ali zaobilaze detekcije zasnovane na ključnim rečima.
* Domenе, poddomene ili URL putanje koje žrtve navode na uverenje da posećuju pouzdan sajt.

Pošto je svaki glyph interno identifikovan svojim **Unicode code point**, samo jedan zamenjeni karakter dovoljan je da porazi naivna poređenja stringova (npr. `"Παypal.com"` naspram `"Paypal.com"`).

## Tipičan tok Phishing napada

1. **Craft message content** – Zameniti određena latinična slova u impersonated brand / keyword vizuelno nerazlikujućim karakterima iz drugog pisma (grčkog, ćiriličnog, jermenskog, Cherokee itd.).
2. **Register supporting infrastructure** – Po želji registrovati homoglyph domen i pribaviti TLS sertifikat (većina CA ne vrši provere vizuelne sličnosti).
3. **Send email / SMS** – Poruka sadrži homoglyphs na jednoj ili više sledećih lokacija:
* Sender display name (npr. `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text ili fully qualified domain name
4. **Redirect chain** – Žrtva se preusmerava kroz naizgled bezopasne sajtove ili URL shorteners pre nego što stigne do malicious host-a koji prikuplja credentials / isporučuje malware.

## Unicode opsezi koji se često zloupotrebljavaju

| Pismo | Opseg | Primer glyph-a | Izgleda kao |
|--------|-------|---------------|------------|
| Grčko  | U+0370-03FF | `Η` (U+0397) | Latinično `H` |
| Grčko  | U+0370-03FF | `ρ` (U+03C1) | Latinično `p` |
| Ćirilično | U+0400-04FF | `а` (U+0430) | Latinično `a` |
| Ćirilično | U+0400-04FF | `е` (U+0435) | Latinično `e` |
| Jermensko | U+0530-058F | `օ` (U+0585) | Latinično `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latinično `T` |

> Savet: Kompletne Unicode tabele dostupne su na [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Tehnike detekcije

### 1. Provera mešovitih pisama

Phishing emails usmereni ka organizaciji koja govori engleski jezik retko bi trebalo da mešaju karaktere iz više pisama. Jednostavna, ali efikasna heuristika jeste:

1. Proći kroz svaki karakter ispitivanog stringa.
2. Mapirati code point na njegov Unicode block.
3. Podignuti upozorenje ako je prisutno više od jednog pisma **ili** ako se nelatinična pisma pojavljuju tamo gde se ne očekuju (display name, domen, subject, URL itd.).

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
### 2. Normalizacija Punycode-a (domeni)

Internationalised Domain Names (IDN-ovi) se kodiraju pomoću **punycode** (`xn--`). Konvertovanje svakog hostname-a u punycode, a zatim nazad u Unicode, omogućava poređenje sa whitelist-om ili proveru sličnosti (npr. Levenshtein distance) **nakon** normalizacije stringa.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph rečnici / algoritmi

Alati kao što su **dnstwist** (`--homoglyph`) ili **urlcrazy** mogu da izlistaju vizuelno slične permutacije domena i korisni su za proaktivno uklanjanje / monitoring.<sup>[[3]](#references)</sup>

## Prevencija i ublažavanje

* Primenite stroge DMARC/DKIM/SPF politike – sprečite spoofing sa neovlašćenih domena.
* Implementirajte navedenu logiku detekcije u **Secure Email Gateways** i **SIEM/XSOAR** playbooks.
* Označite ili stavite u karantin poruke kod kojih se domen display name-a ≠ domen pošiljaoca.
* Edukujte korisnike: kopirajte i nalepite sumnjiv tekst u Unicode inspector, pređite pokazivačem preko linkova i nikada ne verujte URL skraćivačima.

## Primeri iz stvarnog sveta

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (ćirilična slova `С`, `е`, `а`; Cherokee `Ꭲ`; latinično malo kapitalno slovo `ꮯ`).
* Lanac domena: `bestseoservices.com` ➜ municipal `/templates` direktorijum ➜ `kig.skyvaulyt.ru` ➜ lažna Microsoft prijava na `mlcorsftpsswddprotcct.approaches.it.com`, zaštićena prilagođenim OTP CAPTCHA mehanizmom.
* Imitacija Spotify-ja: pošiljalac `Sρօtifս` sa linkom skrivenim iza `redirects.ca`.

Ovi primeri potiču iz istraživanja Unit 42 (jul 2025) i ilustruju kako se zloupotreba homoglifa kombinuje sa URL redirekcijom i zaobilaženjem CAPTCHA-e radi zaobilaženja automatizovane analize.<sup>[[1]](#references)</sup>

## References

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
