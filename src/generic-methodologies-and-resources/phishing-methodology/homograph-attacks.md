# Homograph / Homoglyph napadi u phishingu

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Homograph (poznat i kao homoglyph) napad zloupotrebljava činjenicu da su mnogi **Unicode code points iz nelatiničnih pisama vizuelno identični ili veoma slični ASCII karakterima**. Zamenom jednog ili više latiničnih karaktera njihovim vizuelno sličnim ekvivalentima, napadač može kreirati:

* Display names, predmete ili tela poruka koji ljudskom oku izgledaju legitimno, ali zaobilaze detekcije zasnovane na ključnim rečima.
* Domene, poddomene ili URL putanje koje žrtve navode da poveruju da posećuju pouzdan sajt.<sup>[[1]](#references)</sup>

Pošto se svaki glyph interno identifikuje svojim **Unicode code point**, dovoljna je zamena jednog karaktera da se zaobiđu naivna poređenja stringova (npr. `"Παypal.com"` naspram `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Tipičan phishing workflow

1. **Kreiranje sadržaja poruke** – Zameniti određena latinična slova u impersoniranom brendu / ključnoj reči vizuelno nerazlikujućim karakterima iz drugog pisma (grčkog, ćiriličnog, jermenskog, čiroki itd.).
2. **Registracija supporting infrastructure** – Po želji registrovati homoglyph domen i dobiti TLS certificate (većina CA ne vrši provere vizuelne sličnosti).
3. **Slanje emaila / SMS-a** – Poruka sadrži homoglyphs na jednoj ili više sledećih lokacija:
* Sender display name (npr. `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Tekst hyperlinka ili fully qualified domain name
4. **Redirect chain** – Žrtva se prosleđuje kroz naizgled bezopasne sajtove ili URL shorteners pre nego što stigne na malicious host koji prikuplja credentials / isporučuje malware.<sup>[[1]](#references)</sup>

## Unicode opsezi koji se često zloupotrebljavaju

Sledeći primeri predstavljaju Unicode blokove koji sadrže karaktere koji se često koriste za kreiranje look-alikes između različitih pisama.<sup>[[2]](#references)[[3]](#references)</sup>

| Pismo | Opseg | Primer glyph-a | Izgleda kao |
|--------|-------|---------------|------------|
| Grčko  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Grčko  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Ćirilično | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Ćirilično | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Jermensko | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Čiroki | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Savet: Koristite Unicode code charts da pronađete blokove i code points.

## Tehnike detekcije

### 1. Provera mešovitih pisama

Phishing emailovi usmereni na organizaciju koja govori engleski jezik retko bi trebalo da mešaju karaktere iz više pisama. Jednostavna, ali efikasna heuristika je:

1. Proći kroz svaki karakter ispitivanog stringa.
2. Mapirati code point na naziv pisma ili Unicode blok.
3. Podignuti upozorenje ako je prisutno više od jednog pisma **ili** ako se nelatinična pisma pojavljuju tamo gde se ne očekuju (display name, domen, subject, URL itd.).<sup>[[3]](#references)</sup>

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
### 2. Normalizacija Punycode formata (domeni)

Internationalised Domain Names (IDN-ovi) imaju Unicode oblik i ASCII-kompatibilni oblik **Punycode**, sa prefiksom `xn--`. Konvertujte imena hostova u IDNA/Punycode oblik pre nego što ih dodate na listu dozvoljenih ili uporedite, uz zadržavanje Unicode oblika za prikaz.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Rečnici / algoritmi homoglifova

Alati kao što su **dnstwist** (`--fuzzers homoglyph`) ili **urlcrazy** mogu da enumerišu vizuelno slične permutacije domena i korisni su za proaktivno uklanjanje / monitoring.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevencija i ublažavanje

* Primenite stroge DMARC/DKIM/SPF politike – sprečite spoofing sa neovlašćenih domena.
* Implementirajte navedenu logiku za detekciju u **Secure Email Gateways** i **SIEM/XSOAR** playbook-ovima.
* Obeležite ili stavite u karantin poruke kod kojih se domen prikazanog imena ≠ domen pošiljaoca.
* Edukujte korisnike: kopirajte i nalepite sumnjiv tekst u Unicode inspector, pređite kursorom preko linkova i nikada nemojte verovati URL shortener-ima.

## Primeri iz stvarnog sveta

* Prikazano ime: `Сonfidеntiаl Ꭲiꮯkеt` (ćirilični `С`, `е`, `а`; Cherokee `Ꭲ`; latinični small capital `ꮯ`).
* Lanac domena: `bestseoservices.com` ➜ municipal `/templates` direktorijum ➜ `kig.skyvaulyt.ru` ➜ lažna Microsoft prijava na `mlcorsftpsswddprotcct.approaches.it.com`, zaštićena prilagođenim OTP CAPTCHA mehanizmom.
* Imitacija Spotify-ja: pošiljalac `Sρօtifս` sa linkom sakrivenim iza `redirects.ca`.

Ovi primeri potiču iz istraživanja Unit 42 (jul 2025) i ilustruju kako se zloupotreba homoglifova kombinuje sa URL redirekcijom i CAPTCHA evazijom radi zaobilaženja automatizovane analize.<sup>[[1]](#references)</sup>

## References

- [1] [Iluzija homoglifova: Nije sve onako kako izgleda](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Tabele kodova Unicode znakova](https://www.unicode.org/charts/)
- [3] [Unicode tehnički standard #39: Unicode bezbednosni mehanizmi](https://unicode.org/reports/tr39/)
- [4] [dnstwist – engine za permutacije domena](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – generator grešaka u nazivima domena i varijacija](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internacionalizovani nazivi domena za aplikacije (IDNA): definicije i okvir dokumenta](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
