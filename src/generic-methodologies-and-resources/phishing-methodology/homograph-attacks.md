# Homograph / Homoglyph napadi u phishingu

## Pregled

Homograph (poznat i kao homoglyph) napad zloupotrebljava činjenicu da su mnoge **Unicode code points iz nelatiničnih pisama vizuelno identične ili izuzetno slične ASCII karakterima**. Zamenom jednog ili više latiničnih karaktera njihovim vizuelno sličnim ekvivalentima, napadač može kreirati:

* Display names, naslove ili sadržaj poruka koji ljudskom oku izgledaju legitimno, ali zaobilaze detekcije zasnovane na ključnim rečima.
* Domenе, poddomene ili URL putanje koje žrtve navode da poveruju da posećuju pouzdan sajt.<sup>[[1]](#references)</sup>

Pošto je svaki glyph interno identifikovan svojim **Unicode code point**, dovoljan je jedan zamenjeni karakter da se zaobiđu naivna poređenja stringova (npr. `"Παypal.com"` naspram `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Tipičan Phishing tok

1. **Kreiranje sadržaja poruke** – Zamenite određena latinična slova u lažno predstavljenom brendu / ključnoj reči vizuelno nerazlučivim karakterima iz drugog pisma (grčkog, ćiriličnog, jermenskog, čiroki itd.).
2. **Registracija prateće infrastrukture** – Po želji registrujte homoglyph domen i pribavite TLS sertifikat (većina CA ne vrši provere vizuelne sličnosti).
3. **Slanje emaila / SMS-a** – Poruka sadrži homoglyph znakove na jednom ili više sledećih mesta:
* Display name pošiljaoca (npr. `Ηеlрdеѕk`)
* Naslov poruke (`Urgеnt Аctіon Rеquіrеd`)
* Tekst hyperlinka ili potpuno kvalifikovani naziv domena
4. **Lanac preusmeravanja** – Žrtva se preusmerava kroz naizgled bezopasne sajtove ili URL shorteners pre nego što stigne do malicious hosta koji prikuplja kredencijale / isporučuje malware.<sup>[[1]](#references)</sup>

## Unicode opsezi koji se često zloupotrebljavaju

Sledeći primeri predstavljaju Unicode blokove koji sadrže karaktere koji se često koriste za kreiranje look-alike znakova iz različitih pisama.<sup>[[2]](#references)[[3]](#references)</sup>

| Pismo | Opseg | Primer glyph-a | Izgleda kao |
|--------|-------|---------------|------------|
| Grčko  | U+0370-03FF | `Η` (U+0397) | Latinično `H` |
| Grčko  | U+0370-03FF | `ρ` (U+03C1) | Latinično `p` |
| Ćirilično | U+0400-04FF | `а` (U+0430) | Latinično `a` |
| Ćirilično | U+0400-04FF | `е` (U+0435) | Latinično `e` |
| Jermensko | U+0530-058F | `օ` (U+0585) | Latinično `o` |
| Čiroki | U+13A0-13FF | `Ꭲ` (U+13A2) | Latinično `T` |

> Savet: Koristite Unicode code charts da pronađete blokove i code points.

## Tehnike detekcije

### 1. Inspekcija mešovitih pisama

Phishing emailovi usmereni na organizaciju koja govori engleski jezik retko bi trebalo da mešaju karaktere iz više pisama. Jedna jednostavna, ali efikasna heuristika jeste:

1. Prođite kroz svaki karakter ispitivanog stringa.
2. Mapirajte code point na naziv pisma ili Unicode bloka.
3. Podignite alert ako je prisutno više od jednog pisma **ili** ako se nelatinična pisma pojavljuju tamo gde se ne očekuju (display name, domen, naslov, URL itd.).<sup>[[3]](#references)</sup>

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
### 2. Punycode Normalizacija (Domeni)

Internacionalizovani nazivi domena (IDN-ovi) imaju Unicode oblik i ASCII-kompatibilni **Punycode** oblik sa prefiksom `xn--`. Konvertujte hostnames u IDNA/Punycode oblik pre dodavanja na allow-listu ili njihovog poređenja, uz zadržavanje Unicode oblika za prikaz.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph rečnici / algoritmi

Alati kao što su **dnstwist** (`--fuzzers homoglyph`) ili **urlcrazy** mogu da nabroje vizuelno slične permutacije domena i korisni su za proaktivno uklanjanje / monitoring.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevencija i ublažavanje

* Primenite stroge DMARC/DKIM/SPF politike – sprečite spoofing sa neovlašćenih domena.
* Implementirajte navedenu logiku za detekciju u **Secure Email Gateways** i SIEM/XSOAR playbooks.
* Označite ili stavite u karantin poruke kod kojih se domen display name-a ≠ domenu pošiljaoca.
* Edukujte korisnike: kopirajte i nalepite sumnjiv tekst u Unicode inspector, pređite pokazivačem preko linkova i nikada ne verujte URL skraćivačima.

## Primeri iz stvarnog sveta

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (ćirilična slova `С`, `е`, `а`; Cherokee `Ꭲ`; latinično malo veliko slovo `ꮯ`).
* Lanac domena: `bestseoservices.com` ➜ opštinski direktorijum `/templates` ➜ `kig.skyvaulyt.ru` ➜ lažna Microsoft prijava na `mlcorsftpsswddprotcct.approaches.it.com`, zaštićena prilagođenim OTP CAPTCHA mehanizmom.
* Imitacija Spotify-ja: pošiljalac `Sρօtifս` sa linkom sakrivenim iza `redirects.ca`.

Ovi primeri potiču iz istraživanja Unit 42 (jul 2025) i ilustruju kako se zloupotreba homoglifa kombinuje sa preusmeravanjem URL-ova i zaobilaženjem CAPTCHA-e radi izbegavanja automatizovane analize.<sup>[[1]](#references)</sup>

## References

- [1] [Iluzija homoglifa: Nije sve onako kako izgleda](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Tabele kodova Unicode znakova](https://www.unicode.org/charts/)
- [3] [Unicode tehnički standard #39: Unicode bezbednosni mehanizmi](https://unicode.org/reports/tr39/)
- [4] [dnstwist – engine za permutacije domena](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – generator grešaka u domenu i varijacija](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internacionalizovani nazivi domena za aplikacije (IDNA): definicije i okvir dokumenta](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
