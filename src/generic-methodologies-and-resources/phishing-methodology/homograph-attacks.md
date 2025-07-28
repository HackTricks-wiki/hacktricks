# Homograph / Homoglyph napadi u phishingu

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Homograf (poznat i kao homoglif) napad koristi činjenicu da su mnoge **Unicode tačke kodova iz ne-latinskih pisama vizuelno identične ili ekstremno slične ASCII karakterima**. Zamenom jednog ili više latiničnih karaktera sa njihovim vizuelno sličnim ekvivalentima, napadač može kreirati:

* Imena prikazivanja, teme ili sadržaje poruka koji izgledaju legitimno ljudskom oku, ali zaobilaze detekciju zasnovanu na ključnim rečima.
* Domene, poddomene ili URL putanje koje obmanjuju žrtve da veruju da posećuju pouzdanu stranicu.

Pošto je svaki glif interno identifikovan svojom **Unicode tačkom kodova**, jedna zamenjena karaktera je dovoljna da pobedi naivne poređenja stringova (npr., `"Παypal.com"` naspram `"Paypal.com"`).

## Tipičan phishing radni tok

1. **Kreirajte sadržaj poruke** – Zamenite specifična latinična slova u imitujućem brendu / ključnoj reči sa vizuelno neodvojivim karakterima iz drugog pisma (grčko, ćirilično, armensko, čeroki itd.).
2. **Registrujte podržavajuću infrastrukturu** – Opcionalno registrujte homoglif domenu i dobijte TLS sertifikat (većina CA ne vrši vizuelne provere sličnosti).
3. **Pošaljite email / SMS** – Poruka sadrži homoglife na jednom ili više od sledećih mesta:
* Ime pošiljaoca (npr., `Ηеlрdеѕk`)
* Tema (`Urgеnt Аctіon Rеquіrеd`)
* Tekst hiperveze ili potpuno kvalifikovano ime domena
4. **Lanac preusmeravanja** – Žrtva se preusmerava kroz naizgled benigni veb sajtove ili skraćivače URL-a pre nego što stigne na zloćudni host koji prikuplja akreditive / isporučuje malver.

## Unicode opsezi koji se često zloupotrebljavaju

| Pismo   | Opseg        | Primer glifa | Izgleda kao |
|---------|--------------|---------------|-------------|
| Grčko   | U+0370-03FF | `Η` (U+0397)  | Latinski `H` |
| Grčko   | U+0370-03FF | `ρ` (U+03C1)  | Latinski `p` |
| Ćirilično| U+0400-04FF | `а` (U+0430)  | Latinski `a` |
| Ćirilično| U+0400-04FF | `е` (U+0435)  | Latinski `e` |
| Armensko| U+0530-058F | `օ` (U+0585)  | Latinski `o` |
| Čeroki  | U+13A0-13FF | `Ꭲ` (U+13A2)  | Latinski `T` |

> Savet: Puni Unicode grafikoni su dostupni na [unicode.org](https://home.unicode.org/).

## Tehnike detekcije

### 1. Inspekcija mešanih pisama

Phishing emailovi usmereni na organizacije koje govore engleski jezik retko bi trebali mešati karaktere iz više pisama. Jedna jednostavna, ali efikasna heuristika je:

1. Iterirati kroz svaki karakter inspektovanog stringa.
2. Mapirati tačku koda na njen Unicode blok.
3. Podignuti alarm ako je prisutno više od jednog pisma **ili** ako se ne-latinska pisma pojavljuju gde se ne očekuju (ime prikazivanja, domen, tema, URL itd.).

Python dokaz koncepta:
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

Međunarodni domeni (IDN) su kodirani sa **punycode** (`xn--`). Konvertovanje svake hostname u punycode i zatim nazad u Unicode omogućava upoređivanje sa belom listom ili izvođenje provere sličnosti (npr., Levenshtein razdaljina) **nakon** što je string normalizovan.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Rječnici / Algoritmi

Alati kao što su **dnstwist** (`--homoglyph`) ili **urlcrazy** mogu enumerisati vizuelno slične permutacije domena i korisni su za proaktivno uklanjanje / praćenje.

## Prevencija i Ublažavanje

* Sprovodite stroge DMARC/DKIM/SPF politike – sprečite lažiranje sa neovlašćenih domena.
* Implementirajte logiku detekcije iznad u **Secure Email Gateways** i **SIEM/XSOAR** priručnicima.
* Obeležite ili karantinišite poruke gde se domen prikazanog imena ≠ domen pošiljaoca.
* Obrazujte korisnike: kopirajte i nalepite sumnjiv tekst u Unicode inspektor, pređite mišem preko linkova, nikada ne verujte skraćenicama URL-a.

## Primeri iz Stvarnog Sveta

* Prikazano ime: `Сonfidеntiаl Ꭲiꮯkеt` (Ćirilica `С`, `е`, `а`; Čeroki `Ꭲ`; Latinska mala velika `ꮯ`).
* Lanac domena: `bestseoservices.com` ➜ opštinski `/templates` direktorijum ➜ `kig.skyvaulyt.ru` ➜ lažni Microsoft prijavni ekran na `mlcorsftpsswddprotcct.approaches.it.com` zaštićen prilagođenim OTP CAPTCHA.
* Impersonacija Spotify-a: `Sρօtifւ` pošiljalac sa linkom skrivenim iza `redirects.ca`.

Ovi uzorci potiču iz istraživanja Unit 42 (jul 2025) i ilustruju kako se zloupotreba homografa kombinuje sa preusmeravanjem URL-a i izbegavanjem CAPTCHA kako bi se zaobišla automatska analiza.

## Reference

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
