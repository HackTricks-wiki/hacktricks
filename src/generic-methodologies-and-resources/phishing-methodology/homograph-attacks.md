# Homografiese / Homogliep Aanvalle in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

'n Homografiese (ook bekend as homogliep) aanval misbruik die feit dat baie **Unicode-kodepunte van nie-Latynse skrifte visueel identies of uiters soortgelyk aan ASCII-karakters is**. Deur een of meer Latynse karakters met hul visueel soortgelyke teenhangers te vervang, kan 'n aanvaller skep:

* Vertoonname, onderwerpe of boodskapliggame wat legitiem lyk vir die menslike oog, maar sleutelwoord-gebaseerde opsporings omseil.
* Domeine, subdomeine of URL-paaie wat slagoffers mislei om te glo dat hulle 'n vertroude webwerf besoek.

Omdat elke glif intern geïdentifiseer word deur sy **Unicode-kodepunt**, is 'n enkele vervangde karakter genoeg om naïewe stringvergelykings te oorwin (bv. `"Παypal.com"` teenoor `"Paypal.com"`).

## Tipiese Phishing Werkvloei

1. **Skep boodskapinhoud** – Vervang spesifieke Latynse letters in die geïmpersoniseerde handelsmerk / sleutelwoord met visueel ononderskeibare karakters van 'n ander skrif (Grieks, Sirilies, Armeens, Cherokee, ens.).
2. **Registreer ondersteunende infrastruktuur** – Opsioneel registreer 'n homogliep-domein en verkry 'n TLS-sertifikaat (meeste CA's doen geen visuele soortgelykheidstoetse nie).
3. **Stuur e-pos / SMS** – Die boodskap bevat homogliepe in een of meer van die volgende plekke:
* Sender vertoonnaam (bv. `Ηеlрdеѕk`)
* Onderwerplyn (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink teks of volledig gekwalifiseerde domeinnaam
4. **Herlei ketting** – Slagoffer word deur blykbaar onskadelike webwerwe of URL-verkorters gebounce voordat dit op die kwaadwillige gasheer beland wat akrediteer / malware lewer.

## Unicode Reeks Gewoonlik Misbruik

| Skrif | Reeks | Voorbeeld glif | Lyk soos |
|-------|-------|----------------|----------|
| Grieks | U+0370-03FF | `Η` (U+0397) | Latyn `H` |
| Grieks | U+0370-03FF | `ρ` (U+03C1) | Latyn `p` |
| Sirilies | U+0400-04FF | `а` (U+0430) | Latyn `a` |
| Sirilies | U+0400-04FF | `е` (U+0435) | Latyn `e` |
| Armeens | U+0530-058F | `օ` (U+0585) | Latyn `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latyn `T` |

> Wenk: Volledige Unicode-kaarte is beskikbaar by [unicode.org](https://home.unicode.org/).

## Opsporingstegnieke

### 1. Gemengde-Skrif Inspeksie

Phishing-e-pos wat op 'n Engelssprekende organisasie gemik is, moet selde karakters van verskeie skrifte meng. 'n Eenvoudige maar effektiewe heuristiek is om:

1. Elke karakter van die ondersoekte string te herhaal.
2. Die kodepunt na sy Unicode-blok te kaart.
3. 'n Waarskuwing te laat klink as meer as een skrif teenwoordig is **of** as nie-Latynse skrifte verskyn waar dit nie verwag word nie (vertoonnaam, domein, onderwerp, URL, ens.).

Python bewys-van-konsep:
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
### 2. Punycode Normalisering (Domeine)

Internasionaal Geverifieerde Domeinnames (IDNs) word met **punycode** (`xn--`) gekodeer. Om elke gasheernaam na punycode te omskakel en dan weer na Unicode toe, maak dit moontlik om teen 'n witlys te vergelyk of om ooreenkoms kontroles uit te voer (bv. Levenshtein afstand) **nadat** die string genormaliseer is.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Woordeboeke / Algoritmes

Tools soos **dnstwist** (`--homoglyph`) of **urlcrazy** kan visueel-gelykwaardige domein permutasies opnoem en is nuttig vir proaktiewe afname / monitering.

## Voorkoming & Versagting

* Handhaaf streng DMARC/DKIM/SPF beleid – voorkom spoofing van nie-geautoriseerde domeine.
* Implementeer die opsporingslogika hierbo in **Secure Email Gateways** en **SIEM/XSOAR** speelboeke.
* Merk of karantyn boodskappe waar die vertoonnaam domein ≠ sender domein.
* Onderwys gebruikers: kopieer-plak verdagte teks in 'n Unicode-inspekteur, beweeg oor skakels, vertrou nooit URL-verkorters nie.

## Werklike Voorbeelde

* Vertoonnaam: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latynse klein hoofletter `ꮯ`).
* Domein ketting: `bestseoservices.com` ➜ munisipale `/templates` gids ➜ `kig.skyvaulyt.ru` ➜ vals Microsoft aanmelding by `mlcorsftpsswddprotcct.approaches.it.com` beskerm deur 'n pasgemaakte OTP CAPTCHA.
* Spotify nabootsing: `Sρօtifւ` sender met skakel versteek agter `redirects.ca`.

Hierdie voorbeelde is afkomstig van Unit 42 navorsing (Julie 2025) en illustreer hoe homoglyph misbruik gekombineer word met URL herleiding en CAPTCHA omseiling om geoutomatiseerde analise te omseil.

## Verwysings

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
