# Homograph- / Homoglyph-aanvalle in Phishing

## Oorsig

’n Homograph- (ook bekend as homoglyph-)aanval misbruik die feit dat baie **Unicode-kodepunte uit nie-Latynse skrifte visueel identies of uiters soortgelyk aan ASCII-karakters is**. Deur een of meer Latynse karakters met hul look-alike-eweknieë te vervang, kan ’n aanvaller die volgende skep:

* Vertoonname, onderwerpe of boodskapliggame wat vir die menslike oog legitiem lyk, maar sleutelwoordgebaseerde opsporing omseil.
* Domeine, subdomeine of URL-paaie wat slagoffers mislei om te glo dat hulle ’n vertroude webwerf besoek.<sup>[[1]](#references)</sup>

Omdat elke glyph intern deur sy **Unicode-kodepunt geïdentifiseer word**, is ’n enkele vervangde karakter genoeg om naïewe stringvergelykings te omseil (bv. `"Παypal.com"` vs. `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Tipiese Phishing-werkvloei

1. **Skep boodskapinhoud** – Vervang spesifieke Latynse letters in die nagebootste handelsmerk / sleutelwoord met visueel ononderskeibare karakters uit ’n ander skrif (Grieks, Cyrillies, Armeens, Cherokee, ens.).
2. **Registreer ondersteunende infrastruktuur** – Registreer opsioneel ’n homoglyph-domein en verkry ’n TLS-sertifikaat (die meeste CAs doen geen visuele ooreenkomskontroles nie).
3. **Stuur e-pos / SMS** – Die boodskap bevat homoglyphs in een of meer van die volgende plekke:
* Sender-vertoonnaam (bv. `Ηеlрdеѕk`)
* Onderwerpreël (`Urgеnt Аctіon Rеquіrеd`)
* Hiperskakelteks of volledig gekwalifiseerde domeinnaam
4. **Herleidingsketting** – Die slagoffer word deur oënskynlik onskadelike webwerwe of URL-verkorters gestuur voordat dit by die kwaadwillige gasheer beland wat geloofsbriewe insamel / malware aflewer.<sup>[[1]](#references)</sup>

## Unicode-reekse wat algemeen misbruik word

Die volgende voorbeelde is Unicode-blokke wat karakters bevat wat algemeen gebruik word om look-alikes oor skrifte heen te skep.<sup>[[2]](#references)[[3]](#references)</sup>

| Skrif | Reeks | Voorbeeld-glyph | Lyk soos |
|--------|-------|---------------|------------|
| Grieks  | U+0370-03FF | `Η` (U+0397) | Latynse `H` |
| Grieks  | U+0370-03FF | `ρ` (U+03C1) | Latynse `p` |
| Cyrillies | U+0400-04FF | `а` (U+0430) | Latynse `a` |
| Cyrillies | U+0400-04FF | `е` (U+0435) | Latynse `e` |
| Armeens | U+0530-058F | `օ` (U+0585) | Latynse `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latynse `T` |

> Wenk: Gebruik die Unicode-kodekaarte om blokke en kodepunte op te soek.

## Opsporingstegnieke

### 1. Inspeksie van gemengde skrifte

Phishing-e-posse wat op ’n Engelssprekende organisasie gerig is, behoort selde karakters uit verskeie skrifte te meng. ’n Eenvoudige maar doeltreffende heuristiek is om:

1. Elke karakter van die string wat ondersoek word, te deurloop.
2. Die kodepunt na sy skrifnaam of Unicode-blok te karteer.
3. ’n Waarskuwing te genereer indien meer as een skrif teenwoordig is **of** indien nie-Latynse skrifte voorkom waar dit nie verwag word nie (vertoonnaam, domein, onderwerp, URL, ens.).<sup>[[3]](#references)</sup>

Python-bewys-van-konsep:
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
### 2. Punycode-normalisering (Domeine)

Internationalised Domain Names (IDNs) het ’n Unicode-vorm en ’n ASCII-versoenbare **Punycode**-vorm met die voorvoegsel `xn--`. Skakel gasheername om na die IDNA/Punycode-vorm voordat jy hulle op ’n allow-list plaas of vergelyk, terwyl jy die Unicode-vorm vir vertoon behou.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph-woordeboeke / Algoritmes

Tools soos **dnstwist** (`--fuzzers homoglyph`) of **urlcrazy** kan visueel soortgelyke domeinvariasies opsom en is nuttig vir proaktiewe verwydering / monitering.<sup>[[4]](#references)[[5]](#references)</sup>

## Voorkoming en Versagting

* Dwing streng DMARC/DKIM/SPF-beleide af – voorkom spoofing vanaf ongemagtigde domeine.
* Implementeer die bogenoemde opsporingslogika in **Secure Email Gateways** en **SIEM/XSOAR**-playbooks.
* Merk of plaas boodskappe in kwarantyn waar vertoonnaam se domein ≠ sender se domein.
* Lei gebruikers op: kopieer-plak verdagte teks in ’n Unicode-inspekteur, beweeg oor skakels, en vertrou nooit URL-verkorters nie.

## Voorbeelde uit die Werklike Wêreld

* Vertoonnaam: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrilliese `С`, `е`, `а`; Cherokee `Ꭲ`; Latynse kleinhoofletter `ꮯ`).
* Domeinketting: `bestseoservices.com` ➜ munisipale `/templates`-gids ➜ `kig.skyvaulyt.ru` ➜ vals Microsoft-aanmelding by `mlcorsftpsswddprotcct.approaches.it.com`, beskerm deur ’n pasgemaakte OTP CAPTCHA.
* Spotify-nabootsing: `Sρօtifս`-sender met ’n skakel wat agter `redirects.ca` versteek is.

Hierdie voorbeelde is afkomstig van Unit 42-navorsing (Julie 2025) en illustreer hoe homograph-misbruik met URL-herleiding en CAPTCHA-ontduiking gekombineer word om geoutomatiseerde ontleding te omseil.<sup>[[1]](#references)</sup>

## References

- [1] [Die Homograph-illusie: Nie Alles Is Soos Dit Lyk Nie](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode-karakterkoderingskaarte](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Unicode-sekuriteitsmeganismes](https://unicode.org/reports/tr39/)
- [4] [dnstwist – domeinvariasie-enjin](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – domeintikfout- en variasiegenerator](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Geïnternasionaliseerde domeinname vir toepassings (IDNA): Definisies en dokumentraamwerk](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
