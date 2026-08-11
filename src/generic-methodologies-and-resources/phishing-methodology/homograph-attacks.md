# Homograph / Homoglyph-aanvalle in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

’n Homograph (ook bekend as homoglyph)-aanval misbruik die feit dat baie **Unicode-kodepunte uit nie-Latynse skrifte visueel identies of uiters soortgelyk aan ASCII-karakters is**. Deur een of meer Latynse karakters met hul look-alike-eweknieë te vervang, kan ’n aanvaller die volgende skep:

* Vertoonname, onderwerpe of boodskapliggame wat vir die menslike oog wettig lyk, maar sleutelwoordgebaseerde opsporing omseil.
* Domeine, subdomeine of URL-paaie wat slagoffers mislei om te glo dat hulle ’n vertroude webwerf besoek.<sup>[[1]](#references)</sup>

Omdat elke glyph intern deur sy **Unicode-kodepunt** geïdentifiseer word, is een enkele vervangde karakter genoeg om naïewe stringvergelykings te omseil (bv. `"Παypal.com"` vs. `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Tipiese Phishing-werkvloei

1. **Skep boodskapinhoud** – Vervang spesifieke Latynse letters in die nagebootste handelsmerk / sleutelwoord met visueel ononderskeibare karakters uit ’n ander skrif (Grieks, Cyrillies, Armeens, Cherokee, ens.).
2. **Registreer ondersteunende infrastruktuur** – Registreer opsioneel ’n homoglyph-domein en verkry ’n TLS-sertifikaat (die meeste CA’s doen geen visuele ooreenkomskontroles nie).
3. **Stuur e-pos / SMS** – Die boodskap bevat homoglyphs in een of meer van die volgende liggings:
* Sender-vertoonnaam (bv. `Ηеlрdеѕk`)
* Onderwerpreël (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlinkteks of volledig gekwalifiseerde domeinnaam
4. **Redirect-ketting** – Die slagoffer word deur oënskynlik onskadelike webwerwe of URL-verkorters gestuur voordat hy of sy op die kwaadwillige host beland wat geloofsbriewe insamel / malware lewer.<sup>[[1]](#references)</sup>

## Unicode-reekse wat algemeen misbruik word

Die volgende voorbeelde is Unicode-blokke wat karakters bevat wat algemeen gebruik word om kruis-skrif-look-alikes te skep.<sup>[[2]](#references)[[3]](#references)</sup>

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

Phishing-e-posse wat op ’n Engelssprekende organisasie gemik is, behoort selde karakters uit verskeie skrifte te meng. ’n Eenvoudige maar doeltreffende heuristiek is om:

1. Deur elke karakter van die ondersoekte string te iterereer.
2. Die kodepunt na sy skrifnaam of Unicode-blok te karteer.
3. ’n Waarskuwing te genereer indien meer as een skrif teenwoordig is **of** indien nie-Latynse skrifte verskyn waar hulle nie verwag word nie (vertoonnaam, domein, onderwerp, URL, ens.).<sup>[[3]](#references)</sup>

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
### 2. Punycode-normalisering (Domains)

Geïnternationaliseerde Domain Names (IDN's) het ’n Unicode-vorm en ’n ASCII-versoenbare **Punycode**-vorm wat met `xn--` voorafgegaan word. Skakel gasheername om na die IDNA/Punycode-vorm voordat jy dit op ’n allow-list plaas of vergelyk, terwyl jy die Unicode-vorm vir vertoon behou.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph-woordeboeke / -algoritmes

Gereedskap soos **dnstwist** (`--fuzzers homoglyph`) of **urlcrazy** kan visueel soortgelyke domeinpermutasies opnoem en is nuttig vir proaktiewe verwydering / monitering.<sup>[[4]](#references)[[5]](#references)</sup>

## Voorkoming & Versagting

* Dwing streng DMARC/DKIM/SPF-beleide af – voorkom spoofing vanaf ongemagtigde domeine.
* Implementeer die bogenoemde opsporingslogika in **Secure Email Gateways** en **SIEM/XSOAR**-speelboeke.
* Merk of plaas boodskappe in kwarantyn waar vertoonnaam se domein ≠ sender se domein.
* Leer gebruikers: kopieer-plak verdagte teks in ’n Unicode-inspekteur, beweeg oor skakels, en vertrou nooit URL-verkorters nie.

## Werklike Voorbeelde

* Vertoonnaam: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrilliese `С`, `е`, `а`; Cherokee `Ꭲ`; Latynse klein hoofletter `ꮯ`).
* Domeinketting: `bestseoservices.com` ➜ munisipale `/templates`-gids ➜ `kig.skyvaulyt.ru` ➜ valse Microsoft-aanmelding by `mlcorsftpsswddprotcct.approaches.it.com`, beskerm deur pasgemaakte OTP CAPTCHA.
* Spotify-voorwendsel: `Sρօtifս`-sender met ’n skakel wat agter `redirects.ca` versteek is.

Hierdie voorbeelde is afkomstig van Unit 42-navorsing (Julie 2025) en illustreer hoe homograafmisbruik met URL-herleiding en CAPTCHA-ontduiking gekombineer word om geoutomatiseerde ontleding te omseil.<sup>[[1]](#references)</sup>

## References

- [1] [Die Homograaf-illusie: Nie Alles Is Soos Dit Lyk Nie](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode-karakterkodetabelle](https://www.unicode.org/charts/)
- [3] [Unicode-tegniese standaard #39: Unicode-sekuriteitsmeganismes](https://unicode.org/reports/tr39/)
- [4] [dnstwist – domeinpermutasie-enjin](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – genereerder van domeintikfoute en -variasies](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Geïnternasionaliseerde domeinname vir toepassings (IDNA): Definisies en dokumentraamwerk](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
