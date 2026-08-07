# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

’n Homograph (ook bekend as homoglyph) attack misbruik die feit dat baie **Unicode code points van nie-Latynse skrifte visueel identies of uiters soortgelyk aan ASCII-karakters is**. Deur een of meer Latynse karakters met hul look-alike-eweknieë te vervang, kan ’n aanvaller:

* Display names, onderwerpe of boodskapliggame skep wat vir die menslike oog legitiem lyk, maar keyword-based detections omseil.
* Domains, sub-domains of URL paths skep wat slagoffers mislei om te glo dat hulle ’n trusted site besoek.

Omdat elke glyph intern deur sy **Unicode code point** geïdentifiseer word, is ’n enkele vervangde karakter genoeg om naïewe string comparisons te omseil (bv. `"Παypal.com"` vs. `"Paypal.com"`).

## Tipiese Phishing Workflow

1. **Skep message content** – Vervang spesifieke Latynse letters in die nagebootste brand / keyword met visueel ononderskeibare karakters uit ’n ander skrif (Greek, Cyrillic, Armenian, Cherokee, ens.).
2. **Register supporting infrastructure** – Register opsioneel ’n homoglyph domain en verkry ’n TLS certificate (die meeste CAs doen geen visual similarity checks nie).
3. **Stuur email / SMS** – Die boodskap bevat homoglyphs in een of meer van die volgende locations:
* Sender display name (bv. `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text of fully qualified domain name
4. **Redirect chain** – Die slagoffer word deur oënskynlik benign websites of URL shorteners gestuur voordat dit by die malicious host uitkom wat credentials harvest / malware lewer.

## Unicode Ranges wat algemeen misbruik word

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Wenke: Volledige Unicode charts is beskikbaar by [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Detection Techniques

### 1. Mixed-Script Inspection

Phishing emails wat op ’n English-speaking organisation gemik is, behoort selde karakters uit verskeie skrifte te meng. ’n Eenvoudige maar effektiewe heuristic is om:

1. Elke karakter van die geïnspekteerde string te itereer.
2. Die code point na sy Unicode block te map.
3. ’n Alert te genereer indien meer as een script teenwoordig is **of** indien nie-Latynse skrifte verskyn waar dit nie verwag word nie (display name, domain, subject, URL, ens.).

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
### 2. Punycode-normalisering (Domeine)

Geïnternasionaliseerde domeinname (IDN'e) word met **punycode** (`xn--`) geënkodeer. Deur elke hostnaam na punycode en daarna terug na Unicode om te skakel, kan dit teen 'n whitelist gematch word of kan ooreenkomskontroles (bv. Levenshtein-afstand) uitgevoer word **nadat** die string genormaliseer is.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph-woordeboeke / Algoritmes

Tools soos **dnstwist** (`--homoglyph`) of **urlcrazy** kan visueel soortgelyke domeinvariasies opspoor en is nuttig vir proaktiewe verwydering / monitering.<sup>[[3]](#references)</sup>

## Voorkoming & Versagting

* Dwing streng DMARC/DKIM/SPF-beleide af – voorkom spoofing vanaf ongemagtigde domeine.
* Implementeer die bogenoemde opsporingslogika in **Secure Email Gateways** en **SIEM/XSOAR** playbooks.
* Merk of plaas boodskappe in kwarantyn waar vertoonnaam-domein ≠ senderdomein.
* Leer gebruikers: kopieer-plak verdagte teks in ’n Unicode-inspekteur, beweeg oor skakels, en moet nooit URL-verkorters vertrou nie.

## Voorbeelde uit die Werklike Wêreld

* Vertoonnaam: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrilliese `С`, `е`, `а`; Cherokee `Ꭲ`; Latynse klein hoofletter `ꮯ`).
* Domeinketting: `bestseoservices.com` ➜ munisipale `/templates`-gids ➜ `kig.skyvaulyt.ru` ➜ vals Microsoft-aanmelding by `mlcorsftpsswddprotcct.approaches.it.com`, beskerm deur ’n pasgemaakte OTP CAPTCHA.
* Spotify-voorstelling: `Sρօtifս`-sender met ’n skakel wat agter `redirects.ca` versteek is.

Hierdie voorbeelde is afkomstig van Unit 42-navorsing (Julie 2025) en illustreer hoe homograafmisbruik met URL-herleiding en CAPTCHA-ontduiking gekombineer word om geoutomatiseerde ontleding te omseil.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
