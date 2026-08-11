# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Shambulio la homograph (pia huitwa homoglyph) hutumia ukweli kwamba **Unicode code points nyingi kutoka kwenye scripts zisizo za Kilatini zinafanana kwa mwonekano au zinafanana sana na ASCII characters**. Kwa kubadilisha character moja au zaidi za Kilatini na counterparts zinazoonekana sawa, mshambuliaji anaweza kuunda:

* Display names, subjects au message bodies zinazoonekana halali kwa macho ya binadamu lakini zinapita detections zinazotegemea keywords.
* Domains, sub-domains au URL paths zinazowadanganya waathiriwa waamini kuwa wanatembelea site inayoaminika.<sup>[[1]](#references)</sup>

Kwa kuwa kila glyph hutambuliwa ndani ya mfumo kwa **Unicode code point** yake, character moja iliyobadilishwa inatosha kushinda string comparisons zisizo na uangalifu (kwa mfano, `"Παypal.com"` dhidi ya `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Mtiririko wa Kawaida wa Phishing

1. **Craft message content** – Badilisha herufi maalum za Kilatini katika brand / keyword inayodanganywa na characters zinazoonekana kutofautika kutoka script nyingine (Greek, Cyrillic, Armenian, Cherokee, n.k.).
2. **Register supporting infrastructure** – Kwa hiari register homoglyph domain na upate TLS certificate (CAs nyingi hazifanyi visual similarity checks).
3. **Send email / SMS** – Ujumbe huwa na homoglyphs katika mojawapo au zaidi ya sehemu zifuatazo:
* Sender display name (kwa mfano, `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text au fully qualified domain name
4. **Redirect chain** – Mwathiriwa hupitishwa kupitia websites zinazoonekana kuwa zisizo na madhara au URL shorteners kabla ya kufika kwenye malicious host inayovuna credentials / kuwasilisha malware.<sup>[[1]](#references)</sup>

## Unicode Ranges Zinazotumiwa Vibaya Mara Nyingi

Mifano ifuatayo ni Unicode blocks zilizo na characters zinazotumiwa mara nyingi kuunda cross-script look-alikes.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Kidokezo: Tumia Unicode code charts kutafuta blocks na code points.

## Mbinu za Detection

### 1. Mixed-Script Inspection

Phishing emails zinazolenga organisation inayozungumza Kiingereza kwa kawaida hazipaswi kuchanganya characters kutoka scripts nyingi. Heuristic rahisi lakini yenye ufanisi ni:

1. Pitia kila character ya string inayokaguliwa.
2. Map code point kwenye jina la script yake au Unicode block.
3. Toa alert ikiwa script zaidi ya moja ipo **au** ikiwa scripts zisizo za Kilatini zinaonekana mahali ambapo hazitarajiwi (display name, domain, subject, URL, n.k.).<sup>[[3]](#references)</sup>

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
### 2. Urekebishaji wa Punycode (Vikoa)

Internationalised Domain Names (IDNs) zina umbo la Unicode na umbo la **Punycode** linalooana na ASCII, lenye kiambishi `xn--`. Badilisha hostnames ziwe umbo la IDNA/Punycode kabla ya kuziweka kwenye allow-list au kuzilinganisha, huku ukihifadhi umbo la Unicode kwa ajili ya kuonyesha.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph Dictionaries / Algorithms

Tools such as **dnstwist** (`--fuzzers homoglyph`) au **urlcrazy** can enumerate visually-similar domain permutations and are useful for proactive takedown / monitoring.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* Enforce strict DMARC/DKIM/SPF policies – prevent spoofing from unauthorised domains.
* Implement the detection logic above in **Secure Email Gateways** and **SIEM/XSOAR** playbooks.
* Flag or quarantine messages where display name domain ≠ sender domain.
* Educate users: copy-paste suspicious text into a Unicode inspector, hover links, never trust URL shorteners.

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com` protected by custom OTP CAPTCHA.
* Spotify impersonation: `Sρօtifս` sender with link hidden behind `redirects.ca`.

These samples originate from Unit 42 research (July 2025) and illustrate how homograph abuse is combined with URL redirection and CAPTCHA evasion to bypass automated analysis.<sup>[[1]](#references)</sup>

## References

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Code Charts](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Unicode Security Mechanisms](https://unicode.org/reports/tr39/)
- [4] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – domain typo and variation generator](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
