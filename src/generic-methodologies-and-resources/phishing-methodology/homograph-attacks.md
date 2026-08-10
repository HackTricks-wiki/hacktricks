# Homograph / Homoglyph Attacks in Phishing

## Muhtasari

Shambulio la homograph (pia huitwa homoglyph) hutumia ukweli kwamba **Unicode code points nyingi kutoka kwenye maandishi yasiyo ya Kilatini zinafanana kimuonekano au zinafanana sana na ASCII characters**. Kwa kubadilisha character moja au zaidi za Kilatini na zinazofanana nazo, mshambuliaji anaweza kuunda:

* Display names, subjects au message bodies zinazoonekana halali kwa macho ya binadamu lakini zinapita detections zinazotegemea keywords.
* Domains, sub-domains au URL paths zinazowafanya waathiriwa kuamini kuwa wanatembelea site inayoaminika.<sup>[[1]](#references)</sup>

Kwa kuwa kila glyph hutambuliwa internally kwa kutumia **Unicode code point** yake, character moja iliyobadilishwa inatosha kushinda string comparisons zisizo na ulinzi wa kutosha (kwa mfano, `"Παypal.com"` dhidi ya `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Typical Phishing Workflow

1. **Craft message content** – Badilisha Latin letters maalum katika brand / keyword inayofanyiwa impersonation kwa characters zinazofanana kimuonekano kutoka kwenye script nyingine (Greek, Cyrillic, Armenian, Cherokee, n.k.).
2. **Register supporting infrastructure** – Kwa hiari, register homoglyph domain na upate TLS certificate (CAs nyingi hazifanyi visual similarity checks).
3. **Send email / SMS** – Ujumbe una homoglyphs katika mojawapo au zaidi ya sehemu zifuatazo:
* Sender display name (kwa mfano, `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text au fully qualified domain name
4. **Redirect chain** – Victim hupitishwa kupitia websites zinazoonekana kuwa salama au URL shorteners kabla ya kufika kwenye malicious host inayokusanya credentials / kupeleka malware.<sup>[[1]](#references)</sup>

## Unicode Ranges Commonly Abused

Mifano ifuatayo ni Unicode blocks zenye characters zinazotumiwa kwa kawaida kuunda look-alikes za cross-script.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Tumia Unicode code charts kutafuta blocks na code points.

## Detection Techniques

### 1. Mixed-Script Inspection

Phishing emails zinazolenga organisation inayozungumza Kiingereza kwa kawaida hazipaswi kuchanganya characters kutoka kwenye scripts nyingi. Heuristic rahisi lakini yenye ufanisi ni:

1. Pitia kila character ya string inayokaguliwa.
2. Map code point kwenye script name au Unicode block yake.
3. Toa alert ikiwa script zaidi ya moja ipo **au** ikiwa non-Latin scripts zinaonekana mahali ambapo hazitarajiwi (display name, domain, subject, URL, n.k.).<sup>[[3]](#references)</sup>

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

Majina ya Vikoa vya Kimataifa (IDNs) yana fomu ya Unicode na fomu ya **Punycode** inayooana na ASCII, yenye kiambishi awali `xn--`. Badilisha hostnames ziwe fomu ya IDNA/Punycode kabla ya kuziweka kwenye orodha ya kuruhusiwa au kuzilinganisha, huku ukihifadhi fomu ya Unicode kwa ajili ya kuonyeshwa.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Kamusi / Algorithms za Homoglyph

Tools kama **dnstwist** (`--fuzzers homoglyph`) au **urlcrazy** zinaweza kuorodhesha permutations za domains zinazofanana kimuonekano na ni muhimu kwa kuondoa vitisho proactively / monitoring.<sup>[[4]](#references)[[5]](#references)</sup>

## Kinga na Upunguzaji wa Hatari

* Tekeleza sera kali za DMARC/DKIM/SPF – zuia spoofing kutoka domains zisizoidhinishwa.
* Tekeleza logic ya detection iliyo hapo juu katika **Secure Email Gateways** na playbooks za **SIEM/XSOAR**.
* Weka alama au weka karantini ujumbe ambapo domain ya display name ≠ domain ya mtumaji.
* Waelimishe users: copy-paste maandishi ya kutiliwa shaka kwenye Unicode inspector, elekeza kipanya juu ya links, na usiwahi kuamini URL shorteners.

## Mifano ya Ulimwengu Halisi

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Mfuatano wa domains: `bestseoservices.com` ➜ directory ya `/templates` ya manispaa ➜ `kig.skyvaulyt.ru` ➜ login bandia ya Microsoft kwenye `mlcorsftpsswddprotcct.approaches.it.com`, iliyolindwa na custom OTP CAPTCHA.
* Kujifanya Spotify: mtumaji `Sρօtifս` mwenye link iliyofichwa nyuma ya `redirects.ca`.

Sampuli hizi zimetokana na utafiti wa Unit 42 (Julai 2025) na zinaonyesha jinsi matumizi mabaya ya homograph yanavyochanganywa na URL redirection na CAPTCHA evasion ili kupita automated analysis.<sup>[[1]](#references)</sup>

## References

- [1] [Udanganyifu wa Homograph: Si Kila Kitu Ni Kama Kinavyoonekana](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Chati za Misimbo ya Herufi za Unicode](https://www.unicode.org/charts/)
- [3] [Kiwango cha Kiufundi cha Unicode #39: Mbinu za Usalama za Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – engine ya permutations za domains](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – generator ya makosa ya kuandika na variations za domains](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): Ufafanuzi na Mfumo wa Hati](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
