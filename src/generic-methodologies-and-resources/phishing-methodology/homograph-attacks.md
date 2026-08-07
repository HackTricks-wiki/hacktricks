# Homograph / Homoglyph Attacks katika Phishing

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Shambulio la homograph (pia huitwa homoglyph) hutumia ukweli kwamba **Unicode code points nyingi kutoka kwenye script zisizo za Kilatini zinaonekana sawa au karibu kabisa na characters za ASCII**. Kwa kubadilisha character moja au zaidi za Kilatini na zinazofanana nazo, mshambuliaji anaweza kuunda:

* Majina ya kuonyeshwa, mada au miili ya ujumbe zinazoonekana halali kwa jicho la binadamu lakini zinapita detections zinazotegemea keywords.
* Domains, sub-domains au URL paths zinazowafanya victims waamini kuwa wanatembelea site inayoaminika.

Kwa sababu kila glyph hutambuliwa internally kwa kutumia **Unicode code point**, character moja iliyobadilishwa inatosha kushinda string comparisons za kawaida (mfano, `"Παypal.com"` dhidi ya `"Paypal.com"`).

## Typical Phishing Workflow

1. **Craft message content** – Badilisha herufi mahususi za Kilatini katika brand / keyword inayodhaniwa kuwa ya mtu au kampuni nyingine, kwa kutumia characters zinazoonekana kutotofautiana kutoka script nyingine (Greek, Cyrillic, Armenian, Cherokee, n.k.).
2. **Register supporting infrastructure** – Kwa hiari, sajili homoglyph domain na pata TLS certificate (CAs nyingi hazifanyi visual similarity checks).
3. **Send email / SMS** – Ujumbe huwa na homoglyphs katika moja au zaidi ya maeneo yafuatayo:
* Sender display name (mfano, `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text au fully qualified domain name
4. **Redirect chain** – Victim hupitishwa kupitia websites zinazoonekana kuwa salama au URL shorteners kabla ya kufikishwa kwenye malicious host inayovuna credentials / kuwasilisha malware.

## Unicode Ranges Commonly Abused

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Chati kamili za Unicode zinapatikana kwenye [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Detection Techniques

### 1. Mixed-Script Inspection

Phishing emails zinazolenga organisation inayozungumza Kiingereza kwa kawaida hazipaswi kuchanganya characters kutoka kwenye scripts nyingi. Heuristic rahisi lakini yenye ufanisi ni:

1. Pitia kila character ya string inayokaguliwa.
2. Mape code point kwenye Unicode block yake.
3. Toa alert ikiwa kuna script zaidi ya moja **au** ikiwa non-Latin scripts zinaonekana mahali ambapo hazitarajiwi (display name, domain, subject, URL, n.k.).

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
### 2. Urekebishaji wa Punycode (Domains)

Internationalised Domain Names (IDNs) husimbwa kwa **punycode** (`xn--`). Kubadilisha kila hostname kuwa punycode na kisha kuirudisha kuwa Unicode huruhusu kulinganisha dhidi ya whitelist au kufanya ukaguzi wa ufanano (kwa mfano, umbali wa Levenshtein) **baada ya** mfuatano huo kusanifishwa.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Kamusi / Algorithms za Homoglyph

Tools kama **dnstwist** (`--homoglyph`) au **urlcrazy** zinaweza kuorodhesha mabadiliko ya domain yanayofanana kimwonekano na ni muhimu kwa kuondoa au kufuatilia vitisho kwa njia ya kiutendaji.<sup>[[3]](#references)</sup>

## Kuzuia na Kupunguza Athari

* Tekeleza sera kali za DMARC/DKIM/SPF – zuia spoofing kutoka kwenye domain zisizoidhinishwa.
* Tekeleza mantiki ya utambuzi iliyo hapo juu katika **Secure Email Gateways** na playbooks za **SIEM/XSOAR**.
* Weka alama au hamishia quarantine ujumbe ambao domain ya display name ≠ domain ya mtumaji.
* Waelimisha watumiaji: nakili na ubandike maandishi ya kutiliwa shaka kwenye Unicode inspector, elekeza mshale juu ya links, na usiwahi kuamini URL shorteners.

## Mifano Halisi

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Msururu wa domain: `bestseoservices.com` ➜ directory ya municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ Microsoft login bandia katika `mlcorsftpsswddprotcct.approaches.it.com` iliyolindwa na custom OTP CAPTCHA.
* Uigaji wa Spotify: mtumaji `Sρօtifս` mwenye link iliyofichwa nyuma ya `redirects.ca`.

Sampuli hizi zilitokana na utafiti wa Unit 42 (Julai 2025) na zinaonyesha jinsi matumizi mabaya ya homograph yanavyounganishwa na URL redirection na CAPTCHA evasion ili kukwepa uchanganuzi wa kiotomatiki.<sup>[[1]](#references)</sup>

## Marejeleo

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
