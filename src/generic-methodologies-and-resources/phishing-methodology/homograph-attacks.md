# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Overview

Shambulio la homograph (pia inajulikana kama homoglyph) linatumia ukweli kwamba **mifumo mingi ya Unicode kutoka kwa maandiko yasiyo ya Kilatini ni sawa kabisa au yanafanana sana na wahusika wa ASCII**. Kwa kubadilisha wahusika mmoja au zaidi wa Kilatini na wenzao wanaofanana, mshambuliaji anaweza kuunda:

* Majina ya kuonyesha, mada au maudhui ya ujumbe yanayoonekana kuwa halali kwa jicho la binadamu lakini yanapita kwenye ugunduzi wa msingi wa maneno muhimu.
* Majina ya kikoa, sub-kikoa au njia za URL ambazo zinawadanganya waathirika kuamini wanatembelea tovuti ya kuaminika.

Kwa sababu kila glyph inatambulika ndani kwa **nambari ya Unicode**, wahusika mmoja tu aliyebadilishwa inatosha kushinda kulinganisha nyuzi zisizo na busara (mfano, `"Παypal.com"` dhidi ya `"Paypal.com"`).

## Typical Phishing Workflow

1. **Craft message content** – Badilisha herufi maalum za Kilatini katika chapa / neno muhimu linalojulikana na wahusika wasioonekana kutoka kwa maandiko mengine (Kigiriki, Kirusi, Kiarumeni, Cherokee, nk.).
2. **Register supporting infrastructure** – Kurekebisha kikoa cha homoglyph na kupata cheti cha TLS (zaidi ya CAs hazifanyi ukaguzi wa kufanana kwa kuona).
3. **Send email / SMS** – Ujumbe unajumuisha homoglyphs katika moja au zaidi ya maeneo yafuatayo:
* Jina la kuonyesha la mtumaji (mfano, `Ηеlрdеѕk`)
* Mstari wa mada (`Urgеnt Аctіon Rеquіrеd`)
* Maandishi ya kiungo au jina kamili la kikoa
4. **Redirect chain** – Mwathirika anarudishwa kupitia tovuti zinazonekana kuwa salama au wafupishaji wa URL kabla ya kutua kwenye mwenyeji mbaya anayekusanya akidi / kupeleka malware.

## Unicode Ranges Commonly Abused

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Full Unicode charts are available at [unicode.org](https://home.unicode.org/).

## Detection Techniques

### 1. Mixed-Script Inspection

Barua pepe za phishing zinazolenga shirika linalozungumza Kiingereza zinapaswa nadra kuchanganya wahusika kutoka kwa mifumo mingi. Heuristics rahisi lakini yenye ufanisi ni:

1. Pitia kila wahusika wa nyuzi inayokaguliwa.
2. Ramani ya nambari ya nambari kwa kizuizi chake cha Unicode.
3. Pandisha arifa ikiwa mifumo zaidi ya mmoja ipo **au** ikiwa mifumo isiyo ya Kilatini inaonekana mahali ambapo haitarajiwi (jina la kuonyesha, kikoa, mada, URL, nk.).

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
### 2. Punycode Normalisation (Domains)

Majina ya Kikoa ya Kimataifa (IDNs) yanakodishwa kwa **punycode** (`xn--`). Kubadilisha kila jina la mwenyeji kuwa punycode na kisha kurudi kwenye Unicode kunaruhusu kulinganisha dhidi ya orodha ya kibali au kufanya ukaguzi wa kufanana (kwa mfano, umbali wa Levenshtein) **baada ya** mfuatano kuwa wa kawaida.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Kamusi za Homoglyph / Algorithms

Tools such as **dnstwist** (`--homoglyph`) or **urlcrazy** can enumerate visually-similar domain permutations and are useful for proactive takedown / monitoring.

## Kuzuia & Kupunguza

* Tekeleza sera kali za DMARC/DKIM/SPF – zuia uongo kutoka kwa maeneo yasiyoidhinishwa.
* Tekeleza mantiki ya kugundua hapo juu katika **Secure Email Gateways** na **SIEM/XSOAR** playbooks.
* Flag au karantini ujumbe ambapo jina la kuonyesha domain ≠ domain ya mtumaji.
* Elimisha watumiaji: nakala-paste maandiko ya shaka kwenye mkaguzi wa Unicode, piga juu ya viungo, kamwe usiamini URL shorteners.

## Mifano ya Uhalisia

* Jina la kuonyesha: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Mnyororo wa domain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com` protected by custom OTP CAPTCHA.
* Spotify impersonation: `Sρօtifւ` sender with link hidden behind `redirects.ca`.

These samples originate from Unit 42 research (July 2025) and illustrate how homograph abuse is combined with URL redirection and CAPTCHA evasion to bypass automated analysis.

## Marejeo

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
