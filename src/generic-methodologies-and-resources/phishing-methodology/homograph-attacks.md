# Phishing में Homograph / Homoglyph Attacks

## अवलोकन

एक homograph (जिसे homoglyph भी कहा जाता है) इस तथ्य का दुरुपयोग करता है कि कई **गैर-Latin scripts के Unicode code points, ASCII characters के समान या अत्यंत मिलते-जुलते दिखाई देते हैं**। एक या अधिक Latin characters को उनके समान दिखने वाले counterparts से बदलकर, attacker यह बना सकता है:

* ऐसे display names, subjects या message bodies जो मानव आंखों को वैध दिखें, लेकिन keyword-based detections को bypass कर दें।
* ऐसे domains, sub-domains या URL paths जो victims को यह विश्वास दिलाएं कि वे किसी trusted site पर जा रहे हैं।<sup>[[1]](#references)</sup>

क्योंकि हर glyph की आंतरिक रूप से उसके **Unicode code point** से पहचान होती है, इसलिए एक substituted character naïve string comparisons को विफल करने के लिए पर्याप्त है (जैसे, `"Παypal.com"` बनाम `"Paypal.com"`)।<sup>[[1]](#references)[[3]](#references)</sup>

## सामान्य Phishing Workflow

1. **Message content तैयार करें** – impersonated brand / keyword में मौजूद विशेष Latin letters को किसी अन्य script (Greek, Cyrillic, Armenian, Cherokee आदि) के visually indistinguishable characters से बदलें।
2. **Supporting infrastructure register करें** – वैकल्पिक रूप से एक homoglyph domain register करें और TLS certificate प्राप्त करें (अधिकांश CAs visual similarity checks नहीं करते)।
3. **Email / SMS भेजें** – message में निम्नलिखित एक या अधिक स्थानों पर homoglyphs होते हैं:
* Sender display name (जैसे, `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text या fully qualified domain name
4. **Redirect chain** – victim को credentials harvest करने / malware deliver करने वाले malicious host पर पहुंचने से पहले seemingly benign websites या URL shorteners के माध्यम से redirect किया जाता है।<sup>[[1]](#references)</sup>

## आम तौर पर Abused Unicode Ranges

निम्नलिखित Unicode blocks में cross-script look-alikes बनाने के लिए सामान्यतः उपयोग किए जाने वाले characters होते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: blocks और code points देखने के लिए Unicode code charts का उपयोग करें।

## Detection Techniques

### 1. Mixed-Script Inspection

English-speaking organisation को target करने वाले phishing emails में आमतौर पर multiple scripts के characters को mix नहीं किया जाना चाहिए। एक सरल लेकिन प्रभावी heuristic यह है:

1. inspected string के प्रत्येक character पर iterate करें।
2. code point को उसके script name या Unicode block से map करें।
3. यदि एक से अधिक scripts मौजूद हों **या** जहां अपेक्षित न हों वहां non-Latin scripts दिखाई दें (display name, domain, subject, URL आदि में), तो alert raise करें।<sup>[[3]](#references)</sup>

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

Internationalised Domain Names (IDNs) का Unicode रूप और `xn--` से prefixed ASCII-compatible **Punycode** रूप होता है। Allow-listing या तुलना करने से पहले hostnames को IDNA/Punycode रूप में convert करें, और display के लिए Unicode रूप बनाए रखें।<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph Dictionaries / Algorithms

**dnstwist** (`--fuzzers homoglyph`) या **urlcrazy** जैसे Tools देखने में समान domain permutations की सूची बना सकते हैं और proactive takedown / monitoring के लिए उपयोगी हैं।<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* सख्त DMARC/DKIM/SPF policies लागू करें – unauthorised domains से spoofing को रोकें।
* ऊपर दिए गए detection logic को **Secure Email Gateways** और **SIEM/XSOAR** playbooks में लागू करें।
* उन messages को flag या quarantine करें जिनमें display name domain ≠ sender domain हो।
* Users को शिक्षित करें: suspicious text को Unicode inspector में copy-paste करें, links पर hover करें और URL shorteners पर कभी भरोसा न करें।

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`)।
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHA द्वारा protected fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com`।
* Spotify impersonation: `redirects.ca` के पीछे hidden link वाला `Sρօtifս` sender।

ये samples Unit 42 research (July 2025) से उत्पन्न हुए हैं और दिखाते हैं कि automated analysis को bypass करने के लिए homograph abuse को URL redirection और CAPTCHA evasion के साथ कैसे जोड़ा जाता है।<sup>[[1]](#references)</sup>

## References

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Code Charts](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Unicode Security Mechanisms](https://unicode.org/reports/tr39/)
- [4] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – domain typo and variation generator](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
