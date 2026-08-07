# Phishing में Homograph / Homoglyph Attacks

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

एक homograph (जिसे homoglyph भी कहा जाता है) attack इस तथ्य का दुरुपयोग करता है कि कई **non-Latin scripts के Unicode code points देखने में ASCII characters के समान या उनसे बेहद मिलते-जुलते होते हैं**। एक या अधिक Latin characters को उनके जैसे दिखने वाले counterparts से बदलकर attacker निम्नलिखित तैयार कर सकता है:

* ऐसे display names, subjects या message bodies जो मानव आंखों को वैध दिखें, लेकिन keyword-based detections को bypass कर दें।
* ऐसे domains, sub-domains या URL paths जो victims को यह विश्वास दिला दें कि वे किसी trusted site पर जा रहे हैं।

क्योंकि प्रत्येक glyph की आंतरिक पहचान उसके **Unicode code point** से होती है, इसलिए naïve string comparisons को विफल करने के लिए केवल एक बदला हुआ character ही पर्याप्त है (जैसे, `"Παypal.com"` बनाम `"Paypal.com"`)।

## सामान्य Phishing Workflow

1. **Message content तैयार करें** – impersonated brand / keyword में मौजूद विशेष Latin letters को किसी अन्य script (Greek, Cyrillic, Armenian, Cherokee आदि) के देखने में समान characters से बदलें।
2. **Supporting infrastructure register करें** – वैकल्पिक रूप से एक homoglyph domain register करें और TLS certificate प्राप्त करें (अधिकांश CAs visual similarity checks नहीं करते)।
3. **Email / SMS भेजें** – message में निम्नलिखित में से एक या अधिक स्थानों पर homoglyphs शामिल होते हैं:
* Sender display name (जैसे, `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text या fully qualified domain name
4. **Redirect chain** – credentials harvest करने / malware deliver करने वाले malicious host पर पहुंचने से पहले victim को seemingly benign websites या URL shorteners के माध्यम से redirect किया जाता है।

## आम तौर पर Abused Unicode Ranges

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Full Unicode charts [unicode.org](https://home.unicode.org/) पर उपलब्ध हैं।<sup>[[2]](#references)</sup>

## Detection Techniques

### 1. Mixed-Script Inspection

किसी English-speaking organisation को लक्षित करने वाले Phishing emails में कई scripts के characters का मिश्रण सामान्यतः नहीं होना चाहिए। एक सरल लेकिन प्रभावी heuristic यह है:

1. Inspected string के प्रत्येक character पर iterate करें।
2. Code point को उसके Unicode block से map करें।
3. यदि एक से अधिक scripts मौजूद हों **या** non-Latin scripts ऐसी जगह दिखाई दें जहां उनकी अपेक्षा नहीं है (display name, domain, subject, URL आदि), तो alert raise करें।

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

Internationalised Domain Names (IDNs) को **punycode** (`xn--`) का उपयोग करके encode किया जाता है। प्रत्येक hostname को punycode में और फिर वापस Unicode में convert करने से whitelist के विरुद्ध matching या similarity checks (जैसे, Levenshtein distance) string के **normalised** होने **के बाद** किए जा सकते हैं।
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Dictionaries / Algorithms

**dnstwist** (`--homoglyph`) या **urlcrazy** जैसे Tools दृष्टिगत रूप से समान domain permutations की गणना कर सकते हैं और proactive takedown / monitoring के लिए उपयोगी हैं।<sup>[[3]](#references)</sup>

## Prevention & Mitigation

* सख्त DMARC/DKIM/SPF policies लागू करें – unauthorised domains से spoofing रोकें।
* ऊपर दिए गए detection logic को **Secure Email Gateways** और **SIEM/XSOAR** playbooks में लागू करें।
* उन messages को flag या quarantine करें जिनमें display name domain ≠ sender domain हो।
* Users को educate करें: suspicious text को Unicode inspector में copy-paste करें, links पर hover करें और URL shorteners पर कभी भरोसा न करें।

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`)।
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHA द्वारा protected fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com`।
* Spotify impersonation: `redirects.ca` के पीछे hidden link वाला `Sρօtifս` sender।

ये samples Unit 42 research (July 2025) से प्राप्त हुए हैं और दर्शाते हैं कि automated analysis को bypass करने के लिए homograph abuse को URL redirection और CAPTCHA evasion के साथ कैसे combine किया जाता है।<sup>[[1]](#references)</sup>

## References

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
