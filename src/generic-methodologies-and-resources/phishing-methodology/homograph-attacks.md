# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Overview

एक होमोग्राफ (या होमोग्लिफ) हमला इस तथ्य का लाभ उठाता है कि कई **यूनिकोड कोड पॉइंट जो गैर-लैटिन स्क्रिप्ट से हैं, दृश्य रूप से समान या ASCII वर्णों के लिए अत्यधिक समान होते हैं**। एक या अधिक लैटिन वर्णों को उनके समान दिखने वाले समकक्षों से बदलकर, एक हमलावर निम्नलिखित तैयार कर सकता है:

* डिस्प्ले नाम, विषय या संदेश शरीर जो मानव आंख के लिए वैध लगते हैं लेकिन कीवर्ड-आधारित पहचान को बायपास करते हैं।
* डोमेन, उप-डोमेन या URL पथ जो पीड़ितों को यह विश्वास दिलाते हैं कि वे एक विश्वसनीय साइट पर जा रहे हैं।

क्योंकि प्रत्येक ग्लिफ को इसके **यूनिकोड कोड पॉइंट** द्वारा आंतरिक रूप से पहचाना जाता है, एक एकल प्रतिस्थापित वर्ण साधारण स्ट्रिंग तुलना को पराजित करने के लिए पर्याप्त है (जैसे, `"Παypal.com"` बनाम `"Paypal.com"`).

## Typical Phishing Workflow

1. **संदेश सामग्री तैयार करें** – प्रतिरूपित ब्रांड / कीवर्ड में विशिष्ट लैटिन अक्षरों को दूसरे स्क्रिप्ट (ग्रीक, सायरीलिक, आर्मेनियन, चेरोकी, आदि) से दृश्य रूप से अदृश्य वर्णों से बदलें।
2. **समर्थन अवसंरचना पंजीकृत करें** – वैकल्पिक रूप से एक होमोग्लिफ डोमेन पंजीकृत करें और एक TLS प्रमाणपत्र प्राप्त करें (अधिकांश CA दृश्य समानता जांच नहीं करते)।
3. **ईमेल / SMS भेजें** – संदेश में निम्नलिखित स्थानों में से एक या अधिक में होमोग्लिफ होते हैं:
* प्रेषक डिस्प्ले नाम (जैसे, `Ηеlрdеѕk`)
* विषय पंक्ति (`Urgеnt Аctіon Rеquіrеd`)
* हाइपरलिंक पाठ या पूर्ण रूप से योग्य डोमेन नाम
4. **रीडायरेक्ट श्रृंखला** – पीड़ित को पहले से बेनिग्न वेबसाइटों या URL शॉर्टनर्स के माध्यम से भेजा जाता है, इससे पहले कि वह उस दुर्भावनापूर्ण होस्ट पर पहुंचे जो क्रेडेंशियल्स एकत्र करता है / मैलवेयर वितरित करता है।

## Unicode Ranges Commonly Abused

| स्क्रिप्ट | रेंज | उदाहरण ग्लिफ | जैसा दिखता है |
|--------|-------|---------------|------------|
| ग्रीक  | U+0370-03FF | `Η` (U+0397) | लैटिन `H` |
| ग्रीक  | U+0370-03FF | `ρ` (U+03C1) | लैटिन `p` |
| सायरीलिक | U+0400-04FF | `а` (U+0430) | लैटिन `a` |
| सायरीलिक | U+0400-04FF | `е` (U+0435) | लैटिन `e` |
| आर्मेनियन | U+0530-058F | `օ` (U+0585) | लैटिन `o` |
| चेरोकी | U+13A0-13FF | `Ꭲ` (U+13A2) | लैटिन `T` |

> Tip: Full Unicode charts are available at [unicode.org](https://home.unicode.org/).

## Detection Techniques

### 1. Mixed-Script Inspection

अंग्रेजी बोलने वाले संगठन के लिए लक्षित फ़िशिंग ईमेल में अक्सर कई स्क्रिप्ट के वर्णों का मिश्रण नहीं होना चाहिए। एक सरल लेकिन प्रभावी ह्यूरिस्टिक है:

1. निरीक्षित स्ट्रिंग के प्रत्येक वर्ण पर इटरेट करें।
2. कोड पॉइंट को इसके यूनिकोड ब्लॉक से मैप करें।
3. यदि एक से अधिक स्क्रिप्ट मौजूद हैं **या** यदि गैर-लैटिन स्क्रिप्ट अपेक्षित स्थानों (डिस्प्ले नाम, डोमेन, विषय, URL, आदि) पर दिखाई देती हैं तो एक चेतावनी उठाएं।

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
### 2. Punycode सामान्यीकरण (डोमेन)

अंतर्राष्ट्रीयकृत डोमेन नाम (IDNs) को **punycode** (`xn--`) के साथ एन्कोड किया जाता है। प्रत्येक होस्टनाम को punycode में परिवर्तित करना और फिर Unicode में वापस करना एक व्हाइटलिस्ट के खिलाफ मिलान करने या समानता जांच (जैसे, Levenshtein दूरी) करने की अनुमति देता है **बाद में** जब स्ट्रिंग को सामान्यीकृत किया गया हो।
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. होमोग्लिफ शब्दकोश / एल्गोरिदम

Tools such as **dnstwist** (`--homoglyph`) or **urlcrazy** visually-similar domain permutations को सूचीबद्ध कर सकते हैं और सक्रिय रूप से takedown / monitoring के लिए उपयोगी हैं।

## रोकथाम और शमन

* सख्त DMARC/DKIM/SPF नीतियों को लागू करें – अनधिकृत डोमेन से spoofing को रोकें।
* **Secure Email Gateways** और **SIEM/XSOAR** playbooks में ऊपर दिए गए detection logic को लागू करें।
* उन संदेशों को फ्लैग या क्वारंटाइन करें जहाँ display name domain ≠ sender domain।
* उपयोगकर्ताओं को शिक्षित करें: संदिग्ध पाठ को Unicode inspector में कॉपी-पेस्ट करें, लिंक पर होवर करें, URL शॉर्टनर्स पर कभी भरोसा न करें।

## वास्तविक दुनिया के उदाहरण

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`)।
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com` जो custom OTP CAPTCHA द्वारा सुरक्षित है।
* Spotify impersonation: `Sρօtifւ` sender with link hidden behind `redirects.ca`।

ये उदाहरण Unit 42 research (July 2025) से उत्पन्न होते हैं और दिखाते हैं कि कैसे होमोग्राफ दुरुपयोग को URL redirection और CAPTCHA evasion के साथ मिलाकर स्वचालित विश्लेषण को बायपास किया जाता है।

## संदर्भ

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
