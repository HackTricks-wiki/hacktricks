# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Overview

A homograph (aka homoglyph) attack abuses the fact that many **Unicode code points from non-Latin scripts are visually identical or extremely similar to ASCII characters**. By replacing one or more Latin characters with their look-alike counterparts, an attacker can craft:

* Display names, subjects or message bodies that look legitimate to the human eye but bypass keyword-based detections.
* Domains, sub-domains or URL paths that fool victims into believing they are visiting a trusted site.<sup>[[1]](#references)</sup>

Because every glyph is identified internally by its **Unicode code point**, a single substituted character is enough to defeat naïve string comparisons (e.g., `"Παypal.com"` vs. `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Typical Phishing Workflow

1. **Craft message content** – Replace specific Latin letters in the impersonated brand / keyword with visually indistinguishable characters from another script (Greek, Cyrillic, Armenian, Cherokee, etc.).
2. **Register supporting infrastructure** – Optionally register a homoglyph domain and obtain a TLS certificate (most CAs do no visual similarity checks).
3. **Send email / SMS** – The message contains homoglyphs in one or more of the following locations:
   * Sender display name (e.g., `Ηеlрdеѕk`)
   * Subject line (`Urgеnt Аctіon Rеquіrеd`)
   * Hyperlink text or fully qualified domain name
4. **Redirect chain** – Victim is bounced through seemingly benign websites or URL shorteners before landing on the malicious host that harvests credentials / delivers malware.<sup>[[1]](#references)</sup>

## Unicode Ranges Commonly Abused

The following examples are Unicode blocks that contain characters commonly used to create cross-script look-alikes.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Use the Unicode code charts to look up blocks and code points.

## Detection Techniques

### 1. Mixed-Script Inspection

Phishing emails aimed at an English-speaking organisation should rarely mix characters from multiple scripts.  A simple but effective heuristic is to:

1. Iterate each character of the inspected string.
2. Map the code point to its script name or Unicode block.
3. Raise an alert if more than one script is present **or** if non-Latin scripts appear where they are not expected (display name, domain, subject, URL, etc.).<sup>[[3]](#references)</sup>

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

Internationalised Domain Names (IDNs) have a Unicode form and an ASCII-compatible **Punycode** form prefixed with `xn--`. Convert hostnames to the IDNA/Punycode form before allow-listing or comparing them, while retaining the Unicode form for display.<sup>[[6]](#references)</sup>

```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```

### 3. Homoglyph Dictionaries / Algorithms

Tools such as **dnstwist** (`--fuzzers homoglyph`) or **urlcrazy** can enumerate visually-similar domain permutations and are useful for proactive takedown / monitoring.<sup>[[4]](#references)[[5]](#references)</sup>

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
