# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

To detect a phishing attempt it's important to **understand the phishing techniques that are being used nowadays**. On the parent page of this post, you can find this information, so if you aren't aware of which techniques are being used today I recommend you to go to the parent page and read at least that section.

This post is based on the idea that the **attackers will try to somehow mimic or use the victim's domain name**. If your domain is called `example.com` and you are phished using a completely different domain name for some reason like `youwonthelottery.com`, these techniques aren't going to uncover it.

## Domain name variations

It's kind of **easy** to **uncover** those **phishing** attempts that will use a **similar domain** name inside the email.\
It's enough to **generate a list of the most probable phishing names** that an attacker may use and **check** if it's **registered** or just check if there is any **IP** using it.

### Finding suspicious domains

For this purpose, you can use any of the following tools. Both resolve candidate domains to check whether they are in use.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: If you generate a candidate list, also feed it into your DNS resolver logs to detect **NXDOMAIN lookups from inside your org** (users trying to reach a typo before the attacker actually registers it). Sinkhole or pre-block these domains if policy allows.

### Bitflipping

**For a short explanation, see the parent page; for primary Windows.com bitsquatting research, see [Remy Hax's write-up](https://remyhax.xyz/posts/bitsquatting-windows/) and [BleepingComputer's report](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

For example, a 1 bit modification in the domain microsoft.com can transform it into _windnws.com._\
**Attackers may register as many bit-flipping domains as possible related to the victim to redirect legitimate users to their infrastructure**.<sup>[[1]](#references)[[2]](#references)</sup>

**All possible bit-flipping domain names should be also monitored.**

If you also need to consider homoglyph/IDN lookalikes (e.g., mixing Latin/Cyrillic characters), check:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

Once you have a list of potential suspicious domain names you should **check** them (mainly the ports HTTP and HTTPS) to **see if they are using some login form similar** to someone of the victim's domain.\
You could also check port 3333 to see if it's open and running an instance of `gophish`.\
It's also interesting to know **how old each discovered suspicions domain is**, the younger it's the riskier it is.\
You can also get **screenshots** of the HTTP and/or HTTPS suspicious web page to see if it's suspicious and in that case **access it to take a deeper look**.

### Advanced checks

If you want to go one step further I would recommend you to **monitor those suspicious domains and search for more** once in a while (every day? it only takes a few seconds/minutes). You should also **check** the open **ports** of the related IPs and **search for instances of `gophish` or similar tools** (yes, attackers also make mistakes) and **monitor the HTTP and HTTPS web pages of the suspicious domains and subdomains** to see if they have copied any login form from the victim's web pages.\
In order to **automate this** I would recommend having a list of login forms of the victim's domains, spider the suspicious web pages and comparing each login form found inside the suspicious domains with each login form of the victim's domain using something like `ssdeep`.\
If you have located the login forms of the suspicious domains, you can try to **send junk credentials** and **check if it's redirecting you to the victim's domain**.

---

### Hunting by favicon and web fingerprints (Shodan/Censys)

Many phishing kits reuse favicons from the brand they impersonate. Shodan hashes its base64-encoded favicon data with MurmurHash3, while Censys exposes its own favicon hash fields.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> You can generate a Shodan-compatible hash and pivot on it:

Python example (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Query Shodan: `http.favicon.hash:309020573`
- With tooling: look at community tools like favfreak to calculate hashes and generate Shodan dorks.<sup>[[16]](#references)</sup>

Notes
- Favicons are reused; treat matches as leads and validate content and certs before acting.
- Combine with domain-age and keyword heuristics for better precision.

### URL telemetry hunting (urlscan.io)

`urlscan.io` stores historical screenshots, DOM, requests and TLS metadata of submitted URLs. You can hunt for brand abuse and clones:<sup>[[8]](#references)</sup>

Example queries (UI or API):
- Find lookalikes excluding your legit domains: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Find sites hotlinking your assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restrict to recent results: append `AND date:>now-7d`

API example:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

From the JSON, pivot on:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` to spot very new certs for lookalikes
- `task.source` values like `certstream-suspicious` to tie findings to CT monitoring

### Domain age via RDAP (scriptable)

RDAP returns machine-readable registration events. Useful to flag **newly registered domains (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Enrich your pipeline by tagging domains with registration age buckets (e.g., <7 days, <30 days) and prioritise triage accordingly.

### TLS/JAx fingerprints to spot AiTM infrastructure

Credential-phishing can use **Adversary-in-the-Middle (AiTM)** reverse proxies (e.g., Evilginx) to steal session tokens.<sup>[[11]](#references)</sup> You can add network-side detections:

- Log TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) at egress. Some Evilginx builds have been observed with stable JA4 client/server values. Alert on known-bad fingerprints only as a weak signal and always confirm with content and domain intel.<sup>[[12]](#references)</sup>
- Proactively record TLS certificate metadata (issuer, SAN count, wildcard use, validity) for lookalike hosts discovered via CT or urlscan and correlate with DNS age and geolocation.

> Note: Treat fingerprints as enrichment, not as sole blockers; frameworks evolve and may randomise or obfuscate.

### Domain names using keywords

The parent page also mentions a domain name variation technique that consists of putting the **victim's domain name inside a bigger domain** (e.g. paypal-financial.com for paypal.com).

#### Certificate Transparency

Certificate Transparency (CT) logs expose certificate identities, so searching Subject or SAN names for brand keywords can reveal lookalike domains (for example, a certificate for `paypal-financial.com` exposes the `paypal` keyword). Filter results by issuance date and CA when useful, and validate candidates because keyword matches can be false positives.<sup>[[13]](#references)</sup>

Patrik Hudak's original [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) demonstrates this workflow in Censys, including filters for certificate date and issuer such as Let's Encrypt.<sup>[[13]](#references)</sup>

![Censys certificate search results used to identify lookalike domains](<../../images/image (1115).png>)

You can also use the free [**crt.sh**](https://crt.sh) service to search for a keyword and filter results by date and CA.<sup>[[13]](#references)</sup>

![crt.sh keyword search for suspicious certificate identities](<../../images/image (519).png>)

Its Matching Identities field can help compare identities from the real domain with suspicious domains, but treat matches as leads rather than proof.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) streams CT updates in near real time, and [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) consumes that stream to score suspicious certificate names.<sup>[[14]](#references)[[15]](#references)</sup>

Practical tip: when triaging CT hits, prioritise NRDs, untrusted/unknown registrars, privacy-proxy WHOIS, and certs with very recent `NotBefore` times. Maintain an allowlist of your owned domains/brands to reduce noise.

#### **New domains**

A second option is to collect newly registered domains by TLD (for example, via [Whoxy](https://www.whoxy.com/newly-registered-domains/)) and filter for brand keywords. This misses phishing hosted on subdomains when the keyword is absent from the registered domain.<sup>[[13]](#references)</sup>

Additional heuristic: treat certain **file-extension TLDs** (e.g., `.zip`, `.mov`) with extra suspicion in alerting. These are commonly confused for filenames in lures; combine the TLD signal with brand keywords and NRD age for better precision.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Deep Dive: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON Responses for the Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: How to prevent, detect, and respond to cloud token theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Introducing CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)

{{#include ../../banners/hacktricks-training.md}}
