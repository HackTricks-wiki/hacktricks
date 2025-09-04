# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

To detect a phishing attempt it's important to **understand the phishing techniques that are being used nowadays**. On the parent page of this post, you can find this information, so if you aren't aware of which techniques are being used today I recommend you to go to the parent page and read at least that section.

This post is based on the idea that the **attackers will try to somehow mimic or use the victim's domain name**. If your domain is called `example.com` and you are phished using a completely different domain name for some reason like `youwonthelottery.com`, these techniques aren't going to uncover it.

## Domain name variations

It's kind of **easy** to **uncover** those **phishing** attempts that will use a **similar domain** name inside the email.\
It's enough to **generate a list of the most probable phishing names** that an attacker may use and **check** if it's **registered** or just check if there is any **IP** using it.

### Finding suspicious domains

For this purpose, you can use any of the following tools. Note that these tools will also perform DNS requests automatically to check if the domain has any IP assigned to it:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: If you generate a candidate list, also feed it into your DNS resolver logs to detect **NXDOMAIN lookups from inside your org** (users trying to reach a typo before the attacker actually registers it). Sinkhole or pre-block these domains if policy allows.

### Bitflipping

**You can find a short the explanation of this technique in the parent page. Or read the original research in** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

For example, a 1 bit modification in the domain microsoft.com can transform it into _windnws.com._\
**Attackers may register as many bit-flipping domains as possible related to the victim to redirect legitimate users to their infrastructure**.

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

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

Many phishing kits reuse favicons from the brand they impersonate. Internet-wide scanners compute a MurmurHash3 of the base64-encoded favicon. You can generate the hash and pivot on it:

Python example (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Query Shodan: `http.favicon.hash:309020573`
- With tooling: look at community tools like favfreak to generate hashes and dorks for Shodan/ZoomEye/Censys.

Notes
- Favicons are reused; treat matches as leads and validate content and certs before acting.
- Combine with domain-age and keyword heuristics for better precision.

### URL telemetry hunting (urlscan.io)

`urlscan.io` stores historical screenshots, DOM, requests and TLS metadata of submitted URLs. You can hunt for brand abuse and clones:

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

RDAP returns machine-readable creation events. Useful to flag **newly registered domains (NRDs)**.

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Enrich your pipeline by tagging domains with registration age buckets (e.g., <7 days, <30 days) and prioritise triage accordingly.

### TLS/JAx fingerprints to spot AiTM infrastructure

Modern credential-phishing increasingly uses **Adversary-in-the-Middle (AiTM)** reverse proxies (e.g., Evilginx) to steal session tokens. You can add network-side detections:

- Log TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) at egress. Some Evilginx builds have been observed with stable JA4 client/server values. Alert on known-bad fingerprints only as a weak signal and always confirm with content and domain intel.
- Proactively record TLS certificate metadata (issuer, SAN count, wildcard use, validity) for lookalike hosts discovered via CT or urlscan and correlate with DNS age and geolocation.

> Note: Treat fingerprints as enrichment, not as sole blockers; frameworks evolve and may randomise or obfuscate.

### Domain names using keywords

The parent page also mentions a domain name variation technique that consists of putting the **victim's domain name inside a bigger domain** (e.g. paypal-financial.com for paypal.com).

#### Certificate Transparency

It's not possible to take the previous "Brute-Force" approach but it's actually **possible to uncover such phishing attempts** also thanks to certificate transparency. Every time a certificate is emitted by a CA, the details are made public. This means that by reading the certificate transparency or even monitoring it, it's **possible to find domains that are using a keyword inside its name** For example, if an attacker generates a certificate of [https://paypal-financial.com](https://paypal-financial.com), seeing the certificate it's possible to find the keyword "paypal" and know that suspicious email is being used.

The post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggests that you can use Censys to search for certificates affecting a specific keyword and filter by date (only "new" certificates) and by the CA issuer "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

However, you can do "the same" using the free web [**crt.sh**](https://crt.sh). You can **search for the keyword** and the **filter** the results **by date and CA** if you wish.

![](<../../images/image (519).png>)

Using this last option you can even use the field Matching Identities to see if any identity from the real domain matches any of the suspicious domains (note that a suspicious domain can be a false positive).

**Another alternative** is the fantastic project called [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream provides a real-time stream of newly generated certificates which you can use to detect specified keywords in (near) real-time. In fact, there is a project called [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) that does just that.

Practical tip: when triaging CT hits, prioritise NRDs, untrusted/unknown registrars, privacy-proxy WHOIS, and certs with very recent `NotBefore` times. Maintain an allowlist of your owned domains/brands to reduce noise.

#### **New domains**

**One last alternative** is to gather a list of **newly registered domains** for some TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) provides such service) and **check the keywords in these domains**. However, long domains usually use one or more subdomains, therefore the keyword won't appear inside the FLD and you won't be able to find the phishing subdomain.

Additional heuristic: treat certain **file-extension TLDs** (e.g., `.zip`, `.mov`) with extra suspicion in alerting. These are commonly confused for filenames in lures; combine the TLD signal with brand keywords and NRD age for better precision.

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/ 
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
