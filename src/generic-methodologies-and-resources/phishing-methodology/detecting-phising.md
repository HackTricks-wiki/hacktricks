# Phishing opspoor

## Inleiding

Om 'n phishing-poging op te spoor, is dit belangrik om **die phishing-tegnieke wat tans gebruik word te verstaan**. Op die ouerbladsy van hierdie plasing kan jy hierdie inligting vind; dus, as jy nie bewus is van watter tegnieke vandag gebruik word nie, beveel ek aan dat jy na die ouerbladsy gaan en minstens daardie afdeling lees.

Hierdie plasing is gebaseer op die idee dat die **aanvallers op een of ander manier die slagoffer se domeinnaam sal probeer naboots of gebruik**. As jou domein `example.com` heet en jy om een of ander rede met 'n heeltemal ander domeinnaam soos `youwonthelottery.com` ge-phish word, gaan hierdie tegnieke dit nie blootlê nie.

## Variasies in domeinname

Dit is redelik **maklik** om daardie **phishing**-pogings te **ontbloot** wat 'n **soortgelyke domeinnaam** binne die e-pos sal gebruik.\
Dit is voldoende om **'n lys te genereer van die mees waarskynlike phishing-name** wat 'n aanvaller kan gebruik en te **kontroleer** of dit **geregistreer** is, of bloot te kontroleer of enige **IP** dit gebruik.

### Vind van verdagte domeine

Vir hierdie doel kan jy enige van die volgende tools gebruik. Albei resolve kandidaatdomeine om te kontroleer of hulle gebruik word.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Wenk: As jy 'n kandidaatly genereer, voer dit ook in jou DNS-resolverlogs in om **NXDOMAIN-lookups van binne jou organisasie** op te spoor (gebruikers wat 'n tikfout probeer bereik voordat die aanvaller dit werklik registreer). Sinkhole of blokkeer hierdie domeine vooraf indien beleid dit toelaat.

### Bitflipping

**Vir 'n kort verduideliking, sien die ouerbladsy; vir primêre Windows.com bitsquatting-navorsing, sien [Remy Hax se write-up](https://remyhax.xyz/posts/bitsquatting-windows/) en [BleepingComputer se verslag](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Byvoorbeeld, kan 'n 1-bis-wysiging in die domein microsoft.com dit in _windnws.com_ verander.\
**Aanvallers kan soveel as moontlik bit-flipping-domeine registreer wat met die slagoffer verband hou, om wettige gebruikers na hul infrastruktuur te herlei**.<sup>[[1]](#references)[[2]](#references)</sup>

**Alle moontlike bit-flipping-domeinname behoort ook gemonitor te word.**

As jy ook homoglyph/IDN-lookalikes moet oorweeg (byvoorbeeld die vermenging van Latynse en Cyrilliese karakters), kyk na:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basiese kontroles

Sodra jy 'n lys van potensieel verdagte domeinname het, behoort jy dit te **kontroleer** (hoofsaaklik die HTTP- en HTTPS-poorte) om te **sien of hulle 'n login-vorm gebruik wat soortgelyk is** aan iemand van die slagoffer se domein.\
Jy kan ook poort 3333 kontroleer om te sien of dit oop is en 'n instansie van `gophish` uitvoer.\
Dit is ook interessant om te weet **hoe oud elke ontdekte verdagte domein is**; hoe jonger dit is, hoe groter is die risiko.\
Jy kan ook **screenshots** van die HTTP- en/of HTTPS-verdagte webblad kry om te sien of dit verdag is en dit in daardie geval **toegang om dit van nader te ondersoek**.

### Gevorderde kontroles

As jy een stap verder wil gaan, beveel ek aan dat jy **daardie verdagte domeine monitor en van tyd tot tyd na meer domeine soek** (elke dag? Dit neem slegs 'n paar sekondes/minute). Jy behoort ook die oop **poorte** van die verwante IP's te **kontroleer** en te **soek na instansies van `gophish` of soortgelyke tools** (ja, aanvallers maak ook foute), en die HTTP- en HTTPS-webbladsye van die verdagte domeine en subdomeine te **monitor** om te sien of hulle enige login-vorm van die slagoffer se webbladsye gekopieer het.\
Om dit te **outomatiseer**, beveel ek aan dat jy 'n lys van login-vorms van die slagoffer se domeine byhou, die verdagte webbladsye spider en elke login-vorm wat binne die verdagte domeine gevind word, vergelyk met elke login-vorm van die slagoffer se domein deur iets soos `ssdeep` te gebruik.\
As jy die login-vorms van die verdagte domeine opgespoor het, kan jy probeer om **gemorsbewyse** te stuur en te **kontroleer of dit jou na die slagoffer se domein herlei**.

---

### Jag deur favicon- en webvingerafdrukke (Shodan/Censys)

Baie phishing-kits hergebruik favicons van die handelsmerk wat hulle naboots. Shodan hash sy base64-geënkodeerde favicon-data met MurmurHash3, terwyl Censys sy eie favicon-hash-velde beskikbaar stel.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Jy kan 'n Shodan-versoenbare hash genereer en daarop pivot:

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Doen navraag by Shodan: `http.favicon.hash:309020573`
- Met tooling: kyk na community tools soos favfreak om hashes te bereken en Shodan dorks te genereer.<sup>[[16]](#references)</sup>

Notas
- Favicons word hergebruik; behandel passings as leidrade en valideer inhoud en sertifikate voordat jy optree.
- Kombineer dit met heuristieke vir domeinouderdom en sleutelwoorde vir beter presisie.

### Jag op URL-telemetrie (urlscan.io)

`urlscan.io` stoor historiese skermkiekies, DOM, versoeke en TLS-metadata van ingediende URLs. Jy kan jag vir handelsmerkmisbruik en klone:<sup>[[8]](#references)</sup>

Voorbeeldnavrae (UI of API):
- Vind lookalikes wat jou wettige domeine uitsluit: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Vind werwe wat jou bates hotlink: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Beperk tot onlangse resultate: voeg `AND date:>now-7d` by

API-voorbeeld:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Vanuit die JSON, fokus op:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` om baie nuwe sertifikate vir lookalikes raak te sien
- `task.source`-waardes soos `certstream-suspicious` om bevindings aan CT-monitering te koppel

### Domeinouderdom via RDAP (skripmatig)

RDAP gee masjienleesbare registrasiegebeurtenisse terug. Dit is nuttig om **nuut geregistreerde domeine (NRDs)** uit te ken.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Verryk jou pipeline deur domains met registration age buckets (bv. <7 dae, <30 dae) te tag en triage dienooreenkomstig te prioritiseer.

### TLS/JAx fingerprints om AiTM-infrastruktuur raak te sien

Credential-phishing kan **Adversary-in-the-Middle (AiTM)** reverse proxies (bv. Evilginx) gebruik om session tokens te steel.<sup>[[11]](#references)</sup> Jy kan network-side detections byvoeg:

- Log TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) by egress. Daar is waargeneem dat sommige Evilginx builds stabiele JA4 client/server values het. Alert slegs op bekende slegte fingerprints as 'n swak sein en bevestig altyd met content- en domain intel.<sup>[[12]](#references)</sup>
- Teken TLS certificate metadata (issuer, SAN count, wildcard use, validity) proaktief aan vir lookalike hosts wat via CT of urlscan ontdek is, en korreleer dit met DNS age en geolocation.

> Let wel: Behandel fingerprints as enrichment, nie as die enigste blockers nie; frameworks ontwikkel en kan randomise of obfuscate.

### Domain names wat keywords gebruik

Die ouerbladsy noem ook 'n domain name variation-tegniek wat bestaan uit die plasing van die **victim se domain name binne 'n groter domain** (bv. paypal-financial.com vir paypal.com).

#### Certificate Transparency

Certificate Transparency (CT)-logs stel certificate identities bloot, dus kan die soektog na brand keywords in Subject- of SAN-names lookalike domains onthul (byvoorbeeld, 'n certificate vir `paypal-financial.com` stel die `paypal` keyword bloot). Filter resultate volgens issuance date en CA waar nuttig, en valideer kandidate omdat keyword matches false positives kan wees.<sup>[[13]](#references)</sup>

Patrik Hudak se oorspronklike [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) demonstreer hierdie workflow in Censys, insluitend filters vir certificate date en issuer soos Let's Encrypt.<sup>[[13]](#references)</sup>

Jy kan ook die gratis [**crt.sh**](https://crt.sh)-diens gebruik om vir 'n keyword te soek en resultate volgens date en CA te filter.<sup>[[13]](#references)</sup>

Die Matching Identities-veld kan help om identities van die regte domain met suspicious domains te vergelyk, maar behandel matches as leads eerder as bewys.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) stream CT-updates in byna real time, en [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) consume daardie stream om suspicious certificate names te score.<sup>[[14]](#references)[[15]](#references)</sup>

Praktiese wenk: wanneer jy CT-hits triage, prioritiseer NRDs, untrusted/unknown registrars, privacy-proxy WHOIS, en certs met baie onlangse `NotBefore`-times. Handhaaf 'n allowlist van jou besit domains/brands om noise te verminder.

#### **Nuwe domains**

'n Tweede opsie is om nuut geregistreerde domains volgens TLD te versamel (byvoorbeeld via [Whoxy](https://www.whoxy.com/newly-registered-domains/)) en vir brand keywords te filter. Dit mis phishing wat op subdomains gehuisves word wanneer die keyword nie in die registered domain voorkom nie.<sup>[[13]](#references)</sup>

Bykomende heuristic: behandel sekere **file-extension TLDs** (bv. `.zip`, `.mov`) met ekstra suspicion in alerting. Dit word dikwels in lures met filenames verwar; kombineer die TLD-sein met brand keywords en NRD age vir beter precision.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Verkeer na Microsoft se windows.com met bitflipping gekaap](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Diepgaande ondersoek: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3-dokumentasie](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Hulp met Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON Responses for the Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: Hoe om cloud token theft te voorkom, op te spoor en daarop te reageer](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Introducing CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
