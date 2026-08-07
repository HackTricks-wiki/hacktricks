# Bespeuring van Phishing

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

Om ’n phishing-poging te bespeur, is dit belangrik om **die phishing-tegnieke wat tans gebruik word, te verstaan**. Op die ouerbladsy van hierdie plasing kan jy hierdie inligting vind. As jy dus nie bewus is van watter tegnieke vandag gebruik word nie, beveel ek aan dat jy na die ouerbladsy gaan en ten minste daardie afdeling lees.

Hierdie plasing is gebaseer op die idee dat die **aanvallers op een of ander manier die slagoffer se domeinnaam sal probeer naboots of gebruik**. As jou domein `example.com` heet en jy om een of ander rede met ’n heeltemal ander domeinnaam, soos `youwonthelottery.com`, gephish word, gaan hierdie tegnieke dit nie ontbloot nie.

## Variasies van domeinname

Dit is redelik **maklik** om daardie **phishing**-pogings te **ontbloot** wat ’n **soortgelyke domein**-naam binne die e-pos sal gebruik.\
Dit is genoeg om **’n lys van die waarskynlikste phishing-name te genereer** wat ’n aanvaller kan gebruik en **te kontroleer** of dit **geregistreer** is, of bloot te kontroleer of enige **IP** dit gebruik.

### Vind van verdagte domeine

Vir hierdie doel kan jy enige van die volgende tools gebruik. Let daarop dat hierdie tools ook outomaties DNS-versoeke sal uitvoer om te kontroleer of die domein enige toegewysde IP het:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Wenk: As jy ’n kandidaatlys genereer, voer dit ook na jou DNS-resolver-logboeke om **NXDOMAIN-lookups vanaf binne jou organisasie** te bespeur (gebruikers wat probeer om ’n tikfoutdomein te bereik voordat die aanvaller dit werklik registreer). Sinkhole of blokkeer hierdie domeine vooraf indien beleid dit toelaat.

### Bitflipping

**Jy kan ’n kort verduideliking van hierdie tegniek op die ouerbladsy vind. Of lees die oorspronklike navorsing by** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Byvoorbeeld, kan ’n wysiging van 1 bit in die domein microsoft.com dit in _windnws.com_ verander.\
**Aanvallers kan soveel as moontlik bit-flipping-domeine registreer wat met die slagoffer verband hou om wettige gebruikers na hul infrastruktuur te herlei**.<sup>[[1]](#references)</sup>

**Alle moontlike bit-flipping-domeinname behoort ook gemonitor te word.**

As jy ook homoglyph/IDN-lookalikes moet oorweeg (byvoorbeeld die vermenging van Latynse en Cyrilliese karakters), kyk na:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basiese kontroles

Sodra jy ’n lys van potensieel verdagte domeinname het, behoort jy dit te **kontroleer** (hoofsaaklik die HTTP- en HTTPS-poorte) om **te sien of hulle een of ander login-vorm gebruik wat soortgelyk is** aan dié van die slagoffer se domein.\
Jy kan ook poort 3333 kontroleer om te sien of dit oop is en ’n instansie van `gophish` uitvoer.\
Dit is ook nuttig om te weet **hoe oud elke ontdekte verdagte domein is**; hoe jonger dit is, hoe groter is die risiko.\
Jy kan ook **screenshots** van die HTTP- en/of HTTPS-verdagte webbladsy verkry om te sien of dit verdag is en dit in daardie geval **toegang te verkry om dit van nader te ondersoek**.

### Gevorderde kontroles

As jy ’n stap verder wil gaan, beveel ek aan dat jy **daardie verdagte domeine monitor en kort-kort na meer domeine soek** (elke dag? Dit neem slegs ’n paar sekondes/minute). Jy behoort ook die oop **poorte** van die verwante IP’s te **kontroleer** en **na instansies van `gophish` of soortgelyke tools te soek** (ja, aanvallers maak ook foute), en die HTTP- en HTTPS-webblaaie van die verdagte domeine en subdomeine te **monitor** om te sien of hulle enige login-vorm van die slagoffer se webblaaie gekopieer het.\
Om dit te **outomatiseer**, beveel ek aan dat jy ’n lys van login-vorms van die slagoffer se domeine byhou, die verdagte webblaaie spider en elke login-vorm wat binne die verdagte domeine gevind word, met elke login-vorm van die slagoffer se domein vergelyk deur iets soos `ssdeep` te gebruik.\
As jy die login-vorms van die verdagte domeine opgespoor het, kan jy probeer om **vals geloofsbriewe te stuur** en **te kontroleer of dit jou na die slagoffer se domein herlei**.

---

### Soek volgens favicon en web-fingerprints (Shodan/ZoomEye/Censys)

Baie phishing-kits hergebruik favicons van die handelsmerk wat hulle naboots. Internetwye skandeerders bereken ’n MurmurHash3 van die base64-geënkodeerde favicon. Jy kan die hash genereer en daarop pivot:

Python-voorbeeld (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Query Shodan: `http.favicon.hash:309020573`
- Met tooling: kyk na community tools soos favfreak om hashes en dorks vir Shodan/ZoomEye/Censys te genereer.

Notas
- Favicons word hergebruik; behandel matches as leidrade en valideer content en certs voordat jy optree.
- Kombineer dit met domain-age- en keyword-heuristics vir beter akkuraatheid.

### URL-telemetrie-jag (urlscan.io)

`urlscan.io` stoor historiese screenshots, DOM, requests en TLS-metadata van ingediende URLs. Jy kan jag vir brandmisbruik en clones:<sup>[[2]](#references)</sup>

Voorbeeldqueries (UI of API):
- Vind lookalikes met uitsluiting van jou legit domains: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Vind sites wat jou assets hotlink: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Beperk tot onlangse results: voeg `AND date:>now-7d` by

API-voorbeeld:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Vanuit die JSON, fokus op:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` om baie nuwe sertifikate vir lookalikes raak te sien
- `task.source`-waardes soos `certstream-suspicious` om bevindings aan CT-monitering te koppel

### Domeinouderdom via RDAP (scriptbaar)

RDAP lewer masjienleesbare skeppingsgebeurtenisse. Nuttig om **nuut geregistreerde domeine (NRD's)** te merk.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Verryk jou pipeline deur domains met registrasie-ouderdomsgroepe te tag (bv. <7 dae, <30 dae) en prioriteer triage dienooreenkomstig.

### TLS/JAx-fingerafdrukke om AiTM-infrastruktuur raak te sien

Moderne credential-phishing gebruik toenemend **Adversary-in-the-Middle (AiTM)** reverse proxies (bv. Evilginx) om sessietokens te steel. Jy kan network-side detections byvoeg:

- Log TLS/HTTP-fingerafdrukke (JA3/JA4/JA4S/JA4H) by egress. Daar is waargeneem dat sommige Evilginx-builds stabiele JA4-client/server-waardes het. Genereer slegs as 'n swak sein alerts op bekende slegte fingerprints en bevestig dit altyd met content- en domain-intel.<sup>[[3]](#references)</sup>
- Teken proaktief TLS certificate-metadata aan (issuer, SAN count, wildcard use, validity) vir lookalike hosts wat via CT of urlscan ontdek is, en korreleer dit met DNS-ouderdom en geoligging.

> Nota: Behandel fingerprints as enrichment, nie as alleenstaande blockers nie; frameworks ontwikkel en kan fingerprints randomise of obfuscate.

### Domain names wat keywords gebruik

Die parent page noem ook 'n domain name variation-tegniek wat bestaan uit die plasing van die **slagoffer se domain name binne 'n groter domain** (bv. paypal-financial.com vir paypal.com).

#### Certificate Transparency

Dit is nie moontlik om die vorige "Brute-Force"-benadering te gebruik nie, maar dit is eintlik **moontlik om sulke phishing attempts te ontdek** danksy certificate transparency. Elke keer wanneer 'n certificate deur 'n CA uitgereik word, word die details publiek gemaak. Dit beteken dat dit deur die certificate transparency te lees of selfs te monitor, **moontlik is om domains te vind wat 'n keyword binne hul naam gebruik**. Byvoorbeeld, as 'n attacker 'n certificate vir [https://paypal-financial.com](https://paypal-financial.com) genereer, is dit deur die certificate te sien moontlik om die keyword "paypal" te vind en te weet dat daardie suspicious email gebruik word.

Die post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) stel voor dat jy Censys kan gebruik om te search vir certificates wat 'n spesifieke keyword raak en volgens datum te filter (slegs "new" certificates) en volgens die CA issuer "Let's Encrypt":<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Jy kan egter "dieselfde" doen met die gratis web [**crt.sh**](https://crt.sh). Jy kan **vir die keyword search** en die resultate **volgens datum en CA filter** indien jy wil.

![Domain names wat keywords gebruik - Certificate Transparency: Jy kan egter "dieselfde" doen met die gratis web crt.sh . Jy kan vir die keyword search en die resultate volgens datum en...](<../../images/image (519).png>)

Deur hierdie laaste opsie te gebruik, kan jy selfs die Matching Identities-veld gebruik om te sien of enige identity van die regte domain met enige van die suspicious domains ooreenstem (let daarop dat 'n suspicious domain 'n false positive kan wees).

**Nog 'n alternatief** is die fantastiese projek genaamd [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream verskaf 'n real-time stream van nuutgegenereerde certificates wat jy kan gebruik om gespesifiseerde keywords in (byna) real-time op te spoor. Daar is inderdaad 'n projek genaamd [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) wat presies dit doen.

Praktiese wenk: wanneer jy CT-hits triage, prioritiseer NRDs, onbetroubare/onbekende registrars, privacy-proxy WHOIS, en certs met baie onlangse `NotBefore`-tye. Handhaaf 'n allowlist van jou besit domains/brands om noise te verminder.

#### **Nuwe domains**

**Een laaste alternatief** is om 'n lys van **nuutgeregistreerde domains** vir sekere TLDs in te samel ([Whoxy](https://www.whoxy.com/newly-registered-domains/) verskaf so 'n diens) en die **keywords in hierdie domains te check**. Lang domains gebruik egter gewoonlik een of meer subdomains; daarom sal die keyword nie binne die FLD verskyn nie en sal jy nie die phishing-subdomain kan vind nie.

Bykomende heuristic: behandel sekere **file-extension TLDs** (bv. `.zip`, `.mov`) met ekstra suspicion in alerting. Dit word dikwels in lures met filenames verwar; kombineer die TLD-sein met brand-keywords en NRD-ouderdom vir beter presisie.

## References

- [1] [Verkeer na Microsoft se windows.com kaap met bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Phishing vind: Tools en Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
