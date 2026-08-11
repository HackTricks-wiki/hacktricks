# Bespeuring van Phishing

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

Om 'n phishing-poging op te spoor, is dit belangrik om **die phishing-tegnieke wat deesdae gebruik word, te verstaan**. Op die ouerbladsy van hierdie plasing kan jy hierdie inligting vind. As jy dus nie bewus is van watter tegnieke vandag gebruik word nie, beveel ek aan dat jy na die ouerbladsy gaan en ten minste daardie afdeling lees.

Hierdie plasing is gebaseer op die idee dat die **aanvallers op een of ander manier die slagoffer se domeinnaam sal probeer naboots of gebruik**. As jou domein `example.com` heet en jy om een of ander rede met 'n heeltemal ander domeinnaam, soos `youwonthelottery.com`, ge-phish word, gaan hierdie tegnieke dit nie onthul nie.

## Variasies van domeinname

Dit is redelik **maklik** om daardie **phishing**-pogings te **onthul** wat 'n **soortgelyke domeinnaam** binne die e-pos sal gebruik.\
Dit is genoeg om **'n lys van die waarskynlikste phishing-name te genereer** wat 'n aanvaller moontlik kan gebruik en te **kontroleer** of dit **geregistreer** is, of net te kontroleer of daar enige **IP** is wat dit gebruik.

### Vind van verdagte domeine

Vir hierdie doel kan jy enige van die volgende tools gebruik. Albei resolve kandidaatdomeine om te kontroleer of hulle in gebruik is.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Wenk: As jy 'n kandidaatlys genereer, voer dit ook in jou DNS-resolverlogs in om **NXDOMAIN-lookups van binne jou org** op te spoor (gebruikers wat probeer om 'n tikfout te bereik voordat die aanvaller dit werklik registreer). Sinkhole of blokkeer hierdie domeine vooraf indien die beleid dit toelaat.

### Bitflipping

**Vir 'n kort verduideliking, sien die ouerbladsy; vir primêre navorsing oor Windows.com bitsquatting, sien [Remy Hax se write-up](https://remyhax.xyz/posts/bitsquatting-windows/) en [BleepingComputer se verslag](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Byvoorbeeld, 'n 1-bis-wysiging in die domein microsoft.com kan dit in _windnws.com_ verander.\
**Aanvallers kan soveel as moontlik bit-flipping-domeine registreer wat met die slagoffer verband hou, om wettige gebruikers na hul infrastruktuur te herlei**.<sup>[[1]](#references)[[2]](#references)</sup>

**Alle moontlike bit-flipping-domeinname moet ook gemonitor word.**

As jy ook homoglyph/IDN-lookalikes moet oorweeg (bv. die vermenging van Latynse en Cyrilliese karakters), kyk na:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basiese kontroles

Sodra jy 'n lys van potensieel verdagte domeinname het, moet jy hulle **kontroleer** (hoofsaaklik die HTTP- en HTTPS-poorte) om te **sien of hulle een of ander login-formulier gebruik wat soortgelyk** is aan dié van die slagoffer se domein.\
Jy kan ook poort 3333 kontroleer om te sien of dit oop is en 'n instansie van `gophish` uitvoer.\
Dit is ook interessant om te weet **hoe oud elke ontdekte verdagte domein is**; hoe jonger dit is, hoe groter is die risiko.\
Jy kan ook **screenshots** van die HTTP- en/of HTTPS-webblad van die verdagte domein neem om te sien of dit verdag is en dit in daardie geval **toegang te verkry om dit dieper te ondersoek**.

### Gevorderde kontroles

As jy een stap verder wil gaan, beveel ek aan dat jy **daardie verdagte domeine monitor en van tyd tot tyd na meer domeine soek** (elke dag? Dit neem slegs 'n paar sekondes/minute). Jy moet ook die oop **poorte** van die verwante IP's **kontroleer** en **na instansies van `gophish` of soortgelyke tools soek** (ja, aanvallers maak ook foute), en die HTTP- en HTTPS-webbladsye van die verdagte domeine en subdomeine **monitor** om te sien of hulle enige login-formulier van die slagoffer se webblaaie gekopieer het.\
Om dit te **outomatiseer**, beveel ek aan dat jy 'n lys van die slagoffer se domeine se login-formuliere hou, die verdagte webblaaie spider en elke login-formulier wat binne die verdagte domeine gevind word, met elke login-formulier van die slagoffer se domein vergelyk deur iets soos `ssdeep` te gebruik.\
As jy die login-formuliere van die verdagte domeine opgespoor het, kan jy probeer om **vals aanmeldbewyse te stuur** en te **kontroleer of dit jou na die slagoffer se domein herlei**.

---

### Soektog volgens favicon en webvingerafdrukke (Shodan/Censys)

Baie phishing-kits hergebruik favicons van die handelsmerk wat hulle naboots. Shodan hash sy base64-geënkodeerde favicon-data met MurmurHash3, terwyl Censys sy eie favicon-hashvelde beskikbaar stel.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Jy kan 'n Shodan-versoenbare hash genereer en daarvolgens pivot:

Python-voorbeeld (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Doen navraag op Shodan: `http.favicon.hash:309020573`
- Met tooling: kyk na community tools soos favfreak om hashes te bereken en Shodan dorks te genereer.<sup>[[16]](#references)</sup>

Notas
- Favicons word hergebruik; behandel passings as leidrade en valideer inhoud en sertifikate voordat jy optree.
- Kombineer dit met heuristieke vir domeinouderdom en sleutelwoorde vir beter akkuraatheid.

### Jag met URL-telemetrie (urlscan.io)

`urlscan.io` stoor historiese skermkiekies, DOM, versoeke en TLS-metadata van ingediende URLs. Jy kan jag vir handelsmerkmisbruik en klone:<sup>[[8]](#references)</sup>

Voorbeeldnavrae (UI of API):
- Vind lookalikes terwyl jou wettige domeine uitgesluit word: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Vind werwe wat jou bates hotlink: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Beperk tot onlangse resultate: voeg `AND date:>now-7d` by

API-voorbeeld:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Gebruik die JSON om te fokus op:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` om baie nuwe sertifikate vir lookalikes raak te sien
- `task.source`-waardes soos `certstream-suspicious` om bevindings aan CT-monitering te koppel

### Domeinouderdom via RDAP (scriptbaar)

RDAP gee masjienleesbare registrasiegebeurtenisse terug. Nuttig om **nuutgeregistreerde domeine (NRDs)** uit te wys.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Verryk jou pipeline deur domains met registrasie-ouderdomsgroepe te merk (bv. <7 dae, <30 dae) en triage dienooreenkomstig te prioritiseer.

### TLS/JAx-fingerafdrukke om AiTM-infrastruktuur raak te sien

Credential-phishing kan **Adversary-in-the-Middle (AiTM)**-reverse proxies (bv. Evilginx) gebruik om sessietokens te steel.<sup>[[11]](#references)</sup> Jy kan netwerk-kant-opsporings byvoeg:

- Log TLS/HTTP-fingerafdrukke (JA3/JA4/JA4S/JA4H) by egress. Daar is waargeneem dat sommige Evilginx-builds stabiele JA4-kliënt-/bedienerwaardes het. Waarsku slegs op bekende-slegte-fingerafdrukke as ’n swak sein en bevestig altyd met inhoud- en domain-intelligensie.<sup>[[12]](#references)</sup>
- Teken proaktief TLS-sertifikaatmetadata (uitreiker, SAN-telling, wildcard-gebruik, geldigheid) aan vir lookalike-hosts wat via CT of urlscan ontdek is, en korreleer dit met DNS-ouderdom en geolokasie.

> Nota: Behandel fingerafdrukke as verryking, nie as alleenstaande blokkeerders nie; frameworks ontwikkel en kan hulself randomiseer of verdoesel.

### Domain names wat keywords gebruik

Die ouerbladsy noem ook ’n domain name-variasietegniek wat daaruit bestaan om die **slagoffer se domain name binne ’n groter domain te plaas** (bv. paypal-financial.com vir paypal.com).

#### Certificate Transparency

Certificate Transparency (CT)-logs stel sertifikaat-identiteite bloot, dus kan die soek van Subject- of SAN-name vir handelsmerk-keywords lookalike-domains onthul (byvoorbeeld, ’n sertifikaat vir `paypal-financial.com` stel die `paypal`-keyword bloot). Filtreer resultate volgens uitreikingsdatum en CA waar nuttig, en valideer kandidate omdat keyword-treffers vals positiewe kan wees.<sup>[[13]](#references)</sup>

Patrik Hudak se oorspronklike [phishing-domain-jag-skrywe](https://0xpatrik.com/phishing-domains/) demonstreer hierdie workflow in Censys, insluitend filters vir sertifikaatdatum en uitreiker, soos Let's Encrypt.<sup>[[13]](#references)</sup>

Jy kan ook die gratis [**crt.sh**](https://crt.sh)-diens gebruik om vir ’n keyword te soek en resultate volgens datum en CA te filtreer.<sup>[[13]](#references)</sup>

Die Matching Identities-veld kan help om identiteite van die regte domain met verdagte domains te vergelyk, maar behandel treffers as leidrade eerder as bewys.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) stroom CT-opdaterings byna intyds, en [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) gebruik daardie stroom om verdagte sertifikaatname te beoordeel.<sup>[[14]](#references)[[15]](#references)</sup>

Praktiese wenk: wanneer CT-treffers getriage word, prioritiseer NRDs, onbetroubare/onbekende registrars, privacy-proxy WHOIS en sertifikate met baie onlangse `NotBefore`-tye. Handhaaf ’n allowlist van jou besit-domains/-handelsmerke om geraas te verminder.

#### **Nuwe domains**

’n Tweede opsie is om nuutgeregistreerde domains volgens TLD te versamel (byvoorbeeld via [Whoxy](https://www.whoxy.com/newly-registered-domains/)) en vir handelsmerk-keywords te filtreer. Dit mis phishing wat op subdomains gehuisves word wanneer die keyword nie in die geregistreerde domain voorkom nie.<sup>[[13]](#references)</sup>

Bykomende heuristiek: behandel sekere **file-extension-TLDs** (bv. `.zip`, `.mov`) met ekstra agterdog in alerts. Dit word dikwels in lures met lêername verwar; kombineer die TLD-sein met handelsmerk-keywords en NRD-ouderdom vir beter presisie.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Verkeerskaping na Microsoft se windows.com met bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Diepgaande ontleding: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3-dokumentasie](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property-datastel](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Soek-API-verwysing](https://urlscan.io/docs/search/)
- [9] [Hulp vir Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON-reaksies vir Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token-taktieke: Hoe om token-diefstal in cloud te voorkom, op te spoor en daarop te reageer](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+-netwerkfingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing vind: Gereedskap en tegnieke](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Bekendstelling van CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
