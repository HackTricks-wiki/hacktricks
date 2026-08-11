# Bespeuring van Phishing

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

Om 'n phishing-poging te bespeur, is dit belangrik om **die phishing-tegnieke wat deesdae gebruik word, te verstaan**. Op die ouerblad van hierdie plasing kan jy hierdie inligting vind. As jy dus nie bewus is van watter tegnieke vandag gebruik word nie, beveel ek aan dat jy na die ouerblad gaan en minstens daardie afdeling lees.

Hierdie plasing is gebaseer op die idee dat die **aanvallers op een of ander manier die slagoffer se domeinnaam sal probeer naboots of gebruik**. As jou domein `example.com` genoem word en jy om een of ander rede met 'n heeltemal ander domeinnaam, soos `youwonthelottery.com`, ge-phish word, gaan hierdie tegnieke dit nie blootlê nie.

## Variasies in domeinname

Dit is redelik **maklik** om daardie **phishing**-pogings te **blootlê** wat 'n **soortgelyke domein**-naam binne die e-pos sal gebruik.\
Dit is genoeg om **'n lys te genereer van die mees waarskynlike phishing-name** wat 'n aanvaller kan gebruik en te **kontroleer** of dit **geregistreer** is, of bloot te kontroleer of enige **IP** dit gebruik.

### Vind van verdagte domeine

Vir hierdie doel kan jy enige van die volgende nutsmiddels gebruik. Albei resolve kandidaatdomeine om te kontroleer of hulle in gebruik is.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Wenk: As jy 'n kandidaatelys genereer, voer dit ook in jou DNS-resolver-logboeke in om **NXDOMAIN lookups from inside your org** op te spoor (gebruikers wat probeer om 'n tikfout te bereik voordat die aanvaller dit werklik registreer). Sinkhole of blokkeer hierdie domeine vooraf indien beleid dit toelaat.

### Bitflipping

**Vir 'n kort verduideliking, sien die ouerblad; vir primêre navorsing oor Windows.com bitsquatting, sien [Remy Hax se skrywe](https://remyhax.xyz/posts/bitsquatting-windows/) en [BleepingComputer se verslag](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Byvoorbeeld, kan 'n 1-bit-wysiging in die domein microsoft.com dit in _windnws.com._ verander.\
**Aanvallers kan soveel as moontlik bit-flipping-domeine registreer wat met die slagoffer verband hou, om wettige gebruikers na hul infrastruktuur te herlei**.<sup>[[1]](#references)[[2]](#references)</sup>

**Alle moontlike bit-flipping-domeinname behoort ook gemonitor te word.**

As jy ook homoglyph/IDN-lookalikes moet oorweeg (byvoorbeeld, die vermenging van Latynse/Kirilliese karakters), raadpleeg:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basiese kontroles

Sodra jy 'n lys van potensieel verdagte domeinname het, behoort jy hulle te **kontroleer** (hoofsaaklik die HTTP- en HTTPS-poorte) om te **sien of hulle 'n login-vorm gebruik wat soortgelyk is** aan een van die slagoffer se domeine.\
Jy kan ook poort 3333 kontroleer om te sien of dit oop is en 'n instansie van `gophish` uitvoer.\
Dit is ook interessant om te weet **hoe oud elke ontdekte verdagte domein is**; hoe jonger dit is, hoe groter is die risiko.\
Jy kan ook **skermskote** van die verdagte HTTP- en/of HTTPS-webbladsy neem om te sien of dit verdag is en dit in daardie geval **besoek om dit deegliker te ondersoek**.

### Gevorderde kontroles

As jy 'n stap verder wil gaan, beveel ek aan dat jy **daardie verdagte domeine monitor en van tyd tot tyd na meer soek** (elke dag? Dit neem slegs 'n paar sekondes/minute). Jy behoort ook die oop **poorte** van die verwante IP's te **kontroleer** en **na instansies van `gophish` of soortgelyke nutsmiddels te soek** (ja, aanvallers maak ook foute), asook **die HTTP- en HTTPS-webbladsye van die verdagte domeine en subdomeine te monitor** om te sien of hulle enige login-vorm van die slagoffer se webbladsye gekopieer het.\
Om dit te **outomatiseer**, beveel ek aan dat jy 'n lys van login-vorms van die slagoffer se domeine het, die verdagte webbladsye spider en elke login-vorm wat binne die verdagte domeine gevind word, met elke login-vorm van die slagoffer se domein vergelyk deur iets soos `ssdeep` te gebruik.\
As jy die login-vorms van die verdagte domeine opgespoor het, kan jy probeer om **junk credentials te stuur** en te **kontroleer of dit jou na die slagoffer se domein herlei**.

---

### Hunting volgens favicon en web-fingerprints (Shodan/Censys)

Baie phishing-kits hergebruik favicons van die handelsmerk wat hulle naboots. Shodan hash sy base64-geënkodeerde favicon-data met MurmurHash3, terwyl Censys sy eie favicon-hash-velde blootstel.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Jy kan 'n Shodan-versoenbare hash genereer en dit gebruik om verder te soek:

Python-voorbeeld (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Doen navraag by Shodan: `http.favicon.hash:309020573`
- Met tooling: kyk na community tools soos favfreak om hashes te bereken en Shodan dorks te genereer.<sup>[[16]](#references)</sup>

Notas
- Favicons word hergebruik; behandel treffers as leidrade en valideer inhoud en sertifikate voordat jy optree.
- Kombineer dit met domain-age- en keyword-heuristieke vir beter presisie.

### Jag op URL-telemetrie (urlscan.io)

`urlscan.io` stoor historiese screenshots, DOM, requests en TLS-metadata van ingediende URLs. Jy kan jag vir brand abuse en clones:<sup>[[8]](#references)</sup>

Voorbeeldnavrae (UI of API):
- Vind lookalikes wat jou legitieme domains uitsluit: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Vind sites wat jou assets hotlink: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Beperk tot onlangse resultate: voeg `AND date:>now-7d` by

API-voorbeeld:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Gebruik die volgende velde in die JSON as pivots:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` om baie nuwe sertifikate vir lookalikes raak te sien
- `task.source`-waardes soos `certstream-suspicious` om bevindings aan CT-monitoring te koppel

### Domeinouderdom via RDAP (scriptable)

RDAP gee masjienleesbare registrasiegebeurtenisse terug. Dit is nuttig om **nuut geregistreerde domeine (NRDs)** te identifiseer.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Verryk jou pyplyn deur domeine met registrasie-ouderdomsgroepe te merk (bv. <7 dae, <30 dae) en triage dienooreenkomstig te prioritiseer.

### TLS/JAx-vingerafdrukke om AiTM-infrastruktuur raak te sien

Credential-phishing kan **Adversary-in-the-Middle (AiTM)**-reverse proxies (bv. Evilginx) gebruik om sessietokens te steel.<sup>[[11]](#references)</sup> Jy kan netwerk-kantbespeurings byvoeg:

- Log TLS/HTTP-vingerafdrukke (JA3/JA4/JA4S/JA4H) by egress. Daar is waargeneem dat sommige Evilginx-builds stabiele JA4-kliënt-/bedienerwaardes het. Genereer slegs op bekende slegte vingerafdrukke 'n waarskuwing as 'n swak sein, en bevestig dit altyd met inhoud- en domeinintelligensie.<sup>[[12]](#references)</sup>
- Teken TLS-sertifikaatmetadata proaktief aan (uitreiker, SAN-telling, wildcard-gebruik, geldigheid) vir lookalike-hosts wat deur CT of urlscan ontdek is, en korreleer dit met DNS-ouderdom en geoligging.

> Nota: Behandel vingerafdrukke as verryking, nie as die enigste blokkeerders nie; frameworks ontwikkel voortdurend en kan vingerafdrukke randomiseer of verdoesel.

### Domeinname wat sleutelwoorde gebruik

Die ouerbladsy noem ook 'n domeinnaamvariasietegniek wat daaruit bestaan om die **slagoffer se domeinnaam binne 'n groter domein te plaas** (bv. paypal-financial.com vir paypal.com).

#### Certificate Transparency

Certificate Transparency (CT)-logs stel sertifikaat-identiteite bloot, dus kan die soektog na handelsnaamsleutelwoorde in Subject- of SAN-name lookalike-domeine openbaar (byvoorbeeld, 'n sertifikaat vir `paypal-financial.com` stel die `paypal`-sleutelwoord bloot). Filter resultate volgens uitreikingsdatum en CA waar dit nuttig is, en valideer kandidate omdat sleutelwoordpassings vals positiewes kan wees.<sup>[[13]](#references)</sup>

Patrik Hudak se oorspronklike [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) demonstreer hierdie workflow in Censys, insluitend filters vir sertifikaatdatum en uitreiker soos Let's Encrypt.<sup>[[13]](#references)</sup>

![Censys-sertifikaatsoekresultate wat gebruik word om lookalike-domeine te identifiseer](<../../images/image (1115).png>)

Jy kan ook die gratis [**crt.sh**](https://crt.sh)-diens gebruik om na 'n sleutelwoord te soek en resultate volgens datum en CA te filter.<sup>[[13]](#references)</sup>

![crt.sh-sleutelwoordsoektog vir verdagte sertifikaat-identiteite](<../../images/image (519).png>)

Die Matching Identities-veld kan help om identiteite van die regte domein met verdagte domeine te vergelyk, maar behandel passings as leidrade eerder as bewys.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) stroom CT-opdaterings byna intyds, en [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) verbruik daardie stroom om verdagte sertifikaatname te gradeer.<sup>[[14]](#references)[[15]](#references)</sup>

Praktiese wenk: wanneer jy CT-treffers triage, prioritiseer NRDs, onbetroubare/onbekende registrateurs, privaatheids-proxy-WHOIS en sertifikate met baie onlangse `NotBefore`-tye. Handhaaf 'n allowlist van jou besitte domeine/handelsname om geraas te verminder.

#### **Nuwe domeine**

'n Tweede opsie is om nuutgeregistreerde domeine volgens TLD te versamel (byvoorbeeld via [Whoxy](https://www.whoxy.com/newly-registered-domains/)) en vir handelsnaamsleutelwoorde te filter. Dit mis phishing wat op subdomeine gehuisves word wanneer die sleutelwoord nie in die geregistreerde domein voorkom nie.<sup>[[13]](#references)</sup>

Bykomende heuristiek: behandel sekere **lêeruitbreiding-TLD's** (bv. `.zip`, `.mov`) met ekstra agterdog in waarskuwings. Dit word dikwels in lures met lêername verwar; kombineer die TLD-sein met handelsnaamsleutelwoorde en NRD-ouderdom vir beter akkuraatheid.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Verkeer na Microsoft se windows.com gekaap met bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Diepgaande ontleding: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3-dokumentasie](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Hulp met Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON Responses for the Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token-taktieke: Hoe om wolktokens te voorkom, op te spoor en daarop te reageer](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+-netwerkvingerafdrukke](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing vind: Gereedskap en tegnieke](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream bekendstelling](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
