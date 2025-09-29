# Opsporing van phishing

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

Om 'n phishing-poging op te spoor is dit belangrik om die phishing-tegnieke wat deesdae gebruik word, te verstaan. Op die ouerbladsy van hierdie pos kan jy hierdie inligting vind, so as jy nie bewus is van watter tegnieke vandag gebruik word nie, beveel ek aan dat jy na die ouerbladsy gaan en ten minste daardie afdeling lees.

Hierdie pos is gebaseer op die idee dat die **aanvallers op een of ander manier die slagoffer se domeinnaam sal naboots of gebruik**. As jou domein `example.com` is en 'n phishing-aanval 'n heeltemal ander domeinnaam soos `youwonthelottery.com` gebruik, gaan hierdie tegnieke dit nie ontdek nie.

## Domeinnaamvariasies

Dit is redelik **maklik** om daardie **phishing**-pogings wat 'n **soortgelyke domeinnaam** binne die e-pos gebruik, te **ontdek**.\
Dit is genoeg om **'n lys te genereer van die mees waarskynlike phishing-name** wat 'n aanvaller mag gebruik en te **kontroleer** of dit **geregistreer** is, of net te kyk of daar enige **IP** is wat dit gebruik.

### Om verdagte domeine te vind

Vir hierdie doel kan jy enige van die volgende tools gebruik. Let wel dat hierdie tools ook DNS-versoeke outomaties sal doen om te kontroleer of die domein aan enige IP toegewys is:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: As jy 'n kandidaatlys genereer, voer dit ook in jou DNS-resolver logs in om **NXDOMAIN-opvraginge van binne jou org** op te spoor (gebruikers wat probeer 'n tikfout bereik voordat die aanvaller dit registreer). Sinkhole of pre-block hierdie domeine as beleid dit toelaat.

### Bitflipping

**Jy kan 'n kort verduideliking van hierdie tegniek op die ouerbladsy vind. Of lees die oorspronklike navorsing by** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Byvoorbeeld, 'n 1-bit wysiging in die domein microsoft.com kan dit omskep in _windnws.com._\
**Aanvallers mag soveel bit-flipping domeine as moontlik registreer wat met die slagoffer verband hou om geldige gebruikers na hulle infrastruktuur te herlei.**

**Alle moontlike bit-flipping domeinnaam moet ook gemonitor word.**

As jy ook homoglyph/IDN lookalikes (bv. die meng van Latin/Cyrilliese karakters) in ag moet neem, kyk:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basiese kontrole

Sodra jy 'n lys het van potensiële verdagte domeine moet jy hulle **kontroleer** (hoofsaaklik die poorte HTTP en HTTPS) om te **sien of hulle 'n aanmeldingsvorm gebruik soortgelyk aan dié van die slagoffer se domein**.\
Jy kan ook poort 3333 nagaan om te sien of dit oop is en 'n instansie van `gophish` loop.\
Dit is ook interessant om te weet **hoe oud elke ontdekte verdagte domein is**; hoe jonger dit is, hoe riskanter.\
Jy kan ook **skermkiekies** van die HTTP en/of HTTPS verdagte webblad kry om te sien of dit verdag is en in daardie geval dit te besoek om 'n dieper ondersoek te doen.

### Gevorderde kontroles

As jy 'n stap verder wil gaan, beveel ek aan dat jy daardie verdagte domeine monitor en af en toe (elke dag? dit neem net 'n paar sekondes/minute) vir meer soek. Jy moet ook die oop poorte van die verwante IP's nagaan en soek na instansies van `gophish` of soortgelyke tools (ja, aanvallers maak ook foute) en die HTTP en HTTPS webblaaie van die verdagte domeine en subdomeine monitor om te sien of hulle enige aanmeldingsvorm van die slagoffer se webblaaie gekopieer het.\
Om dit te outomatiseer beveel ek aan om 'n lys aanmeldingsvorms van die slagoffer se domeine te hê, die verdagte webblaaie te spider en elke aanmeldingsvorm wat in die verdagte domeine gevind word te vergelyk met elke aanmeldingsvorm van die slagoffer se domein met iets soos `ssdeep`.\
As jy die aanmeldingsvorms van die verdagte domeine gevind het, kan jy probeer om vals inlogbewyse te stuur en te kyk of dit jou na die slagoffer se domein herlei.

---

### Jag deur favicon en webvingerafdrukke (Shodan/ZoomEye/Censys)

Baie phishing-kit hergebruik favicons van die handelsmerk wat hulle naboots. Internet-wye skandeerders bereken 'n MurmurHash3 van die base64-gekodeerde favicon. Jy kan die hash genereer en daarop pivot:

Python voorbeeld (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Navraag op Shodan: `http.favicon.hash:309020573`
- Met gereedskap: kyk na community tools soos favfreak om hashes en dorks vir Shodan/ZoomEye/Censys te genereer.

Aantekeninge
- Favicons word hergebruik; behandel treffers as leidrade en valideer inhoud en certs voordat jy optree.
- Kombineer dit met domain-age en keyword heuristics vir beter presisie.

### URL telemetry hunting (urlscan.io)

`urlscan.io` stoor historiese skermskote, DOM, requests en TLS metadata van ingediende URLs. Jy kan soek na brand abuse en clones:

Voorbeeld navrae (UI of API):
- Vind lookalikes terwyl jy jou legit domeine uitsluit: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Vind sites wat jou assets hotlink: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Beperk tot onlangse resultate: voeg by `AND date:>now-7d`

API voorbeeld:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
From die JSON, pivot op:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` om baie nuwe certs vir lookalikes op te spoor
- `task.source` waardes soos `certstream-suspicious` om bevindings aan CT monitoring te koppel

### Domein ouderdom via RDAP (skripbaar)

RDAP lewer masjienleesbare skeppingsgebeure. Nutig om **nuut geregistreerde domeine (NRDs)** te merk.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Verryk jou pyllyn deur domeine te merk met registrasie-ouderdomsbuckets (bv., <7 dae, <30 dae) en prioritiseer triage daarvolgens.

### TLS/JAx fingerprints to spot AiTM infrastructure

Moderne credential-phishing gebruik toenemend **Adversary-in-the-Middle (AiTM)** reverse proxies (bv. Evilginx) om session tokens te steel. Jy kan netwerk-kant detectors toevoeg:

- Log TLS/HTTP vingerafdrukke (JA3/JA4/JA4S/JA4H) by uitgaande verkeer. Sommige Evilginx-builds is waargeneem met stabiele JA4 kliënt/server-waardes. Gee waarskuwings slegs op bekend-slegte vingerafdrukke as 'n swak sein en bevestig altyd met inhoud- en domein-intel.
- Neem proaktief TLS sertifikaat-metadata op (issuer, SAN count, wildcard gebruik, geldigheid) vir lookalike hosts wat via CT of urlscan ontdek is en korreleer dit met DNS-ouderdom en geolokalisasie.

> Let wel: Behandel vingerafdrukke as verriking, nie as enkele blokkeerders nie; frameworks ontwikkel en kan randomiseer of obfuskeer.

### Domain names using keywords

Die ouerblad bespreek ook 'n domeinnaamvariasiemetode wat bestaan uit om die **slagoffer se domeinnaam binne 'n groter domein te plaas** (bv. paypal-financial.com vir paypal.com).

#### Certificate Transparency

Dit is nie moontlik om die vorige "Brute-Force" benadering te gebruik nie, maar dit is eintlik **moontlik om sulke phishing-pogings op te spoor** danksy Certificate Transparency. Elke keer as 'n sertifikaat deur 'n CA uitgegee word, word die besonderhede openbaar gemaak. Dit beteken dat deur die certificate transparency te lees of selfs te monitor, dit **moontlik is om domeine te vind wat 'n sleutelwoord in hul naam gebruik**. Byvoorbeeld, as 'n aanvaller 'n sertifikaat genereer vir [https://paypal-financial.com](https://paypal-financial.com), kan jy deur die sertifikaat die sleutelwoord "paypal" vind en weet dat 'n verdagte e-pos gebruik word.

Die post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) stel voor dat jy Censys kan gebruik om na sertifikate te soek wat 'n spesifieke sleutelwoord raak en te filter op datum (slegs "nuwe" sertifikate) en op die CA-uitreiker "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Jy kan egter "dieselfde" doen met die gratis web [**crt.sh**](https://crt.sh). Jy kan **soek na die sleutelwoord** en die resultate **filter** **per datum en CA** indien jy wil.

![](<../../images/image (519).png>)

Met hierdie opsie kan jy selfs die veld Matching Identities gebruik om te sien of enige identiteit van die regte domein ooreenstem met enige van die verdagte domeine (let wel dat 'n verdagte domein 'n vals-positief kan wees).

**Nog 'n alternatief** is die fantastiese projek genaamd [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream voorsien 'n real-time stroom van nuut gegenereerde sertifikate wat jy kan gebruik om gespesifiseerde sleutelwoorde in (naby) real-time te ontdek. Daar is eintlik 'n projek genaamd [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) wat presies dit doen.

Praktiese wenk: wanneer jy CT-hits triageer, prioritiseer NRDs, onbetroubare/onbekende registrars, privacy-proxy WHOIS, en certs met baie onlangse `NotBefore`-tye. Handhaaf 'n allowlist van jou eie domeine/handelsmerke om geraas te verminder.

#### **Nuwe domeine**

**Een laaste alternatief** is om 'n lys te versamel van **nuut geregistreerde domeine** vir sommige TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) bied so 'n diens) en **kontroleer die sleutelwoorde in hierdie domeine**. Lang domeine gebruik egter gewoonlik een of meer subdomeine, daarom sal die sleutelwoord nie binne die FLD verskyn nie en sal jy nie die phishing-subdomein kan vind nie.

Bykomende heuristiek: behandel sekere **file-extension TLDs** (bv. `.zip`, `.mov`) met ekstra agterdog in waarskuwings. Hierdie word dikwels verwar met lêernaam in lures; kombineer die TLD-sein met handelsmerk-sleutelwoorde en NRD-ouderdom vir beter presisie.

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
