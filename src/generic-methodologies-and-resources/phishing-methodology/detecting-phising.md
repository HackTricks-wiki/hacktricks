# Opsporing van Phishing

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

Om ’n phishing-poging op te spoor, is dit belangrik om **die phishing-tegnieke te verstaan wat deesdae gebruik word**. Op die ouerbladsy van hierdie plasing kan jy hierdie inligting kry. As jy dus nie weet watter tegnieke vandag gebruik word nie, beveel ek aan dat jy na die ouerbladsy gaan en ten minste daardie afdeling lees.

Hierdie plasing is gebaseer op die idee dat die **aanvallers op een of ander manier die slagoffer se domeinnaam sal probeer naboots of gebruik**. As jou domein `example.com` heet en jy om een of ander rede met ’n heeltemal ander domeinnaam soos `youwonthelottery.com` geteiken word, gaan hierdie tegnieke dit nie opspoor nie.

## Domeinnaamvariasies

Dit is redelik **maklik** om daardie **phishing**-pogings **op te spoor** wat ’n **soortgelyke domeinnaam** in die e-pos sal gebruik.\
Dit is genoeg om ’n **lys te genereer van die waarskynlikste phishing-name** wat ’n aanvaller kan gebruik en **te kyk** of hulle **geregistreer** is, of bloot te kyk of enige **IP** hulle gebruik.

### Vind verdagte domeine

Vir hierdie doel kan jy enige van die volgende nutsmiddels gebruik. Albei soek kandidaatdomeine op om te kyk of hulle in gebruik is.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Wenk: As jy ’n kandidaatlys genereer, voer dit ook in jou DNS-resolverlogboeke in om **NXDOMAIN-opsoeke van binne jou organisasie** op te spoor (gebruikers wat probeer om ’n tikfoutdomein te bereik voordat die aanvaller dit werklik registreer). Sinkhole of blokkeer hierdie domeine vooraf as die beleid dit toelaat.

### Bitflipping

**Vir ’n kort verduideliking, sien die ouerbladsy; vir oorspronklike navorsing oor Windows.com-bitsquatting, sien [Remy Hax se artikel](https://remyhax.xyz/posts/bitsquatting-windows/) en [BleepingComputer se berig](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Byvoorbeeld, ’n 1-bit-verandering in die domein microsoft.com kan dit in _windnws.com_ verander.\
**Aanvallers kan soveel as moontlik bit-flipping-domeine registreer wat met die slagoffer verband hou, om wettige gebruikers na hul infrastruktuur te herlei**.<sup>[[1]](#references)[[2]](#references)</sup>

**Alle moontlike bit-flipping-domeinname moet ook gemonitor word.**

As jy ook homoglyph/IDN-nabootsings (bv. ’n mengsel van Latynse en Cyrilliese karakters) moet oorweeg, kyk na:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basiese kontroles

Sodra jy ’n lys potensieel verdagte domeinname het, moet jy hulle **nagaan** (hoofsaaklik die HTTP- en HTTPS-poorte) om **te kyk of hulle ’n aanmeldvorm gebruik wat soortgelyk is aan een van die slagoffer se domeine**.\
Jy kan ook poort 3333 nagaan om te sien of dit oop is en ’n `gophish`-instansie gebruik.\
Dit is ook nuttig om te weet **hoe oud elke opgespoorde verdagte domein is**; hoe jonger dit is, hoe groter is die risiko.\
Jy kan ook **skermskote** van die verdagte HTTP- en/of HTTPS-webblad kry om te sien of dit verdag lyk, en dit dan **besoek om dit van nader te ondersoek**.

### Gevorderde kontroles

As jy ’n stap verder wil gaan, beveel ek aan dat jy **daardie verdagte domeine monitor en van tyd tot tyd na meer soek** (elke dag? Dit neem net ’n paar sekondes/minute). Jy moet ook die oop **poorte** van die verwante IP’s **nagaan en na `gophish`-instansies of soortgelyke nutsmiddels soek** (ja, aanvallers maak ook foute) en **die HTTP- en HTTPS-webblaaie van die verdagte domeine en subdomeine monitor** om te sien of hulle enige aanmeldvorm van die slagoffer se webblaaie gekopieer het.\
Om dit te **outomatiseer**, beveel ek aan dat jy ’n lys van die slagoffer se domeine se aanmeldvorms maak, die verdagte webblaaie deursoek en elke aanmeldvorm wat op die verdagte domeine gevind word, met elke aanmeldvorm van die slagoffer se domein vergelyk deur iets soos `ssdeep` te gebruik.\
As jy die aanmeldvorms van die verdagte domeine opgespoor het, kan jy probeer om **gemorsbewyse te stuur** en **kyk of dit jou na die slagoffer se domein herlei**.

---

### Soek op favicon- en webvingerafdrukke (Shodan/Censys)

Baie phishing-kits hergebruik favicons van die handelsmerk wat hulle naboots. Shodan bereken ’n hash van die base64-geënkodeerde favicon-data met MurmurHash3, terwyl Censys sy eie favicon-hashvelde beskikbaar stel.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Jy kan ’n Shodan-versoenbare hash genereer en daarmee soek:

Python-voorbeeld (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Soek in Shodan: `http.favicon.hash:309020573`
- Met tools: kyk na community tools soos favfreak om hashes te bereken en Shodan-dorks te genereer.<sup>[[16]](#references)</sup>

Aantekeninge
- Favicons word hergebruik; behandel passings as leidrade en valideer inhoud en sertifikate voordat jy optree.
- Kombineer met heuristieke vir domeinouderdom en sleutelwoorde vir beter presisie.

### URL-telemetrie-hunting (urlscan.io)

`urlscan.io` stoor historiese skermskote, DOM, versoeke en TLS-metadata van ingediende URL's. Jy kan soek na handelsmerkmisbruik en klone:<sup>[[8]](#references)</sup>

Voorbeeldnavrae (UI of API):
- Vind soortgelyke domeine, uitgesluit jou wettige domeine: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Vind werwe wat hotlinking na jou bates doen: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Beperk tot onlangse resultate: voeg `AND date:>now-7d` by

API-voorbeeld:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

Vanuit die JSON, ondersoek:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` om baie nuwe sertifikate vir lookalikes raak te sien
- `task.source`-waardes soos `certstream-suspicious` om bevindinge aan CT-monitering te koppel

### Domeinouderdom via RDAP (skripteerbaar)

RDAP gee masjienleesbare registrasiegebeurtenisse terug. Dit is nuttig om **nuut geregistreerde domeine (NRDs)** te merk.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Verryk jou pipeline deur domeine met registrasie-ouderdomskategorieë te merk (bv. <7 dae, <30 dae) en prioritiseer triage dienooreenkomstig.

### TLS/JAx-vingerafdrukke om AiTM-infrastruktuur raak te sien

Credential-phishing kan **Adversary-in-the-Middle (AiTM)**-reverse proxies (bv. Evilginx) gebruik om sessietokens te steel.<sup>[[11]](#references)</sup> Jy kan netwerkgebaseerde opsporing byvoeg:

- Teken TLS/HTTP-vingerafdrukke (JA3/JA4/JA4S/JA4H) by egress aan. Daar is waargeneem dat sommige Evilginx-bouweergawes stabiele JA4-kliënt-/bedienerwaardes het. Stel waarskuwings op vir bekende slegte vingerafdrukke, maar behandel dit slegs as ’n swak sein en bevestig altyd met inhouds- en domeininligting.<sup>[[12]](#references)</sup>
- Teken proaktief TLS-sertifikaatmetadata (uitreiker, SAN-telling, gebruik van wildcards, geldigheid) aan vir lookalike-gashere wat via CT of urlscan ontdek is, en korreleer dit met DNS-ouderdom en geoligging.

> Let wel: Behandel vingerafdrukke as verryking, nie as enigste blokkeerders nie; frameworks ontwikkel en kan waardes ewekansig maak of verdoesel.

### Domeinname wat sleutelwoorde gebruik

Die ouerbladsy noem ook ’n domeinnaamvariasietegniek wat behels dat die **slagoffer se domeinnaam binne ’n groter domein geplaas word** (bv. paypal-financial.com vir paypal.com).

#### Certificate Transparency

Certificate Transparency (CT)-logboeke stel sertifikaatidentiteite bloot; daarom kan soektogte na handelsmerksleutelwoorde in Subject- of SAN-name lookalike-domeine onthul (byvoorbeeld, ’n sertifikaat vir `paypal-financial.com` bevat die sleutelwoord `paypal`). Filtreer resultate volgens uitreikingsdatum en CA waar dit nuttig is, en valideer kandidate aangesien sleutelwoordtreffers vals positiewe kan wees.<sup>[[13]](#references)</sup>

Patrik Hudak se oorspronklike [skrywe oor die opsporing van phishing-domeine](https://0xpatrik.com/phishing-domains/) demonstreer hierdie werkvloei in Censys, insluitend filters vir sertifikaatdatum en uitreiker soos Let's Encrypt.<sup>[[13]](#references)</sup>

![Censys-sertifikaatsoekresultate wat gebruik word om lookalike-domeine te identifiseer](<../../images/image (1115).png>)

Jy kan ook die gratis diens [**crt.sh**](https://crt.sh) gebruik om na ’n sleutelwoord te soek en resultate volgens datum en CA te filtreer.<sup>[[13]](#references)</sup>

![crt.sh-sleutelwoordsoektog na verdagte sertifikaatidentiteite](<../../images/image (519).png>)

Die veld Matching Identities kan help om identiteite van die regte domein met dié van verdagte domeine te vergelyk, maar behandel ooreenstemmings as leidrade eerder as bewys.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) stroom CT-opdaterings byna intyds, en [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) verwerk dié stroom om verdagte sertifikaatname ’n telling te gee.<sup>[[14]](#references)[[15]](#references)</sup>

Praktiese wenk: Wanneer jy CT-treffers triage, prioritiseer NRD's, onbetroubare/onbekende registrateurs, WHOIS met privaatheidsinstaanbedieners en sertifikate met baie onlangse `NotBefore`-tye. Hou ’n toelaatlys van jou besitdomeine/-handelsmerke by om geraas te verminder.

#### **Nuwe domeine**

’n Tweede opsie is om nuutgeregistreerde domeine per TLD in te samel (byvoorbeeld via [Whoxy](https://www.whoxy.com/newly-registered-domains/)) en volgens handelsmerksleutelwoorde te filtreer. Dit mis phishing wat op subdomeine aangebied word wanneer die sleutelwoord nie in die geregistreerde domein voorkom nie.<sup>[[13]](#references)</sup>

Bykomende heuristiek: behandel sekere **lêeruitbreiding-TLD's** (bv. `.zip`, `.mov`) met ekstra agterdog in waarskuwings. Dit word dikwels in lokmiddels met lêername verwar; kombineer die TLD-sein met handelsmerksleutelwoorde en NRD-ouderdom vir beter akkuraatheid.

## References

- [1] [Remy Hax – Bitsquatting van Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Verkeer na Microsoft se windows.com kaap met bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Diepgaande ondersoek: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3-dokumentasie](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform-datastel van webeienskappe](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Verwysing vir die Search API](https://urlscan.io/docs/search/)
- [9] [Hulp vir die Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON-antwoorde vir die Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token-taktieke: Hoe om wolktoken-diefstal te voorkom, op te spoor en daarop te reageer](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+-netwerkvingerafdrukke](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing opspoor: gereedskap en tegnieke](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Bekendstelling van CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
