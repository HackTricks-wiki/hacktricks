# Kugundua Phishing

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

Ili kugundua jaribio la phishing, ni muhimu **kuelewa mbinu za phishing zinazotumika siku hizi**. Kwenye ukurasa mkuu wa chapisho hili, unaweza kupata taarifa hii; kwa hivyo, kama hujui ni mbinu zipi zinatumika leo, ninapendekeza uende kwenye ukurasa mkuu na usome angalau sehemu hiyo.

Chapisho hili linatokana na wazo kwamba **washambuliaji watajaribu kwa namna fulani kuiga au kutumia jina la domain ya mwathiriwa**. Kama domain yako inaitwa `example.com` na umefanyiwa phishing kwa kutumia jina la domain tofauti kabisa kwa sababu fulani kama `youwonthelottery.com`, mbinu hizi hazitaweza kuigundua.

## Tofauti za majina ya domain

Ni **rahisi** kwa kiasi fulani **kugundua** majaribio hayo ya **phishing** yanayotumia jina la **domain linalofanana** ndani ya barua pepe.\
Inatosha **kutengeneza orodha ya majina ya phishing yanayowezekana zaidi** ambayo mshambuliaji anaweza kutumia na **kuangalia** kama **imesajiliwa**, au kuangalia tu kama kuna **IP** inayoitumia.

### Kupata domain zinazotiliwa shaka

Kwa madhumuni haya, unaweza kutumia mojawapo ya tools zifuatazo. Zote mbili hutatua candidate domains ili kuangalia kama zinatumika.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Kidokezo: Ukitengeneza orodha ya candidates, pia ipeleke kwenye DNS resolver logs zako ili kugundua **NXDOMAIN lookups kutoka ndani ya org yako** (watumiaji wanaojaribu kufikia typo kabla mshambuliaji hajaisajili). Tumia sinkhole au zuia mapema domains hizi ikiwa policy inaruhusu.

### Bitflipping

**Kwa maelezo mafupi, tazama ukurasa mkuu; kwa utafiti wa msingi kuhusu bitsquatting ya Windows.com, tazama [maandishi ya Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) na [ripoti ya BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Kwa mfano, marekebisho ya bit 1 katika domain microsoft.com yanaweza kuibadilisha kuwa _windnws.com._\
**Washambuliaji wanaweza kusajili domains nyingi za bit-flipping iwezekanavyo zinazohusiana na mwathiriwa, ili kuwaelekeza watumiaji halali kwenye infrastructure yao**.<sup>[[1]](#references)[[2]](#references)</sup>

**Majina yote yanayowezekana ya domains za bit-flipping yanapaswa pia kufuatiliwa.**

Ikiwa pia unahitaji kuzingatia homoglyph/IDN lookalikes (kwa mfano, kuchanganya herufi za Kilatini na Kirylic), angalia:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Ukaguzi wa msingi

Baada ya kuwa na orodha ya majina ya domains zinazoweza kutiliwa shaka, unapaswa **kuzikagua** (hasa ports za HTTP na HTTPS) ili **kuona kama zinatumia login form inayofanana** na ile ya domain ya mwathiriwa.\
Unaweza pia kuangalia port 3333 ili kuona kama iko wazi na inaendesha instance ya `gophish`.\
Pia ni muhimu kujua **kila domain inayotiliwa shaka iliyogunduliwa ina umri gani**, kwa sababu kadiri ilivyo changa ndivyo hatari inavyokuwa kubwa.\
Unaweza pia kupata **screenshots** za ukurasa wa web unaotiliwa shaka wa HTTP na/au HTTPS ili kuona kama unatiliwa shaka, na katika hali hiyo **kuufikia ili kuuchunguza kwa kina zaidi**.

### Ukaguzi wa hali ya juu

Ukitaka kwenda hatua moja zaidi, ninapendekeza **ufuatilie domains hizo zinazotiliwa shaka na kutafuta nyingine zaidi** mara kwa mara (kila siku? inachukua sekunde/dakika chache tu). Unapaswa pia **kuangalia** **ports** zilizo wazi za IP zinazohusiana na **kutafuta instances za `gophish` au tools zinazofanana** (ndiyo, washambuliaji pia hufanya makosa), na **kufuatilia kurasa za web za HTTP na HTTPS za domains na subdomains zinazotiliwa shaka** ili kuona kama zimenakili login form yoyote kutoka kwenye kurasa za web za mwathiriwa.\
Ili **kuautomate hili**, ninapendekeza uwe na orodha ya login forms za domains za mwathiriwa, ufanye spidering ya kurasa za web zinazotiliwa shaka, kisha ulinganishe kila login form iliyopatikana ndani ya domains zinazotiliwa shaka na kila login form ya domain ya mwathiriwa ukitumia kitu kama `ssdeep`.\
Ikiwa umezipata login forms za domains zinazotiliwa shaka, unaweza kujaribu **kutuma junk credentials** na **kuangalia kama zinakuelekeza kwenye domain ya mwathiriwa**.

---

### Hunting kwa kutumia favicon na web fingerprints (Shodan/Censys)

Phishing kits nyingi hutumia tena favicons kutoka kwenye brand zinazoiga. Shodan huhash data ya favicon iliyosimbwa kwa base64 kwa kutumia MurmurHash3, huku Censys ikionyesha favicon hash fields zake yenyewe.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Unaweza kutengeneza hash inayooana na Shodan na kuitumia kufanya pivot:

Mfano wa Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Query Shodan: `http.favicon.hash:309020573`
- Kwa kutumia zana: angalia zana za community kama favfreak ili kukokotoa hash na kutengeneza Shodan dorks.<sup>[[16]](#references)</sup>

Maelezo
- Favicons hutumiwa tena; chukulia matokeo yanayolingana kama vidokezo na uhakiki maudhui na vyeti kabla ya kuchukua hatua.
- Changanya na heuristics za umri wa domain na keywords kwa usahihi zaidi.

### Uwindaji wa URL telemetry (urlscan.io)

`urlscan.io` huhifadhi screenshots za kihistoria, DOM, requests na metadata ya TLS ya URL zilizowasilishwa. Unaweza kuwindia matumizi mabaya ya brand na clones:<sup>[[8]](#references)</sup>

Mifano ya queries (UI au API):
- Tafuta lookalikes ukiondoa domain zako halali: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Tafuta sites zinazotumia assets zako kupitia hotlinking: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Punguza kwenye matokeo ya hivi karibuni: ongeza `AND date:>now-7d`

Mfano wa API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Kutoka kwenye JSON, chuza kwa kutumia:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` ili kutambua certs mpya sana za domains zinazofanana
- Thamani za `task.source` kama `certstream-suspicious` ili kuhusisha matokeo na ufuatiliaji wa CT

### Umri wa domain kupitia RDAP (scriptable)

RDAP hurejesha matukio ya usajili yanayoweza kusomeka na mashine. Ni muhimu kwa kutambua **domains zilizosajiliwa hivi karibuni (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Boresha pipeline yako kwa kuweka tag za vikoa kulingana na makundi ya umri wa usajili (kwa mfano, <7 days, <30 days) na uipe kipaumbele triage ipasavyo.

### TLS/JAx fingerprints za kutambua AiTM infrastructure

Credential-phishing inaweza kutumia **Adversary-in-the-Middle (AiTM)** reverse proxies (kwa mfano, Evilginx) kuiba session tokens.<sup>[[11]](#references)</sup> Unaweza kuongeza detections upande wa network:

- Rekodi TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) kwenye egress. Baadhi ya Evilginx builds zimeonekana zikiwa na JA4 client/server values thabiti. Toa alert kwa fingerprints zinazojulikana kuwa hatari kama signal dhaifu pekee, na kila mara thibitisha kwa content na domain intel.<sup>[[12]](#references)</sup>
- Rekodi mapema metadata ya TLS certificate (issuer, SAN count, wildcard use, validity) kwa lookalike hosts zilizogunduliwa kupitia CT au urlscan, kisha linganisha na umri wa DNS na geolocation.

> Kumbuka: Chukulia fingerprints kama enrichment, si blockers pekee; frameworks hubadilika na zinaweza kufanya randomise au obfuscate.

### Domain names zinazotumia keywords

Ukurasa wa parent pia unataja mbinu ya domain name variation inayohusisha kuweka **victim's domain name ndani ya domain kubwa zaidi** (kwa mfano, paypal-financial.com kwa paypal.com).

#### Certificate Transparency

Certificate Transparency (CT) logs hufichua certificate identities, hivyo kutafuta Subject au SAN names kwa brand keywords kunaweza kufichua lookalike domains (kwa mfano, certificate ya `paypal-financial.com` hufichua keyword ya `paypal`). Chuja matokeo kwa issuance date na CA inapofaa, na validate candidates kwa sababu keyword matches zinaweza kuwa false positives.<sup>[[13]](#references)</sup>

Patrik Hudak's original [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) inaonyesha workflow hii kwenye Censys, ikijumuisha filters za certificate date na issuer kama Let's Encrypt.<sup>[[13]](#references)</sup>

![Censys certificate search results zilizotumika kutambua lookalike domains](<../../images/image (1115).png>)

Unaweza pia kutumia huduma ya bure ya [**crt.sh**](https://crt.sh) kutafuta keyword na kuchuja matokeo kwa date na CA.<sup>[[13]](#references)</sup>

![crt.sh keyword search ya suspicious certificate identities](<../../images/image (519).png>)

Sehemu yake ya Matching Identities inaweza kusaidia kulinganisha identities kutoka domain halisi na suspicious domains, lakini chukulia matches kama leads badala ya proof.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) husambaza CT updates karibu na real time, na [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) hutumia stream hiyo kuweka score kwenye suspicious certificate names.<sup>[[14]](#references)[[15]](#references)</sup>

Ushauri wa vitendo: unapofanya triage ya CT hits, zipatie kipaumbele NRDs, untrusted/unknown registrars, privacy-proxy WHOIS, na certs zenye `NotBefore` times za hivi karibuni sana. Dumisha allowlist ya domains/brands zako ili kupunguza noise.

#### **Vikoa vipya**

Chaguo la pili ni kukusanya newly registered domains kwa TLD (kwa mfano, kupitia [Whoxy](https://www.whoxy.com/newly-registered-domains/)) na kuchuja kwa brand keywords. Hii hukosa phishing inayohostiwa kwenye subdomains wakati keyword haipo kwenye registered domain.<sup>[[13]](#references)</sup>

Heuristic ya ziada: chukulia baadhi ya **file-extension TLDs** (kwa mfano, `.zip`, `.mov`) kwa suspicion ya ziada kwenye alerting. Hizi mara nyingi huchanganywa na filenames kwenye lures; changanya TLD signal na brand keywords pamoja na NRD age ili kupata precision bora.

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
- [11] [Token tactics: Jinsi ya kuzuia, kutambua na kujibu wizi wa cloud token](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Kutafuta Phishing: Zana na Mbinu](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Kuanzisha CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
