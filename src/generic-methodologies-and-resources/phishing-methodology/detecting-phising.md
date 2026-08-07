# Kugundua Phishing

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

Ili kugundua jaribio la phishing, ni muhimu **kuelewa mbinu za phishing zinazotumiwa siku hizi**. Kwenye ukurasa mkuu wa chapisho hili, unaweza kupata maelezo hayo. Kwa hiyo, kama hujui ni mbinu zipi zinazotumiwa leo, ninapendekeza uende kwenye ukurasa mkuu na usome angalau sehemu hiyo.

Chapisho hili linatokana na wazo kwamba **washambuliaji watajaribu kwa namna fulani kuiga au kutumia jina la domain ya mwathiriwa**. Ikiwa domain yako inaitwa `example.com` na umefanyiwa phishing kwa kutumia jina tofauti kabisa la domain, kwa sababu kama `youwonthelottery.com`, mbinu hizi hazitaigundua.

## Tofauti za majina ya domain

Ni **rahisi kiasi** **kugundua** majaribio hayo ya **phishing** yatakayotumia jina la **domain inayofanana** ndani ya barua pepe.\
Inatosha **kutengeneza orodha ya majina ya phishing yanayowezekana zaidi** ambayo mshambuliaji anaweza kutumia na **kuangalia** ikiwa yamesajiliwa, au kuangalia tu ikiwa kuna **IP** inayotumia jina hilo.

### Kupata domain zinazotia shaka

Kwa kusudi hili, unaweza kutumia zana zozote kati ya hizi. Kumbuka kwamba zana hizi pia zitatuma maombi ya DNS kiotomatiki ili kuangalia ikiwa domain ina IP iliyotengewa:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Kidokezo: Ukitengeneza orodha ya majina yanayoweza kutumiwa, pia ipeleke kwenye logs za DNS resolver yako ili kugundua **NXDOMAIN lookups kutoka ndani ya org yako** (watumiaji wanaojaribu kufikia typo kabla mshambuliaji hajaisajili). Weka domains hizo kwenye sinkhole au uzizuie mapema ikiwa policy inaruhusu.

### Bitflipping

**Unaweza kupata maelezo mafupi ya mbinu hii kwenye ukurasa mkuu. Au soma utafiti wa awali katika** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Kwa mfano, mabadiliko ya bit 1 kwenye domain microsoft.com yanaweza kuibadilisha kuwa _windnws.com._\
**Washambuliaji wanaweza kusajili domains nyingi za bit-flipping iwezekanavyo zinazohusiana na mwathiriwa, ili kuwaelekeza watumiaji halali kwenye infrastructure yao**.<sup>[[1]](#references)</sup>

**Majina yote ya domains yanayowezekana ya bit-flipping yanapaswa pia kufuatiliwa.**

Ikiwa pia unahitaji kuzingatia homoglyph/IDN lookalikes (kwa mfano, kuchanganya herufi za Latin/Cyrillic), angalia:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Ukaguzi wa msingi

Baada ya kuwa na orodha ya majina ya domains yanayoweza kuwa za kutiliwa shaka, unapaswa **kuyakagua** (hasa ports za HTTP na HTTPS) ili **kuona ikiwa yanatumia login form inayofanana** na ya domain ya mwathiriwa.\
Unaweza pia kuangalia port 3333 ili kuona ikiwa iko wazi na inaendesha instance ya `gophish`.\
Pia ni muhimu kujua **kila domain iliyogunduliwa na inayotia shaka ina umri gani**; ikiwa ni changa, hatari huwa kubwa zaidi.\
Unaweza pia kupata **screenshots** za ukurasa wa web wa HTTP na/au HTTPS unaotia shaka, ili kuona ikiwa una shaka, na katika hali hiyo **kuufikia ili kuuchunguza kwa kina**.

### Ukaguzi wa hali ya juu

Ikiwa unataka kwenda hatua moja zaidi, ninapendekeza **kufuatilia domains hizo zinazotia shaka na kutafuta nyingine zaidi** mara kwa mara (kila siku? huchukua sekunde/dakika chache tu). Unapaswa pia **kuangalia** **ports** zilizo wazi za IP zinazohusiana na **kutafuta instances za `gophish` au tools zinazofanana** (ndiyo, washambuliaji pia hufanya makosa), na **kufuatilia kurasa za web za HTTP na HTTPS za domains na subdomains zinazotia shaka** ili kuona ikiwa zimenakili login form kutoka kwenye kurasa za web za mwathiriwa.\
Ili **kuautomate hili**, ninapendekeza uwe na orodha ya login forms za domains za mwathiriwa, ufanye spidering ya kurasa za web zinazotia shaka, kisha ulinganishe kila login form iliyopatikana ndani ya domains zinazotia shaka na kila login form ya domain ya mwathiriwa kwa kutumia kitu kama `ssdeep`.\
Ikiwa umezipata login forms za domains zinazotia shaka, unaweza kujaribu **kutuma credentials za kubuni** na **kuangalia ikiwa zinakupeleka kwenye domain ya mwathiriwa**.

---

### Hunting kwa kutumia favicon na web fingerprints (Shodan/ZoomEye/Censys)

Phishing kits nyingi hutumia tena favicons za brand wanayoiga. Scanners za Internet-wide huhesabu MurmurHash3 ya favicon iliyowekwa katika mfumo wa base64. Unaweza kutengeneza hash hiyo na kuitumia kutafuta zinazohusiana:

Mfano wa Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Query Shodan: `http.favicon.hash:309020573`
- Kwa kutumia tooling: angalia community tools kama favfreak ili kuzalisha hashes na dorks za Shodan/ZoomEye/Censys.

### Maelezo
- Favicons hutumiwa tena; chukulia matches kama leads na uhakiki content na certs kabla ya kuchukua hatua.
- Changanya na heuristics za umri wa domain na keywords ili kupata usahihi bora.

### Uwindaji wa URL telemetry (urlscan.io)

`urlscan.io` huhifadhi screenshots za kihistoria, DOM, requests na TLS metadata za URLs zilizowasilishwa. Unaweza kuwindia brand abuse na clones:<sup>[[2]](#references)</sup>

Mfano wa queries (UI au API):
- Tafuta lookalikes ukiondoa domains zako halali: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Tafuta sites zinazotumia assets zako kupitia hotlinking: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Punguza kwenye results za hivi karibuni: ongeza `AND date:>now-7d`

Mfano wa API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Kutoka kwenye JSON, pivot kwa:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` ili kubaini vyeti vipya sana vya lookalikes
- Thamani za `task.source` kama vile `certstream-suspicious` ili kuhusisha matokeo na ufuatiliaji wa CT

### Umri wa domain kupitia RDAP (scriptable)

RDAP hurejesha matukio ya uundaji yanayoweza kusomeka na mashine. Ni muhimu kwa kuashiria **newly registered domains (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Boresha pipeline yako kwa kuweka domains katika makundi ya umri wa usajili (kwa mfano, <7 days, <30 days) na uyape kipaumbele cha triage ipasavyo.

### TLS/JAx fingerprints za kutambua AiTM infrastructure

Credential-phishing ya kisasa inazidi kutumia **Adversary-in-the-Middle (AiTM)** reverse proxies (kwa mfano, Evilginx) ili kuiba session tokens. Unaweza kuongeza network-side detections:

- Rekodi TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) kwenye egress. Baadhi ya Evilginx builds zimeonekana zikiwa na JA4 client/server values thabiti. Toa alert kwa fingerprints zinazojulikana kuwa mbaya kama weak signal pekee, na kila mara thibitisha kwa content na domain intel.<sup>[[3]](#references)</sup>
- Rekodi kwa proactively TLS certificate metadata (issuer, SAN count, wildcard use, validity) kwa lookalike hosts zilizogunduliwa kupitia CT au urlscan, na ulinganishe na DNS age pamoja na geolocation.

> Note: Chukulia fingerprints kama enrichment, si blockers pekee; frameworks hubadilika na zinaweza randomise au obfuscate.

### Domain names zinazotumia keywords

Parent page pia inataja domain name variation technique inayohusisha kuweka **victim's domain name ndani ya domain kubwa zaidi** (kwa mfano, paypal-financial.com kwa paypal.com).

#### Certificate Transparency

Haiwezekani kutumia approach ya awali ya "Brute-Force", lakini kwa hakika **inawezekana kugundua phishing attempts kama hizi** pia kwa msaada wa certificate transparency. Kila mara certificate inapotolewa na CA, details zake huwekwa hadharani. Hii inamaanisha kwamba kwa kusoma certificate transparency au hata kuifuatilia, **inawezekana kupata domains zinazotumia keyword ndani ya jina lake**. Kwa mfano, attacker akitengeneza certificate ya [https://paypal-financial.com](https://paypal-financial.com), kwa kuona certificate inawezekana kupata keyword "paypal" na kujua kwamba suspicious email inatumika.

Post ya [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) inapendekeza kutumia Censys kutafuta certificates zinazoathiri keyword maalum na kuchuja kwa date (certificates "new" pekee) na kwa CA issuer "Let's Encrypt":<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Hata hivyo, unaweza kufanya "the same" ukitumia web ya bure [**crt.sh**](https://crt.sh). Unaweza **kutafuta keyword** na **kuchuja** results **kwa date na CA** ukitaka.

![Domain names zinazotumia keywords - Certificate Transparency: Hata hivyo, unaweza kufanya "the same" ukitumia web ya bure crt.sh . Unaweza kutafuta keyword na kuchuja results kwa date na...](<../../images/image (519).png>)

Ukitumia option hii ya mwisho, unaweza hata kutumia field ya Matching Identities kuona kama identity yoyote kutoka kwenye real domain inalingana na suspicious domains (kumbuka kwamba suspicious domain inaweza kuwa false positive).

**Another alternative** ni project nzuri inayoitwa [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream hutoa real-time stream ya certificates mpya zilizotengenezwa, ambayo unaweza kutumia kutambua keywords maalum kwa (near) real-time. Kwa kweli, kuna project inayoitwa [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) inayofanya hivyo.

Practical tip: unapofanya triage ya CT hits, panga kipaumbele kwa NRDs, untrusted/unknown registrars, privacy-proxy WHOIS, na certs zenye `NotBefore` times za hivi karibuni sana. Dumisha allowlist ya domains/brands zako ili kupunguza noise.

#### **New domains**

**One last alternative** ni kukusanya list ya **newly registered domains** kwa baadhi ya TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) hutoa service hiyo) na **kuangalia keywords katika domains hizo**. Hata hivyo, long domains kwa kawaida hutumia subdomains moja au zaidi; kwa hiyo keyword haitaonekana ndani ya FLD na hutaweza kupata phishing subdomain.

Additional heuristic: chukulia **file-extension TLDs** fulani (kwa mfano, `.zip`, `.mov`) kwa suspicion ya ziada wakati wa alerting. Hizi huchanganywa kwa urahisi na filenames katika lures; changanya TLD signal na brand keywords pamoja na NRD age ili kupata precision bora.

## References

- [1] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
