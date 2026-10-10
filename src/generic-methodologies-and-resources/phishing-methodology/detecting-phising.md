# Kutambua Phishing

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

Ili kutambua jaribio la phishing, ni muhimu **kuelewa mbinu za phishing zinazotumiwa siku hizi**. Unaweza kupata maelezo haya kwenye ukurasa mkuu wa chapisho hili. Kwa hiyo, ikiwa hujui mbinu zinazotumiwa leo, ninapendekeza uende kwenye ukurasa mkuu na usome angalau sehemu hiyo.

Chapisho hili linatokana na dhana kwamba **washambuliaji watajaribu kwa njia fulani kuiga au kutumia jina la domain la mwathiriwa**. Ikiwa domain yako inaitwa `example.com` na unafanyiwa phishing kwa kutumia jina la domain tofauti kabisa kwa sababu fulani, kama `youwonthelottery.com`, mbinu hizi hazitaweza kuligundua.

## Tofauti za majina ya domain

Ni **rahisi** kwa kiasi **kugundua** majaribio hayo ya **phishing** yanayotumia jina la **domain linalofanana** ndani ya barua pepe.\
Inatosha **kutengeneza orodha ya majina ya phishing yanayowezekana zaidi** ambayo mshambuliaji anaweza kutumia na **kuangalia** ikiwa yamesajiliwa, au kuangalia tu kama kuna **IP** yoyote inayoyatumia.

### Kutafuta domain zinazotia shaka

Kwa madhumuni haya, unaweza kutumia zana zozote kati ya hizi. Zote hutatua candidate domains ili kuangalia kama zinatumika.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Kidokezo: Ukitengeneza orodha ya candidate domains, iwasilishe pia kwenye kumbukumbu za DNS resolver yako ili kugundua **NXDOMAIN lookups kutoka ndani ya shirika lako** (watumiaji wanaojaribu kufikia domain iliyoandikwa vibaya kabla mshambuliaji hajaisajili). Elekeza domain hizo kwenye sinkhole au uzizuie mapema ikiwa sera inaruhusu.

### Bitflipping

**Kwa maelezo mafupi, tazama ukurasa mkuu; kwa utafiti wa msingi kuhusu bitsquatting ya Windows.com, tazama [makala ya Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) na [ripoti ya BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Kwa mfano, kubadilisha biti 1 katika domain microsoft.com kunaweza kuibadilisha kuwa _windnws.com._\
**Washambuliaji wanaweza kusajili domain nyingi iwezekanavyo zilizobadilishwa kwa bit-flipping zinazohusiana na mwathiriwa, ili kuelekeza watumiaji halali kwenye miundombinu yao**.<sup>[[1]](#references)[[2]](#references)</sup>

**Majina yote ya domain yanayowezekana kupitia bit-flipping yanapaswa pia kufuatiliwa.**

Ikiwa unahitaji pia kuzingatia majina yanayofanana kwa kutumia homoglyph/IDN (kwa mfano, kuchanganya herufi za Kilatini na Kikirili), angalia:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Ukaguzi wa msingi

Ukiwa na orodha ya majina ya domain yanayoweza kutia shaka, unapaswa **kuyakagua** (hasa port za HTTP na HTTPS) ili **kuona kama yanatumia fomu ya kuingia inayofanana** na ile ya domain ya mwathiriwa.\
Unaweza pia kuangalia port 3333 ili kuona kama iko wazi na inaendesha instance ya `gophish`.\
Pia ni muhimu kujua **kila domain inayotia shaka iliyogunduliwa ina umri gani**; kadiri ilivyo changa, ndivyo hatari inavyokuwa kubwa.\
Unaweza pia kupata **picha za skrini** za ukurasa wa wavuti wa HTTP na/au HTTPS unaotia shaka ili kuona kama unatia shaka, na ikiwa ndivyo, **kuufikia ili kuuchunguza kwa kina zaidi**.

### Ukaguzi wa kina

Ukitaka kwenda hatua moja mbele, ningependekeza **ufuatilie domain hizo zinazotia shaka na utafute nyingine zaidi** mara kwa mara (kila siku? huchukua sekunde/dakika chache tu). Unapaswa pia **kukagua** **port** zilizo wazi za IP zinazohusiana na **kutafuta instance za `gophish` au zana zinazofanana** (ndiyo, washambuliaji pia hufanya makosa), na **kufuatilia kurasa za wavuti za HTTP na HTTPS za domain na subdomain zinazotia shaka** ili kuona kama zimenakili fomu yoyote ya kuingia kutoka kwenye kurasa za wavuti za mwathiriwa.\
Ili **kuotomatisha hili**, ningependekeza uwe na orodha ya fomu za kuingia za domain za mwathiriwa, utambaze kurasa za wavuti zinazotia shaka na kulinganisha kila fomu ya kuingia iliyopatikana kwenye domain zinazotia shaka na kila fomu ya kuingia ya domain ya mwathiriwa kwa kutumia kitu kama `ssdeep`.\
Ukishazipata fomu za kuingia za domain zinazotia shaka, unaweza kujaribu **kutuma credentials za kubuni** na **kuangalia kama zinakuelekeza kwenye domain ya mwathiriwa**.

---

### Kutafuta kwa favicon na alama za utambulisho wa wavuti (Shodan/Censys)

Phishing kits nyingi hutumia tena favicon za chapa wanazojifanya kuwa. Shodan huhesabu hash ya data ya favicon iliyosimbwa kwa base64 kwa kutumia MurmurHash3, huku Censys ikiweka wazi sehemu zake za hash ya favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Unaweza kutengeneza hash inayooana na Shodan na kuitumia kutafuta matokeo yanayohusiana:

Mfano wa Python (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Tafuta kwenye Shodan: `http.favicon.hash:309020573`
- Kwa kutumia zana: angalia zana za jamii kama favfreak ili kukokotoa hashes na kutengeneza Shodan dorks.<sup>[[16]](#references)</sup>

Vidokezo
- Favicons hutumiwa tena; chukulia matokeo yanayolingana kama vidokezo na uthibitishe maudhui na certs kabla ya kuchukua hatua.
- Changanya na heuristics za umri wa domain na maneno muhimu ili kupata matokeo sahihi zaidi.

### Uwindaji wa telemetry ya URL (urlscan.io)

`urlscan.io` huhifadhi picha za skrini za kihistoria, DOM, maombi na metadata ya TLS ya URL zilizowasilishwa. Unaweza kuitumia kutafuta matumizi mabaya ya brand na clones:<sup>[[8]](#references)</sup>

Mifano ya queries (UI au API):
- Tafuta zinazofanana na domain zako, ukiondoa domain zako halali: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Tafuta sites zinazotumia assets zako kupitia hotlinking: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Zuia matokeo ya hivi karibuni: ongeza `AND date:>now-7d`

Mfano wa API:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

Kutoka kwenye JSON, chunguza:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` ili kubaini vyeti vipya sana vya domains zinazofanana
- Thamani za `task.source` kama `certstream-suspicious` ili kuhusisha matokeo na ufuatiliaji wa CT

### Umri wa domain kupitia RDAP (inaweza kuendeshwa kwa script)

RDAP hurejesha matukio ya usajili katika muundo unaosomeka na mashine. Ni muhimu kubaini **domains zilizosajiliwa hivi karibuni (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Boresha pipeline yako kwa kuweka lebo za makundi ya umri wa usajili wa domain (kwa mfano, <7 days, <30 days) na upe kipaumbele cha triage ipasavyo.

### Fingerprints za TLS/JAx za kutambua miundombinu ya AiTM

Credential-phishing inaweza kutumia reverse proxies za **Adversary-in-the-Middle (AiTM)** (kwa mfano, Evilginx) kuiba session tokens.<sup>[[11]](#references)</sup> Unaweza kuongeza detections za upande wa mtandao:

- Rekodi fingerprints za TLS/HTTP (JA3/JA4/JA4S/JA4H) kwenye egress. Baadhi ya builds za Evilginx zimeonekana zikiwa na thamani thabiti za JA4 za client/server. Weka alert kwa fingerprints zinazojulikana kuwa mbaya kama ishara dhaifu tu, na thibitisha kila wakati kwa kutumia maudhui na taarifa za domain.<sup>[[12]](#references)</sup>
- Rekodi mapema metadata ya TLS certificate (issuer, idadi ya SAN, matumizi ya wildcard, validity) kwa hosts zinazofanana na halisi zilizogunduliwa kupitia CT au urlscan, kisha linganisha na umri wa DNS na geolocation.

> Kumbuka: Tumia fingerprints kama taarifa za ziada, si vizuizi pekee; frameworks hubadilika na zinaweza kubadilisha au kuficha fingerprints.

### Majina ya domain yanayotumia keywords

Ukurasa mkuu pia unataja mbinu ya kubadilisha jina la domain inayojumuisha kuweka **jina la domain la mwathiriwa ndani ya domain kubwa zaidi** (kwa mfano, paypal-financial.com kwa paypal.com).

#### Certificate Transparency

Logs za Certificate Transparency (CT) huonyesha utambulisho wa certificates, kwa hivyo kutafuta majina ya Subject au SAN kwa keywords za chapa kunaweza kufichua domains zinazofanana na halisi (kwa mfano, certificate ya `paypal-financial.com` huonyesha keyword `paypal`). Chuja matokeo kwa tarehe ya kutolewa na CA inapofaa, na hakiki wagombea kwa sababu ulinganifu wa keywords unaweza kutoa false positives.<sup>[[13]](#references)</sup>

[Maelezo ya awali ya Patrik Hudak kuhusu kutafuta domains za phishing](https://0xpatrik.com/phishing-domains/) yanaonyesha workflow hii katika Censys, ikijumuisha filters za tarehe ya certificate na issuer kama Let's Encrypt.<sup>[[13]](#references)</sup>

![Matokeo ya utafutaji wa certificates katika Censys yaliyotumika kutambua domains zinazofanana na halisi](<../../images/image (1115).png>)

Unaweza pia kutumia huduma ya bure ya [**crt.sh**](https://crt.sh) kutafuta keyword na kuchuja matokeo kwa tarehe na CA.<sup>[[13]](#references)</sup>

![Utafutaji wa keyword katika crt.sh kwa utambulisho wa certificates unaotiliwa shaka](<../../images/image (519).png>)

Sehemu yake ya Matching Identities inaweza kusaidia kulinganisha utambulisho wa domain halisi na domains zinazotiliwa shaka, lakini chukulia ulinganifu kama vidokezo, si uthibitisho.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) hutiririsha masasisho ya CT karibu kwa wakati halisi, na [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) hutumia mtiririko huo kukadiria alama za majina ya certificates yanayotiliwa shaka.<sup>[[14]](#references)[[15]](#references)</sup>

Kidokezo cha vitendo: unapofanya triage ya matokeo ya CT, weka kipaumbele kwa NRDs, registrars zisizoaminika/wasiojulikana, WHOIS inayotumia privacy-proxy, na certificates zenye nyakati za `NotBefore` za hivi karibuni sana. Dumisha allowlist ya domains/chapa unazomiliki ili kupunguza alerts zisizo za lazima.

#### **Domains mpya**

Chaguo la pili ni kukusanya domains zilizosajiliwa hivi karibuni kwa TLD (kwa mfano, kupitia [Whoxy](https://www.whoxy.com/newly-registered-domains/)) na kuzichuja kwa keywords za chapa. Hii hukosa phishing inayopangishwa kwenye subdomains wakati keyword haipo kwenye domain iliyosajiliwa.<sup>[[13]](#references)</sup>

Heuristic ya ziada: chukulia baadhi ya **file-extension TLDs** (kwa mfano, `.zip`, `.mov`) kwa mashaka zaidi katika alerting. Mara nyingi huchanganywa na filenames katika lures; changanya ishara ya TLD na keywords za chapa pamoja na umri wa NRD ili kuboresha usahihi.

## References

- [1] [Remy Hax – Bit-squatting ya Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Kuteka traffic ya Microsoft's windows.com kwa bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Uchambuzi wa kina: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Nyaraka za mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Dataset ya Web Property ya Platform](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Marejeo ya Search API](https://urlscan.io/docs/search/)
- [9] [Msaada wa Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Majibu ya JSON kwa Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Mbinu za token: Jinsi ya kuzuia, kugundua na kukabiliana na wizi wa cloud token](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – Fingerprinting ya mtandao ya JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Kutafuta phishing: Zana na mbinu](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Utangulizi wa CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
