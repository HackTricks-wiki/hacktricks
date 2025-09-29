# Kutambua Phishing

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

Ili kutambua jaribio la phishing ni muhimu **kuelewa phishing techniques zinazotumika sasa hivi**. Kwenye ukurasa mzazi wa chapisho hiki, unaweza kupata taarifa hizi, hivyo ikiwa hufahamu ni tekniki gani zinatumika leo ninakushauri uende kwenye ukurasa mzazi na usome angalau sehemu hiyo.

Chapisho hili limetegemea wazo kwamba **washambuliaji watajaribu kwa namna fulani kuiga au kutumia jina la domain la mwathiriwa**. Ikiwa domain yako inaitwa `example.com` na umepigwa phishing ukitumia kwa sababu fulani domain tofauti kabisa kama `youwonthelottery.com`, mbinu hizi hazitatambua hilo.

## Mabadiliko ya jina la domain

Ni aina ya **rahisi** ku**gundua** yale majaribio ya **phishing** yatakayotumia **jina la domain linalofanana** ndani ya barua pepe.\
Inatosha **kutengeneza orodha ya majina ya phishing yanayowezekana zaidi** ambayo mshambuliaji anaweza kutumia na **kuangalia** ikiwa yameorodheshwa au angalia tu ikiwa kuna **IP** inayoyatumia.

### Kupata domain zenye kutiliwa shaka

Kwa kusudi hili, unaweza kutumia zana yoyote kati ya zifuatazo. Kumbuka kwamba zana hizi pia zitafanya maombi ya DNS moja kwa moja ili kuangalia ikiwa domain ina IP yoyote iliyotengwa:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Vidokezo: Ikiwa utatengeneza orodha ya wagombea, pia ingiza kwenye DNS resolver logs zako ili kugundua **NXDOMAIN lookups from inside your org** (watumiaji wakijaribu kufikia typo kabla mshambuliaji hajayasajili). Sinkhole or pre-block these domains if policy allows.

### Bitflipping

**You can find a short the explanation of this technique in the parent page. Or read the original research in** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Kwa mfano, mabadiliko ya 1 bit kwenye domain microsoft.com yanaweza kuibadilisha kuwa _windnws.com._\
**Washambuliaji wanaweza kusajili kadri iwezekanavyo domain nyingi za bit-flipping zinazohusiana na mwathiriwa ili kupeleka watumiaji halali kwenye miundombinu yao**.

**All possible bit-flipping domain names should be also monitored.**

Ikiwa pia unahitaji kuzingatia homoglyph/IDN lookalikes (kwa mfano, kuchanganya herufi za Latin/Cyrillic), angalia:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Ukaguzi wa Msingi

Mara tu ukiwa na orodha ya majina ya domain yenye kutiliwa shaka unapaswa **kuzijaribu** (hasa ports HTTP na HTTPS) ili **kuona kama zinatumia fomu ya login inayofanana** na moja ya domain za mwathiriwa.\
Unaweza pia kuangalia port 3333 kuona ikiwa imefunguliwa na inaendesha mfano wa `gophish`.\
Pia inavutia kujua **umri wa kila domain ya mashaka uliyogundua**, kadri mdogo ndivyo hatari zaidi.\
Unaweza pia kupata **screenshots** za ukurasa wa HTTP na/au HTTPS wa tovuti yenye mashaka ili kuona ikiwa ni ya hovyo na katika hali hiyo **uingie ili ukaangalie kwa undani zaidi**.

### Ukaguzi wa Juu

Ikiwa ungependa kwenda hatua moja zaidi ningependekeza **kufuatilia domain hizo za mashaka na kutafuta zaidi** mara kwa mara (kila siku? huchukua sekunde/dakika chache tu). Pia unapaswa **kuangalia** ports zilizo wazi za IP zinazohusiana na **kutafuta instances za `gophish` au zana zinazofanana** (ndio, washambuliaji pia hufanya makosa) na **kuangalia HTTP na HTTPS wa kurasa za domain na subdomains zenye shaka** kuona kama wameiga fomu yoyote ya login kutoka kwenye kurasa za mwathiriwa.\
Ili **kuziweka otomatiki** ningependekeza kuwa na orodha ya fomu za login za domain za mwathiriwa, spider the suspicious web pages na kulinganisha kila fomu ya login iliyopatikana ndani ya domain zenye mashaka na kila fomu ya login ya domain ya mwathiriwa kwa kutumia kitu kama `ssdeep`.\
Kama umeweka fomu za login za domain zenye mashaka, unaweza kujaribu **kutuma nywila za junk** na **kuangalia kama inakurudisha kwenye domain ya mwathiriwa**.

---

### Kufatilia kwa kutumia favicon na web fingerprints (Shodan/ZoomEye/Censys)

Mifumo mingi ya phishing hutumia tena favicons kutoka kwa brand wanayoiga. Skana za mtandao wote huhesabu MurmurHash3 ya favicon iliyotangazwa kwa base64. Unaweza kuunda hash na kuifanya pivot:

Mfano wa Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Tafuta kwenye Shodan: `http.favicon.hash:309020573`
- Kwa kutumia tooling: angalia community tools kama favfreak ku-generate hashes na dorks kwa Shodan/ZoomEye/Censys.

Notes
- Favicons zinatumika tena; chukulia matches kama leads na validate content na certs kabla ya kuchukua hatua.
- Unganisha na domain-age na keyword heuristics kwa usahihi zaidi.

### Utafutaji wa telemetry za URL (urlscan.io)

`urlscan.io` inahifadhi historical screenshots, DOM, requests na TLS metadata za URL zilizotumwa. Unaweza kutafuta brand abuse na clones:

Example queries (UI or API):
- Tafuta lookalikes ukiondoa domain zako halali: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Tafuta sites zinazongeuka assets zako (hotlinking): `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Punguza kwa matokeo ya karibuni: ongeza `AND date:>now-7d`

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Kutoka kwenye JSON, zingatia:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` ili kugundua vyeti vipya kabisa kwa matovuti yanayofanana
- `task.source` values like `certstream-suspicious` ili kuhusisha matokeo na ufuatiliaji wa CT

### Umri wa domain kupitia RDAP (inayoweza kuendeshwa kwa script)

RDAP hurudisha matukio ya uundaji yanayosomeka na mashine. Inafaa kuashiria **domain zilizosajiliwa hivi karibuni (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Boresheni pipeline yenu kwa ku-tag domains na makundi ya umri wa usajili (mf., <7 days, <30 days) na panga triage kwa kipaumbele ipasavyo.

### TLS/JAx fingerprints to spot AiTM infrastructure

Phishing za kisasa za credential mara nyingi zinatumia **Adversary-in-the-Middle (AiTM)** reverse proxies (mf., Evilginx) kuiba session tokens. Unaweza kuongeza utambuzi upande wa mtandao:

- Rekodi TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) kwenye egress. Baadhi ya builds za Evilginx zimetazamwa zikiwa na JA4 client/server values thabiti. Toa tahadhari kwa fingerprints zinazojulikana-kutwa mbaya kama ishara dhaifu tu na thibitisha kila mara kwa content na domain intel.
- Rekodi kwa njia ya hiari metadata ya TLS certificate (issuer, SAN count, wildcard use, validity) kwa lookalike hosts zilizogunduliwa kupitia CT au urlscan na zilelekee/korelasha na umri wa DNS na geolocation.

> Kumbuka: Chukulia fingerprints kama uboreshaji, sio kama vikwazo pekee; frameworks hubadilika na zinaweza kubadilisha au kuficha taarifa.

### Domain names using keywords

Ukurasa mzazi pia unataja mbinu ya utofauti wa jina la domain inayojumuisha kuweka **jina la domain la mwathirika ndani ya domain kubwa** (mf., paypal-financial.com kwa paypal.com).

#### Certificate Transparency

Haiwezekani kutumia mbinu ya "Brute-Force" iliyotajwa hapo awali lakini kwa kweli **inawezekana kugundua jaribio kama hilo la phishing** pia shukrani kwa certificate transparency. Kila wakati CA inapotoa certificate, maelezo yake yanakuwa ya umma. Hii inamaanisha kwamba kwa kusoma certificate transparency au hata kuifuatilia, ni **inawezekana kupata domains zinazotumia neno muhimu ndani ya jina lao**. Kwa mfano, kama mshambuliaji anazalisha certificate ya [https://paypal-financial.com](https://paypal-financial.com), kwa kuona certificate inawezekana kupata neno muhimu "paypal" na kujua kwamba email inayoshukiwa inatumiwa.

Chapisho [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) kinapendekeza unaweza kutumia Censys kutafuta certificates zinazohusiana na neno maalum na kuchuja kwa tarehe (tu certificates "mpya") na kwa CA issuer "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Hata hivyo, unaweza kufanya "the same" ukitumia tovuti ya bure [**crt.sh**](https://crt.sh). Unaweza **kutafuta neno muhimu** na **kichuja** matokeo **kwa tarehe na CA** ikiwa unataka.

![](<../../images/image (519).png>)

Kwa kutumia chaguo la mwisho unaweza hata kutumia uwanja Matching Identities kuona kama identity yoyote kutoka domain halisi inaendana na yoyote ya domain zinazoshukiwa (kumbuka kwamba domain inayoshukiwa inaweza kuwa false positive).

**Another alternative** ni mradi mzuri uitwao [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream hutoa mtiririko wa wakati-halisi wa certificates mpya zilizotengenezwa ambao unaweza kutumia kugundua maneno maalum kwa wakati (karibu) halisi. Kwa kweli, kuna mradi uitwao [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) unaofanya hivyo.

Tip ya vitendo: unapotriage hits za CT, panga kipaumbele NRDs, registrars zisizo za kuaminika/zisizojulikana, privacy-proxy WHOIS, na certs zenye `NotBefore` za hivi karibuni. Dumisha allowlist ya domains/brand zako ili kupunguza kelele.

#### **Domain mpya**

**Chaguo la mwisho** ni kukusanya orodha ya **domains zilizosajiliwa hivi karibuni** kwa baadhi ya TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) inatoa huduma hiyo) na **kukagua maneno muhimu katika domains hizi**. Hata hivyo, domains ndefu kwa kawaida hutumia subdomain moja au zaidi, hivyo neno muhimu hautaonekana ndani ya FLD na hautaweza kupata subdomain ya phishing.

Mchakato wa ziada: chukulia baadhi ya **file-extension TLDs** (mf., `.zip`, `.mov`) kwa tahadhari zaidi katika onyo. Hizi mara nyingi huchanganywa na majina ya faili katika lures; changanya ishara ya TLD na maneno ya brand na umri wa NRD kwa usahihi zaidi.

## Marejeo

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
