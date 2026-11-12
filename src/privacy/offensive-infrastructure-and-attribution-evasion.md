# Miundombinu ya Mashambulizi na Kukwepa Uhusishaji

{{#include ../banners/hacktricks-training.md}}

Mara chache opereta hupata kutokujulikana kwa maana kwa kutumia proxy moja tu. Kampeni halisi hujenga **grafu ya utenganisho**: opereta hufikia nodi ya ufikiaji, nodi za upitishaji huficha nodi hiyo isionekane kutoka kwa nodi ya kutoka, redirector hulinda C2 halisi, na majina ya muda huelekeza kwenye ukingo wa umma.

Tumia [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) kwa muhtasari uliosanifishwa wa faida/hasara, uwekaji na ugunduzi wa kila njia. Ukurasa huu unaeleza kwa kina zaidi jinsi ya kuunganisha miundombinu dhidi ya wapinzani.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Anwani ya mwisho iliyoonekana na mlengwa kwa hiyo ni ushahidi wa njia iliyotumika, si uthibitisho wa nani aliyetumia kibodi. MITRE huainisha vipengele vikuu kama Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) na Web Service (T1102).<sup>[[1]](#references)</sup>

## Aina za miundombinu

| Aina | Kwa nini mhusika huitumia | Athari zinazodumu | Sehemu bora zaidi ya uchunguzi kwa mlinzi |
|---|---|---|---|
| VPS/cloud iliyokodishwa | Haraka, ya kutabirika, inaweza kuelekezwa kwa urahisi, rahisi kujenga upya | historia ya tenant, malipo, console, source-login na image | matukio ya akaunti/control-plane na alama za seva zinazojirudia |
| Commercial VPN/Tor | Seti kubwa ya anwani za kutoka zinazoshirikiwa; haihitaji usimamizi wa seva | mwonekano wa mtoa huduma/mwangalizi na muda wa mawasiliano kutoka mwanzo hadi mwisho | tabia ya lengwa, ushahidi wa endpoint na ulinganisho wa mitiririko |
| Residential/mobile proxy | ASN ya watumiaji na mwonekano unaoaminika wa eneo | rekodi za broker/mteja; tabia ya proxyware au host iliyoambukizwa | safari isiyowezekana, itifaki za proxy na mabadiliko ya anwani kwa kila session |
| Seva/router/IoT iliyoathiriwa | Hutumia sifa na mamlaka ya kisheria ya mwathiriwa | implant, mtiririko wa usimamizi na controller ya juu inayojirudia | telemetry ya kifaa na topolojia ya ORB, si IP moja ya kutoka |
| CDN/redirector | Hutenganisha edge ya umma na C2 ya nyuma | TLS/HTTP grammar, certificate, routing na alama za akaunti ya cloud | ulinganisho wa edge na origin na kupanga makundi ya umbo la maombi |
| Web service halali | Hujichanganya na trafiki inayoruhusiwa ya GitHub/cloud/social | API token, vitambulisho vya tenant/object na mfuatano usio wa kawaida wa michakato | mchakato wa endpoint pamoja na semantiki za service/API |
| Njia ya kimwili/simu ya mkononi/satelaiti | Hubadilisha asili ya kimwili inayoonekana | rekodi za RF, mtoa huduma, msajili, kifaa na eneo | ushahidi wa redio/kimwili pamoja na ushahidi wa mtandao |

## Mitandao ya relay box ya kiutendaji

**Mtandao wa ORB** ni kundi la proxy linalosimamiwa na kutumiwa kama huduma ya kati. Mandiant huigawa katika mitandao iliyosanidiwa ya seva zilizokodishwa, mitandao isiyosanidiwa ya router/IoT zilizoathiriwa, na mitandao mseto. Topolojia iliyokomaa ina majukumu manne ya kimantiki:<sup>[[2]](#references)</sup>

1. **Seva ya usimamizi (ACOS):** hudumisha orodha, credentials, hali ya utendaji na sera ya routing.
2. **Nodi ya ufikiaji/relay:** huthibitisha wateja au waendeshaji; ndiyo lango thabiti la kuingia kwenye mesh inayobadilika.
3. **Nodi za kupitishia:** mfumo mmoja au zaidi uliokodishwa au ulioathiriwa hupitisha miunganisho isiyo wazi.
4. **Nodi ya kutoka/maandalizi:** huonyesha anwani ya mwisho ya chanzo kwa reconnaissance, exploitation au malengo ya C2.

Mesh inaweza kuchagua nodi za kutoka kulingana na nchi, ASN, latency au upatikanaji, na kubadilisha nodi zisizofanya kazi vizuri. Vikundi vingi vya vitisho vinaweza kukodisha mtandao huo huo. Mandiant iliona anwani ya IPv4 ikibaki ikihusishwa na baadhi ya ORB kwa siku 31 pekee; kwa hiyo inapendekeza kuichukulia **mtandao kama huluki inayoendelea kubadilika inayofanana na mhusika**, badala ya kuzuia orodha iliyopitwa na wakati ya IP.<sup>[[2]](#references)</sup>

### Hili linawezesha nini—na nini linavuja

- Lengwa huona nodi ya kutoka ambayo inaweza kuwa karibu kijiografia na kuonekana kuwa ya makazi.
- Nodi ya kutoka huona lengwa na hop iliyotangulia, lakini si lazima imjue mwendeshaji.
- Huduma ya ufikiaji huona mteja na ombi la njia. Mesh inayosimamiwa kivyake inaweza kumtenganisha mteja na nodi za kutoka, lakini huunda rekodi muhimu za mhusika mwingine.
- Port zinazojirudia, mpangilio wa handshake, mabango ya seva, certificates, vipindi vya uptime na uhusiano wa controller vinaweza kufichua kundi hilo hata IP zinapobadilika.
- Router iliyoathiriwa mara nyingi haina telemetry ya endpoint, lakini ISP yake bado ina data ya msajili na mtiririko; kunaswa kwake hufichua alama za implant/configuration.

{% hint style="info" %}
Kwa zoezi lililoidhinishwa, tengeneza upya topolojia hiyo kwa kutumia VM au router zinazomilikiwa na shirika na uhifadhi ramani ya attribution ya controller. Usitumie open proxy au vifaa vya wahusika wengine. [Mwongozo wa maabara](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) huunda muundo uleule wa hop unaoonekana kwa walinzi bila kumdhuru mpatanishi.
{% endhint %}

## Mitandao ya residential na mobile proxy

Huduma za residential proxy hugawa sessions kwa anwani za broadband za watumiaji; mobile proxy hutoka kupitia makundi ya carrier NAT. Vyanzo vinaweza kuwa vifaa vilivyosajiliwa kwa uwazi, SDK/proxyware iliyojumuishwa kwenye programu za watumiaji, wauzaji upya au malware. Asili hizi hazifanani: kukosekana kwa ridhaa iliyoeleweka hugeuza huduma ya faragha kuwa miundombinu iliyoathiriwa.

Njia za rotation huathiri ugunduzi:

- **rotation kwa kila ombi** husababisha mabadiliko ya haraka ya IP na ASN/eneo, huku utambulisho wa tabaka za juu ukiendelea kuwa uleule;
- **sticky sessions** hudumisha nodi ya kutoka kwa dakika au saa, na kufanana na msajili wa kawaida;
- **backconnect gateways** humwonyesha mteja endpoint moja ya broker na kuchagua nodi za kutoka ndani ya mfumo;
- **mobile pools** huweka wasajili wengi halisi nyuma ya idadi ndogo ya anwani za carrier NAT, na kufanya kuzuia IP kuwa na gharama kubwa.

Mawalinzi wanapaswa kulinganisha IP na session iliyothibitishwa, TLS/client fingerprint, mpangilio wa HTTP, device cookie na tabia. Login ya residential inayodaiwa kuwa ya eneo husika ikifuatiwa na nchi nyingine huku vipengele vyote vya tabaka za juu vikibaki vilevile ni ushahidi imara zaidi kuliko sifa ya IP pekee. Kinyume chake, kushiriki anwani na handoff za simu husababisha mabadiliko halali, kwa hiyo usichukulie kamwe uainishaji wa residential/proxy kama hukumu ya mwisho.

### Control plane za proxyware na mwingiliano wa wauzaji upya

Usiichukulie residential pool kama orodha tambarare ya nodi za kutoka. Uchambuzi wa mfumo ikolojia wa IPIDEA ulifichua **control plane ya tabaka mbili** inayoweza kutumiwa tena: SDK iliyopachikwa kwanza hutuma metadata ya kifaa/usajili kwenye domain ya Tier One na kupokea ratiba pamoja na jozi za IP:port za `connect`/`proxy` za Tier Two. Nodi hupiga kura mara kwa mara kwenye port ya Tier Two ya connect ili kupata kazi iliyosimbwa, hufungua muunganisho wa pili kwenye port ya proxy iliyooanishwa, kisha hupitisha bytes zilizotolewa kwenda kwenye lengwa lililoombwa. SDK na chapa za proxy zilizokuwa tofauti kwa jina zilikuwa na discovery domains tofauti lakini ziliungana kwenye miundombinu ya Tier Two iliyoshirikiwa na makundi ya nodi za kutoka yanayopishana kupitia umiliki wa pamoja na uhusiano wa wauzaji upya.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Hii huzalisha viashiria vya ufuatiliaji vilivyo thabiti zaidi kuliko kizuizi cha IP za makazi:<sup>[[13]](#references)</sup>

- mchakato usiotarajiwa wa utility, VPN, mchezo au kifaa kilichopachikwa hutuma kitambulisho thabiti cha kifaa/ufunguo wa mteja na kupokea orodha ya seva inayobadilika;
- endpoint huulizia IP ya moja kwa moja kwenye port isiyo ya kawaida, kisha huunganisha kwenye port nyingine kwenye anwani hiyo hiyo mara moja kabla ya kufungua socket ya kuelekea lengwa jipya;
- chapa kadhaa zinazoonekana kuwa tofauti hutumia anwani za Tier Two zinazofanana, sintaksia ya itifaki, msimbo wa SDK au mwingiliano wa exit node;
- programu tofauti zinazowasiliana na vikoa tofauti vya Tier One hupokea anwani kutoka kwenye kundi lilelile la Tier Two.

Mwingiliano huu pia hupunguza uwezo wa kufanya attribution: kuona IP kwenye kundi lililotangazwa na vendor mmoja hakuthibitishi ni reseller, mteja au threat actor gani aliyeitumia wakati husika. Hifadhi mihuri ya muda ya mtiririko, mfuatano wa michakato, miili ya majibu ya Tier One na vitambulisho vya kazi za Tier Two.<sup>[[13]](#references)</sup> Katika zoezi lililoidhinishwa, iga mpangilio huu kwa kutumia tu endpoints zinazomilikiwa na shirika; usiwahi kusajili vifaa vya watumiaji au proxyware ya wahusika wengine.

## Multi-hop proxy chains

MITRE hutofautisha proxies za nje na **multi-hop proxies (T1090.003)**. Sifa muhimu si idadi ya hops, bali mgawanyo wa maarifa na usimamizi.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Ikiwa mhusika mmoja anaendesha A na B, kumbukumbu za pamoja au muda wa mtiririko wa data vinaweza kutumika kujenga upya mzunguko. Kuongeza VPN za kibiashara zinazofuatana kutoka endpoint/akaunti ileile kunaweza kuongeza ucheleweshaji huku kukiacha ushahidi wa utambulisho, malipo na muda wa shughuli ulio wa pamoja. Tor hupunguza tatizo hili kwa kutumia relays zilizochaguliwa kwa kujitegemea na muundo wa mteja unaoshirikiwa, lakini mtandao shirikishi wenye ucheleweshaji mdogo hauwezi kuahidi kustahimili mwangalizi anayepima ncha zote mbili.

Matatizo ya kawaida ni DNS au IPv6 kupita njia ya tunnel, programu kufungua sockets zake zenyewe, trafiki ya usimamizi kufikia relays moja kwa moja, shughuli zinazolingana kwa wakati, matumizi ya mara kwa mara ya funguo za SSH, na kuingia kwenye akaunti zinazoweza kumtambulisha mtumiaji. Uthibitishaji sahihi ni jaribio la hitilafu: simamisha kila relay kwa zamu na uhakikishe kuwa workload haiwezi kutumia njia ya wazi kama mbadala.

### Kuporomoka kwa tunnel na leak ya upstream

Mara nyingi usanifu wa relay hutambulika zaidi unaposhindwa. Unit 42 iliandika njia ya ujasusi ya ngazi nyingi iliyotumia VPS zinazoelekea kwa wahanga, VPS za relay, proxies za makazi, Tor na huduma nyingine za proxy; tunnel ilipoachwa au kuporomoka, miundombinu fiche ya upstream iliunganishwa moja kwa moja na mifumo ya relay na ile inayoelekea kwa wahanga. Uchunguzi huohuo pia ulitumia cheti cha X.509 kilichofichuliwa kwa muda kwenye miundombinu ya upstream kama kiunganishi cha uchunguzi kati ya ngazi.<sup>[[14]](#references)</sup>

Weka **data plane** (`victim <-> exit`) tofauti na **control plane** (`operator/upstream -> relay administration`). Hifadhi kumbukumbu za ingress na uthibitishaji katika kila ngazi unayomiliki, historia za vyeti na miunganisho mifupi iliyoshindwa—si vipindi vya C2 vilivyofanikiwa pekee. Chanzo kinachoonekana tu wakati relays zimekatika au kinachosimamia moja kwa moja nodi nyingi zinazoelekea kwa wahanga ni mgombea bora zaidi wa kuwa upstream kuliko exit ya kawaida, lakini ASN/eneo la kijiografia bado ni dhana, si uthibitisho wa utambulisho wa operator.

Maabara iliyoidhinishwa inapaswa kufanya workload ishindwe kwa usalama. Kwa workload iliyotengwa kwenye Linux network namespace, route ya kwanza lazima ipitie kwenye tunnel; baada ya kuiondoa, ombi na ukaguzi wa route lazima vishindwe badala ya kuchagua uplink halisi:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Rudia jaribio la DNS na IPv6, na katika kila mpaka wa relay. Probe yoyote ikifaulu, rekodi interface/address ya chanzo halisi kabla ya kurekebisha uelekezaji wa sera au firewall; uchunguzi huo ndio attribution leak ambayo mchunguzi angeona.

## Tabaka za redirector na uundaji wa trafiki

**redirector** ya umma hupokea trafiki inayolingana na sarufi maalum ya operesheni na kuielekeza kwa team server iliyolindwa. Kila kitu kingine kinaweza kukataliwa au kupewa maudhui yasiyo na madhara.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Tabaka nyingi hupunguza uwezekano wa kufichuliwa: kuchoma domain ya umma hakulazimishi kufichua seva ya timu. CDN huongeza uwezo wa anycast na domain ya nje inayoaminika, lakini akaunti ya CDN na edge logs huwa pointi za attribution. TLS fingerprints, historia ya certificate, njia tofauti/vichwa kwa mpangilio tofauti, ukubwa wa majibu, tabia ya redirect na allowlists za origin zinaweza kuunganisha front zinazodhaniwa kuwa hazihusiani.

Kwa ajili ya detection, hifadhi sehemu za reverse-proxy kabla ya normalization, linganisha SNI/Host/authority, kagua mchanganyiko adimu wa vichwa, panga miili ya majibu na TLS fingerprints katika vikundi, na tafuta mwingiliano wa usanidi kwenye cloud/CDN audit logs. Kwa red teams zilizoidhinishwa, epuka kunakili brand halisi au kuweka ukusanyaji wa credentials nyuma ya third party isiyohusiana.

## Domain fronting na domainless fronting

Katika **domain fronting (T1090.004)** ya kawaida, muunganisho wa TLS hutangaza front domain inayoruhusiwa kwenye SNI huku HTTP `Host` iliyosimbwa kwa njia fiche au HTTP/2 `:authority` ikiomba back-end domain tofauti. CDN inayoshirikiana huelekeza trafiki kwa kutumia thamani ya ndani. Mwangalizi wa mtandao asiye na TLS decryption huona front; CDN huona thamani zote mbili na origin. Katika variants za domainless, SNI inaweza kuwa tupu huku sehemu nyingine ya uelekezaji ikichagua lengwa.<sup>[[4]](#references)</sup>

Huu si uigaji wa kichawi: hufanya kazi tu pale intermediary inaporuhusu kwa makusudi au kwa bahati kutolingana huko na kujua jinsi ya kuelekeza jina la ndani. Watoa huduma wakuu wamezuia fronting kati ya akaunti tofauti. Encrypted ClientHello (ECH) hubadilisha kile ambacho mwangalizi aliye kwenye njia anaweza kuona, lakini haifuti rekodi za CDN, endpoint au application.

Sehemu za detection ni pamoja na:

- asili ya michakato ya endpoint na lengwa lisilotarajiwa kwa application hiyo;
- kutolingana kwa SNI na HTTP authority pale ambapo ukaguzi wa TLS ni halali na unapatikana;
- CDN logs zinazoonyesha tenant/front moja ikielekeza trafiki kwa authority/origin nyingine;
- sessions zisizo za kawaida, za muda mrefu au za vipindi, zinazoelekezwa kwa huduma ambayo kwa kawaida hutumiwa kwa mwingiliano;
- ukubwa thabiti wa mtiririko uliosimbwa na mfuatano wake unaojirudia katika front domains zinazobadilika.

Maabara salama huiga kutolingana kwa uelekezaji kwenye reverse proxy inayomilikiwa; haitumii vibaya CDN ya umma.

## Uelekezaji unaobadilika: DDNS, DGA na fast flux

Uelekezaji unaobadilika hutenganisha huduma ya kimantiki na miundombinu isiyobadilika:

- **DDNS:** client iliyothibitishwa husasisha jina thabiti baada ya anwani yake kubadilika.
- **DGA:** endpoint hukokotoa domain names kutoka kwa seed, mara nyingi muda au ufunguo, lakini wakati mwingine maudhui ya umma yanayobadilika; operator hupanga DNS kwa jina linalotumika.<sup>[[17]](#references)</sup>
- **Fast flux:** jina hurudisha seti inayobadilika haraka ya anwani zilizoathiriwa/proxy, mara nyingi zikiwa na TTL za chini.
- **Double flux:** anwani za huduma na anwani za authoritative name-server huzungushwa zote, na hivyo kuficha pia control layer.

Fast flux ni muundo wa kusambaza mzigo unaotumiwa kwa nia ovu, si tu “majibu mengi ya DNS.” Ushahidi thabiti zaidi huchanganya TTL ya chini, idadi kubwa ya anwani za kipekee, usambazaji mpana wa ASN/jiografia, muda mfupi wa maisha ya node, tabia ya application inayojirudia na historia ya usajili inayotia shaka. CDN hutumia kihalali baadhi ya sifa hizi. MITRE inapendekeza kuoanisha tabia ya DNS na mchakato pamoja na miunganisho inayofuata.<sup>[[5]](#references)</sup>

DGA inaweza kugunduliwa kupitia lexical entropy, mifumo ya konsonanti/namba, milipuko ya NXDOMAIN, domain zilizoonekana kwa mara ya kwanza kwa wakati mmoja na muktadha wa mchakato. Wordlist DGA na generative models hushinda kanuni rahisi za entropy, hivyo kufanya clustering ya muda katika fleet nzima na mfuatano wa asili ya endpoint kuwa muhimu zaidi.

### Seed ya picha inayobadilika kwa wordlist DGA

DGA si lazima itegemee muda. Loader moja hupakua ukurasa wa public Telegram channel, husoma `src` ya kipengele chake cha `tgme_page_photo_image`, hupakua picha hiyo ya wasifu, na ku-hash **baiti 50 za mwisho za faili** badala ya pikseli zake zilizodecodeiwa. Hash seeds nne huchagua kivumishi, nomino, kitenzi na namba. Kubadilisha picha hubadilisha jina la DNS linalotokana bila kusambaza client mpya. Tumia baiti zilezile kamili za picha iliyopakuliwa na mpangilio uleule wa word-list pande zote mbili; ku-encode upya picha au kubadilisha mpangilio wa orodha hutoa majina tofauti.<sup>[[17]](#references)</sup>

Kwa kutumia word lists zilizorejeshwa kutoka kwa client, hatua hii ya kuchagua jina inaweza kurudiwa. Hash ya chanzo inayotumia baiti kwa mpangilio hutumia accumulator ya biti 64, multiplier `0x1000193`, na seeds tofauti kwa kila sehemu:<sup>[[17]](#references)</sup>

<details>
<summary>Rudia uteuzi wa jina la wordlist unaotumia seed ya picha</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

Tofauti na [dead-drop resolver](#web-services-and-dead-drop-resolvers) inayochapisha endpoint yenyewe, objecti ya umma hapa hutoa tu seed inayoweza kubadilishwa; client hutengeneza endpoint ndani ya kifaa.

Jina linalozalishwa huuliziwa rekodi ya DNS TXT kupitia `https://dns.google/resolve?name=<domain>&type=TXT`. Client hufanya Base64-decode ya sehemu ya `data` katika jibu la JSON, huthibitisha saini ya Ed25519 kwa kutumia public key iliyopachikwa, kisha tu hufanya AES-ECB-decrypt ya amri. Maandishi yaliyofichuliwa huanza na kiteuzi cha method na URL ya payload iliyosimbwa. Ukaguzi wa saini unamaanisha kuwa rekodi ya TXT inayoweza kutatuliwa pekee haiwezi kutoa tasking inayokubalika.<sup>[[17]](#references)</sup>

## Domains zilizohackiwa na domain shadowing

Mhusika anaweza kuteka nyara akaunti ya registrar/DNS, kutwaa subdomain iliyoachwa bila mmiliki, au kuongeza rekodi chini ya domain inayoaminika vinginevyo. **Domain shadowing** huhifadhi apex halali huku idadi kubwa ya subdomains zinazodhibitiwa na mshambuliaji zikielekeza kwenye hosts za delivery au C2 zinazobadilika. Hukopa umri na sifa nzuri, na huenda ikakwepa vizuizi vya kiwango cha domain.<sup>[[6]](#references)</sup>

Watetezi wanahitaji logi za ukaguzi za registrar na authoritative-DNS, MFA, kufunga registry/registrar, arifa za delegations/API tokens/name servers mpya, ufuatiliaji wa certificate transparency, na orodha ya rasilimali za cloud zinazorejelewa na DNS. Chunguza resolution na historia ya cheti cha subdomain bila kutegemea sifa ya apex.

## Web services na dead-drop resolvers

**Dead-drop resolver (T1102.001)** huhifadhi pointer iliyosimbwa inayoelekeza kwenye C2 ya sasa ndani ya post, profile, document, repository, cloud object au blockchain field halali. Malware huchukua objecti ya umma, hufungua encoding ya domain/IP, kisha huwasiliana na hatua inayofuata. Aina za mawasiliano ya pande mbili hubadilishana amri au faili kupitia service APIs.<sup>[[7]](#references)</sup>

Tofauti moja ya resolver inayohusiana na GitHub hutumia Issues Search API tu pale channel ya repository iliyothibitishwa inaposhindwa. Client hutafuta issues zinazolingana na tarehe ya sasa, repository na aina ya issue, hufuata URL ya maoni ya kila issue, na kutoa ciphertext iliyo kati ya viashiria vya `<!--` na `-->`. Baada ya decryption inayotegemea host na tarehe, sehemu kama `Owner`, `LicRepo` na `LicToken` hubadilisha mmiliki mkuu wa repository, path na token. Hii humwezesha operator kubadilisha credentials na endpoints bila kubadilisha client; maoni ya issue ni resolver, huku faili za repository zikiendelea kuwa channel ya tasking.<sup>[[15]](#references)</sup>

Aina moja ya Android huchagua mojawapo ya kurasa mbili za umma za Telegram wakati wa kuanza, kisha hutoa ciphertext iliyo kati ya matukio mawili ya marker iliyopachikwa kwenye APK. Hufanya Base64URL-decode ya thamani na kuifungua kwa AES-128-CBC: bytes 16 za kwanza za `SHA-256(marker)` ndizo key, na bytes 16 zinazobaki ndizo IV. Maandishi wazi ni base URL halisi ya C2, si URL ya ukurasa wa Telegram. Hifadhi maudhui ya ukurasa na marker halisi unapojaribu kurudia resolution; kubadilisha ukurasa wa umma hubadilisha endpoint bila kujenga upya APK.<sup>[[16]](#references)</sup>

Hii huongeza ustahimilivu na kuficha C2 ya nyuma ya mfumo dhidi ya uchanganuzi tuli wa binary. Pia hutengeneza vitambulishi thabiti vya object, tenant, repository, API na mifumo ya ufikiaji. Watetezi wanapaswa kuunganisha:

1. process iliyowasiliana na service;
2. API path/object na response hash halisi;
3. shughuli za decoding au usindikaji wa string;
4. muunganisho mpya wa nje muda mfupi baadaye; na
5. tabia inayofanana mahali pengine kwenye fleet.

Kuzuia GitHub, cloud storage au social media yote si jambo linalowezekana mara nyingi. Sera ya egress inayozingatia service na ulinganishaji katika kiwango cha process hufanya kazi vizuri zaidi kuliko kuzuia domains pekee.

## Personas, akaunti na sehemu za ununuzi

Kutokujulikana kwa miundombinu hushindwa persona, recovery email, simu, malipo, browser au admin IP inapounganisha sehemu tofauti. Operesheni zinazohusishwa na serikali zimekuza profiles za kijamii, utambulisho wa barua pepe na akaunti za cloud muda mrefu kabla ya kuzitumia; ATT&CK hurekodi hili kama Establish Accounts (T1585), ikijumuisha sub-techniques za social, email na cloud.<sup>[[8]](#references)</sup>

Mtetezi au mchunguzi huunda grafu kutokana na:

- muda wa kuunda akaunti na wa kuingia kwa mara ya kwanza, eneo, saa za eneo na ratiba ya kazi;
- sehemu za urejeshaji akaunti, vifaa vya MFA, nyaraka za utambulisho na njia za malipo;
- browser/TLS fingerprints na historia ya mtandao chanzo;
- matumizi tena ya avatar, chanzo cha picha, mtindo wa uandishi na ukuaji wa mtandao wa kijamii;
- domain registrant, name server, cheti, analytics ID au repository commit zinazoshirikiwa;
- vitendo vya management plane vinavyopita usanifu wa public relay.

Kwa red team iliyoidhinishwa, personas za kubuniwa zinapaswa kuandikwa kwa msimamizi wa zoezi, kutumia njia za urejeshaji/malipo zinazomilikiwa na shirika, kuepuka kujifanya watu halisi wasiohusika, na kuwa na mpango wa kuziondoa. SOC inaweza kubaki bila kujua; operesheni haipaswi kukosa uwajibikaji.

## Miundo changamano inayoibuka ya kutathmini vitisho

Yafuatayo ni **miunganiko inayotokana na mtazamo wa mtetezi**, si madai kwamba mhusika fulani ametumia kila usanifu huu kamili. Huchanganya mbinu msingi ambazo tayari zimeonekana, na zinafaa kama dhana za purple-team.

### Tasking ya njia moja isiyo sawia

Amri huwasili kupitia chanzo cha umma, cha utangazaji au cha append-only, huku matokeo yakitoka kupitia channel tofauti baada ya kuchelewa. Mifano ya mbinu msingi ni mawasiliano ya njia moja kupitia web service na dead drops. Kutenganisha njia huzuia mtiririko mmoja kuonekana kuwa wa pande mbili na hutatiza ulinganishaji rahisi wa request/response.<sup>[[9]](#references)</sup>

**Ugunduzi:** hifadhi rekodi za usomaji wa kiwango cha objecti, kisha linganisha mabadiliko ya hali ya process na uhamisho wa baadaye wa nje katika kipindi kipana zaidi. Tafuta process adimu inayosoma objecti ileile ya umma hata kama hakuna jibu la papo hapo.

### Uhamishaji wa channel wa hatua nyingi

Hatua ya kwanza tulivu hukusanya taarifa na kuhamisha mifumo iliyochaguliwa pekee kwenda channel tofauti ya hatua ya pili. Endpoint, protocol na process ya pili huenda zisiwe na miundombinu yoyote inayofanana na ya kwanza. Hii hupunguza kufichuliwa kwa miundombinu yenye uwezo mkubwa, na imefafanuliwa wazi kama ATT&CK T1104.<sup>[[10]](#references)</sup>

**Ugunduzi:** unganisha `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; usifunge tukio baada ya kuzuia domain ya kwanza.

### Tafsiri ya relay kati ya protocols

Hops tofauti hutafsiri HTTPS, QUIC, WebSocket, DNS, SSH au message-queue API badala ya kusambaza packets bila mabadiliko. Tafsiri huondoa fingerprint moja ya protocol ya mwanzo hadi mwisho, lakini huunda gateways zenye tabia bainifu za muda, buffering na ubadilishaji wa maana. Protocol tunneling (T1572) inaweza kuunganishwa na proxies na uigaji wa service.<sup>[[11]](#references)</sup>

**Ugunduzi:** tafuta gateway hosts zinazopokea protocol moja na kuanzisha nyingine huku zikiwa na tabia ya karibu ya bytes/muda; linganisha madhumuni ya endpoint na protocol inayobebwa.

### Uamilishaji tulivu kwenye vifaa vya edge

Badala ya kutuma beacon, implant hufuatilia trafiki inayofika tayari kwenye router/VPN na huamilishwa tu kwa thamani maalum, muundo wa source-port au token iliyothibitishwa. Trafiki ya kawaida huendelea kwenda kwenye service halisi. ATT&CK huita hii Traffic Signaling (T1205), na ina mifano iliyorekodiwa ya vifaa vya mtandao na APT.<sup>[[12]](#references)</sup>

**Ugunduzi:** hakiki uadilifu wa firmware/faili, nasa packets ghafi wakati wa uchunguzi ulioidhinishwa, tafuta socket filters zisizotarajiwa na tofauti za tabia ya service. Kukosekana kwa beacon ya mara kwa mara hakuthibitishi kuwa kifaa cha edge ni safi.

### Mzunguko wa origin wa serverless na wa muda mfupi

Front hudumisha utambulisho wa kimantiki ulio thabiti huku functions/containers za muda mfupi zikishughulikia hatua mahususi katika regions/accounts kadhaa. Hii hupunguza muda wa data kukaa kwenye diski na IP za origin zisizobadilika, lakini rekodi za uundaji wa control-plane, image/layer, role, secret, request ID na billing huwa grafu ya kudumu.

**Ugunduzi:** hifadhi logi za ukaguzi wa cloud na invocation nje ya workload; panga deployment templates, roles, environment keys na uhusiano wa front-to-origin kwa makundi.

### Utofauti wa tabaka za faragha

Operesheni inaweza kuepuka kwa makusudi chain moja inayofanana: kwa mfano, channel moja hutumia relay iliyokodishwa, tasking hutumia objecti ya umma, exit hutoka kwenye kiungo cha cellular cha maabara kinachomilikiwa, na usimamizi hutumia mtandao tofauti wa shirika. Hii hupunguza manufaa ya kuingilia mtoa huduma mmoja, lakini huongeza hatari ya kuhusianisha muda kati ya tabaka na makosa ya kiutendaji.

**Ugunduzi:** tengeneza ratiba za kampeni kwa kuunganisha vihisi vya utambulisho, DNS, SaaS, mtandao na cloud. Tafuta mabadiliko ya hali yanayotokea kwa wakati mmoja badala ya viashiria vinavyofanana.

### Dead drops za mifumo iliyogatuliwa au logi za uwazi

Mhusika anaweza kuweka pointer ndogo iliyosimbwa kwenye mfumo wowote wa umma wa kudumu wa append-only, hifadhi ya content-addressed au feed inayofanana na ya transparency. Objecti ya umma hustahimili mabadiliko, lakini index/content hash yake halisi na tabia ya client ya kuikagua huwa vitambulishi thabiti.

**Ugunduzi:** rekodi vitambulishi kamili vya API/object na response hashes; toa arifa kuhusu processes zisizo za kawaida zinazokagua objecti zisizobadilika, zikifuatiwa na decoding au miunganisho mipya.

### Operesheni zilizocheleweshwa za store-and-forward

C2 ya maingiliano huunda ulinganifu mkubwa wa muda. Muundo wa store-and-forward huweka kazi zilizosimbwa kwenye makundi na kurudisha matokeo dakika au saa baadaye kupitia queue tofauti au uhamisho wa kimwili. Huacha kasi ya majibu ili kupunguza ulinganifu wa muda wa mwanzo hadi mwisho.

**Ugunduzi:** ongeza muda wa madirisha ya ulinganishaji, tengeneza modeli za ufikiaji wa queue wa mara kwa mara na kagua maandalizi ya endpoint. Kuweka kwenye makundi huhamisha ishara kutoka muda wa packets kwenda kwenye tabia ya mchakato/faili iliyopangwa; hakuiondoi.

## Mapitio ya usanifu: fikiria kwa mtazamo wa wachunguzi

Kwa kila njia, jaza jedwali hili kabla ya kupeleka na baada ya kukusanya data:

| Tabaka | Huona chanzo? | Huona lengwa? | Huona maudhui? | Vitambulishi thabiti | Mmiliki wa uhifadhi/data kisheria |
|---|---:|---:|---:|---|---|
| mtandao wa ndani/mtoa huduma | | | | | |
| huduma ya kuingia/ufikiaji | | | | | |
| waendeshaji wa traversal | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| lengwa | | | | | |
| mtoa huduma wa akaunti/malipo | | | | | |

Ikiwa mtoa huduma mmoja wa kawaida anaweza kujaza safu zote, usanifu huficha shughuli dhidi ya lengwa lakini hautoi utenganisho thabiti. Ikiwa hakuna msimamizi wa ndani anayeweza kuhusisha shughuli na zoezi husika, usanifu huo haufai kwa red teaming ya kitaalamu.

## References

- [1] [MITRE ATT&CK — Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), na Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Wahusika wa ujasusi wanaohusishwa na China hutumia mitandao ya ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Kuvuruga mtandao mkubwa zaidi duniani wa residential proxy](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Kampeni za Shadow: Kufichua Ujasusi wa Kimataifa](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Kampeni ya Blinder Tunnel Inalenga Miundombinu ya Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI Ilijenga Overlays. Waathiriwa Wanapoteza PIN Zao](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Mbinu za Zamani Zilizotumika Kupitia Binaries Zilizosainiwa za ChatGPT na Claude](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
