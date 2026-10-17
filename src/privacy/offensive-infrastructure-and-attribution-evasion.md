# Miundombinu ya Mashambulizi na Kukwepa Uhusishaji

{{#include ../banners/hacktricks-training.md}}

Mwendeshaji hapati kutokujulikana kwa maana kupitia proxy moja pekee. Kampeni halisi huunda **grafu ya utengano**: mwendeshaji hufikia nodi ya ufikiaji, nodi za upitishaji huficha nodi hiyo kutoka kwa nodi ya kutoka, redirectors hulinda C2 halisi, na majina ya muda hutaja ukingo wa umma.

Tumia [Katalogi ya Mbinu za Ufikiaji wa Mtandao Bila Kujulikana](anonymous-internet-access-techniques.md) kwa muhtasari sanifu wa faida/hasara, uwekaji na ugunduzi wa kila njia. Ukurasa huu unaeleza kwa kina zaidi jinsi ya kuunganisha miundombinu pinzani.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Anwani ya mwisho iliyoonekana na mlengwa kwa hiyo ni ushahidi wa njia iliyotumika, si uthibitisho wa aliyekuwa akidhibiti kibodi. MITRE inaainisha vipengele vikuu chini ya Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) na Web Service (T1102).<sup>[[1]](#references)</sup>

## Aina za miundombinu

| Aina | Kwa nini mhusika huitumia | Mfiduo wa kudumu | Hatua bora ya mchunguzi |
|---|---|---|---|
| VPS/cloud ya kukodi | Haraka, inayotabirika, inayoweza kufikiwa kwa njia za mtandao, rahisi kujenga upya | Historia ya mpangaji, bili, console, kuingia kwa chanzo na image | Matukio ya akaunti/control-plane na fingerprint za server zinazojirudia |
| VPN/Tor ya kibiashara | Seti kubwa ya anwani za pamoja za egress; hakuna usimamizi wa server | Mwonekano wa provider/mlinzi na muda wa mawasiliano kutoka mwisho hadi mwisho | Tabia ya kulengwa, ushahidi wa endpoint na ulinganishaji wa mtiririko |
| Proxy ya makazi/simu | ASN ya watumiaji na uhalisia wa kijiografia | Rekodi za broker/mteja; tabia ya proxyware au host iliyoambukizwa | Usafiri usiowezekana, itifaki za proxy na mabadiliko ya anwani kwa kila session |
| Server/router/IoT iliyoathiriwa | Hukopa sifa na mamlaka ya kisheria ya mwathiriwa | Implant, mtiririko wa usimamizi na controller ya juu inayojirudia | Telemetry ya kifaa na topolojia ya ORB, si IP moja ya kutoka |
| CDN/redirector | Hutenganisha edge ya umma na C2 ya back-end | TLS/HTTP grammar, certificate, routing na mabaki ya akaunti ya cloud | Ulinganishaji wa edge na origin na upangaji wa makundi ya maumbo ya maombi |
| Huduma halali ya wavuti | Hujificha katika trafiki inayoruhusiwa ya GitHub/cloud/social | API token, vitambulishi vya tenant/object na mfuatano usio wa kawaida wa michakato | Mchakato wa endpoint pamoja na maana ya service/API |
| Njia ya kimwili/simu/satelaiti | Hubadilisha asili halisi inayoonekana | Rekodi za RF, carrier, mteja, kifaa na eneo | Ushahidi wa redio/kimwili na wa mtandao kwa pamoja |

## Mitandao ya relay box ya kiutendaji

**Mtandao wa ORB** ni kundi la proxy linalosimamiwa na kutumika kama huduma ya kati. Mandiant huzigawa katika mitandao iliyosanidiwa ya server zilizokodiwa, mitandao isiyosanidiwa ya router/IoT zilizoathiriwa, na mitandao mseto. Topolojia iliyokomaa huwa na majukumu manne ya kimantiki:<sup>[[2]](#references)</sup>

1. **Server ya usimamizi (ACOS):** huhifadhi orodha ya vifaa, vitambulisho, hali na sera ya routing.
2. **Nodi ya ufikiaji/relay:** huthibitisha wateja au waendeshaji; ndiyo lango thabiti la kuingia kwenye mesh inayobadilika.
3. **Nodi za kuvukia:** mfumo mmoja au zaidi uliokodiwa au ulioathiriwa hurudisha miunganisho isiyo wazi.
4. **Nodi ya kutoka/hatua ya maandalizi:** huwasilisha anwani ya mwisho ya chanzo kwa malengo ya upelelezi, unyonyaji au C2.

Mesh inaweza kuchagua nodi za kutoka kulingana na nchi, ASN, muda wa kusubiri au upatikanaji, na kubadilisha nodi zisizo na afya. Makundi mengi ya vitisho yanaweza kukodi mtandao mmoja. Mandiant iliona anwani ya IPv4 ikibaki kuhusishwa na baadhi ya ORB kwa siku 31 tu; kwa hiyo inapendekeza kuchukulia **mtandao kama huluki inayobadilika inayofanana na mhusika**, badala ya kuzuia orodha iliyopitwa na wakati ya IP.<sup>[[2]](#references)</sup>

### Hii hutoa nini—na inavuja nini

- Mlengwa huona nodi ya kutoka ambayo inaweza kuwa karibu kijiografia na inayoonekana kuwa ya makazi.
- Nodi ya kutoka huona mlengwa na hop iliyotangulia, si lazima mwendeshaji.
- Huduma ya ufikiaji huona mteja na ombi la njia. Mesh inayosimamiwa kivyake inaweza kumtenganisha mteja na nodi za kutoka, lakini huunda rekodi muhimu ya upande mwingine.
- Port, mpangilio wa handshake, mabango ya server, certificates, vipindi vya uptime na uhusiano wa controller vinavyojirudia vinaweza kufichua kundi la vifaa hata IP zinapobadilika.
- Router iliyoathiriwa mara nyingi haina telemetry ya endpoint, lakini ISP yake bado ina data ya mteja na mtiririko; kukamatwa kwake hufichua mabaki ya implant/configuration.

{% hint style="info" %}
Kwa zoezi lililoidhinishwa, tengeneza upya topolojia kwa kutumia VM au router zinazomilikiwa na shirika na uhifadhi ramani ya attribution ya controller. Usitumie proxy zilizo wazi au vifaa vya watu wengine. [Mwongozo wa maabara](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) huunda muundo uleule wa hop unaoonekana kwa watetezi bila kumdhuru mpatanishi.
{% endhint %}

## Mitandao ya proxy ya makazi na simu

Huduma za proxy ya makazi hugawa session kwa anwani za broadband za watumiaji; proxy za simu hutumia madimbwi ya carrier NAT kwa egress. Chanzo kinaweza kuwa vifaa vilivyojiunga kwa hiari, SDK/proxyware iliyojumuishwa kwenye programu za watumiaji, wauzaji upya, au malware. Asili hizi si sawa: kutokuwepo kwa ridhaa yenye taarifa hugeuza huduma ya faragha kuwa miundombinu iliyoathiriwa.

Mbinu za kubadilisha anwani huathiri ugunduzi:

- **kubadilisha kwa kila ombi** husababisha mabadiliko ya haraka ya IP na ASN/eneo huku utambulisho wa tabaka za juu ukiendelea kuwa thabiti;
- **session zinazonata** hudumisha nodi ya kutoka kwa dakika au saa, zikifanana na mteja wa kawaida;
- **gateway za backconnect** humwonyesha mteja endpoint moja ya broker na kuchagua nodi za kutoka ndani ya mfumo;
- **madimbwi ya simu** huweka wateja wengi halisi nyuma ya anwani chache za carrier NAT, na kufanya kuzuia IP kuwa na gharama kubwa.

Watetezi wanapaswa kulinganisha IP na session iliyothibitishwa, fingerprint ya TLS/client, mpangilio wa HTTP, cookie ya kifaa na tabia. Kuingia kunakodaiwa kuwa kwa eneo la karibu kupitia proxy ya makazi, kisha kufuatiwa na nchi nyingine huku vipengele vyote vya tabaka za juu vikibaki vilevile, ni ushahidi thabiti zaidi kuliko sifa pekee. Kinyume chake, kushiriki anwani na kubadilisha minara ya simu husababisha mabadiliko halali, kwa hiyo usichukulie kamwe uainishaji wa makazi/proxy kama hitimisho la mwisho.

### Control plane za proxyware na mwingiliano wa wauzaji upya

Usiichukulie pool ya makazi kama orodha bapa ya nodi za kutoka. Uchambuzi wa mfumo ikolojia wa IPIDEA ulifichua **control plane ya ngazi mbili inayoweza kutumika tena**: SDK iliyopachikwa kwanza hutuma metadata ya kifaa/kujiunga kwenye domain ya Tier One na kupokea jozi za IP:port za `connect`/`proxy` za Tier Two pamoja na maelekezo ya kuratibu. Nodi huwasiliana mara kwa mara na port ya connect ya Tier Two ili kupata kazi iliyosimbwa, hufungua muunganisho wa pili kwenye port ya proxy inayolingana, na kupeleka byte zilizopewa hadi kwenye destination iliyoombwa. SDK na chapa za proxy zilizodaiwa kuwa tofauti zilikuwa na domain tofauti za ugunduzi, lakini ziliungana kwenye miundombinu ya Tier Two na pool za nodi za kutoka zilizopishana kupitia umiliki wa pamoja na mahusiano ya wauzaji upya.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Hii huzalisha viashiria vya ufuatiliaji vilivyo imara zaidi kuliko kuzuia anwani za IP za makazi:<sup>[[13]](#references)</sup>

- mchakato usiotarajiwa wa utility, VPN, mchezo au kifaa kilichopachikwa hutuma kitambulisho thabiti cha kifaa/ufunguo wa mteja na kupokea orodha ya seva inayobadilika;
- endpoint huulizia IP ya moja kwa moja kwenye port isiyo ya kawaida, kisha huunganisha kwenye port nyingine kwenye anwani hiyo hiyo mara moja kabla ya kufungua socket ya destination mpya;
- chapa kadhaa zinazoonekana tofauti hushiriki anwani za Tier Two, sarufi ya protocol, msimbo wa SDK au mwingiliano wa exit node;
- programu tofauti zinazowasiliana na domains tofauti za Tier One hupokea anwani kutoka kwenye pool ileile ya Tier Two.

Muingiliano huo pia hupunguza uwezo wa kufanya attribution: kuona IP kwenye pool iliyotangazwa na vendor mmoja hakuthibitishi ni reseller, mteja au threat actor gani aliyeitumia wakati husika. Hifadhi mihuri ya muda ya mtiririko wa data, mfuatano wa michakato, maudhui ya majibu ya Tier One na vitambulisho vya kazi za Tier Two.<sup>[[13]](#references)</sup> Katika zoezi lililoidhinishwa, iga mpangilio huu kwa kutumia tu endpoints zinazomilikiwa na shirika; usiwahi kusajili vifaa vya watumiaji au proxyware ya watu wengine.

## Minyororo ya proxy za multi-hop

MITRE hutofautisha proxies za nje na **multi-hop proxies (T1090.003)**. Sifa muhimu si idadi ya hops, bali kutenganishwa kwa taarifa na usimamizi.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Ikiwa mhusika mmoja anaendesha A na B, kumbukumbu za pamoja au muda wa mtiririko vinaweza kutumika kujenga upya mzunguko. Kuongeza VPN za kibiashara zinazofuatana kutoka kwenye endpoint/akaunti ileile kunaweza kuongeza ucheleweshaji huku kukiacha ushahidi wa utambulisho, malipo na muda unaofanana. Tor hupunguza tatizo hili kwa kutumia relays zilizochaguliwa kwa kujitegemea na muundo wa mteja unaofanana, lakini mtandao shirikishi wenye latency ndogo hauwezi kuahidi kukinga dhidi ya mwangalizi anayepima ncha zote mbili.

Makosa ya kawaida ni DNS au IPv6 bypass, programu kufungua sockets zake, trafiki ya usimamizi kufikia relays moja kwa moja, shughuli zinazolingana kwa wakati, kutumia tena funguo za SSH, na kuingia kwenye akaunti zinazofichua utambulisho. Uthibitishaji sahihi ni jaribio la kushindwa: simamisha kila relay kwa zamu na uthibitishe kuwa workload haiwezi kutumia njia wazi kama mbadala.

### Kuanguka kwa handaki na upstream leakage

Mara nyingi, usanifu wa relay hutambulika zaidi unaposhindwa. Unit 42 iliandika njia ya ujasusi yenye tabaka nyingi iliyotumia VPS zinazoelekezwa kwa waathiriwa, relay VPS, proxies za makazi, Tor na huduma nyingine za proxy; handaki lilipoachwa au kuanguka, miundombinu fiche ya upstream iliunganishwa moja kwa moja na mifumo ya relay na ile inayoelekezwa kwa waathiriwa. Uchunguzi huohuo pia ulitumia cheti cha X.509 kilichofichuliwa kwa muda kwenye miundombinu ya upstream kama kiungo cha kuchunguza kati ya tabaka.<sup>[[14]](#references)</sup>

Tenganisha **data plane** (`victim <-> exit`) na **control plane** (`operator/upstream -> relay administration`). Hifadhi kumbukumbu za ingress na uthibitishaji katika kila tabaka unalomiliki, historia za vyeti na miunganisho mifupi iliyoshindwa—si vipindi vya C2 vilivyofanikiwa pekee. Chanzo kinachoonekana tu wakati relays hazifanyi kazi au kinachosimamia moja kwa moja nodes nyingi zinazoelekezwa kwa waathiriwa ni mgombea bora zaidi wa kuwa upstream kuliko exit ya kawaida, lakini ASN/geolocation yake bado ni dhana, si uthibitisho wa utambulisho wa operator.

Maabara iliyoidhinishwa inapaswa kufanya workload ishindwe kwa usalama. Kwa workload iliyotengwa katika Linux network namespace, route ya kwanza lazima ipitie kwenye tunnel; baada ya kuiondoa, ombi na ukaguzi wa route lazima vyote vishindwe badala ya kuchagua uplink halisi:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Rudia jaribio la DNS na IPv6, na katika kila mpaka wa relay. Ikiwa uchunguzi wowote utafaulu, rekodi interface/anwani halisi ya chanzo kabla ya kurekebisha uelekezaji wa policy au firewall; uchunguzi huo ndio attribution leak ambayo mchunguzi angeona.

## Tabaka za redirector na uundaji wa trafiki

**Redirector** ya umma hupokea trafiki inayolingana na sarufi mahususi ya operesheni na kuipeleka kwa team server iliyolindwa. Kila kitu kingine kinaweza kukataliwa au kupewa maudhui yasiyo na madhara.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Tabaka nyingi hupunguza uwezekano wa kufichuka: kuchoma domain ya umma si lazima kufichue team server. CDN huongeza uwezo wa anycast na domain ya nje yenye sifa nzuri, lakini akaunti ya CDN na edge logs huwa sehemu zinazoweza kuhusisha shughuli na mhusika. TLS fingerprints, historia ya certificate, paths/order ya headers zinazotambulika, ukubwa wa majibu, tabia ya redirects na orodha za origin zinazoruhusiwa vinaweza kuunganisha fronts zinazodhaniwa kutohusiana.

Kwa utambuzi, hifadhi sehemu za reverse-proxy kabla ya normalization, linganisha SNI/Host/authority, kagua mchanganyiko adimu wa headers, linganisha response bodies na TLS fingerprints katika makundi, na tafuta mwingiliano wa usanidi kwenye cloud/CDN audit logs. Kwa red teams zilizoidhinishwa, epuka kunakili brand halisi au kuweka ukusanyaji wa credentials nyuma ya third party isiyohusiana.

## Domain fronting na domainless fronting

Katika **domain fronting (T1090.004)** ya kawaida, muunganisho wa TLS hutangaza front domain inayoruhusiwa kwenye SNI, ilhali HTTP `Host` iliyosimbwa kwa njia fiche au HTTP/2 `:authority` huomba back-end domain tofauti. CDN inayoshirikiana huelekeza trafiki kulingana na thamani ya ndani. Mwangalizi wa mtandao asiye na TLS decryption huona front; CDN huona thamani zote mbili na origin. Katika matoleo ya domainless, SNI inaweza kuwa tupu huku sehemu nyingine ya uelekezaji ikichagua lengwa.<sup>[[4]](#references)</sup>

Huu si uigaji wa kimiujiza: hufanya kazi tu pale intermediary inaporuhusu kutolingana huko kimakusudi au kwa bahati na inajua jinsi ya kuelekeza jina la ndani. Watoa huduma wakuu wamezuia fronting kati ya akaunti tofauti. Encrypted ClientHello (ECH) hubadilisha kile ambacho mwangalizi aliye kwenye njia anaweza kuona, lakini haifuti rekodi za CDN, endpoint au application.

Sehemu za utambuzi ni pamoja na:

- nasaba ya michakato ya endpoint na lengwa lisilotarajiwa kwa application hiyo;
- kutolingana kwa SNI na HTTP authority pale TLS inspection inaporuhusiwa kisheria na inapatikana;
- CDN logs zinazoonyesha tenant/front moja ikielekeza kwa authority/origin nyingine;
- sessions zisizo za kawaida za muda mrefu au za vipindi kwenda kwenye huduma ambayo kwa kawaida hutumiwa kwa mawasiliano ya moja kwa moja;
- ukubwa na mpangilio thabiti wa encrypted flows katika front domains zinazobadilika.

Lab salama huiga kutolingana kwa uelekezaji kwenye reverse proxy inayomilikiwa; haitumii vibaya CDN ya umma.

## Dynamic resolution: DDNS, DGA na fast flux

Dynamic resolution hutenganisha huduma ya kimantiki na miundombinu isiyobadilika:

- **DDNS:** client iliyothibitishwa husasisha jina thabiti baada ya anwani yake kubadilika.
- **DGA:** endpoint na controller zote hukokotoa majina ya domain yanayowezekana kutoka kwenye seed ya muda/ufunguo; operator husajili sehemu ndogo tu.
- **Fast flux:** jina hurudisha seti inayobadilika haraka ya anwani zilizoathiriwa/proxy, mara nyingi zikiwa na TTL fupi.
- **Double flux:** anwani za huduma na anwani za authoritative name-server huzungushwa zote, na hivyo kuficha pia control layer.

Fast flux ni muundo wa usambazaji wa mzigo unaotumiwa kwa nia ovu, si tu “majibu mengi ya DNS.” Ushahidi imara zaidi huunganisha TTL fupi, idadi kubwa ya anwani za kipekee, usambazaji mpana wa ASN/jiografia, muda mfupi wa nodi kuishi, tabia ya application inayojirudia na historia ya usajili yenye kutia shaka. CDN hutumia kihalali baadhi ya sifa hizi. MITRE inapendekeza kulinganisha tabia ya DNS na mchakato pamoja na miunganisho inayofuata.<sup>[[5]](#references)</sup>

DGA inaweza kutambuliwa kupitia lexical entropy, mifumo ya konsonanti/nambari, milipuko ya NXDOMAIN, domains zinazoonekana kwa mara ya kwanza kwa wakati mmoja na muktadha wa mchakato. Wordlist DGAs na generative models hushinda kanuni rahisi za entropy, hivyo clustering ya muda katika fleet nzima na ufuatiliaji wa asili ya endpoint huwa muhimu zaidi.

## Domains zilizoathiriwa na domain shadowing

Mhusika anaweza kuteka akaunti ya registrar/DNS, kuchukua subdomain iliyoachwa, au kuongeza records chini ya domain yenye sifa nzuri. **Domain shadowing** huhifadhi apex halali huku idadi kubwa ya subdomains zinazodhibitiwa na mshambulizi zikielekeza kwenye delivery au C2 hosts zinazobadilika. Hukopa umri na sifa nzuri ya domain, na inaweza kukwepa kuzuia domain nzima.<sup>[[6]](#references)</sup>

Watetezi wanahitaji registrar na authoritative-DNS audit logs, MFA, kufunga registry/registrar, arifa za delegations/API tokens/name servers mpya, ufuatiliaji wa certificate transparency, na orodha ya cloud resources zinazorejelewa na DNS. Chunguza resolution na historia ya certificate ya subdomain bila kutegemea sifa ya apex.

## Web services na dead-drop resolvers

**Dead-drop resolver (T1102.001)** huhifadhi pointer iliyosimbwa kwa njia fiche ya C2 ya sasa ndani ya post, profile, document, repository, cloud object au blockchain field halali. Malware hupakua object ya umma, hutoa domain/IP kwa kuifungua, kisha huwasiliana na hatua inayofuata. Matoleo ya njia mbili hubadilishana commands au files kupitia service APIs.<sup>[[7]](#references)</sup>

Toleo moja la resolver mahususi kwa GitHub hutumia Issues Search API tu pale channel ya repository iliyothibitishwa inaposhindwa. Client hutafuta issues zinazolingana na tarehe ya sasa, repository na aina ya issue, hufuata comments URL ya kila issue, kisha hutoa ciphertext iliyo kati ya alama za `<!--` na `-->`. Baada ya decryption inayotegemea host na tarehe, fields kama `Owner`, `LicRepo` na `LicToken` hubadilisha owner, path na token za repository ya msingi. Hii humwezesha operator kuzungusha credentials na endpoints bila kubadilisha client; maoni ya issue ni resolver, huku files za repository zikibaki channel ya tasking.<sup>[[15]](#references)</sup>

Toleo la Android huchagua mojawapo ya kurasa mbili za Telegram za umma linapoanza na kutoa ciphertext iliyo kati ya sehemu mbili za marker iliyo ndani ya APK. Hufungua thamani kwa Base64URL na kuifungua kwa AES-128-CBC: bytes 16 za kwanza za `SHA-256(marker)` ndizo ufunguo na bytes 16 zinazobaki ndizo IV. Plaintext ni base URL halisi ya C2, si URL ya ukurasa wa Telegram. Hifadhi maudhui ya ukurasa na marker halisi unapozalisha tena resolution; kubadilisha ukurasa wa umma huzungusha endpoint bila kujenga upya APK.<sup>[[16]](#references)</sup>

Hii huongeza uimara na kuficha back-end C2 dhidi ya uchanganuzi tuli wa binary. Pia huunda identifiers thabiti za object, tenant, repository, API na mifumo ya ufikiaji. Watetezi wanapaswa kuunganisha:

1. mchakato uliowasiliana na huduma;
2. API path/object halisi na response hash;
3. shughuli za decoding au uchakataji wa string;
4. muunganisho mpya wa kutoka muda mfupi baadaye; na
5. tabia inayofanana kwingineko kwenye fleet.

Kuzuia GitHub yote, cloud storage au social media si jambo linalowezekana mara nyingi. Sera za egress zinazotambua huduma na ulinganishaji katika kiwango cha mchakato hufanya vizuri zaidi kuliko kuzuia domains pekee.

## Personas, akaunti na compartments za ununuzi

Kutokujulikana kwa miundombinu hushindwa pale persona, recovery email, simu, malipo, browser au admin IP inapounganisha compartments. Operesheni zinazohusishwa na mataifa zimejenga social profiles, email identities na cloud accounts muda mrefu kabla ya kuzitumia; ATT&CK huandika hili kama Establish Accounts (T1585), ikijumuisha sub-techniques za social, email na cloud.<sup>[[8]](#references)</sup>

Mtetezi au mchunguzi hujenga graph kutokana na:

- muda wa kuunda na kuingia kwa mara ya kwanza, locale, time zone na ratiba ya kazi;
- recovery fields, vifaa vya MFA, hati za utambulisho na njia za malipo;
- browser/TLS fingerprints na historia ya source network;
- matumizi tena ya avatar, chanzo cha picha, mtindo wa uandishi na ukuaji wa social graph;
- domain registrant, name server, certificate, analytics ID au repository commit zinazotumiwa kwa pamoja;
- hatua za management plane zinazokwepa usanifu wa public relay.

Kwa red team iliyoidhinishwa, synthetic personas zinapaswa kurekodiwa kwa exercise controller, zitumie njia za recovery/malipo zinazomilikiwa na shirika, ziepuke kujifanya watu halisi wasiohusika, na ziwe na mpango wa kuziondoa. SOC inaweza kubaki bila taarifa; operesheni haipaswi kukosa uwajibikaji.

## Mifumo mipya ya mchanganyiko ya kuweka kwenye threat model

Yafuatayo ni **mchanganyiko unaoongozwa na watetezi**, si madai kwamba mhusika aliyetajwa ametumia kila muundo huu hasa. Huchanganya primitives ambazo tayari zimeonekana na ni dhana muhimu kwa purple-team.

### Tasking ya njia moja isiyo linganifu

Commands huwasili kupitia chanzo cha umma, cha kutangaza au cha append-only, ilhali matokeo hutoka kupitia channel isiyohusiana baada ya kuchelewa. Mifano ya primitive ni mawasiliano ya njia moja kupitia web service na dead drops. Utenganishaji huzuia flow moja kuonekana kuwa ya pande mbili na hutatiza ulinganishaji rahisi wa ombi/jibu.<sup>[[9]](#references)</sup>

**Utambuzi:** hifadhi usomaji wa object, kisha linganisha mabadiliko ya hali ya mchakato na uhamisho wa baadaye wa kutoka katika muda mpana zaidi. Tafuta mchakato adimu unaosoma object ileile ya umma hata kama hakuna jibu la papo hapo.

### Uhamishaji wa channel wa hatua nyingi

Hatua ya kwanza tulivu hukusanya taarifa na kupandisha mifumo iliyochaguliwa pekee hadi channel ya hatua ya pili isiyohusiana. Endpoint, protocol na mchakato wa pili vinaweza visiwe na miundombinu yoyote sawa na ya kwanza. Hii hupunguza kufichua miundombinu yenye uwezo na imeigwa waziwazi kama ATT&CK T1104.<sup>[[10]](#references)</sup>

**Utambuzi:** unganisha `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; usifunge tukio baada ya kuzuia domain ya kwanza.

### Tafsiri ya relay kati ya protocols

Hops tofauti hutafsiri HTTPS, QUIC, WebSocket, DNS, SSH au message-queue API badala ya kusambaza packets bila mabadiliko. Tafsiri huondoa fingerprint moja ya protocol ya mwanzo hadi mwisho, lakini huunda gateways zenye muda, buffering na ubadilishaji wa maana unaotambulika. Protocol tunneling (T1572) inaweza kuunganishwa na proxies na uigaji wa huduma.<sup>[[11]](#references)</sup>

**Utambuzi:** tafuta gateway hosts zinazopokea protocol moja na kuanzisha nyingine huku tabia ya bytes/muda ikihusiana kwa karibu; linganisha nia ya endpoint na protocol inayobebwa kwa hakika.

### Uanzishaji tulivu kwenye edge devices

Badala ya kutuma beacon, implant hufuatilia trafiki inayofika tayari kwenye router/VPN na hujiwasha tu inapokutana na thamani maalum, muundo wa source-port au token iliyothibitishwa. Trafiki ya kawaida huendelea kwenda kwenye huduma halisi. ATT&CK huita hili Traffic Signaling (T1205), na kuna mifano iliyorekodiwa ya network devices na APT.<sup>[[12]](#references)</sup>

**Utambuzi:** uadilifu wa firmware/file, raw packet capture wakati wa hunt iliyoidhinishwa, socket filters zisizotarajiwa na tofauti za tabia ya huduma. Kutokuwepo kwa beacon ya vipindi hakuthibitishi kuwa edge device ni safi.

### Serverless na mzunguko wa origin wa muda mfupi

Front hudumisha utambulisho wa kimantiki thabiti huku functions/containers za muda mfupi zikishughulikia hatua moja moja katika regions/accounts kadhaa. Hii hupunguza muda wa kuwepo kwenye disk na origin IP zisizobadilika, lakini uundaji wa control-plane, image/layer, role, secret, request ID na billing telemetry huwa graph ya kudumu.

**Utambuzi:** hifadhi cloud audit na invocation logs nje ya workload; linganisha deployment templates, roles, environment keys na uhusiano wa front-to-origin katika makundi.

### Utofauti wa privacy layer

Operesheni inaweza kuepuka kimakusudi mnyororo mmoja uliofanana: kwa mfano, channel moja hutumia relay iliyokodishwa, tasking hutumia object ya umma, exit hutoka kwenye cellular link ya lab inayomilikiwa, na usimamizi hutumia mtandao tofauti wa shirika. Hii hupunguza faida ya kuathiri provider mmoja, lakini huongeza hatari ya ulinganishaji wa muda kati ya layers na makosa ya kiutendaji.

**Utambuzi:** tengeneza timelines za kampeni kutoka kwenye sensors za identity, DNS, SaaS, mtandao na cloud. Tafuta mabadiliko ya hali yanayotokea kwa wakati mmoja badala ya indicators zinazofanana.

### Dead drops za decentralized au transparency-log

Mhusika anaweza kuweka pointer ndogo iliyosimbwa kwa njia fiche kwenye mfumo wowote wa umma unaodumu na wa append-only, content-addressed store au feed inayofanana na transparency. Object ya umma ni imara, lakini index/content hash yake halisi na tabia ya client ya kuikagua huwa identifiers thabiti.

**Utambuzi:** rekodi identifiers kamili za API/object na response hashes; toa arifa kwa michakato isiyo ya kawaida inayokagua objects zisizobadilika, ikifuatiwa na decoding au miunganisho mipya.

### Operesheni za store-and-forward zilizocheleweshwa

C2 ya mawasiliano ya moja kwa moja huunda ulinganifu mkubwa wa muda. Muundo wa store-and-forward hukusanya jobs zilizosimbwa kwa njia fiche na kurudisha matokeo dakika au saa kadhaa baadaye kupitia queue tofauti au uhamisho wa kimwili. Hupunguza kasi ya majibu ili kupunguza ulinganifu wa muda wa mwanzo hadi mwisho.

**Utambuzi:** ongeza muda wa madirisha ya ulinganishaji, tengeneza modeli ya ufikiaji wa queue wa vipindi na kagua maandalizi ya endpoint. Kukusanya pamoja huhamisha ishara kutoka muda wa packets hadi tabia iliyopangwa ya mchakato/faili; hakuifuti.

## Mapitio ya usanifu: fikiria kwa kuzingatia waangalizi

Kwa kila njia, jaza jedwali hili kabla ya deployment na baada ya kukusanya data:

| Tabaka | Huona chanzo? | Huona lengwa? | Huona maudhui? | Identifiers thabiti | Mmiliki wa retention/kisheria |
|---|---:|---:|---:|---|---|
| mtandao wa eneo/carrier | | | | | |
| huduma ya kuingia/ufikiaji | | | | | |
| operator(s) wa traversal | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| lengwa | | | | | |
| provider wa akaunti/malipo | | | | | |

Ikiwa provider mmoja wa kawaida anaweza kujaza kila safu wima, usanifu huo hutoa ufichaji dhidi ya lengwa lakini si utenganishaji imara. Ikiwa hakuna controller wa ndani anayeweza kuhusisha shughuli na zoezi, usanifu huo haufai kwa red teaming ya kitaalamu.

## References

- [1] [MITRE ATT&CK — Pata Miundombinu (T1583), Athiri Miundombinu (T1584), na Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Wapelelezi wanaohusishwa na China hutumia mitandao ya ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Athiri Miundombinu: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Fungua Akaunti (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: Mawasiliano ya Njia Moja (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Kuvuruga Mtandao Mkubwa Zaidi wa Residential Proxy Duniani](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Kampeni za Shadow: Kufichua Ujasusi wa Kimataifa](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Kampeni ya Blinder Tunnel Yalenga Miundombinu ya Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI Ilitengeneza Overlays. Waathiriwa Wanapoteza PIN Zao](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
