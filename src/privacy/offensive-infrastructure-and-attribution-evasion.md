# Miundombinu ya Mashambulizi na Kukwepa Uhusishaji

{{#include ../banners/hacktricks-training.md}}

Mwendeshaji hupata nadra kutokujulikana kwa maana kwa kutumia proxy moja tu. Kampeni halisi huunda **grafu ya utenganisho**: mwendeshaji hufikia node ya ufikiaji, node za upitishaji huficha node hiyo dhidi ya node ya kutoka, redirector hulinda C2 halisi, na majina yanayotupwa huelekeza kwenye ukingo wa umma.

Tumia [Katalogi ya Mbinu za Ufikiaji wa Mtandao Bila Kutambulika](anonymous-internet-access-techniques.md) kupata muhtasari sanifu wa faida/hasara, uwekaji na ugunduzi wa kila njia. Ukurasa huu unaeleza kwa undani zaidi jinsi ya kuunda miundombinu ya kihasama.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Anwani ya mwisho iliyoonekana na mlengwa kwa hiyo ni ushahidi wa njia iliyotumika, si uthibitisho wa nani aliyedhibiti kibodi. MITRE inaainisha vipengele vikuu kama Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) na Web Service (T1102).<sup>[[1]](#references)</sup>

## Aina za miundombinu

| Aina | Kwa nini mhusika huitumia | Mfiduo unaodumu | Njia bora zaidi ya mlinzi kufuatilia |
|---|---|---|---|
| VPS/cloud ya kukodisha | Haraka, inayotabirika, inayoweza kufikiwa kupitia mtandao, rahisi kujenga upya | mpangaji, malipo, console, historia ya kuingia kutoka chanzo na picha za mfumo | matukio ya akaunti/control-plane na alama za vidole za seva zinazojirudia |
| VPN/Tor za kibiashara | Seti kubwa ya anwani za kutoka zinazoshirikiwa; hakuna usimamizi wa seva | mwonekano wa mtoa huduma/mwangalizi na muda wa mawasiliano kutoka mwanzo hadi mwisho | tabia ya lengwa, ushahidi wa endpoint na ulinganishaji wa mtiririko |
| Proxy za makazi/simu | ASN ya watumiaji na uaminifu wa kijiografia | rekodi za wakala/mteja; tabia ya proxyware au kifaa kilichoambukizwa | safari zisizowezekana, itifaki za proxy na mabadiliko ya anwani kwa kila session |
| Seva/router/IoT iliyoathiriwa | Hutumia sifa na mamlaka ya kisheria ya mwathiriwa | implant, mtiririko wa usimamizi na kidhibiti cha juu kinachojirudia | telemetry ya kifaa na topolojia ya ORB, si IP moja ya kutoka |
| CDN/redirector | Hutenganisha edge ya umma na C2 ya nyuma | sarufi ya TLS/HTTP, cheti, uelekezaji na mabaki ya akaunti ya cloud | ulinganishaji wa edge na origin na kupanga maombi kwa makundi kulingana na umbo |
| Huduma halali ya wavuti | Hujichanganya na trafiki ya GitHub/cloud/mitandao ya kijamii inayoruhusiwa | tokeni ya API, vitambulishi vya tenant/object na mfuatano usio wa kawaida wa michakato | mchakato wa endpoint pamoja na maana ya huduma/API |
| Njia ya kimwili/simu ya mkononi/setilaiti | Hubadilisha chanzo halisi kinachoonekana | rekodi za RF, mtoa huduma, mteja, kifaa na eneo | ushahidi wa redio/kimwili na wa mtandao kwa pamoja |

## Mitandao ya visanduku vya relay vya uendeshaji

**Mtandao wa ORB** ni kundi la proxy linalosimamiwa na kutumika kama huduma ya kati. Mandiant huzigawa katika mitandao iliyosanidiwa kwa seva zilizokodishwa, mitandao isiyosanidiwa kwa router/IoT zilizoathiriwa, na mitandao mseto. Topolojia iliyokomaa ina majukumu manne ya kimantiki:<sup>[[2]](#references)</sup>

1. **Seva ya usimamizi (ACOS):** hudumisha orodha ya vifaa, vitambulisho, hali na sera ya uelekezaji.
2. **Nodi ya ufikiaji/relay:** huthibitisha wateja au waendeshaji; ndiyo lango thabiti la kuingia kwenye mesh inayobadilika.
3. **Nodi za upitishaji:** mfumo mmoja au zaidi uliokodishwa au ulioathiriwa hupeleka miunganisho isiyo wazi.
4. **Nodi ya kutoka/maandalizi:** huwasilisha anwani ya mwisho ya chanzo kwa malengo ya upelelezi, unyonyaji au C2.

Mesh inaweza kuchagua nodi za kutoka kulingana na nchi, ASN, muda wa kusubiri au upatikanaji, na kubadilisha nodi zisizo na afya. Makundi mengi ya vitisho yanaweza kukodisha mtandao mmoja. Mandiant iliona anwani ya IPv4 ikihusishwa na baadhi ya ORB kwa muda mfupi kama siku 31; kwa hiyo inapendekeza kuichukulia **network kama huluki inayobadilika inayofanana na mhusika**, badala ya kuzuia orodha ya IP zilizopitwa na wakati.<sup>[[2]](#references)</sup>

### Faida zake—na kile inachovujisha

- Mlengwa huona nodi ya kutoka ambayo huenda iko karibu kijiografia na inaonekana kuwa ya makazi.
- Nodi ya kutoka huona mlengwa na hop iliyotangulia, lakini si lazima imwone mwendeshaji.
- Huduma ya ufikiaji humwona mteja na ombi la njia. Mesh inayosimamiwa kivyake inaweza kumtenganisha mteja na nodi za kutoka, lakini huunda rekodi yenye nguvu ya mhusika mwingine.
- Milango inayojirudia, mpangilio wa handshake, mabango ya seva, vyeti, vipindi vya upatikanaji na uhusiano wa vidhibiti vinaweza kufichua kundi zima hata IP zinapobadilika.
- Router iliyoathiriwa mara nyingi haina telemetry ya endpoint, lakini ISP yake bado ina data ya mteja na mtiririko; kukamatwa kwake hufichua mabaki ya implant/configuration.

{% hint style="info" %}
Kwa zoezi lililoidhinishwa, tengeneza upya topolojia hii kwa kutumia VM au router zinazomilikiwa na shirika na uhifadhi ramani ya attribution ya kidhibiti. Usitumie proxy zilizo wazi au vifaa vya watu wengine. [Mwongozo wa maabara](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) hutengeneza muundo uleule wa hop unaoonekana kwa walinzi bila kumdhuru mpatanishi.
{% endhint %}

## Mitandao ya proxy za makazi na simu za mkononi

Huduma za proxy za makazi hugawa session kwa anwani za broadband za watumiaji; proxy za simu hutoka kupitia makundi ya NAT ya watoa huduma. Chanzo kinaweza kuwa vifaa vilivyojiandikisha waziwazi, SDK/proxyware iliyojumuishwa kwenye programu za watumiaji, wauzaji upya au malware. Vyanzo hivi si sawa: kutokuwepo kwa idhini yenye ufahamu hugeuza huduma ya faragha kuwa miundombinu iliyoathiriwa.

Mbinu za kubadilisha anwani huathiri ugunduzi:

- **per-request rotation** husababisha mabadiliko ya haraka ya IP na ASN/eneo huku utambulisho wa tabaka za juu ukibaki thabiti;
- **sticky sessions** hudumisha nodi ya kutoka kwa dakika au saa, na kufanana na mteja wa kawaida;
- **backconnect gateways** humwonyesha mteja endpoint moja ya broker huku zikichagua nodi za kutoka ndani ya mfumo;
- **mobile pools** huweka wateja wengi halisi nyuma ya anwani chache za carrier NAT, hivyo kuzuia IP kuna gharama kubwa.

Walinzi wanapaswa kuoanisha IP na session iliyothibitishwa, alama ya kidole ya TLS/client, mpangilio wa HTTP, cookie ya kifaa na tabia. Kuingia kunakodaiwa kuwa kwa eneo la karibu kupitia makazi, kisha kufuatiwa na eneo lingine la nchi huku vipengele vyote vya tabaka za juu vikibaki vilevile, ni ushahidi wenye nguvu zaidi kuliko sifa ya anwani pekee. Kinyume chake, kushiriki anwani na kubadilisha mtandao wa simu husababisha mabadiliko halali, kwa hiyo kamwe usichukulie uainishaji wa makazi/proxy kama hukumu.

### Control plane za proxyware na mwingiliano wa wauzaji upya

Usiichukulie pool ya makazi kama orodha bapa ya nodi za kutoka. Uchambuzi wa mfumo ikolojia wa IPIDEA ulifichua **control plane ya ngazi mbili inayoweza kutumika tena**: SDK iliyopachikwa huripoti kwanza metadata ya kifaa/usajili kwa domain ya Tier One na kupokea maelekezo ya upangaji pamoja na jozi za IP:port za Tier Two `connect`/`proxy`. Nodi huuliza mara kwa mara port ya Tier Two connect ili kupata kazi iliyosimbwa, hufungua muunganisho wa pili kwenye port ya proxy inayolingana, na kupeleka bytes zilizotolewa hadi kwenye lengwa lililoombwa. SDK na chapa za proxy zilizoonekana tofauti zilikuwa na domain tofauti za ugunduzi, lakini ziliungana kwenye miundombinu ya Tier Two iliyoshirikiwa na pool za nodi za kutoka zinazopishana kupitia umiliki wa pamoja na uhusiano wa wauzaji upya.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Hii huunda pivoti za hunting zinazodumu zaidi kuliko kuzuia IP ya makazi:<sup>[[13]](#references)</sup>

- mchakato usiotarajiwa wa utility, VPN, game au kifaa kilichopachikwa hutuma kitambulisho thabiti cha kifaa/ufunguo wa mteja na kupokea orodha ya seva inayobadilika;
- endpoint huuliza IP ya moja kwa moja kwenye port isiyo ya kawaida, kisha huunganisha kwenye port nyingine kwenye anwani hiyo hiyo mara moja kabla ya kufungua socket ya kwenda kwenye destination mpya;
- chapa kadhaa zinazoonekana kuwa tofauti hushiriki anwani za Tier Two, sarufi ya protocol, msimbo wa SDK au mwingiliano wa exit-node;
- programu tofauti zinazowasiliana na domain tofauti za Tier One hupokea anwani kutoka kwenye pool ileile ya Tier Two.

Mwingiliano huo pia hupunguza uwezo wa kuhusisha shughuli na mhusika: kuona IP kwenye pool iliyotangazwa na vendor mmoja hakuthibitishi ni reseller, mteja au threat actor gani aliyeitumia wakati husika. Hifadhi timestamp za mtiririko, mfuatano wa michakato, miili ya majibu ya Tier One na vitambulisho vya task za Tier Two.<sup>[[13]](#references)</sup> Katika zoezi lililoidhinishwa, iga daraja hili kwa kutumia tu endpoints zinazomilikiwa na shirika; usisajili kamwe vifaa vya watumiaji au proxyware ya wahusika wengine.

## Minyororo ya proxy za multi-hop

MITRE hutofautisha proxy za nje na **proxy za multi-hop (T1090.003)**. Sifa muhimu si idadi ya hop, bali ni mgawanyo wa taarifa na usimamizi.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Ikiwa mhusika mmoja anaendesha A na B, kumbukumbu za pamoja au muda wa mtiririko zinaweza kufichua mzunguko. Kuongeza VPN za kibiashara zinazofuatana kutoka endpoint/akaunti ileile kunaweza kuongeza ucheleweshaji huku kukiacha ushahidi wa utambulisho, malipo na muda wa pamoja. Tor hupunguza tatizo hili kwa kutumia relays zinazochaguliwa kwa kujitegemea na muundo wa pamoja wa mteja, lakini mtandao wa mwingiliano wa latency ya chini hauwezi kuahidi kustahimili mtazamaji anayepima ncha zote mbili.

Hitilafu za kawaida ni DNS au IPv6 bypass, programu kufungua sockets zake, trafiki ya usimamizi kufikia relays moja kwa moja, shughuli zilizosawazishwa, funguo za SSH zilizotumiwa tena, na kuingia katika akaunti zinazoweza kutambulisha mtumiaji. Uthibitishaji sahihi ni jaribio la hitilafu: simamisha kila relay kwa zamu na uthibitishe kuwa mzigo wa kazi hauwezi kutumia njia isiyosimbwa kwa njia fiche.

### Kuporomoka kwa tunnel na kuvuja kwa trafiki ya upstream

Mara nyingi, usanifu wa relay hutambulika zaidi unaposhindwa. Unit 42 iliandika njia ya ujasusi ya ngazi nyingi iliyotumia VPS zinazokabili waathiriwa, relay VPS, residential proxies, Tor na huduma nyingine za proxy; tunnel ilipoachwa au kuporomoka, miundombinu iliyofichwa ya upstream iliunganishwa moja kwa moja na mifumo ya relay na ile inayokabili waathiriwa. Uchunguzi huohuo pia ulitumia cheti cha X.509 kilichofichuliwa kwa muda kwenye miundombinu ya upstream kama njia ya pivot kati ya ngazi.<sup>[[14]](#references)</sup>

Tenganisha **data plane** (`victim <-> exit`) na **control plane** (`operator/upstream -> relay administration`). Hifadhi kumbukumbu za ingress na uthibitishaji katika kila ngazi unayomiliki, historia za vyeti na miunganisho mifupi iliyoshindwa—si vipindi vya C2 vilivyofaulu pekee. Chanzo kinachoonekana tu wakati relays hazifanyi kazi au kinachosimamia moja kwa moja node nyingi zinazokabili waathiriwa ni mgombea bora zaidi wa kuwa upstream kuliko exit ya kawaida, lakini ASN/eneo lake la kijiografia bado ni dhana, si uthibitisho wa utambulisho wa opereta.

Maabara iliyoidhinishwa inapaswa kufanya mzigo wa kazi ushindwe kwa usalama. Kwa mzigo wa kazi uliotengwa katika Linux network namespace, route ya kwanza lazima itumie tunnel; baada ya kuiondoa, ombi na ukaguzi wa route vyote lazima vishindwe badala ya kuchagua uplink halisi:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Rudia jaribio la DNS na IPv6, na katika kila mpaka wa relay. Ikiwa uchunguzi wowote utafanikiwa, rekodi interface/anwani halisi ya source kabla ya kurekebisha policy routing au firewall; uchunguzi huo ndio attribution leak ambayo mchunguzi angeiona.

## Tabaka za redirector na uundaji wa trafiki

**redirector** ya umma hupokea trafiki inayolingana na sarufi maalum ya operesheni na kuisambaza kwa team server iliyolindwa. Kila kitu kingine kinaweza kukataliwa au kupewa maudhui yasiyo na madhara.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Tabaka nyingi hupunguza uwezekano wa kufichuka: kuchoma domain ya umma si lazima kufichue team server. CDN huongeza uwezo wa anycast na domain ya nje yenye sifa nzuri, lakini akaunti ya CDN na edge logs huwa vidokezo vya attribution. TLS fingerprints, historia ya vyeti, paths za kipekee/mpangilio wa headers, ukubwa wa majibu, tabia ya redirects na allowlists za origin zinaweza kuunganisha fronts zinazodhaniwa kuwa hazihusiani.

Kwa detection, rekodi sehemu za reverse-proxy kabla ya normalization, linganisha SNI/Host/authority, kagua mchanganyiko adimu wa headers, unganisha response bodies na TLS fingerprints, na tafuta mwingiliano wa usanidi katika cloud/CDN audit logs. Kwa red teams zilizoidhinishwa, epuka kunakili chapa halisi au kuweka ukusanyaji wa credentials nyuma ya third party isiyohusika.

## Domain fronting and domainless fronting

Katika **domain fronting (T1090.004)** ya kawaida, muunganisho wa TLS hutangaza front domain inayoruhusiwa katika SNI, huku HTTP `Host` au HTTP/2 `:authority` iliyosimbwa ikiomba back-end domain tofauti. CDN inayoshirikiana huelekeza trafiki kwa kutumia thamani ya ndani. Mwangalizi wa mtandao asiyeweza kufungua usimbaji wa TLS huona front; CDN huona thamani zote mbili na origin. Katika aina za domainless, SNI inaweza kuwa tupu huku sehemu nyingine ya uelekezaji ikichagua lengwa.<sup>[[4]](#references)</sup>

Huu si uigaji wa kichawi: hufanya kazi tu ikiwa mpatanishi anaruhusu kutolingana huko kwa makusudi au kwa bahati, na anajua kuelekeza jina la ndani. Watoa huduma wakuu wamezuia fronting kati ya akaunti tofauti. Encrypted ClientHello (ECH) hubadilisha kile ambacho mwangalizi aliye kwenye njia anaweza kuona, lakini haifuti rekodi za CDN, endpoint au application.

Sehemu za detection ni pamoja na:

- nasaba ya michakato ya endpoint na destination isiyotarajiwa kwa application hiyo;
- kutolingana kwa SNI na HTTP authority pale ambapo ukaguzi wa TLS ni halali na unapatikana;
- CDN logs zinazoonyesha tenant/front moja ikielekeza kwenye authority/origin nyingine;
- sessions zisizo za kawaida za muda mrefu au za vipindi kwa huduma ambayo kwa kawaida hutumiwa kwa mawasiliano shirikishi;
- ukubwa na mpangilio wa muda thabiti wa encrypted flows katika front domains zinazobadilika.

Lab salama huiga kutolingana kwa uelekezaji kwenye reverse proxy inayomilikiwa; haitumii CDN ya umma vibaya.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution hutenganisha huduma ya kimantiki na miundombinu isiyobadilika:

- **DDNS:** client iliyothibitishwa husasisha jina thabiti baada ya anwani yake kubadilika.
- **DGA:** endpoint na controller zote hukokotoa majina ya domain yanayowezekana kutoka kwenye seed ya muda/ufunguo; operator husajili baadhi tu.
- **Fast flux:** jina hurudisha seti ya anwani za wahusika waliodukuliwa/proxy zinazobadilika haraka, mara nyingi zikiwa na TTL za chini.
- **Double flux:** anwani za huduma na za name server zenye mamlaka huzungushwa zote, na kuficha pia control layer.

Fast flux ni muundo wa usambazaji wa mzigo unaotumiwa kwa madhumuni hasidi, si “majibu mengi ya DNS” tu. Ushahidi thabiti zaidi huunganisha TTL ya chini, idadi kubwa ya anwani za kipekee, usambazaji mpana wa ASN/jiografia, muda mfupi wa uhai wa node, tabia ya application inayojirudia na historia ya usajili inayotia shaka. CDN zina sifa kadhaa kati ya hizi kwa matumizi halali. MITRE inapendekeza kuoanisha tabia ya DNS na mchakato pamoja na miunganisho inayofuata.<sup>[[5]](#references)</sup>

DGA inaweza kutambuliwa kupitia lexical entropy, miundo ya konsonanti/tarakimu, milipuko ya NXDOMAIN, domains zinazoonekana kwa mara ya kwanza kwa wakati mmoja na muktadha wa mchakato. Wordlist DGA na generative models hushinda sheria rahisi za entropy, hivyo clustering ya muda katika fleet nzima na lineage ya endpoint huwa muhimu zaidi.

## Compromised domains and domain shadowing

Actor anaweza kuteka akaunti ya registrar/DNS, kuchukua subdomain iliyoachwa bila mmiliki, au kuongeza records chini ya domain yenye sifa nzuri. **Domain shadowing** huhifadhi apex halali huku subdomains nyingi zinazodhibitiwa na mshambuliaji zikielekeza kwenye hosts zinazobadilika za delivery au C2. Hukopa umri na sifa nzuri, na inaweza kuepuka kuzuia domain nzima.<sup>[[6]](#references)</sup>

Watetezi wanahitaji registrar na authoritative-DNS audit logs, MFA, registry/registrar locks, arifa za delegations/API tokens/name servers mpya, ufuatiliaji wa certificate transparency, na orodha ya cloud resources zinazorejelewa na DNS. Chunguza resolution na historia ya cheti ya subdomain bila kutegemea sifa ya apex.

## Web services and dead-drop resolvers

**Dead-drop resolver (T1102.001)** huhifadhi pointer iliyosimbwa inayoelekeza kwenye C2 ya sasa ndani ya post, profile, document, repository, cloud object au sehemu ya blockchain halali. Malware hupakua object ya umma, hutoa domain/IP kutoka humo, kisha huwasiliana na hatua inayofuata. Aina za mawasiliano ya pande mbili hubadilishana commands au files kupitia service APIs.<sup>[[7]](#references)</sup>

Aina moja mahususi ya resolver ya GitHub hutumia Issues Search API tu pale ambapo authenticated repository channel inashindwa. Client hutafuta issues zinazolingana na tarehe ya sasa, repository na aina ya issue, hufuata URL ya comments ya kila issue, na kutoa ciphertext kati ya alama za `<!--` na `-->`. Baada ya decryption inayotegemea host na tarehe, sehemu kama `Owner`, `LicRepo` na `LicToken` hubadilisha owner, path na token za repository kuu. Hii humwezesha operator kuzungusha credentials na endpoints bila kubadilisha client; maoni ya issue ni resolver, huku files za repository zikiendelea kuwa channel ya tasking.<sup>[[15]](#references)</sup>

Hii huongeza uimara na kuficha back-end C2 dhidi ya uchanganuzi tuli wa binary. Pia huunda vitambulisho thabiti vya object, tenant, repository, API na mifumo ya ufikiaji. Watetezi wanapaswa kuoanisha:

1. mchakato uliowasiliana na huduma;
2. API path/object halisi na response hash;
3. shughuli za decoding au string-processing;
4. muunganisho mpya wa kutoka nje muda mfupi baadaye; na
5. tabia ileile mahali pengine kwenye fleet.

Kuzuia GitHub, cloud storage au social media yote kwa kawaida hakutekelezeki. Sera ya egress inayotambua huduma na ulinganishaji katika kiwango cha mchakato hufanya kazi vizuri zaidi kuliko kuzuia domain pekee.

## Personas, accounts and procurement compartments

Kutokujulikana kwa miundombinu hushindwa pale persona, recovery email, simu, malipo, browser au admin IP inapounganisha compartments. Operesheni zinazohusishwa na serikali zimeunda social profiles, email identities na cloud accounts muda mrefu kabla ya kuzitumia; ATT&CK huorodhesha hili kama Establish Accounts (T1585), ikijumuisha sub-techniques za social, email na cloud.<sup>[[8]](#references)</sup>

Defender au mpelelezi huunda graph kutokana na:

- muda wa kuundwa na wa kuingia kwa mara ya kwanza, locale, time zone na ratiba ya kazi;
- recovery fields, vifaa vya MFA, nyaraka za utambulisho na njia za malipo;
- browser/TLS fingerprints na historia ya source network;
- matumizi tena ya avatar, asili ya picha, mtindo wa uandishi na ukuaji wa social graph;
- domain registrant, name server, cheti, analytics ID au repository commit zinazoshirikiwa;
- vitendo vya management plane vinavyopita usanifu wa public relay.

Kwa red team iliyoidhinishwa, synthetic personas zinapaswa kurekodiwa kwa exercise controller, zitumie recovery/payment channels zinazomilikiwa na shirika, ziepuke kujifanya watu halisi wasiohusika, na ziwe na mpango wa kuziondoa. SOC inaweza isiwe na taarifa; lakini operesheni lazima iwajibike.

## Emerging compound patterns to threat-model

Yafuatayo ni **miunganiko inayoundwa kwa mtazamo wa watetezi**, si madai kwamba actor aliyetajwa ametumia kila muundo huu mahususi. Huunganisha primitives ambazo tayari zimeonekana, na zinafaa kama dhana za purple-team.

### Asymmetric one-way tasking

Commands hupitia chanzo cha umma, broadcast au append-only, huku matokeo yakitoka kupitia channel isiyohusiana baada ya kuchelewa. Mifano ya primitives ni one-way communication ya web service na dead drops. Kutenganisha channels huzuia flow moja kuonekana kuwa ya pande mbili na hutatiza ulinganishaji rahisi wa request/response.<sup>[[9]](#references)</sup>

**Detection:** hifadhi rekodi za usomaji wa object, kisha linganisha mabadiliko ya hali ya mchakato na uhamishaji wa baadaye wa kutoka nje katika dirisha pana zaidi la muda. Tafuta mchakato adimu unaosoma object ileile ya umma hata kama hakuna jibu la papo hapo.

### Multi-stage channel promotion

Hatua ya kwanza tulivu hufanya inventory na kuendeleza mifumo iliyochaguliwa tu hadi channel isiyohusiana ya hatua ya pili. Endpoint, protocol na mchakato wa pili huenda usishiriki miundombinu yoyote na wa kwanza. Hii hupunguza kufichuka kwa miundombinu yenye uwezo mkubwa na imeigwa waziwazi kama ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** oanisha `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; usifunge tukio baada ya kuzuia domain ya kwanza.

### Cross-protocol relay translation

Hops tofauti hutafsiri HTTPS, QUIC, WebSocket, DNS, SSH au message-queue API badala ya kusambaza packets moja kwa moja. Tafsiri huondoa TLS fingerprint moja ya mwisho-hadi-mwisho, lakini huunda gateways zenye muda, buffering na ubadilishaji wa maana wa kipekee. Protocol tunneling (T1572) inaweza kuunganishwa na proxies na uigaji wa huduma.<sup>[[11]](#references)</sup>

**Detection:** tafuta gateway hosts zinazopokea protocol moja na kuanzisha nyingine huku tabia ya bytes/muda ikiwa na uhusiano wa karibu; linganisha nia ya endpoint na protocol inayobebwa.

### Passive activation on edge devices

Badala ya kutuma beacon, implant hufuatilia trafiki ambayo tayari inafika kwenye router/VPN na huwashwa tu na magic value, muundo wa source-port au token iliyothibitishwa. Trafiki ya kawaida huendelea kwenda kwenye huduma halisi. ATT&CK huliita hili Traffic Signaling (T1205), ikiwa na mifano iliyorekodiwa ya vifaa vya mtandao na APT.<sup>[[12]](#references)</sup>

**Detection:** uadilifu wa firmware/files, raw packet capture wakati wa hunt iliyoidhinishwa, socket filters zisizotarajiwa na tabia tofauti ya huduma. Kutokuwepo kwa beacon ya vipindi hakuthibitishi kuwa edge device ni safi.

### Serverless and ephemeral origin rotation

Front hudumisha utambulisho wa kimantiki thabiti huku functions/containers za muda mfupi zikishughulikia hatua moja moja katika regions/accounts kadhaa. Hii hupunguza muda wa kuwepo kwa data kwenye disk na IPs zisizobadilika za origin, lakini uundaji wa control plane, image/layer, role, secret, request ID na telemetry ya billing huwa graph ya kudumu.

**Detection:** hifadhi cloud audit na invocation logs nje ya workload; unganisha deployment templates, roles, environment keys na uhusiano wa front-to-origin.

### Privacy-layer diversity

Operesheni inaweza kuepuka kwa makusudi kutumia chain moja inayofanana kila mahali: kwa mfano, channel moja hutumia relay iliyokodishwa, tasking hutumia public object, exit hutoka kwenye cellular link ya lab inayomilikiwa, na usimamizi hutumia network tofauti ya shirika. Hii hupunguza manufaa ya kuathiri provider mmoja lakini huongeza hatari ya kuunganisha muda kati ya tabaka na makosa ya kiutendaji.

**Detection:** tengeneza timelines za kampeni kwa kutumia vitambuzi vya identity, DNS, SaaS, network na cloud. Tafuta mabadiliko ya hali yanayotokea kwa wakati mmoja badala ya indicators zinazofanana.

### Decentralized or transparency-log dead drops

Actor anaweza kuweka pointer ndogo iliyosimbwa katika mfumo wowote wa umma unaodumu na append-only, content-addressed store au feed inayofanana na transparency log. Object ya umma ni imara, lakini index/content hash yake halisi na tabia ya client ya kuikagua mara kwa mara huwa vitambulisho thabiti.

**Detection:** rekodi object identifiers kamili za API na response hashes; toa arifa kuhusu michakato isiyo ya kawaida inayokagua objects zisizobadilika, ikifuatiwa na decoding au miunganisho mipya.

### Delayed store-and-forward operations

C2 shirikishi huunda ulinganifu mkubwa wa muda. Muundo wa store-and-forward hukusanya encrypted jobs na kurudisha matokeo dakika au saa kadhaa baadaye kupitia queue tofauti au uhamisho wa kimwili. Hupoteza kasi ya majibu ili kupunguza ulinganifu wa muda wa mwisho-hadi-mwisho.

**Detection:** ongeza muda wa madirisha ya ulinganishaji, tengeneza modeli ya ufikiaji wa queue wa vipindi na kagua staging ya endpoint. Kukusanya pamoja huhamisha ishara kutoka kwenye muda wa packets hadi kwenye tabia iliyopangwa ya process/file; hakuifuti.

## Design review: think in observers

Kwa kila njia, jaza jedwali hili kabla ya deployment na baada ya ukusanyaji:

| Tabaka | Huona chanzo? | Huona lengwa? | Huona maudhui? | Vitambulisho thabiti | Mmiliki wa retention/kisheria |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Ikiwa provider mmoja wa kawaida anaweza kujaza safu wima zote, usanifu huo huficha shughuli kwa target lakini hautoi utenganisho thabiti. Ikiwa hakuna controller wa ndani anayeweza kuhusisha shughuli na zoezi husika, haufai kwa red teaming ya kitaalamu.

## References

- [1] [MITRE ATT&CK — Kupata Miundombinu (T1583), Kuhatarisha Miundombinu (T1584), na Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Wahusika wa ujasusi wanaohusishwa na China hutumia mitandao ya ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Kuhatarisha Miundombinu: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Kuunda Akaunti (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: Mawasiliano ya Njia Moja (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Kuvuruga Mtandao Mkubwa Zaidi wa Residential Proxy Duniani](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Kampeni za Kivuli: Kufichua Ujasusi wa Kimataifa](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Kampeni ya Blinder Tunnel Yalenga Miundombinu ya Iraq](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
