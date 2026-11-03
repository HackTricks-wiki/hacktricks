# Faragha ya Mtandao na Muunganisho Usiojulikana

{{#include ../banners/hacktricks-training.md}}

Faragha ya mtandao ni uamuzi wa njia ya trafiki, si utambulisho kamili. Chagua njia kwa kujiuliza ni nani hapaswi kuweza kuunganisha **chanzo**, **lengwa**, **maudhui**, na **muda**.

Kwa orodha sanifu—`Pros`, `Cons`, `Procedure` ya hatua kwa hatua, na `Detection` kwa kila familia ya njia ya ufikiaji—anza na [Katalogi ya Mbinu za Ufikiaji wa Mtandao Bila Kujulikana](anonymous-internet-access-techniques.md). Ukurasa huu unaeleza kwa undani zaidi chaguo za kawaida zinazoweza kutumika.

## Kile ambacho kila mwangalizi anaweza kuona kwa kawaida

| Njia | Mtandao wa ndani / ISP | Mpatanishi | Lengwa | Kizuizi kikuu | Kasi ya kadirio |
|---|---|---|---|---|---|
| HTTPS ya moja kwa moja | Chanzo, metadata ya lengwa, muda/ujazo | Mtoa huduma wa hosting/CDN huona muunganisho | IP ya chanzo, data ya kivinjari/programu | Hakuna faragha ya IP ya chanzo | Ya kasi zaidi |
| VPN ya kibiashara | Chanzo kimeunganishwa na VPN; kwa kawaida si metadata ya lengwa | VPN huona chanzo na metadata ya lengwa | IP ya kutoka ya VPN | Mtoa huduma mmoja huwa sehemu ya kulinganisha miunganisho | Kwa kawaida ya kasi |
| VPN/VPS inayojisimamiwa | Chanzo kimeunganishwa na VPS | Rekodi za hosti/akaunti/malipo/control plane | IP ya kutoka ya VPS | Ni rahisi kuhusisha na seva/akaunti iliyokodishwa | Kwa kawaida ya kasi |
| Tor Browser | Chanzo kimeunganishwa na Tor/bridge; muda/ujazo | Relay huona tu sehemu ndogo | Tor exit, data ya kivinjari | Polepole zaidi; hatari za akaunti/endpoint/kulinganisha | Ya wastani/polepole |
| Tails/Whonix | Njia ya Tor inayofanana, yenye mipaka imara zaidi ya uelekezaji | Vizuizi vilevile vya Tor | Tor exit/data ya programu | Makosa ya kiutendaji na hosti/vifaa bado ni hatari | Ya wastani/polepole |
| Wi-Fi ya wageni ya umma + HTTPS | Eneo huona kifaa cha ndani/muda na malengo | ISP ya eneo huona metadata | IP ya umma ya mgeni | Ulinganishaji wa eneo halisi/ukurasa wa captive portal/kifaa | Ya kasi/inayotofautiana |
| Hotspot ya simu | Mtoa huduma huona mteja/kifaa/mahali na malengo | VPN/Tor ikitumika | IP ya kutoka ya mtoa huduma, VPN au Tor | Usajili wa simu na mahali ni vitambulisho vinavyodumu | Ya kasi/inayotofautiana |
| Mixnet | Ufikiaji huona matumizi ya mixnet; muda/ujazo | Nodi nyingi za kuchanganya | Gateway/egress | Mfumo ikolojia unaochipuka; gharama ya muda wa kusubiri na kipimo data | Polepole zaidi |

HTTPS hulinda maudhui yanaposafirishwa lakini si metadata yote. EFF inabainisha kuwa domain, muda na ukubwa wa trafiki vinaweza kubaki vinaonekana kwa wapatanishi hata wakati njia za kurasa, vitambulisho na ujumbe vimesimbwa kwa njia fiche.<sup>[[1]](#references)</sup>

Overlay iliyosimbwa kwa njia fiche si mtandao wa kutokujulikana moja kwa moja: peers za moja kwa moja za Yggdrasil zinaweza kuona anwani za IP za wenzao.<sup>[[20]](#references)</sup> [Usambazaji wa userspace na usafirishaji wa SOCKS](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) ni chaguo la tunneling, si safu ya kuficha chanzo.<sup>[[20]](#references)[[21]](#references)</sup>

## VPN: faragha ya haraka yenye uaminifu uliokolezwa

VPN husaidia kuficha metadata ya lengwa kutoka kwa ISP ya ufikiaji, kulinda hop ya kwanza kwenye mtandao usioaminika, kutoa anwani thabiti ya egress kwa kazi, au kufikia mtandao wa faragha. **Haifanyi mtumiaji asijulikane.** VPN huona muunganisho wa chanzo na inaweza kuona metadata ya lengwa; akaunti, cookies, GPS, fingerprint na taarifa za malipo hubaki.<sup>[[1]](#references)</sup>

### Orodha ya kutathmini mtoa huduma

1. **Umiliki na mamlaka ya kisheria:** tambua huluki ya kisheria, kampuni mama, nchi za uendeshaji, wakandarasi wadogo wa miundombinu na taratibu za kisheria zinazotumika.
2. **Data inayokusanywa:** tofautisha data ya akaunti/malipo, IP ya chanzo, mihuri ya muda ya muunganisho, kipimo data, telemetry ya hitilafu, maswali ya DNS na rekodi za malengo. “Hakuna rekodi za kuvinjari” haimaanishi “hakuna data.”
3. **Uhifadhi na ufutaji:** tafuta muda kamili wa kuhifadhi data na kama nakala rudufu, mifumo ya kuzuia ulaghai na wachakataji hufuata ratiba hiyo hiyo.
4. **Ushahidi:** pendelea ukaguzi wa umma unaoeleza upeo, tarehe, matokeo na marekebisho; clients zilizo wazi zinazoweza kujengwa tena; ripoti za uwazi; na matukio yaliyoandikwa.
5. **Itifaki na client:** WireGuard, OpenVPN au itifaki nyingine inayotunzwa na kukaguliwa; masasisho ya kiotomatiki; ushughulikiaji wa DNS na IPv6; kill switch; na majaribio ya leak kwa kila jukwaa.
6. **Muundo wa biashara:** elewa jinsi huduma ya bure au inayofadhiliwa inavyolipiwa. Kuwepo kwenye app store pekee si ushahidi wa uendeshaji unaoaminika.
7. **Ufaafu wa malipo:** njia mbadala ya malipo inaweza kupunguza taarifa za malipo zinazofichuliwa kwa VPN lakini haifuti IP ya chanzo inayoonekana kila muunganisho unapofanyika.

### Sanidi na uthibitishe VPN

1. Sakinisha client iliyosainiwa ya mtoa huduma/shirika kutoka chanzo chake rasmi.
2. Chagua **full tunnel** isipokuwa kuna route iliyoandikwa ambayo lazima ipite nje yake. Split tunneling huunda njia za kulinganisha miunganisho na leak.
3. Washa tabia ya fail-closed/always-on na uzuie trafiki wakati wa kuunganisha tena.
4. Elekeza DNS kupitia tunnel na ujaribu IPv4 na IPv6 zote mbili. Zima itifaki ikiwa tu haiwezi kupitishwa kwa usalama kupitia tunnel na umekubali kupoteza utendaji wake.
5. Jaribu kulala/kuamka, kubadili mtandao, kuingia kwenye captive portal, kuanguka kwa tunnel na kushiriki intaneti kupitia hotspot. NCSC inaonya kuwa clients zilizounganishwa kupitia tethering zinaweza kupita VPN ya simu kwenye baadhi ya majukwaa.<sup>[[2]](#references)</sup>
6. Tumia endpoint ya majaribio inayodhibitiwa na shirika kurekodi IPv4, IPv6, DNS resolver na muda wa muunganisho unaoonekana. Usifichue kazi nyeti kwa tovuti za nasibu za “leak test”.
7. Jaribu tena baada ya mabadiliko ya client, OS, mtandao au sera.

### Njia za kukwepa uelekezaji kwenye LAN hasimu

VPN inaweza kuonekana kuwa “imeunganishwa” huku baadhi ya pakiti zikipita nje yake kwa sababu mfumo wa uendeshaji huchagua route **kabla** VPN haijasimba pakiti. TunnelCrack ilionyesha njia mbili za kutumia vibaya misamaha ya kawaida ya uelekezaji: **LocalNet** hufanya lengwa la intaneti lionekane kuwa kwenye subnet iliyounganishwa moja kwa moja, huku **ServerIP** ikighushi utatuzi wa gateway ya VPN ili anwani lengwa irithi msamaha wa mtandao usiosimbwa unaohitajika na usafirishaji wa VPN. Haya ni mapungufu ya client/uelekezaji, si uvunjaji wa WireGuard, OpenVPN, IPsec au TLS; payload za HTTPS hubaki zimesimbwa kutoka mwisho hadi mwisho, lakini mwangalizi wa ndani anaweza kupata metadata ya lengwa/muda na data yoyote ya itifaki iliyo wazi.<sup>[[18]](#references)</sup>

TunnelVision hutumia primitive hiyo hiyo ya kabla ya usimbaji kupitia DHCP option 121. Seva hasimu au iliyoathiriwa ya DHCP inaweza kusakinisha route isiyo na class ambayo ni mahususi zaidi kuliko route ya VPN inayojumuisha yote, na hivyo kuchagua kiolesura halisi kwa hosti au masafa yoyote. Chaneli ya udhibiti wa VPN inaweza kubaki hai, kwa hiyo kill switch inayowashwa tu tunnel inapokatika inaweza kutofanya kazi, na ukaguzi mmoja wa umma wa “IP leak” unaweza kukosa bypass za kuchagua.<sup>[[19]](#references)</sup>

Kill switch ya packet-filter inayoruhusu DHCP na usafirishaji wa VPN uliothibitishwa pekee kwenye kiolesura halisi inapaswa kusababisha fail-closed, lakini uingizaji lengwa wa route bado unaweza kuunda side channel ya kunyima huduma kwa kuchagua. Kwa workload za Linux zenye matokeo makubwa, pendelea [muundo imara zaidi wa network-namespace unaotekeleza route](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), ambapo namespace ya programu haina kiolesura halisi wala default route ya mtandao usiosimbwa.<sup>[[19]](#references)</sup>

#### Uthibitishaji kwenye maabara inayomilikiwa

Jaribu client/OS/toleo husika hasa kwenye AP, seva ya DHCP, endpoint ya VPN na lengwa unalomiliki; madai yanayohusu bidhaa nzima hupitwa na wakati haraka kwa sababu utekelezaji wa uelekezaji na packet-filter hutofautiana kulingana na jukwaa. Nasa trafiki kwenye endpoint yenyewe na pia kwenye seva ya majaribio—tovuti inayoonyesha egress-IP pekee haithibitishi kuwa kila lengwa hufuata tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Unganisha VPN, rekodi anwani ya seva ya VPN, na uhifadhi kila jedwali la uelekezaji la IPv4/IPv6 na kanuni ya policy-routing. Kwenye Windows tumia `route print`; kwenye macOS tumia `netstat -rn`; kwenye Linux tumia amri zilizo hapa chini.
2. Uliza route iliyochaguliwa kwa IP kadhaa za malengo unayomiliki. Hop/kiolesura kinachofuata lazima kiwe tunnel, isipokuwa endpoint ya usafirishaji wa VPN iliyoandikwa.
3. Kwa TunnelVision, fanya upya lease kwenye mtandao unaodhibitiwa wa DHCP na usakinishe route ya option 121 **kwa lengwa moja tu la majaribio unalomiliki**. Jaribio limefaulu ikiwa trafiki bado inapitia tunnel au imezuiwa—haitoki kamwe kama trafiki ya lengwa kwenye kiolesura halisi.
4. Kwa LocalNet, weka subnet ya majaribio ya nyaraka za umma inayotumika maabara pekee, kama `203.0.113.0/24`, kwa client na uweke lengwa la majaribio unalomiliki ndani yake. Thibitisha kuwa kuwasha ufikiaji wa LAN hakufanyi malengo ya aina ya intaneti yapite nje ya tunnel.
5. Kwa ServerIP, kabla ya kuunganisha VPN, elekeza DNS inayodhibitiwa itatue hostname ya VPN unayomiliki kuwa lengwa la majaribio unalomiliki, huku gateway ya maabara ikielekeza usafirishaji wa VPN kwenye endpoint halisi ya VPN unayomiliki. Client haipaswi kuondoa ulinzi wa trafiki isiyohusiana ya programu inayoelekezwa kwenye anwani iliyoghushiwa.
6. Rudia jaribio ukiwasha na kuzima “local network access”, baada ya kuunganisha tena, kulala/kuamka, kubadili mtandao na kuanguka kwa mchakato wa VPN. Jaribu IPv4, IPv6 na DNS kila moja kivyake.
7. Kagua capture ya kiolesura halisi. Inapaswa kuwa na DHCP na pakiti zilizosimbwa kwa seva ya VPN, si pakiti zinazoelekezwa moja kwa moja kwa lengwa la majaribio unalomiliki. Pia thibitisha kuwa bypass iliyokataliwa haiwezi kurejea kimyakimya baada ya maombi ya mtumiaji au kurekebisha muunganisho.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: kutounganishwa kwa shughuli za wavuti kwa nguvu zaidi

Tor huunda mzunguko kupitia relays nyingi ili kwa kawaida relay moja isiweze kujua chanzo na lengwa vyote viwili. Lengwa huona Tor exit badala ya IP ya mtumiaji; mtandao wa karibu kwa kawaida huona muunganisho wa Tor.<sup>[[3]](#references)</sup> Tor imeundwa kwa programu za TCP zenye latency ndogo, kwa hiyo huwa polepole zaidi na haiwezi kuhakikisha ulinzi dhidi ya mshambulizi anayeweza kulinganisha ncha zote mbili.<sup>[[4]](#references)</sup>

### Mtiririko salama wa kazi wa Tor Browser

1. Pakua Tor Browser kutoka Tor Project au kioo rasmi pekee, na uthibitishe saini inapowezekana.
2. Tumia **Tor Browser**, si kivinjari cha kawaida kilichoelekezwa kwenye port ya Tor SOCKS. Vivinjari vya kawaida vinaweza kuvuja DNS/WebRTC na hali inayoweza kukutambulisha.<sup>[[5]](#references)</sup>
3. Dumisha ukubwa, fonti, viendelezi na mipangilio ya faragha ya chaguomsingi. Viongezi vya ziada vinaweza kufanya kivinjari kiwe cha kipekee zaidi.<sup>[[6]](#references)</sup>
4. Chagua kiwango cha usalama **Safer** au **Safest** ikiwa unaweza kukubali hitilafu zaidi.
5. Tumia bridge pale Tor ya moja kwa moja inapozuiwa au IP za relay za kawaida zitakapoonyesha shughuli nyingi mno kwa mtandao wa karibu. Bridges hupunguza utambuzi rahisi; haziondoi uchanganuzi wa trafiki.<sup>[[7]](#references)</sup>
6. Usiingie kwenye akaunti inayokutambulisha, usitoe taarifa zinazokutambulisha, wala kufungua hati amilifu zilizopakuliwa kwenye programu ya nje iliyo kwenye mtandao.
7. Tumia kipindi/muktadha tofauti kwa kila utambulisho. “New circuit” si sawa na kufuta utambulisho wa kivinjari/programu; tumia **New Identity** au uwashe upya mazingira yaliyotengwa inapofaa.
8. Pendelea HTTPS iliyothibitishwa au huduma ya onion iliyothibitishwa. Tor exit inaweza kuona trafiki ya HTTP isiyosimbwa kwa njia fiche.

### Tor pamoja na VPN

Kuzichanganya si salama zaidi moja kwa moja. VPN kabla ya Tor inaweza kuficha miunganisho ya moja kwa moja ya Tor relay kutoka kwa ISP huku VPN ikiona chanzo; Tor kabla ya VPN huipa VPN mwonekano thabiti wa shughuli za baada ya Tor na huenda ikapunguza kundi la kutokutambulika. Mipangilio isiyo sahihi inaweza kusababisha leaks. Tor Project inapendekeza michanganyiko hiyo kwa miundo ya vitisho iliyo wazi na kwa watumiaji wa hali ya juu pekee.<sup>[[8]](#references)</sup>

## Wi-Fi ya umma na ya wageni

HTTPS ya kisasa humaanisha kwamba majirani wanaofuatilia tu kwa kawaida hawawezi kusoma maudhui ya wavuti yaliyosimbwa kwa njia fiche ipasavyo, lakini Wi-Fi ya wageni si kutokujulikana. Eneo linaweza kurekodi nyakati za kuunganishwa, vitambulishi vya kifaa, data ya captive portal, maeneo lengwa na maelezo ya DHCP; kamera, manunuzi, usafiri na uangalizi wa moja kwa moja vinaweza kumtambua mtumiaji. Hotspot bandia yenye jina linalofanana inaweza pia kunasa vitambulisho vya portal au kubadilisha trafiki isiyosimbwa kwa njia fiche.<sup>[[9]](#references)</sup>

### Mtiririko wa kazi halali wa mtandao wa wageni

1. Tumia mtandao unaotolewa kwa wageni pekee, au mtandao ambao mmiliki amekupa ruhusa ya wazi kuutumia. Waulize wafanyakazi SSID kamili na utaratibu wa portal.
2. Sasisha endpoint na travel router kabla ya kufika. Zima kushiriki faili/printa, ugunduzi unaoingia, kujiunga kiotomatiki na uchunguzi wa mitandao iliyokumbukwa.
3. Washa anwani ya Wi-Fi ya faragha/ya kubahatishwa ya OS. Mifumo ya sasa ya Apple inaweza kutumia anwani zinazobadilika kwenye mitandao iliyo wazi/dhaifu; ubahatishaji wa Android za kisasa kwa kawaida hudumu kwa kila SSID. Hili hupunguza kitambulishi kimoja tu cha karibu.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Pendelea travel router inayodhibitiwa na shirika au kifaa cha bridge kisichoaminika sana kati ya workstation yenye ruhusa za juu na mtandao wa wageni. Hii huweka pamoja sera za firewall/VPN lakini haifichi router kutoka kwa eneo.<sup>[[12]](#references)</sup>
5. Kamilisha captive portal kupitia kifaa/kivinjari maalum kisichoaminika sana pekee. Usiweke kamwe vitambulisho vya kibinafsi au vilivyotumika tena katika muktadha unaodhaniwa kuwa haukutambulishi. Funga kivinjari cha portal baada ya muunganisho kuanzishwa.
6. Anzisha VPN ya full-tunnel au Tor kabla ya shughuli nyeti na uthibitishe tabia ya fail-closed.
7. Sahau mtandao baada ya kuutumia na kagua sera ya akaunti ya portal/uhifadhi wa data.

{% hint style="danger" %}
Kuvunja Wi-Fi ya jirani, kukwepa portal, kutumia vitambulisho vya wageni vilivyovuja, kunakili ufikiaji wa mgeni mwingine, au kuficha Raspberry Pi kwenye mkahawa ni shughuli zisizoidhinishwa—si mbinu za faragha. Njia salama zinazolingana ni mtandao halali wa wageni, tovuti iliyoidhinishwa na mteja, au drop node iliyoandikwa na kuwekwa na kurejeshwa kwa idhini ya maandishi ya mmiliki wa mali.
{% endhint %}

## Travel routers

Travel router inaweza kutenga workstation dhidi ya matangazo ya ndani yenye uhasama, kutekeleza firewall, kutoa SSID ya ndani inayobaki thabiti na kuunganisha VPN upya kiotomatiki. **Haikufanyi usitambulike**: mtandao wa juu huona utambulisho wake wa redio na muda wa trafiki, na mtoa huduma wa VPN huona chanzo cha tunnel.

- Tumia firmware inayoungwa mkono ya OpenWrt/vendor na uondoe huduma zisizotumika.
- Simamia kupitia Ethernet au SSID maalum ya usimamizi yenye nenosiri la kipekee.
- Zima usimamizi kupitia upande wa WAN, UPnP, WPS, kushiriki faili na trafiki inayoingia ambayo haijaombwa.
- Tumia MAC ya WAN ya faragha/iliyobahatishwa pale tu inapoungwa mkono na kuruhusiwa.
- Tekeleza sera ya VPN kwenye router, ikijumuisha DNS na IPv6, na zuia trafiki ya nje tunnel inaposhindwa.
- Usidhani hotspot ya simu hupitisha vifaa vilivyounganishwa kupitia VPN ya simu; jaribu.

## Cellular, SIM na eSIM

Cellular ni rahisi kutumia lakini haikufanyi usitambulike. Waendeshaji huhifadhi vitambulishi vya mteja/kifaa na eneo linalotokana na kuunganishwa kwenye mtandao; eSIM bado ni usajili wa simu. Kulipia kabla hakumaanishi kwa uhakika kuwa usajili hauhitajiki—masharti hutofautiana kulingana na nchi na hubadilika.<sup>[[13]](#references)</sup>

Kwa upande wa uendeshaji:

- Tumia kifaa tofauti kinachoungwa mkono ili kupunguza kufichuliwa kwa data ya kibinafsi, si kuunda mteja wa kubuni.
- Usibebe kifaa “tofauti” kila wakati pamoja na simu ya kibinafsi ikiwa kuonekana pamoja kwa vifaa hivyo ni sehemu ya muundo wa vitisho.
- Zima cellular, Wi-Fi, Bluetooth na ufikiaji wa eneo usiotumika; kuzima kifaa ni kizuizi kikubwa zaidi cha redio kuliko vitufe vya UI.
- Pitisha trafiki nyeti ndani ya njia ya VPN/Tor iliyoidhinishwa, huku ukitambua kwamba mtoa huduma wa simu bado anajua usajili/eneo la kifaa na ncha ya tunnel.
- Thibitisha kanuni za sasa za usajili na uhifadhi kwa mdhibiti wa kitaifa au mshauri wa eneo husika; usitegemee orodha za mtandaoni za “nchi zenye SIM zisizotambulika.”

## Metadata ya DNS na TLS

- **DoH/DoT/DoQ** husimba DNS kwa njia fiche kati ya mteja na resolver, hivyo kuzuia usomaji au urekebishaji rahisi wa ndani, lakini resolver bado huona maswali na vitambulishi vya usafirishaji. Huhamisha uaminifu; havikufanyi usitambulike.<sup>[[14]](#references)</sup>
- **ODoH** huongeza proxy ili resolver isihitaji kujua IP ya mteja, ikidhaniwa kuwa proxy na target hazishirikiani. Uchanganuzi wa trafiki haujajumuishwa waziwazi.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** inaweza kulinda jina la ndani la seva katika TLS handshake wakati mteja, DNS na seva vinapoiunga mkono. IP lengwa, muda, kiasi cha trafiki na endpoint bado huonekana.<sup>[[16]](#references)</sup>
- Katika mazingira ya VPN au Tor yaliyosanidiwa ipasavyo, DNS inapaswa kufuata njia inayoungwa mkono na mazingira hayo. Kuongeza resolver tofauti kunaweza kuunda mtazamaji mpya au alama ya utambulisho.

### Mtiririko wa uthibitishaji wa DNS iliyosimbwa kwa njia fiche/ECH

1. Amua kama DNS inadhibitiwa na mazingira ya VPN/Tor, OS au programu. Isanidi kwenye tabaka **moja** linalokusudiwa badala ya kuweka resolvers zisizohusiana juu kwa juu.
2. Chagua resolver kulingana na sera yake iliyochapishwa ya faragha/uhifadhi na uwashe hali fiche kali pale mfumo unapoiunga mkono. Kurudi nyuma kwa hiari kunaweza kurudisha DNS kwenye maandishi wazi bila taarifa.
3. Tuma ombi kwa subdomain ya kipekee chini ya eneo la majaribio la authoritative unalodhibiti; thibitisha kwamba logi ya authoritative inaona recursive resolver iliyokusudiwa.
4. Nasa trafiki ya kifaa cha majaribio pekee na kwa idhini. Thibitisha kuwa mtandao wa ufikiaji hauwezi kusoma DNS iliyo kwenye maandishi wazi, huku ukitambua kwamba unaweza kuona ncha ya resolver/tunnel iliyosimbwa kwa njia fiche.
5. Jaribu resolver iliyosimbwa kwa njia fiche iliyozuiwa/isiyofikika. Hali ya kufaulu ni tabia iliyochaguliwa ya fail-closed au kurudi nyuma iliyorekodiwa—si ombi la wazi lililotokea kwa bahati mbaya.
6. Kwa ECH, tumia host inayodhibitiwa na inayowezesha ECH na kagua uchunguzi wa mteja/seva ili kuthibitisha kwamba **inner** ClientHello ilikubaliwa. Kutoa tu rekodi ya HTTPS hakuthibitishi kuwa ECH ilifaulu.
7. Rudia baada ya mabadiliko ya mtandao, captive portals, masasisho ya kivinjari na kuunganishwa upya kwa VPN. Rekodi ni kipengele gani kinachodhibiti DNS/ECH ili wasimamizi wa baadaye wasitengeneze njia ya kukwepa.

## Mixnets

Mixnets kama Nym au Katzenpost huongeza pakiti za ukubwa usiobadilika, ucheleweshaji, kupanga upya na trafiki ya kuficha ili kupinga ulinganishaji wa muda. Sifa hizo hugharimu latency na bandwidth, na ushahidi huru wa matumizi kwa kiwango kikubwa ni mdogo. Chukulia mixnets za sasa za watumiaji kama **chaguo zinazoibuka/zenye latency kubwa**, si mbadala za Tor/VPN zilizo za haraka au za uhakika.<sup>[[17]](#references)</sup>

### Mtiririko wa tathmini

1. Tambua mteja anayodumishwa na programu mahususi inayoungwa mkono; usilazimishe trafiki ya kivinjari/mfumo isiyoainishwa kupitia proxy isiyo na nyaraka.
2. Soma muundo wa sasa wa vitisho kuhusu entry, mix nodes, gateway, lengwa na dhana za ushirikiano.
3. Sakinisha kutoka chanzo rasmi chenye saini katika sehemu tofauti ya majaribio na utumie endpoint yako mwenyewe isiyo na madhara pekee.
4. Pima latency ya uwasilishaji, vikomo vya ukubwa wa ujumbe, kutegemewa, kutuma tena na kinachotokea gateway isipatikane.
5. Kagua trafiki ya ndani na endpoint yako mwenyewe ili kuthibitisha njia na chanzo kilichokusudiwa. Angalia kama majibu yanatumia muundo huo huo wa faragha.
6. Jaribu kuzima/hitilafu: programu haipaswi kurudi kimyakimya kwenye ufikiaji wa moja kwa moja wa Internet.
7. Usizime trafiki ya kuficha, kupunguza ucheleweshaji au kuchagua njia zisizo za kawaida zisizobadilika kwa ajili ya kasi tu; mabadiliko haya yanaweza kubatilisha muundo uliotajwa wa kutokutambulika.
8. Iweke katika hali ya majaribio hadi matumizi mahususi, uchanganuzi huru na kutegemewa kwa uendeshaji vifikie kiwango kinachohitajika na madhara yanayoweza kutokea.

## Orodha ya ukaguzi kabla ya kutumia mtandao

- [ ] Idhini inajumuisha mtandao wa ufikiaji, lengwa, tarehe na miundombinu ya chanzo.
- [ ] Endpoint haina utambulisho mwingine usiohusiana au vipindi amilifu vya usawazishaji.
- [ ] IPv4, IPv6, DNS na tabia ya kuunganisha upya vinaendana na mpango.
- [ ] Uingizaji wa njia unaodhibitiwa wa DHCP/subnet ya ndani hauwezi kuelekeza trafiki ya majaribio kwenye kiolesura halisi.
- [ ] Lengwa huona egress inayotarajiwa pekee.
- [ ] Tabia ya captive portal na hotspot imejaribiwa bila trafiki nyeti.
- [ ] Kushiriki/kugundua vifaa kwenye mtandao wa ndani na kujiunga kiotomatiki kwenye mitandao kumezimwa.
- [ ] Jedwali la watazamaji na hatari iliyobaki ya kulinganisha trafiki limekubaliwa.
- [ ] Sera ya mtoa huduma, uhifadhi wa data na mawasiliano ya dharura ni ya sasa.

Kwa relays za maarifa yaliyogawanywa, workloads zinazolazimishwa kufuata njia, pluggable transports, huduma za onion, I2P na vivinjari vya mbali vinavyotupwa baada ya matumizi, endelea kwenye [Miundo ya Kina ya Faragha ya Mtandao](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Kuchagua VPN Inayokufaa](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Mwongozo wa usalama wa kifaa: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Ulinzi wa faragha na kutokutambulika unaotolewa na Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Utangulizi mfupi wa Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Kutumia Tor pamoja na vivinjari vingine](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins na viongezi katika Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Kufungua Tor iliyozuiwa](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Kutumia Tor Browser pamoja na VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Je, mitandao ya Wi-Fi ya umma ni salama?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Faragha ya Wi-Fi kwenye vifaa vya Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Kutekeleza ubahatishaji wa MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Kanuni za workstation salama zenye ufikiaji wa juu](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Usajili wa lazima wa SIM: mitazamo ya sera na udhibiti](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Mapendekezo kwa waendeshaji wa huduma za faragha ya DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Muundo wa vitisho](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Kukwepa Tunnels: Kuvuja kwa Trafiki ya VPN Client kwa Kutumia Vibaya Jedwali za Uelekezaji](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Jinsi Washambuliaji Wanavyoweza Kufichua VPN Zinazotegemea Uelekezaji na Kusababisha VPN Leak Kamili](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Maswali Yanayoulizwa Mara kwa Mara kuhusu Yggdrasil: Je, Yggdrasil haikutambulishi?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
