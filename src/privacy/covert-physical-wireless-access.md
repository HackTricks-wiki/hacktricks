# Ufikiaji Fiche wa Kimwili na Wireless

{{#include ../banners/hacktricks-training.md}}

Kwa utekelezaji wa kina ulioidhinishwa na mwenye mfumo unaohusisha outbound rendezvous, urejeshaji wa nishati/uplink, secrets chache zinazoshikiliwa na kifaa, majaribio ya capture na monitoring ya uwezekano wa kugunduliwa, tazama [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Kubadilisha njia ya mtandao kunaweza pia kubadilisha asili ya kimwili inayoonekana. Mhusika mwenye ustadi anaweza kutumia mfumo wa karibu uliocompromisiwa, kifaa kilichofichwa, public access, cellular backhaul au satellite receiver ili logs za target zielekeze mbali na operator. Hakuna kati ya hivi kinachoondoa ushahidi wa kimwili, radio au provider; kunahamisha attribution kwenye datasets tofauti.

## Matrix ya mbinu

| Mbinu | Asili inayoonekana | Sharti linalohitajika | Ushahidi wenye thamani kubwa |
|---|---|---|---|
| Nearby wireless pivot | biashara/nyumba iliyo karibu na target | host yenye dual-homed iliyocompromisiwa na ufikiaji wa target Wi-Fi | endpoint logs za host ya jirani, RF association na target RADIUS/DHCP |
| Public/guest network | venue NAT au tunnel exit | access halali au access-control bypass | captive portal, DHCP, AP association, CCTV na payment/location records |
| Covert drop device | anwani ya target/eneo la karibu ya wired, Wi-Fi au cellular | uwekaji au uwasilishaji wa kimwili | switchport/USB, RF, inventory, power na outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT au dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier account na traffic timing |
| Satellite-link abuse | anwani ya subscriber ndani ya beam footprint | udhaifu maalum wa protocol na service | RF location, uplink flow, impossible RTT/routing na provider records |

## Nearest-neighbor attack

Volexity iliandika kuhusu operesheni ya APT28/GRU ya mwaka 2022 ambapo mhusika alikuwa mbali na target yake ya mwisho. Ilifanya password-spraying dhidi ya public service ya target ili kupata credentials halali, lakini MFA ilizuia kuingia moja kwa moja kupitia Internet. Enterprise Wi-Fi ya target ilikubali credentials hizo bila MFA. Mhusika alicompromise mashirika yaliyokuwa karibu kimwili na target, akapata mfumo wenye dual-homed wenye wireless reach, kisha akautumia mfumo huo ku-authenticate kwenye target Wi-Fi. Volexity iliita hili **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Ubunifu upo katika muunganiko huo. Hakuna operator anayesafiri kwenda kwa target, na MFA ya service inayoonekana kwenye Internet bado inafanya kazi. Jirani aliyecompromise hutoa ukaribu wa kimwili; credential ya target iliyoibwa hutoa access ya kimantiki; Wi-Fi ya target huwa njia ya kuvuka mpaka.

### Masharti ya awali na mwonekano

- Mfumo wa karibu lazima uweze kudhibitiwa remotely na uwe na radio inayooana au uweze kufikia pivot nyingine ya karibu.
- SSID ya target lazima ifikie mfumo huo, na Wi-Fi admission lazima ikubali credential/certificate/device state inayoweza kutumika tena.
- Pivot mara nyingi huhitaji paths mbili kwa wakati mmoja: moja ya kurudi kwa operator na nyingine ya kuingia kwenye WLAN ya target.
- Target inaweza kuona station MAC mpya na username halali, lakini isiwe na managed-device certificate, posture, history au building entry inayotarajiwa inayolingana.
- Logs za endpoint ya jirani zinaweza kuonyesha wireless scans, profiles mpya, mabadiliko ya interface, tunneling na shughuli za remote-control.

### Detection na prevention

1. Hitaji certificate-backed EAP-TLS na managed-device posture kwa enterprise Wi-Fi; usifanye password iliyoshindwa MFA kwenye Internet iwe sufficient kwa sababu tu imewasili kupitia radio.
2. Linganisha RADIUS authentication na MDM/NAC identity, historical station/device binding, AP location, matukio ya physical-access na sessions zinazotokea kwa wakati mmoja.
3. Tuma alert wakati account ina-associate kwa mara ya kwanza, kutoka AP edge isiyo ya kawaida, bila managed certificate, au wakati identity hiyo hiyo iko active kwingine.
4. Monitor endpoints zinazoweza ku-bridge interfaces. Kwenye Windows, Linux na network appliances, chunguza WLAN profiles zisizotarajiwa, forwarding/NAT configuration, virtual adapters na persistent tunnels.
5. Punguza signal spill isiyo ya lazima kwa kutumia AP placement na power planning zinazofaa. Hii ni supporting control, si authentication.
6. Ratibu incident response na tenants wa jirani: chanzo cha mwisho cha radio huenda chenyewe kikawa victim.

[owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) inazalisha observables hizi bila kushambulia jirani.

## Public venues na third-party Wi-Fi

Kutumia Wi-Fi ya café, hotel, airport au municipal hubadilisha IP inayoonyeshwa kwa destination. Hakuleti anonymity. Venue au provider wake anaweza kuhifadhi AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation na flow logs. Physical entry, CCTV, ununuzi, mobile-location na travel records vinaweza kuunganisha tukio la kidijitali na mtu.

Actor anaweza kujaribu kupunguza handle moja kwa kutumia randomized MAC addresses, device tofauti, cash au tunnel. Cross-layer correlation bado inawezekana kupitia arrival time, venue pattern inayojirudia, radio fingerprints, portal behavior, traffic timing, camera footage na tunnel provider. VPN pia huhamisha destination kutoka venue logs hadi VPN logs; haiondoi ujuzi wa venue kwamba device ilikuwepo.

Defenders wa public access wanapaswa kutenga clients, kuzuia lateral traffic, kutumia WPA2/3-Enterprise au per-device keys inapowezekana, kuhifadhi DHCP/RADIUS/security logs kwa uwiano unaofaa, kulinda captive portals, na kuchapisha abuse process. Red teams wanapaswa kutumia venue kama hiyo tu wakati masharti yake na engagement yanaruhusu; kubypass portal, kuiba access au ku-target guests wengine si njia ya mkato iliyoidhinishwa ya testing.

## Covert drop devices na warshipping

Drop ni mfumo mdogo unaowekwa au kupelekwa kwenye site, kisha kudhibitiwa kupitia outbound Ethernet, Wi-Fi au cellular. “Warshipping” hupakia device kwa namna ambayo delivery ya kawaida huipeleka ndani ya radio perimeter. Hardware inayowezekana inaanzia single-board computer hadi charger iliyorekebishwa, USB peripheral, network appliance au battery-powered modem.

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Kifaa kinaweza kutoa foothold ya mbali, kufanya vipimo vya wireless, kuiga peripheral iliyoidhinishwa ya zoezi, au ku-relay traffic. Chanzo chake kinachoonekana ni cha ndani, lakini huunda vielelezo vya kimwili: namba za serial, packaging, fingerprints, kamera, access logs, matumizi ya nguvu, USB descriptors, switchport negotiation, DHCP fingerprints, tabia ya MAC OUI/randomization, RF emissions na connections za mara kwa mara za rendezvous.

### Controls za kujilinda

- Dumisha taratibu za receiving room na asset inventory; kagua electronics na packages zisizotarajiwa zilizoelekezwa kwa wafanyakazi wasiokuwepo.
- Tumia 802.1X/NAC kwenye wired na wireless access, zima ports zisizotumika, na weka vifaa visivyojulikana kwenye restricted remediation VLAN.
- Weka alerts kwa DHCP fingerprints mpya, MACs zinazosimamiwa ndani zinazoendelea kuwepo, network/HID devices mpya za USB, Wi-Fi Direct/Bluetooth zisizoidhinishwa na outbound tunnels zinazodumu muda mrefu.
- Weka baseline ya switchport, power-over-Ethernet, DNS na TLS behavior. Host ndogo isiyo na rekodi ya inventory inayofanya connections za periodic encrypted ina signal kubwa kuliko “Raspberry Pi OUI” pekee.
- Wakati wa zoezi, weka inventory, weka labels, bainisha scope, encrypt, toa remote kill, weka deadline ya retrieval na hakikisha upotevu hauwezi kufichua credentials zinazoweza kutumika tena.

## Cellular na eSIM backhaul

Cellular modem huepuka Internet gateway ya target na inaweza kuweka drop ipatikane nyuma ya carrier NAT kupitia outbound rendezvous. Mobile addresses zinaweza kubadilika au kushirikishwa; cellular operator bado ana ushahidi madhubuti wa subscriber na network: utambulisho wa SIM/eSIM, IMSI, device IMEI, addresses/ports zilizogawiwa, muda wa cell/sector, account/payment na roaming records.

Kwa mtazamo wa enterprise, tambua modems zisizotarajiwa na personal hotspots kwa wireless/RF surveys, endpoint USB/PCI inventory, MDM restrictions, rogue-SSID monitoring na physical inspection. Drop inayotumia cellular kwa control bado inaweza kugunduliwa kupitia local Ethernet/Wi-Fi behavior yake na radio emissions zake.

Kwa authorized exercises, shirika linapaswa kumiliki subscription na modem, kurekodi identifiers pamoja na controller na kuthibitisha kwamba masharti ya carrier/provider yanaruhusu traffic hiyo. Lebo ya prepaid au ununuzi wa cryptocurrency hauondoi tower, device au retail records.

## MAC randomization na device fingerprinting

Mifumo ya kisasa inaweza kutumia locally administered random MAC kwa kila network. Hii hupunguza passive long-term tracking kupitia factory MAC thabiti; haifichi:

- muda wa probe/association na seti ya network capabilities zilizoombwa;
- 802.11 information elements, supported rates na vendor-specific behavior;
- DHCP options/hostname, IPv6 identifiers na captive-portal/browser fingerprint;
- authenticated 802.1X identity au certificate;
- account ya higher-layer, tunnel na traffic pattern; au
- physical observation.

Defenders hawapaswi kutumia MAC allowlists kama authentication. Unganisha radio identity na certificate/device posture na chukulia MAC zinazobadilika kama jambo la kawaida isipokuwa muktadha mwingine uwe wa kutia shaka.

## Utekaji wa satellite-link

Kaspersky aliandika kuhusu Turla kutumia udhaifu katika satellite Internet ya zamani ya one-way DVB-S. Katika model iliyoripotiwa, remote subscriber halali alituma outbound requests kupitia terrestrial link lakini akapokea downstream data kupitia wide-area satellite broadcast isiyo na encryption. Actor aliyekuwa ndani ya satellite footprint angeweza kuona downlink, kuchagua subscriber IP inayotumika na kupanga C2 replies zielekezwe kwenye IP hiyo. Subscriber halali na actor wote walipokea broadcast; actor alitoa traffic ya port iliyochaguliwa, huku subscriber halali akitupa unsolicited packets. Kisha C2 operator alionekana kutumia satellite-provider address katika geography nyingine.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Hii ilikuwa mahususi kwa protocol/service, yenye bandwidth iliyowekewa mipaka, na haikuwa sawa na ku-compromise satellite terminal ya kisasa yenye encryption ya pande mbili. Pia haikuficha njia ya ombi la actor kuelekea nje kutoka kwa observer mwenye uwezo wa kutosha. Fursa za detection zinajumuisha routing isiyolingana/isiyowezekana, traffic kuelekea kwa subscriber ambaye hakuanzisha flow, destination ports zisizo za kawaida, provider telemetry, receiver location/RF investigation na malware configuration. Tumia case hii kupinga dhana kwamba kufanya geolocation ya C2 IP kunakuonyesha eneo la controller wake—si kama build recipe.

## Physical-to-digital correlation worksheet

Chanzo kinachoonekana kuwa cha ndani kinapokuwa na mashaka, tengeneza timeline moja:

1. synchronize saa za AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch na physical-access;
2. tambua radio association au link-up ya kwanza, si alert ya kwanza pekee;
3. linganisha station na certificate, device posture, DHCP fingerprint na eneo la switch/AP;
4. tafuta remote-control/tunnel activity inayotokea kwa wakati mmoja kwenye mifumo ya karibu;
5. kagua deliveries, visitors, inventory exceptions, cameras na RF findings kwa kuzingatia policy/law zinazotumika;
6. hifadhi device inayoshukiwa na volatile network state; usi-power-cycle bila mpango;
7. bainisha kama source inayoonekana ni infrastructure inayodhibitiwa na actor au victim mwingine.

## References

- [1] [Volexity — The Nearest Neighbor Attack: Jinsi Russian APT ilivyotumia weaponize mitandao ya karibu ya Wi-Fi](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT command and control angani](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Miongozo ya Kulinda Wireless Local Area Networks](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
