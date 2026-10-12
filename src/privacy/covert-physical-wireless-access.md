# Ufikiaji wa Kificho wa Kimwili na Bila Waya

{{#include ../banners/hacktricks-training.md}}

Kwa maelezo ya utekelezaji wa kina ulioidhinishwa na mmiliki, unaojumuisha muunganisho wa rendezvous ya kutoka, urejeshaji wa umeme/uplink, siri chache zinazohifadhiwa kwenye kifaa, majaribio ya kunasa kifaa na ufuatiliaji wa uwezekano wa kugunduliwa, tazama [Nodi za Uwanjani Zilizoidhinishwa na Zinazostahimili Kunasa](capture-resilient-authorized-field-nodes.md).

Kubadilisha njia ya mtandao kunaweza pia kubadilisha asili halisi inayoonekana. Mhusika mahiri anaweza kutumia mfumo wa karibu uliovamiwa, kifaa kilichofichwa, ufikiaji wa umma, backhaul ya simu za mkononi au kipokezi cha setilaiti ili kumbukumbu za lengwa zionyeshe eneo tofauti na la mwendeshaji. Hakuna kati ya njia hizi kinachofuta ushahidi wa kimwili, wa redio au wa mtoa huduma; huhamishia tu uhusishaji kwenye seti nyingine za data.

## Jedwali la mbinu

| Mbinu | Asili inayoonekana | Sharti la lazima | Ushahidi wenye thamani kubwa |
|---|---|---|---|
| Njia ya kupitia mtandao wa jirani usiotumia waya | biashara/nyumba iliyo karibu na lengwa | hosti iliyovamiwa yenye miunganisho miwili na ufikiaji wa Wi-Fi ya lengwa | kumbukumbu za endpoint za hosti ya jirani, muunganisho wa RF na RADIUS/DHCP ya lengwa |
| Mtandao wa umma/mgeni | NAT ya eneo au njia ya kutoka ya tunnel | ufikiaji halali au kupita udhibiti wa ufikiaji | captive portal, DHCP, muunganisho wa AP, CCTV na kumbukumbu za malipo/eneo |
| Kifaa fiche kilichowekwa | anwani ya waya, Wi-Fi au simu za mkononi ya lengwa/eneo la karibu | kuwekwa au kuwasilishwa kimwili | switchport/USB, RF, orodha ya vifaa, umeme na telemetry ya tunnel ya kutoka |
| Router ya simu za mkononi/eSIM | NAT ya mtoa huduma au APN maalum | modem/SIM/usajili | IMEI/IMSI/eSIM, sekta ya mnara wa simu, akaunti ya mtoa huduma na muda wa trafiki |
| Matumizi mabaya ya kiungo cha setilaiti | anwani ya mteja ndani ya eneo la mwangaza wa setilaiti | udhaifu maalum kwa itifaki na huduma | eneo la RF, mtiririko wa uplink, RTT/uelekezaji usiowezekana na rekodi za mtoa huduma |

## Shambulio la Jirani wa Karibu

Volexity iliandika operesheni ya APT28/GRU ya mwaka 2022 ambapo mhusika alikuwa mbali na lengwa lake kuu. Alifanya password spraying kwenye huduma ya umma ya lengwa ili kupata vitambulisho halali, lakini MFA ilizuia kuingia moja kwa moja kutoka Intaneti. Wi-Fi ya kampuni ya lengwa ilikubali vitambulisho hivyo bila MFA. Mhusika alivamia mashirika yaliyokuwa karibu kimwili na lengwa, akapata mfumo wenye miunganisho miwili ulioweza kufikia mtandao wa wireless, na akautumia mfumo huo kuingia kwenye Wi-Fi ya lengwa. Volexity ililiita hili **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

Ubunifu mpya uko kwenye muunganiko huu. Hakuna operator anayesafiri kwenda kwa lengo, na MFA ya huduma inayofikiwa kupitia Internet bado inafanya kazi. Jirani aliyeathiriwa huwezesha ukaribu wa kimwili; credential ya lengo iliyoibwa huwezesha ufikiaji wa kimantiki; Wi-Fi ya lengo huwa njia ya kuvuka mpaka.

### Masharti ya awali na mwonekano

- Mfumo ulio karibu lazima uweze kudhibitiwa kwa mbali na uwe na redio inayooana au ufikie pivot nyingine iliyo karibu.
- SSID ya lengo lazima ifikie mfumo huo, na udhibiti wa kujiunga na Wi-Fi lazima ukubali credential/cheti/hali ya kifaa inayoweza kutumika tena.
- Mara nyingi pivot huhitaji njia mbili zinazofanya kazi kwa wakati mmoja: moja ya kurudi kwa operator na nyingine ya kuingia kwenye WLAN ya lengo.
- Lengo linaweza kuona MAC mpya ya station na username halali lakini lisione cheti cha kifaa kinachosimamiwa, hali ya usalama, historia au ingizo linalotarajiwa la jengo linalohusiana nayo.
- Logi za endpoint ya jirani zinaweza kuonyesha uchanganuzi wa wireless, profaili mpya, mabadiliko ya interface, tunneling na shughuli za udhibiti wa mbali.

### Utambuzi na uzuiaji

1. Hitaji EAP-TLS inayotegemea cheti na hali ya kifaa kinachosimamiwa kwa Wi-Fi ya enterprise; usikubali kwamba password iliyoshindwa MFA kwenye Internet inatosha kwa sababu tu inatumwa kupitia radio.
2. Linganisha uthibitishaji wa RADIUS na utambulisho wa MDM/NAC, uhusishaji wa kihistoria wa station/kifaa, eneo la AP, matukio ya ufikiaji wa kimwili na sessions zinazoendana kwa wakati mmoja.
3. Toa tahadhari akaunti inapounganishwa kwa mara ya kwanza, kutoka ukingo wa AP usio wa kawaida, bila cheti cha kifaa kinachosimamiwa, au wakati utambulisho huohuo unatumika mahali pengine.
4. Fuatilia endpoint zinazoweza kuunganisha interfaces. Kwenye Windows, Linux na vifaa vya mtandao, chunguza profaili za WLAN zisizotarajiwa, mipangilio ya forwarding/NAT, virtual adapters na tunnels zinazoendelea.
5. Punguza mwangwi wa mawimbi usiohitajika kwa kuweka AP mahali panapofaa na kupanga nguvu ya mawimbi. Hii ni hatua saidizi, si uthibitishaji.
6. Ratibu mwitikio wa tukio na wapangaji jirani: chanzo cha mwisho cha radio huenda chenyewe kikawa mwathiriwa.

[Maabara inayomilikiwa ya mashirika mawili](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) huiga viashiria hivi bila kushambulia jirani.

### Thibitisha njia ya pivot ya Windows

Host ya Windows yenye miunganisho miwili ya mtandao haiunganishi interfaces zake kiotomatiki. Kwanza orodhesha adapters, routes na hali ya WLAN, kisha unganisha kupitia profaili iliyoidhinishwa pekee. Kigezo cha `name` katika `netsh wlan connect` hutambua profaili iliyosakinishwa, si SSID na password yoyote tu. Linganisha jedwali la routes kabla na baada ya kuunganishwa ili kuhakikisha route mpya chaguomsingi haivunji njia ya udhibiti au kubatilisha matokeo. Endelea na [ukaguzi baada ya kuunganishwa](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) baada tu ya kuthibitisha interface na route iliyokusudiwa.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Toleo la Volexity la artifact ya tukio linaonyesha tofauti nyingine muhimu. C# iliyopachikwa hufungua WLAN API, huhesabu interfaces, husoma EAP XML kutoka kwenye diski na kuita `WlanSetProfileEapXmlUserData` kwa profile iliyotajwa kwenye interface ya kwanza ya wireless. API huweka credentials za mtumiaji wa EAP kwenye profile iliyopo ya 802.1X, lakini component iliyotolewa haina `WlanConnect` wala logic ya ugunduzi iliyoelezwa kwenye ripoti. Ichukulie kama utoaji wa profile badala ya connector kamili, na kagua profile inayotokana nayo kama sehemu ya [tathmini ya client na supplicant](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Maeneo ya umma na Wi-Fi ya wahusika wengine

Kutumia Wi-Fi ya mkahawa, hoteli, uwanja wa ndege au manispaa hubadilisha IP inayoonyeshwa kwa lengwa. Hakuleti kutokujulikana. Eneo au mtoa huduma wake anaweza kuhifadhi rekodi za kuunganishwa na AP, MAC ya kifaa, lease ya DHCP, akaunti ya captive portal, uthibitishaji wa SMS/barua pepe na rekodi za mtiririko wa trafiki. Kuingia eneo kimwili, CCTV, ununuzi, data ya mahali pa simu na rekodi za safari vinaweza kuunganisha tukio la kidijitali na mtu.

Mhusika anaweza kujaribu kuficha kidokezo kimoja kwa kutumia MAC address zilizobadilishwa nasibu, kifaa tofauti, pesa taslimu au tunnel. Hata hivyo, ulinganishaji wa taarifa katika tabaka mbalimbali bado unawezekana kupitia muda wa kuwasili, mifumo ya kurudia kutembelea eneo, alama za kipekee za redio, tabia ya portal, muda wa trafiki, picha za kamera na mtoa huduma wa tunnel. VPN pia huhamisha rekodi zinazohusiana na lengwa kutoka kwa eneo hadi kwa rekodi za VPN; haifuti ukweli kwamba eneo linajua kifaa kilikuwepo hapo.

Watetezi wa huduma za umma za ufikiaji wanapaswa kutenga clients, kuzuia trafiki ya pembeni, kutumia WPA2/3-Enterprise au funguo za kila kifaa inapowezekana, kuhifadhi rekodi sawia za DHCP/RADIUS/usalama, kulinda captive portals na kuchapisha utaratibu wa kushughulikia matumizi mabaya. Red teams zinapaswa kutumia eneo kama hilo tu pale ambapo masharti yake na makubaliano ya kazi yanaruhusu; kukwepa portal, kuiba ufikiaji au kulenga wageni wengine si njia ya mkato ya upimaji iliyoidhinishwa.

## Vifaa vya drop vya siri na warshipping

Drop ni mfumo mdogo unaowekwa au kuletwa ndani ya eneo, kisha kudhibitiwa kupitia Ethernet, Wi-Fi au mtandao wa simu unaotoka nje. “Warshipping” hupakia kifaa kwa njia ambayo usafirishaji wa kawaida hukipitisha ndani ya eneo la mawimbi ya redio. Vifaa vinavyowezekana ni kuanzia kompyuta ya bodi moja hadi chaja iliyorekebishwa, kifaa cha USB, kifaa cha mtandao au modem inayotumia betri.

Muundo wa uendeshaji:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

Kifaa hiki kinaweza kutoa foothold ya mbali, kufanya vipimo vya wireless, kuiga peripheral ya zoezi lililoidhinishwa, au kusambaza trafiki. Chanzo chake kinachoonekana ni cha ndani, lakini huacha athari halisi: nambari za mfululizo, vifungashio, alama za vidole, kamera, kumbukumbu za ufikiaji, matumizi ya umeme, maelezo ya USB, mazungumzo ya switchport, alama za DHCP, tabia ya MAC OUI/randomization, mawimbi ya RF na miunganisho ya rendezvous inayojirudia.

### Vidhibiti vya ulinzi

- Dumisha taratibu za kupokea bidhaa na kuhifadhi orodha ya mali; kagua vifaa vya kielektroniki na vifurushi visivyotarajiwa vilivyoelekezwa kwa wafanyakazi wasiokuwepo.
- Tumia 802.1X/NAC kwenye ufikiaji wa wired na wireless, zima port zisizotumika, na weka vifaa visivyojulikana kwenye VLAN yenye vizuizi kwa ajili ya kurekebisha.
- Toa tahadhari kuhusu alama mpya za DHCP, MAC zilizowekwa kama za ndani zinazoendelea kuwepo, vifaa vipya vya USB network/HID, Wi-Fi Direct/Bluetooth zisizoidhinishwa na tunnel za nje zinazodumu kwa muda mrefu.
- Weka viwango vya msingi vya tabia ya switchport, power-over-Ethernet, DNS na TLS. Kompyuta ndogo isiyo kwenye orodha ya mali inayofanya miunganisho iliyosimbwa kwa njia fiche mara kwa mara ni ishara muhimu zaidi kuliko “Raspberry Pi OUI” pekee.
- Wakati wa zoezi, orodhesha, weka lebo, fafanua upeo, simba kwa njia fiche, toa uwezo wa kuzima kwa mbali, weka tarehe ya mwisho ya kurejesha na uhakikishe kuwa kupotea kwake hakuwezi kufichua credentials zinazoweza kutumiwa tena.

## Backhaul ya simu za mkononi na eSIM

Modemu ya simu za mkononi huepuka gateway ya Internet ya lengwa na inaweza kuweka drop ipatikane nyuma ya carrier NAT kupitia rendezvous ya nje. Anwani za simu zinaweza kubadilika au kutumiwa na watu wengi; hata hivyo, operator wa simu za mkononi bado ana ushahidi thabiti wa mteja na mtandao: utambulisho wa SIM/eSIM, IMSI, IMEI ya kifaa, anwani/port zilizogawiwa, muda wa kutumia minara/sehemu zake, pamoja na kumbukumbu za akaunti/malipo na roaming.

Kwa mtazamo wa biashara, gundua modemu na personal hotspot zisizotarajiwa kwa kutumia ukaguzi wa wireless/RF, orodha ya USB/PCI ya endpoint, vizuizi vya MDM, ufuatiliaji wa rogue-SSID na ukaguzi wa kimwili. Drop inayotumia simu za mkononi kwa udhibiti bado inaweza kugunduliwa kupitia tabia yake ya ndani ya Ethernet/Wi-Fi na mawimbi yake ya redio.

Kwa mazoezi yaliyoidhinishwa, shirika linapaswa kumiliki subscription na modemu, kurekodi vitambulisho pamoja na controller na kuthibitisha kuwa masharti ya carrier/provider yanaruhusu trafiki hiyo. Lebo ya malipo ya awali au ununuzi wa cryptocurrency hauondoi kumbukumbu za mnara, kifaa au muuzaji wa rejareja.

## MAC randomization na fingerprinting ya kifaa

Mifumo ya kisasa inaweza kutumia MAC ya nasibu iliyowekwa kama ya ndani kwa kila mtandao. Hii hupunguza ufuatiliaji wa muda mrefu usiohusisha kuingiliana unaotumia MAC thabiti ya kiwandani; lakini haifichi:

- muda wa probe/association na seti ya uwezo wa mtandao inayoombwa;
- vipengele vya taarifa vya 802.11, viwango vinavyotumika na tabia mahususi ya vendor;
- chaguo za DHCP/jina la host, vitambulishi vya IPv6 na fingerprint ya captive-portal/browser;
- utambulisho au certificate ya 802.1X iliyothibitishwa;
- akaunti za tabaka za juu, tunnel na mifumo ya trafiki; au
- uangalizi wa kimwili.

Watetezi hawapaswi kutumia orodha za kuruhusu za MAC kama uthibitishaji. Linganisha utambulisho wa redio na certificate/mkao wa kifaa, na chukulia MAC zinazobadilika kuwa za kawaida isipokuwa muktadha mwingine uwe na kasoro.

## Utekaji nyara wa kiungo cha satelaiti

Kaspersky iliandika kuwa Turla ilitumia udhaifu katika huduma ya zamani ya Internet ya satelaiti ya njia moja ya DVB-S. Katika mfano ulioripotiwa, mteja halali wa mbali alituma maombi ya kutoka kupitia kiungo cha ardhini lakini akapokea data ya chini kupitia matangazo ya satelaiti ya eneo pana ambayo hayajasimbwa kwa njia fiche. Mhusika aliyekuwa ndani ya eneo linalofikiwa na satelaiti angeweza kuchunguza data ya chini, kuchagua IP ya mteja aliyekuwa anatumika na kuhakikisha kuwa majibu ya C2 yanaelekezwa kwenye IP hiyo. Mteja halali na mhusika wote walipokea matangazo hayo; mhusika alitoa trafiki ya port iliyochaguliwa, huku mteja halali akitupa pakiti ambazo hakuwa ameziomba. Kisha operator wa C2 alionekana kutumia anwani ya mtoa huduma wa satelaiti katika eneo jingine.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Hii ilikuwa mahususi kwa protocol/service, yenye bandwidth finyu, na haikuwa sawa na kucompromise terminal ya kisasa ya satellite yenye mawasiliano yaliyosimbwa kwa njia fiche ya pande mbili. Pia haikuficha njia ya ombi la kutoka la mtendaji dhidi ya mwangalizi mwenye uwezo wa kutosha. Fursa za kutambua hali hii ni pamoja na routing isiyolingana/isiyowezekana, traffic kwenda kwa subscriber ambaye hakuanzisha muunganisho, destination port zisizo za kawaida, telemetry ya provider, uchunguzi wa eneo la receiver/RF na usanidi wa malware. Tumia kesi hii kupinga dhana kwamba kutambua eneo la IP ya C2 kunatambua eneo la controller wake—si kama mwongozo wa kutengeneza mbinu hiyo.

## Karatasi ya kazi ya kuhusisha matukio ya kimwili na ya kidijitali

Chanzo kinachoonekana kuwa cha ndani kinapotia shaka, tengeneza timeline moja:

1. sawazisha saa za AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch na mifumo ya udhibiti wa ufikiaji wa kimwili;
2. tambua radio association au link-up ya kwanza, si alert ya kwanza tu;
3. husisha station na certificate, hali ya kifaa, DHCP fingerprint na eneo la switch/AP;
4. tafuta shughuli za remote-control/tunnel zilizotokea wakati huohuo kwenye mifumo iliyo karibu;
5. kagua deliveries, wageni, tofauti za inventory, kamera na matokeo ya RF kwa kufuata policy/sheria husika;
6. hifadhi kifaa kinachoshukiwa na hali tete ya mtandao; usikizime na kukiwasha tena bila kufikiri;
7. bainisha kama chanzo kinachoonekana ni miundombinu inayodhibitiwa na mtendaji au mwathiriwa mwingine.

## References

- [1] [Volexity — Shambulio la Nearest Neighbor: Jinsi APT ya Urusi ilivyotumia mitandao ya Wi-Fi iliyo karibu kwa ufikiaji fiche](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: Amri na udhibiti wa APT angani](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Nyongeza za vifaa (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Miongozo ya kulinda mitandao ya eneo la ndani isiyotumia waya](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Msimbo wa WLAN wa PowerShell/C# uliorekebishwa](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — Kazi ya WlanSetProfileEapXmlUserData](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
