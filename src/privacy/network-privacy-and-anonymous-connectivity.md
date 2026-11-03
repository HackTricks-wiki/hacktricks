# Netwerkprivaatheid en anonieme konnektiwiteit

{{#include ../banners/hacktricks-training.md}}

Netwerkprivaatheid is ’n roeteringsbesluit, nie ’n volledige identiteit nie. Kies ’n pad deur te vra wie nie die **bron**, **bestemming**, **inhoud** en **tydsberekening** moet kan koppel nie.

Vir die genormaliseerde inventaris—`Pros`, `Cons`, stap-vir-stap-`Procedure` en `Detection` vir elke toegangsroetefamilie—begin by die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Hierdie bladsy brei die algemene ontplooibare opsies uit.

## Wat elke waarnemer gewoonlik kan sien

| Pad | Plaaslike netwerk / ISP | Tussenganger | Bestemming | Belangrikste beperking | Relatiewe spoed |
|---|---|---|---|---|---|
| Direkte HTTPS | Bron, bestemmingsmetadata, tydsberekening/volume | Gasheer/CDN sien die verbinding | Bron-IP, blaaier-/toepassingdata | Geen privaatheid van bron-IP nie | Vinnigste |
| Kommersiële VPN | Bron wat aan VPN gekoppel is; gewoonlik nie bestemmingsmetadata nie | VPN sien bron- en bestemmingsmetadata | VPN-uitgangs-IP | Een verskaffer word ’n korrelasiepunt | Gewoonlik vinnig |
| Selfgehoste VPN/VPS | Bron wat aan VPS gekoppel is | Gasheer-/rekening-/betalings-/beheervlaklogboeke | VPS-uitgangs-IP | Maklik om aan die gehuurde bediener/rekening toe te skryf | Gewoonlik vinnig |
| Tor Browser | Bron wat aan Tor/bridge gekoppel is; tydsberekening/volume | Elke relay sien ’n beperkte deel | Tor-exit, blaaierdata | Stadiger; rekening-/eindpunt-/korrelasierisiko’s | Gemiddeld/stadig |
| Tails/Whonix | Soortgelyke Tor-pad, met sterker roeteringsgrense | Dieselfde Tor-beperkings | Tor-exit/toepassingdata | Operasionele foute en die gasheer/hardeware bly risiko’s | Gemiddeld/stadig |
| Openbare gas-Wi-Fi + HTTPS | Lokaal sien die lokaal die toestel/tydsberekening en bestemmings | Lokaal se ISP sien metadata | Gas se openbare IP | Fisiese/kaptieweportaal-/toestelkorrelasie | Vinnig/wisselend |
| Sellulêre hotspot | Draer sien intekenaar/toestel/ligging en bestemmings | VPN/Tor, indien gebruik | Draer-, VPN- of Tor-uitgangs-IP | Mobiele intekening en ligging is blywende identifiseerders | Vinnig/wisselend |
| Mixnet | Toegang sien mixnet-gebruik; tydsberekening/volume | Verskeie mengnodusse | Gateway/uitgang | Ontluikende ekosisteem; latensie- en bandwydtekoste | Stadigste |

HTTPS beskerm inhoud tydens oordrag, maar nie alle metadata nie. EFF meld dat domein, tyd en verkeersgrootte vir tussengangers sigbaar kan bly, selfs wanneer bladsyroetes, geloofsbriewe en boodskappe geïnkripteer is.<sup>[[1]](#references)</sup>

’n Geënkripteerde oorlaag is nie outomaties ’n anonimiteitsnetwerk nie: Yggdrasil-direkte eweknieë kan mekaar se IP-adresse sien.<sup>[[20]](#references)</sup> Die [userspace-aanstuur en SOCKS-vervoer daarvan](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) is ’n tonnelopsie, nie ’n laag vir bronanonimiteit nie.<sup>[[20]](#references)[[21]](#references)</sup>

## VPN’s: vinnige privaatheid met gekonsentreerde vertroue

’n VPN is nuttig om bestemmingsmetadata vir die toegangs-ISP te verberg, die eerste sprong op ’n onbetroubare netwerk te beskerm, ’n stabiele uitgangsadres vir ’n betrokkenheid te bied, of ’n private netwerk te bereik. Dit maak ’n gebruiker **nie** anoniem nie. Die VPN sien die bronverbinding en kan bestemmingsmetadata waarneem; rekeninge, koekies, GPS, vingerafdrukke en betalingsinligting bly steeds sigbaar.<sup>[[1]](#references)</sup>

### Kontrolelys vir die evaluering van verskaffers

1. **Eienaarskap en jurisdiksie:** identifiseer die regsentiteit, moedermaatskappy, bedryfslande, infrastruktuur-onderaannemers en toepaslike regsprosesse.
2. **Data wat ingesamel word:** onderskei tussen rekening-/faktureringsdata, bron-IP, verbindingstydstempels, bandwydte, ongeluktelemetrie, DNS-navrae en bestemmingslogboeke. “Geen blaaierlogboeke” beteken nie “geen data” nie.
3. **Bewaring en verwydering:** vind die presiese tydperke en bepaal of rugsteune, bedrogstelsels en verwerkers dieselfde skedule volg.
4. **Bewyse:** verkies openbare oudits met omvang, datum, bevindings en regstellings; herhaalbare/oop kliënte; deursigtigheidsverslae; en gedokumenteerde voorvalle.
5. **Protokol en kliënt:** onderhoude WireGuard, OpenVPN of ’n ander nagegane protokol; outomatiese opdaterings; DNS- en IPv6-hantering; kill switch; en leak-toetse vir elke platform.
6. **Besigheidsmodel:** verstaan hoe ’n gratis of gesubsidieerde diens befonds word. Teenwoordigheid in ’n toepassingwinkel is op sigself nie bewys van betroubare bedryf nie.
7. **Geskiktheid van betaalmetodes:** alternatiewe betaling kan faktureringsinligting vir die VPN beperk, maar vee nie die bron-IP uit wat by elke verbinding waargeneem word nie.

### Stel ’n VPN op en verifieer dit

1. Installeer die verskaffer/organisasie se ondertekende kliënt vanaf die amptelike bron.
2. Kies **full tunnel**, tensy ’n gedokumenteerde roete dit moet omseil. Split tunneling skep korrelasie- en leak-roetes.
3. Aktiveer fail-closed/altyd-aan-gedrag en blokkeer verkeer tydens herverbinding.
4. Stuur DNS deur die tonnel en toets IPv4 én IPv6. Deaktiveer ’n protokol net as dit nie veilig deur die tonnel gestuur kan word nie en die verlies aan funksionaliteit aanvaar word.
5. Toets slaap/wakker-word, netwerkwisseling, aanmelding by ’n kaptiewe portaal, tonnelongeluk en hotspot-tethering. NCSC waarsku dat gekoppelde kliënte op sommige platforms die VPN van ’n foon kan omseil.<sup>[[2]](#references)</sup>
6. Gebruik ’n organisasie-beheerde toetspunt om die waargenome IPv4, IPv6, DNS-resolver en verbindingstydsberekening aan te teken. Moenie ’n sensitiewe betrokkenheid aan willekeurige “leak test”-webwerwe blootstel nie.
7. Toets weer ná veranderinge aan die kliënt, bedryfstelsel, netwerk of beleid.

### Omseiling van roetering op ’n vyandige LAN

’n VPN kan sigbaar “gekoppel” bly terwyl sekere pakkette dit omseil, omdat die bedryfstelsel ’n roete kies **voordat** die VPN die pakket enkripteer. TunnelCrack het twee maniere gedemonstreer om algemene roeteringsuitsonderings te misbruik: **LocalNet** laat ’n internetbestemming lyk asof dit op die direk gekoppelde subnet is, terwyl **ServerIP** die VPN-gateway se naamoplossing vervals sodat ’n teikenadres die uitsondering vir die ongeënkripteerde netwerk erf wat die VPN-vervoer benodig. Dit is kliënt-/roeteringsfoute, nie krake in WireGuard, OpenVPN, IPsec of TLS nie; HTTPS-loonvragte bly end-tot-end geënkripteer, maar die plaaslike waarnemer kan bestemmings-/tydsberekeningsmetadata en enige ongeënkripteerde protokoldata verkry.<sup>[[18]](#references)</sup>

TunnelVision gebruik dieselfde voor-enkripsie-primitief deur DHCP-opsie 121. ’n Kwaadwillige of gekompromitteerde DHCP-bediener kan ’n klaslose roete installeer wat meer spesifiek is as die VPN se catch-all-roete, en sodoende die fisiese koppelvlak vir ’n willekeurige gasheer of reeks kies. Die VPN-beheerkanaal kan aktief bly; daarom sal ’n kill switch wat slegs deur tonnelontkoppeling geaktiveer word dalk nie aanskakel nie, en kan ’n enkele openbare “IP leak”-kontrole selektiewe omseiling mis.<sup>[[19]](#references)</sup>

’n Pakketfilter-kill switch wat slegs DHCP en die geverifieerde VPN-vervoer op die fisiese koppelvlak toelaat, behoort dit in fail-closed-gedrag te verander, maar geteikende roete-inspuiting kan steeds ’n selektiewe ontkenningskanaal skep. Vir Linux-werkladings met hoë gevolge, verkies die sterker [roete-afgedwonge netwerknaamruimtepatroon](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), waar die toepassingsnaamruimte geen fisiese koppelvlak of verstekroete vir die ongeënkripteerde netwerk het nie.<sup>[[19]](#references)</sup>

#### Verifikasie in ’n eie laboratorium

Toets die presiese kliënt/bedryfstelsel/weergawe op ’n eie AP, DHCP-bediener, VPN-eindpunt en bestemming; aansprake oor die hele produk verouder vinnig omdat roeterings- en pakketfilterimplementasies platformspesifiek is. Neem pakkette op die eindpunt self én op die toetsbediener vas—’n webwerf wat die uitgangs-IP toon, bewys nie op sigself dat elke bestemming die tonnel volg nie.<sup>[[18]](#references)[[19]](#references)</sup>

1. Koppel aan die VPN, teken die VPN-bedieneradres aan en stoor elke IPv4-/IPv6-roeteringstabel en beleidroeteringsreël. Gebruik `route print` op Windows, `netstat -rn` op macOS en die opdragte hieronder op Linux.
2. Vra na die geselekteerde roete vir verskeie IP-adresse van bestemmings wat jy besit. Die volgende sprong/koppelvlak moet die tonnel wees, behalwe vir die gedokumenteerde VPN-vervoer-eindpunt.
3. Vir TunnelVision, hernu die huurtermyn op die beheerde DHCP-netwerk en installeer ’n opsie 121-roete **slegs vir ’n toetsteiken wat jy besit**. ’n Slaagresultaat beteken dat verkeer steeds deur die tonnel gestuur of geblokkeer word—dit mag nooit as bestemmingsverkeer op die fisiese koppelvlak uitgestuur word nie.
4. Vir LocalNet, ken die kliënt ’n openbare dokumentasiesubnet toe wat net vir die laboratorium gebruik word, soos `203.0.113.0/24`, en plaas die toetsteiken wat jy besit daarin. Verifieer dat die aktivering van LAN-toegang nie veroorsaak dat internetbestemmings die tonnel omseil nie.
5. Vir ServerIP, laat beheerde DNS vóór die VPN-verbinding die VPN-gasheernaam na die toetsteiken wat jy besit verwys, terwyl die laboratoriumgateway die VPN-vervoer na die werklike VPN-eindpunt wat jy besit aanstuur. Die kliënt mag nie onverwante toepassingverkeer na die vervalste adres uitsonder nie.
6. Herhaal met “local network access” geaktiveer én gedeaktiveer, ná herverbinding, slaap/wakker-word, netwerkwisseling en ’n VPN-prosesongeluk. Toets IPv4, IPv6 en DNS afsonderlik.
7. Inspekteer die opname van die fisiese koppelvlak. Dit moet DHCP en geënkripteerde pakkette na die VPN-bediener bevat, nie pakkette wat direk aan die toetsteiken wat jy besit gerig is nie. Bevestig ook dat ’n afgekeurde omseiling nie stilweg kan terugval ná gebruikersaanwysings of herstel van konnektiwiteit nie.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: sterker ontkoppelbaarheid op die web

Tor bou ’n circuit deur verskeie relays, sodat geen enkele relay normaalweg beide die bron en bestemming ken nie. Die bestemming sien ’n Tor-exit eerder as die gebruiker se IP; die plaaslike netwerk sien normaalweg ’n Tor-verbinding.<sup>[[3]](#references)</sup> Tor is ontwerp vir TCP-toepassings met lae latensie, en is dus stadiger. Dit kan ook nie beskerming waarborg teen ’n teenstander wat albei eindpunte kan korreleer nie.<sup>[[4]](#references)</sup>

### Veilige Tor Browser-werkvloei

1. Laai Tor Browser slegs van die Tor Project of ’n amptelike mirror af, en verifieer die handtekening waar moontlik.
2. Gebruik **Tor Browser**, nie ’n gewone browser wat op ’n Tor SOCKS-poort gerig is nie. Gewone browsers kan DNS/WebRTC en identifiserende toestand uitlek.<sup>[[5]](#references)</sup>
3. Behou die verstekgrootte, fonts, extensions en privaatheidinstellings. Bykomende add-ons kan die browser meer uniek maak.<sup>[[6]](#references)</sup>
4. Kies die **Safer**- of **Safest**-sekuriteitsvlak wanneer die groter kans op probleme aanvaarbaar is.
5. Gebruik ’n bridge wanneer direkte Tor geblokkeer word of wanneer gewone relay-IP’s onaanvaarbare sigbaarheid op die plaaslike netwerk sou veroorsaak. Bridges maak maklike herkenning moeiliker; hulle skakel verkeersanalise nie uit nie.<sup>[[7]](#references)</sup>
6. Moenie by ’n identifiserende rekening aanmeld, identifiserende inligting verskaf of afgelaaide aktiewe dokumente in ’n eksterne netwerktoepassing oopmaak nie.
7. Gebruik ’n aparte sessie/konteks vir elke identiteit. “New circuit” is nie dieselfde as om die browser-/toepassingsidentiteit uit te wis nie; gebruik **New Identity** of herbegin die geïsoleerde omgewing soos toepaslik.
8. Verkies geverifieerde HTTPS of ’n geverifieerde onion service. ’n Tor-exit kan ongeënkripteerde HTTP-verkeer waarneem.

### Tor plus VPN

Die kombinasie is nie outomaties veiliger nie. ’n VPN voor Tor kan direkte Tor-relay-verbindings vir ’n ISP verberg, terwyl die VPN die bron sien; Tor voor ’n VPN gee die VPN ’n stabiele beeld van aktiwiteit ná Tor en kan die anonimiteitsgroep verklein. Verkeerde opstelling kan leaks veroorsaak. Die Tor Project beveel sulke kombinasies slegs aan vir gevorderde, uitdruklike bedreigingsmodelle.<sup>[[8]](#references)</sup>

## Openbare en gas-Wi-Fi

Moderne HTTPS beteken dat passiewe bure gewoonlik nie behoorlik geënkripteerde webinhoud kan lees nie, maar gas-Wi-Fi bied nie anonimiteit nie. Die lokaal kan verbindingstye, toestelidentifiseerders, captive-portal-data, bestemmings en DHCP-besonderhede aanteken; kameras, aankope, vervoer en fisiese waarneming kan die gebruiker identifiseer. ’n Vals hotspot met ’n soortgelyke naam kan ook portal-aanmeldbesonderhede vaslê of ongeënkripteerde verkeer manipuleer.<sup>[[9]](#references)</sup>

### Wettige werkvloei vir ’n gasnetwerk

1. Gebruik slegs ’n netwerk wat vir gaste aangebied word of waarvoor die eienaar uitdruklike toestemming gegee het. Vra personeel vir die presiese SSID en portal-prosedure.
2. Dateer die eindpunt en reisroeteerder op voor aankoms. Deaktiveer lêer-/drukkerdeling, inkomende ontdekking, outomatiese aansluiting en die soek na gestoorde netwerke.
3. Skakel die bedryfstelsel se private/gerandomiseerde Wi-Fi-adres aan. Huidige Apple-stelsels kan roterende adresse op oop/swak netwerke gebruik; moderne Android-randomisering is gewoonlik permanent per SSID. Dit verminder slegs een plaaslike identifiseerder.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Verkies ’n reisroeteerder wat deur die organisasie beheer word, of ’n brugtoestel met lae vertroue tussen ’n werkstasie met bevoorregte toegang en die gasnetwerk. Dit sentraliseer firewall-/VPN-beleid, maar verberg nie die roeteerder vir die lokaal nie.<sup>[[12]](#references)</sup>
5. Voltooi ’n captive portal slegs deur die aangewese toestel/browser met lae vertroue. Moet nooit persoonlike of hergebruikte aanmeldbesonderhede vir ’n sogenaamd anonieme konteks invoer nie. Maak die portal-browser toe nadat verbinding tot stand gebring is.
6. Begin ’n full-tunnel-VPN of Tor voor sensitiewe aktiwiteit en bevestig dat dit faalgesluit is.
7. Vergeet die netwerk ná gebruik en hersien die portal-rekening-/databewaringsbeleid.

{% hint style="danger" %}
Om ’n buurman se Wi-Fi te kraak, ’n portal te omseil, gelekte gas-aanmeldbesonderhede te gebruik, ’n ander gas se toegang te kloon of ’n Raspberry Pi in ’n kafee weg te steek, is ongemagtigde aktiwiteit—nie ’n privaatheidstegniek nie. Die veilige alternatiewe is ’n wettige gasnetwerk, ’n kliëntgoedgekeurde terrein of ’n gedokumenteerde drop node wat met die eiendomseienaar se skriftelike toestemming geplaas en verwyder word.
{% endhint %}

## Reisroeteerders

’n Reisroeteerder kan ’n werkstasie van vyandige plaaslike broadcasts isoleer, ’n firewall afdwing, ’n konsekwente interne SSID verskaf en outomaties weer aan ’n VPN koppel. Dit is **nie** anoniem nie: die stroomop-netwerk sien sy radio-identiteit en verkeerspatrone, en sy VPN-verskaffer sien die bron van die tonnel.

- Gebruik ondersteunde OpenWrt-/verskaffer-firmware en verwyder ongebruikte dienste.
- Administreer oor Ethernet of ’n toegewyde bestuurs-SSID met ’n unieke wagwoord.
- Deaktiveer WAN-bestuur, UPnP, WPS, lêerdeling en ongevraagde inkomende verkeer.
- Gebruik ’n gerandomiseerde/private WAN MAC slegs waar dit ondersteun en toegelaat word.
- Dwing VPN-beleid op die roeteerder af, insluitend DNS en IPv6, en blokkeer uitgaande verkeer wanneer die tonnel faal.
- Moenie aanvaar dat ’n foon-hotspot vasgemaakte toestelle deur die foon se VPN tonnel nie; toets dit.

## Sellulêr, SIM’s en eSIM’s

Sellulêre konneksie is gerieflik, maar nie anoniem nie. Operateurs hou intekenaar-/toestelidentifiseerders en liggingdata by wat uit netwerkverbinding afgelei word; ’n eSIM is steeds ’n mobiele intekening. Voorafbetaal beteken nie betroubaar ongeregistreer nie—vereistes verskil per land en verander.<sup>[[13]](#references)</sup>

Operasioneel:

- Gebruik ’n aparte, ondersteunde toestel om blootstelling van persoonlike data te verminder, nie om ’n fiktiewe intekenaar te skep nie.
- Moenie ’n “aparte” toestel voortdurend saam met ’n persoonlike foon dra as saambestaan op dieselfde plek deel van die bedreigingsmodel is nie.
- Deaktiveer ongebruikte sellulêre, Wi-Fi-, Bluetooth- en liggingtoegang; afskakel bied ’n sterker radiogrens as koppelvlaktoggles.
- Plaas sensitiewe verkeer binne die goedgekeurde VPN/Tor-roete, maar onthou dat die diensverskaffer steeds die intekening/toestelligging en tonnel-eindpunt ken.
- Verifieer huidige registrasie- en bewaringsreëls by die nasionale reguleerder of plaaslike regsadviseur; moenie staatmaak op aanlyn lyste van “anonieme SIM-lande” nie.

## DNS- en TLS-metadata

- **DoH/DoT/DoQ** enkripteer DNS tussen die kliënt en resolver en voorkom eenvoudige plaaslike lees of wysiging, maar die resolver sien steeds navrae en vervoeridentifiseerders. Dit verskuif vertroue; dit bied nie anonimiteit nie.<sup>[[14]](#references)</sup>
- **ODoH** voeg ’n proxy by sodat die resolver nie die kliënt-IP hoef te ken nie, mits die proxy en teiken nie saamsweer nie. Verkeersanalise val uitdruklik buite die bestek daarvan.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** kan die interne bedienernaam in ’n TLS-handdruk beskerm wanneer die kliënt, DNS en bediener dit ondersteun. Bestemming-IP, tydsberekening, volume en die eindpunt bly sigbaar.<sup>[[16]](#references)</sup>
- Met ’n korrek opgestelde VPN- of Tor-omgewing behoort DNS die omgewing se ondersteunde roete te volg. Die byvoeging van ’n aparte resolver kan ’n nuwe waarnemer of vingerafdruk skep.

### Verifikasiewerkvloei vir geënkripteerde DNS/ECH

1. Besluit of DNS deur die VPN-/Tor-omgewing, die bedryfstelsel of die toepassing beheer word. Stel dit in **een** beoogde laag op, eerder as om onverwante resolvers op mekaar te stapel.
2. Kies ’n resolver op grond van sy gepubliseerde privaatheids-/bewaringsbeleid en aktiveer streng geënkripteerde modus waar die platform dit ondersteun. Opportunistiese terugval kan ongemerk na gewone teks terugkeer.
3. Doen ’n navraag vir ’n unieke subdomein onder ’n gesaghebbende toetszone wat jy beheer; bevestig dat die gesaghebbende log die beoogde rekursiewe resolver sien.
4. Vang slegs die toets toestel se verkeer vas, met toestemming. Bevestig dat die toegangsnetwerk gewone teks-DNS nie kan lees nie, maar onthou dat dit die geënkripteerde resolver-/tonnel-eindpunt kan sien.
5. Toets ’n geblokkeerde/ontoeganklike geënkripteerde resolver. Die slaagkriterium is die gekose faalgeslote of gedokumenteerde terugvalgedrag—nie ’n toevallige navraag in gewone teks nie.
6. Gebruik vir ECH ’n beheerde ECH-geaktiveerde gasheer en ondersoek kliënt-/bedienerdiagnostiek om te bevestig dat die **interne** ClientHello aanvaar is. Die blote aanbied van ’n HTTPS-rekord bewys nie dat ECH geslaag het nie.
7. Herhaal ná netwerkveranderinge, captive portals, browser-opdaterings en VPN-herverbindings. Teken aan watter komponent DNS/ECH beheer, sodat latere administrateurs nie ’n omseiling skep nie.

## Mixnets

Mixnets soos Nym of Katzenpost voeg pakkette van vaste grootte, vertragings, herrangskikking en dekkingverkeer by om tydsberekeningskorrelasie teë te werk. Dié eienskappe kos latensie en bandwydte, en onafhanklike bewyse op ontplooiingskaal is beperk. Beskou huidige mixnets vir verbruikers as **ontluikende/hoë-latensie-opsies**, nie as vinniger of gewaarborgde plaasvervangers vir Tor/VPN’s nie.<sup>[[17]](#references)</sup>

### Evalueringswerkvloei

1. Identifiseer ’n onderhoude kliënt en die presiese ondersteunde toepassing; moenie arbitrêre browser-/stelselverkeer deur ’n ongedokumenteerde proxy forseer nie.
2. Lees die huidige bedreigingsmodel vir toegangspunt, mix nodes, gateway, bestemming en aannames oor samespanning.
3. Installeer vanaf die amptelike ondertekende bron in ’n aparte toetskompartement en gebruik slegs ’n onskadelike eindpunt wat jy besit.
4. Meet afleweringslatensie, boodskapgroottebeperkings, betroubaarheid, heruitsendings en wat gebeur wanneer die gateway onbeskikbaar is.
5. Ondersoek plaaslike verkeer en die eindpunt wat jy besit om die beoogde roete en bron te bevestig. Kyk of antwoorde dieselfde privaatheidsontwerp gebruik.
6. Toets afskakeling/faling: die toepassing mag nie ongemerk terugval na direkte internettoegang nie.
7. Moenie dekkingverkeer deaktiveer, vertragings verminder of ongewone vaste roetes kies net vir spoed nie; sulke veranderinge kan die gestelde anonimiteitsmodel ongeldig maak.
8. Hou dit eksperimenteel totdat die spesifieke ontplooiing, onafhanklike ontleding en operasionele betroubaarheid by die gevolgrisikovlak pas.

## Netwerkvoorafkontrolelys

- [ ] Magtiging dek die toegangsnetwerk, teiken, datums en broninfrastruktuur.
- [ ] Die eindpunt bevat geen onverwante identiteite of aktiewe sinkroniseringsessies nie.
- [ ] IPv4-, IPv6-, DNS- en herverbindingsgedrag stem ooreen met die plan.
- [ ] Beheerde DHCP-/plaaslike-subnet-roete-inspuiting kan nie toetsverkeer na die fisiese koppelvlak verskuif nie.
- [ ] Die bestemming sien slegs die verwagte uitgangspunt.
- [ ] Captive-portal- en hotspotgedrag is sonder sensitiewe verkeer getoets.
- [ ] Plaaslike deling/ontdekking en outomatiese aansluiting by netwerke is gedeaktiveer.
- [ ] Die waarnemerstabel en oorblywende risiko van verkeerskorrelasie is aanvaar.
- [ ] Verskafferbeleid, bewaring en noodkontak is op datum.

Vir relays met verdeelde kennis, roete-afgedwonge werkladings, pluggable transports, onion services, I2P en tydelike afgeleë browsers, gaan voort na [Gevorderde netwerkprivaatheidsargitekture](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Kies die VPN wat reg is vir jou](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Riglyne vir toestelbeveiliging: Virtuele privaat netwerke](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Die privaatheids- en anonimiteitsbeskerming wat Tor bied](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — ’n Kort inleiding tot Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Gebruik Tor met ander browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins en add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Ontblokkering van Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Gebruik Tor Browser met ’n VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Is openbare Wi-Fi-netwerke veilig?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi-privaatheid met Apple-toestelle](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementeer MAC-randomisering](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Beginsels vir veilige werkstasies met bevoorregte toegang](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Verpligte SIM-registrasie: beleids- en regulatoriese perspektiewe](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Aanbevelings vir operateurs van DNS-privaatheidsdienste](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS oor HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Bedreigingsmodel](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Omseiling van tonnels: Lekking van VPN-kliëntverkeer deur roetetabelle te misbruik](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Hoe aanvallers roetegebaseerde VPN’s kan ontmasker en ’n totale VPN-leak kan veroorsaak](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil FAQ: Is Yggdrasil anoniem?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
