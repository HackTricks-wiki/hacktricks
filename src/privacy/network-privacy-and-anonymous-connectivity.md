# Netwerkprivaatheid en anonieme verbinding

{{#include ../banners/hacktricks-training.md}}

Netwerkprivaatheid is 'n roeteringsbesluit, nie volledige identiteit nie. Kies 'n pad deur te vra wie nie die **bron**, **bestemming**, **inhoud** en **tydsberekening** behoort te kan verbind nie.

Vir die genormaliseerde inventaris—`Pros`, `Cons`, stap-vir-stap `Procedure`, en `Detection` vir elke toegangs-padfamilie—begin met die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Hierdie bladsy brei die algemeen ontplooibare opsies uit.

## Wat elke waarnemer gewoonlik kan sien

| Pad | Plaaslike netwerk / ISP | Tussenganger | Bestemming | Belangrikste beperking | Relatiewe spoed |
|---|---|---|---|---|---|
| Direkte HTTPS | Bron, bestemmingmetadata, tydsberekening/volume | Hosting/CDN sien verbinding | Bron-IP, blaaier-/toepassingsdata | Geen bron-IP-privaatheid nie | Vinnigste |
| Kommersiële VPN | Bron gekoppel aan VPN; nie gewone bestemmingmetadata nie | VPN sien bron- en bestemmingmetadata | VPN-uitgangs-IP | Een verskaffer word 'n korrelasiepunt | Gewoonlik vinnig |
| Self-gehoste VPN/VPS | Bron gekoppel aan VPS | Gasheer-/rekening-/betaling-/beheerlaag-logboeke | VPS-uitgangs-IP | Maklik toe te skryf aan die gehuurde bediener/rekening | Gewoonlik vinnig |
| Tor Browser | Bron gekoppel aan Tor/bridge; tydsberekening/volume | Relays sien elk 'n beperkte gedeelte | Tor-exit, blaaierdata | Stadiger; rekening-/endpoint-/korrelasierisiko's | Gematig/stadig |
| Tails/Whonix | Soortgelyke Tor-pad, met sterker roeteringsgrense | Dieselfde Tor-beperkings | Tor-exit/toepassingsdata | Operasionele foute en gasheer/hardeware bly oor | Gematig/stadig |
| Publieke gaste-Wi-Fi + HTTPS | Lokaal sien toestel/tydsberekening en bestemmings | Lokaal se ISP sien metadata | Gastepublieke IP | Fisiese/kaptiewe-portaal-/toestelkorrelasie | Vinnig/wisselvallig |
| Sellulêre hotspot | Draer sien intekenaar/toestel/ligging en bestemmings | VPN/Tor indien gebruik | Draer-, VPN- of Tor-uitgangs-IP | Mobiele intekening en ligging is blywende identifiseerders | Vinnig/wisselvallig |
| Mixnet | Toegang sien mixnet-gebruik; tydsberekening/volume | Veelvuldige mixing nodes | Gateway/uitgang | Ontluikende ekosisteem; latensie- en bandwydtekoste | Stadigste |

HTTPS beskerm inhoud tydens oordrag, maar nie alle metadata nie. EFF merk op dat domein, tyd en verkeersgrootte vir tussengangers sigbaar kan bly, selfs wanneer bladsy-paaie, geloofsbriewe en boodskappe geënkripteer is.<sup>[[1]](#references)</sup>

## VPN's: vinnige privaatheid met gekonsentreerde vertroue

'n VPN is nuttig om bestemmingmetadata vir die toegangs-ISP te verberg, 'n eerste hop op 'n onvertroude netwerk te beskerm, 'n stabiele engagement-uitgangsadres te toon, of 'n private netwerk te bereik. Dit maak 'n gebruiker **nie** anoniem nie. Die VPN sien die bronverbinding en kan bestemmingmetadata waarneem; rekeninge, koekies, GPS, fingerprints en betalingsinligting bly sigbaar.<sup>[[1]](#references)</sup>

### Kontrolelys vir verskafferevaluering

1. **Eienaarskap en jurisdiksie:** identifiseer die regsentiteit, moedermaatskappy, bedryfslande, infrastruktuur-onderaannemers en toepaslike regsprosesse.
2. **Versamelde data:** onderskei tussen rekening-/faktureringdata, bron-IP, verbindingstydstempels, bandwydte, crash-telemetrie, DNS-navrae en bestemmingslogboeke. “Geen browsing logs” beteken nie “geen data” nie.
3. **Bewaring en verwydering:** vind presiese tydsduur en of backups, fraudestelsels en verwerkers dieselfde skedule volg.
4. **Bewyse:** verkies openbare audits met omvang, datum, bevindings en regstelling; reproduseerbare/open clients; deursigtigheidsverslae; en gedokumenteerde insidente.
5. **Protokol en client:** onderhoude WireGuard, OpenVPN of 'n ander hersiene protokol; outomatiese updates; DNS- en IPv6-hantering; kill switch; en per-platform leak-toetse.
6. **Besigheidsmodel:** verstaan hoe 'n gratis of gesubsidieerde diens befonds word. Teenwoordigheid in 'n app store is op sigself nie bewys van betroubare werking nie.
7. **Betalingspassing:** alternatiewe betaling kan faktureringsopenbaring aan die VPN verminder, maar vee nie die bron-IP uit wat by elke verbinding waargeneem word nie.

### Konfigureer en verifieer 'n VPN

1. Installeer die verskaffer/organisasie se getekende client vanaf sy amptelike bron.
2. Kies **full tunnel** tensy 'n gedokumenteerde roete dit moet omseil. Split tunneling skep korrelasie- en leak-paaie.
3. Aktiveer fail-closed/always-on-gedrag en blokkeer verkeer tydens herverbinding.
4. Stuur DNS deur die tunnel en toets beide IPv4 en IPv6. Deaktiveer 'n protokol slegs indien dit nie veilig deur die tunnel gestuur kan word nie en die verlies aan funksionaliteit aanvaar word.
5. Toets slaap/wakker-word, netwerkwisseling, kaptiewe-portaal-aanmelding, tunnel-crash en hotspot-tethering. NCSC waarsku dat getetherde clients op sommige platforms 'n foon se VPN kan omseil.<sup>[[2]](#references)</sup>
6. Gebruik 'n organisasie-beheerde toets-endpoint om waargenome IPv4, IPv6, DNS-resolver en verbindingstydsberekening aan te teken. Moenie 'n sensitiewe engagement aan willekeurige “leak test”-webwerwe blootstel nie.
7. Toets weer ná client-, OS-, netwerk- of beleidsveranderings.

### Roeteringsomseilings op vyandige LAN's

'n VPN kan sigbaar “gekoppel” bly terwyl geselekteerde pakkette dit omseil, omdat die bedryfstelsel 'n roete kies **voordat** die VPN die pakket enkripteer. TunnelCrack het twee maniere gedemonstreer om algemene roeteringsuitsonderings te misbruik: **LocalNet** laat 'n Internet-bestemming lyk asof dit op die direk gekoppelde subnet is, terwyl **ServerIP** VPN-gateway-resolusie vervals sodat 'n teikenadres die clear-network-uitsondering erf wat die VPN-transport benodig. Dit is client-/roeteringsfoute eerder as breuke in WireGuard, OpenVPN, IPsec of TLS; HTTPS-payloads bly end-tot-end geënkripteer, maar die plaaslike waarnemer kan bestemming-/tydsberekeningsmetadata en enige cleartext-protokoldata herwin.<sup>[[18]](#references)</sup>

TunnelVision pas dieselfde pre-encryption-primitief deur DHCP-opsie 121 toe. 'n Kwaadwillige of gekompromitteerde DHCP-bediener kan 'n classless route installeer wat meer spesifiek as die VPN se catch-all-roete is, en sodoende die fisiese koppelvlak vir 'n arbitrêre gasheer of reeks kies. Die VPN-beheerkanaal kan aktief bly, sodat 'n kill switch wat slegs deur tonneldiskonneksie geaktiveer word, moontlik nie sal aktiveer nie en 'n enkele openbare “IP leak”-kontrole selektiewe omseilings kan mis.<sup>[[19]](#references)</sup>

'n Packet-filter-kill switch wat slegs DHCP en die geverifieerde VPN-transport op die fisiese koppelvlak toelaat, behoort dit in fail-closed-gedrag te omskep, maar geteikende roete-inspuiting kan steeds 'n selektiewe-denial-side-channel skep. Vir Linux-workloads met hoë gevolge, verkies die sterker [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), waar die toepassingsnamespace geen fisiese koppelvlak of clear-network-verstekroete het nie.<sup>[[19]](#references)</sup>

#### Verifikasie in 'n beheerde laboratorium

Toets die presiese client/OS/weergawe op 'n besitte AP, DHCP-bediener, VPN-endpoint en bestemming; produk-wye aansprake verouder vinnig omdat roeterings- en packet-filter-implementerings platformspesifiek is. Neem vaslegging op die endpoint self sowel as op die toetsbediener—'n webwerf wat slegs die uitgangs-IP wys, bewys nie dat elke bestemming die tunnel volg nie.<sup>[[18]](#references)[[19]](#references)</sup>

1. Koppel die VPN, teken die VPN-bedieneradres aan, en stoor elke IPv4/IPv6-roeteringstabel en policy-routing-reël. Gebruik op Windows `route print`; op macOS `netstat -rn`; op Linux die opdragte hieronder.
2. Doen navraag oor die geselekteerde roete vir verskeie besitte bestemmings-IP's. Die volgende hop/koppelvlak moet die tunnel wees, behalwe vir die gedokumenteerde VPN-transport-endpoint.
3. Vir TunnelVision, hernu die lease op die beheerde DHCP-netwerk en installeer 'n opsie-121-roete **slegs vir 'n besitte toetsbestemming**. 'n Slaag beteken dat verkeer steeds deur die tunnel gestuur of geblokkeer word—dit mag nooit as bestemmingsverkeer op die fisiese koppelvlak uitgestuur word nie.
4. Vir LocalNet, ken die client 'n publieke dokumentasie-subnet wat slegs vir die laboratorium gebruik word, soos `203.0.113.0/24`, toe en plaas die besitte toetsbestemming daarin. Verifieer dat die aktivering van LAN-toegang nie Internet-klas-bestemmings die tunnel laat omseil nie.
5. Vir ServerIP, laat beheerde DNS die besitte VPN-hostname vóór VPN-verbinding na die besitte toetsbestemming oplos, terwyl die laboratoriumgateway die VPN-transport na die werklike besitte VPN-endpoint aanstuur. Die client mag nie onverwante toepassingverkeer na die vervalste adres vrystel nie.
6. Herhaal met “local network access” geaktiveer én gedeaktiveer, ná herverbinding, slaap/wakker-word, netwerkwisseling en 'n VPN-proses-crash. Toets IPv4, IPv6 en DNS onafhanklik.
7. Inspekteer die fisiese-koppelvlak-vaslegging. Dit behoort DHCP en geënkripteerde pakkette na die VPN-bediener te bevat, nie pakkette wat direk aan die besitte toetsbestemming gerig is nie. Bevestig ook dat 'n afgekeurde omseiling nie stilweg kan terugval ná gebruikersaanwysings of konnektiwiteitsherstel nie.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: sterker web-onkoppelbaarheid

Tor bou ’n kring deur verskeie relays sodat geen enkele relay normaalweg beide bron en bestemming ken nie. Die bestemming sien ’n Tor exit eerder as die gebruiker se IP; die plaaslike netwerk sien normaalweg ’n Tor-verbinding.<sup>[[3]](#references)</sup> Tor is ontwerp vir lae-latensie-TCP-toepassings, dus is dit stadiger en kan dit nie beskerming waarborg teen ’n teenstander wat albei kante kan korreleer nie.<sup>[[4]](#references)</sup>

### Veilige Tor Browser-werkvloei

1. Laai Tor Browser slegs van die Tor Project of ’n amptelike mirror af en verifieer die signature wanneer moontlik.
2. Gebruik **Tor Browser**, nie ’n gewone browser wat na ’n Tor SOCKS-port verwys nie. Gewone browsers kan DNS/WebRTC en identifiserende state uitlek.<sup>[[5]](#references)</sup>
3. Behou die verstekgrootte, fonts, extensions en privaatheidsinstellings. Bykomende add-ons kan die browser meer uniek maak.<sup>[[6]](#references)</sup>
4. Kies die **Safer**- of **Safest**-sekuriteitsvlak wanneer die verhoogde breekbaarheid aanvaarbaar is.
5. Gebruik ’n bridge wanneer direkte Tor geblokkeer word of wanneer gewone relay-IP’s onaanvaarbare plaaslike sigbaarheid sou veroorsaak. Bridges verminder maklike herkenning; hulle elimineer nie traffic analysis nie.<sup>[[7]](#references)</sup>
6. Moenie by ’n identifiserende account aanmeld, identifiserende inligting verskaf of afgelaaide aktiewe dokumente in ’n eksterne netwerktoepassing oopmaak nie.
7. Gebruik ’n aparte session/context vir elke identiteit. “New circuit” is nie dieselfde as om browser-/toepassingsidentiteit uit te vee nie; gebruik **New Identity** of herbegin die geïsoleerde omgewing soos toepaslik.
8. Verkies geauthentiseerde HTTPS of ’n geauthentiseerde onion service. ’n Tor exit kan ongeënkripteerde HTTP-verkeer waarneem.

### Tor plus VPN

Om hulle te kombineer is nie outomaties veiliger nie. ’n VPN voor Tor kan direkte Tor-relay-verbindings vir ’n ISP verberg terwyl die VPN die bron sien; Tor voor ’n VPN gee die VPN ’n stabiele beeld van aktiwiteit ná Tor en kan die anonymity set verklein. Verkeerde konfigurasie kan leaks veroorsaak. Tor Project beveel sulke kombinasies slegs aan vir gevorderde, eksplisiete threat models.<sup>[[8]](#references)</sup>

## Openbare en gas-Wi-Fi

Moderne HTTPS beteken dat passiewe bure gewoonlik nie behoorlik geënkripteerde webinhoud kan lees nie, maar gas-Wi-Fi is nie anonimiteit nie. Die lokaal kan verbindingstye, toestelidentifiseerders, captive-portal-data, bestemmings en DHCP-besonderhede aanteken; kameras, aankope, vervoer en fisiese waarneming kan die gebruiker identifiseer. ’n Vals hotspot met ’n soortgelyke naam kan ook portal-aanmeldbesonderhede vaslê of ongeënkripteerde verkeer manipuleer.<sup>[[9]](#references)</sup>

### Wettige gasnetwerk-werkvloei

1. Gebruik slegs ’n netwerk wat vir gaste aangebied word of waarvoor die eienaar uitdruklike toestemming verleen het. Vra personeel vir die presiese SSID en portal-prosedure.
2. Dateer die endpoint en travel router voor aankoms op. Deaktiveer lêer-/drukkerdeling, inbound discovery, auto-join en probing vir onthoude netwerke.
3. Aktiveer die OS se private/randomized Wi-Fi-adres. Huidige Apple-stelsels kan roterende adresse op oop/sw ak netwerke gebruik; moderne Android-randomization is gewoonlik permanent per SSID. Dit verminder slegs een plaaslike identifiseerder.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Verkies ’n organisasie-beheerde travel router of low-trust bridge-toestel tussen ’n bevoorregte workstation en die gasnetwerk. Dit sentraliseer firewall-/VPN-beleid, maar verberg nie die router vir die lokaal nie.<sup>[[12]](#references)</sup>
5. Voltooi ’n captive portal slegs deur die aangewese low-trust-toestel/browser. Moet nooit persoonlike of hergebruikte credentials vir ’n sogenaamd anonieme context invoer nie. Sluit die portal-browser nadat verbinding gevestig is.
6. Begin ’n full-tunnel VPN of Tor voor sensitiewe aktiwiteit en bevestig fail-closed-gedrag.
7. Vergeet die netwerk ná gebruik en hersien die portal-account-/dataretensiebeleid.

{% hint style="danger" %}
Om ’n buurman se Wi-Fi te crack, ’n portal te bypass, gelekte gas-credentials te gebruik, ’n ander gas se toegang te clone of ’n Raspberry Pi in ’n kafee te versteek, is ongemagtigde aktiwiteit—nie ’n privaatheidstegniek nie. Die veilige ekwivalente is ’n wettige gasnetwerk, ’n kliëntgoedgekeurde terrein of ’n gedokumenteerde drop node wat met die eiendomseienaar se skriftelike toestemming geplaas en teruggehaal word.
{% endhint %}

## Travel routers

’n Travel router kan ’n workstation van vyandige plaaslike broadcasts isoleer, ’n firewall afdwing, ’n konsekwente interne SSID verskaf en ’n VPN outomaties herverbind. Dit is **nie** anoniem nie: die upstream sien sy radio-identiteit en verkeerstydsberekening, en sy VPN-provider sien die bron van die tunnel.

- Gebruik ondersteunde OpenWrt/vendor-firmware en verwyder ongebruikte services.
- Administreer oor Ethernet of ’n toegewyde management-SSID met ’n unieke wagwoord.
- Deaktiveer WAN-side-administrasie, UPnP, WPS, lêerdeling en ongevraagde inbound-verkeer.
- Gebruik ’n randomized/private WAN MAC slegs waar dit ondersteun en toegelaat word.
- Dwing VPN-beleid op die router af, insluitend DNS en IPv6, en blokkeer egress wanneer die tunnel faal.
- Moenie aanvaar dat ’n phone hotspot tethered-toestelle deur die phone se VPN tonnel nie; toets dit.

## Cellular, SIM’s en eSIM’s

Cellular is gerieflik maar nie anoniem nie. Operateurs behou subscriber-/toestelidentifiseerders en ligging wat van netwerkattachering afgelei word; ’n eSIM is steeds ’n mobiele subscription. Prepaid beteken nie betroubaar ongeregistreer nie—vereistes verskil per land en verander.<sup>[[13]](#references)</sup>

Operasioneel:

- Gebruik ’n aparte, ondersteunde toestel om blootstelling van persoonlike data te verminder, nie om ’n fiktiewe subscriber te skep nie.
- Moenie voortdurend ’n “aparte” toestel langs ’n persoonlike phone dra as co-location deel van die threat model is nie.
- Deaktiveer ongebruikte cellular, Wi-Fi, Bluetooth en location access; afskakeling is ’n sterker radiogrens as UI-toggles.
- Plaas sensitiewe verkeer binne die goedgekeurde VPN/Tor-pad, terwyl jy erken dat die carrier steeds die subscription/toestelligging en tunnel-endpoint ken.
- Verifieer huidige registrasie- en retensiereëls by die nasionale reguleerder of plaaslike regsadviseur; moenie op aanlynlyste van “anonymous SIM countries” staatmaak nie.

## DNS- en TLS-metadata

- **DoH/DoT/DoQ** enkripteer DNS tussen client en resolver, wat eenvoudige plaaslike lees of wysiging voorkom, maar die resolver sien steeds queries en transport-identifiseerders. Hulle verskuif vertroue; hulle verskaf nie anonimiteit nie.<sup>[[14]](#references)</sup>
- **ODoH** voeg ’n proxy by sodat die resolver nie die client-IP hoef te leer nie, mits proxy en target nie saamspan nie. Traffic analysis is uitdruklik buite omvang.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** kan die interne servernaam in ’n TLS-handshake beskerm wanneer client, DNS en server dit ondersteun. Bestemming-IP, tydsberekening, volume en die endpoint bly sigbaar.<sup>[[16]](#references)</sup>
- Met ’n korrek gekonfigureerde VPN- of Tor-omgewing behoort DNS daardie omgewing se ondersteunde roete te volg. Die byvoeging van ’n aparte resolver kan ’n nuwe waarnemer of fingerprint skep.

### Encrypted-DNS/ECH-verifikasie-werkvloei

1. Bepaal of DNS deur die VPN/Tor-omgewing, die OS of die toepassing beheer word. Konfigureer dit in **een** beoogde laag eerder as om onverwante resolvers te stapel.
2. Kies ’n resolver volgens sy gepubliseerde privaatheids-/retensiebeleid en aktiveer strict encrypted mode waar die platform dit ondersteun. Opportunistic fallback kan stilweg na plaintext terugkeer.
3. Query ’n unieke subdomain onder ’n authoritative test zone wat jy beheer; bevestig dat die authoritative log die beoogde recursive resolver sien.
4. Capture slegs die toets-toestel se verkeer met toestemming. Bevestig dat die toegangnetwerk nie plaintext DNS kan lees nie, terwyl jy erken dat dit die encrypted resolver-/tunnel-endpoint kan sien.
5. Toets ’n geblokkeerde/onbereikbare encrypted resolver. Die slaagtoestand is die gekose fail-closed- of gedokumenteerde fallback-gedrag—nie ’n toevallige clear query nie.
6. Gebruik vir ECH ’n beheerde ECH-enabled host en inspekteer client-/server-diagnostics om te bevestig dat die **inner** ClientHello aanvaar is. Die blote aanbieding van ’n HTTPS-record bewys nie dat ECH geslaag het nie.
7. Herhaal ná netwerkveranderinge, captive portals, browser-opdaterings en VPN-herverbindings. Teken aan watter komponent DNS/ECH besit sodat latere administrators nie ’n bypass skep nie.

## Mixnets

Mixnets soos Nym of Katzenpost voeg fixed-size packets, delay, reordering en cover traffic by om timing correlation te weerstaan. Hierdie eienskappe kos latency en bandwydte, en onafhanklike bewyse op deployment-skaal is beperk. Behandel huidige consumer mixnets as **emerging/high-latency options**, nie as vinniger of gewaarborgde plaasvervangers vir Tor/VPN’s nie.<sup>[[17]](#references)</sup>

### Evaluasie-werkvloei

1. Identifiseer ’n onderhoude client en die presies ondersteunde toepassing; moenie arbitrêre browser-/stelselverkeer deur ’n ongedokumenteerde proxy forseer nie.
2. Lees die huidige threat model vir entry, mix nodes, gateway, destination en collusion-aannames.
3. Installeer vanaf die amptelike signed source in ’n aparte toetscompartment en gebruik slegs ’n onskadelike endpoint wat jy besit.
4. Meet afleweringslatency, message-size limits, betroubaarheid, retransmission en wat gebeur wanneer die gateway onbeskikbaar is.
5. Inspekteer plaaslike verkeer en die endpoint wat jy besit om die beoogde pad en bron te bevestig. Kontroleer of replies dieselfde privaatheidsontwerp gebruik.
6. Toets shutdown/failure: die toepassing mag nie stilweg na direkte Internet-toegang terugval nie.
7. Moenie cover traffic deaktiveer, delays verminder of ongewone fixed routes kies bloot vir spoed nie; hierdie veranderinge kan die gestelde anonymity model ongeldig maak.
8. Hou dit eksperimenteel totdat die spesifieke deployment, onafhanklike analise en operasionele betroubaarheid by die consequence level pas.

## Netwerk-preflight-kontrolelys

- [ ] Magtiging dek die toegangnetwerk, target, datums en broninfrastruktuur.
- [ ] Die endpoint bevat geen onverwante identiteite of aktiewe sync-sessies nie.
- [ ] IPv4, IPv6, DNS en reconnect-gedrag stem met die plan ooreen.
- [ ] Beheerde DHCP-/local-subnet-route-injection kan nie toetsverkeer na die fisiese interface verskuif nie.
- [ ] Die bestemming sien slegs die verwagte egress.
- [ ] Captive-portal- en hotspot-gedrag is sonder sensitiewe verkeer getoets.
- [ ] Plaaslike sharing/discovery en outomatiese netwerkjoining is gedeaktiveer.
- [ ] Die observer table en oorblywende traffic-correlation risk word aanvaar.
- [ ] Provider policy, retention en emergency contact is op datum.

Vir split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P en disposable remote browsers, gaan voort na [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Die keuse van die VPN wat reg is vir jou](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Toestelsekuriteitsriglyne: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Die privaatheids- en anonimiteitsbeskerming wat Tor bied](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — ’n Kort inleiding tot Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Gebruik van Tor met ander browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins en add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Deblokkering van Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Gebruik van Tor Browser met ’n VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Is openbare Wi-Fi-netwerke veilig?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi-privaatheid met Apple-toestelle](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementering van MAC-randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Beginsels vir veilige bevoorregte toegang-workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Verpligte SIM-registrasie: beleids- en regulatoriese perspektiewe](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Aanbevelings vir DNS-privaatheidsdiensoperateurs](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS oor HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Bypassing Tunnels: Leaking VPN Client Traffic by Abusing Routing Tables](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: How Attackers Can Decloak Routing-Based VPNs for a Total VPN Leak](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
