# Netwerkprivaatheid & Anonieme Verbinding

Netwerkprivaatheid is 'n roeteringsbesluit, nie 'n volledige identiteit nie. Kies 'n pad deur te vra wie nie **bron**, **bestemming**, **inhoud** en **tydsberekening** moet kan verbind nie.

Vir die genormaliseerde inventaris—`Pros`, `Cons`, stap-vir-stap `Procedure`, en `Detection` vir elke toegangs-padfamilie—begin met die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Hierdie bladsy brei die algemene ontplooibare opsies uit.

## Wat elke waarnemer gewoonlik kan sien

| Pad | Plaaslike netwerk / ISP | Tussenganger | Bestemming | Belangrikste beperking | Relatiewe spoed |
|---|---|---|---|---|---|
| Direkte HTTPS | Bron, bestemmingmetadata, tydsberekening/volume | Hosting/CDN sien verbinding | Bron-IP, blaaier-/appdata | Geen bron-IP-privaatheid nie | Vinnigste |
| Kommersiële VPN | Bron gekoppel aan VPN; nie gewone bestemmingmetadata nie | VPN sien bron- en bestemmingmetadata | VPN-uitgangs-IP | Een verskaffer word 'n korrelasiepunt | Gewoonlik vinnig |
| Self-gehoste VPN/VPS | Bron gekoppel aan VPS | Host-/rekening-/betaling-/beheerlaag-logboeke | VPS-uitgangs-IP | Maklik aan die gehuurde bediener/rekening toe te skryf | Gewoonlik vinnig |
| Tor Browser | Bron gekoppel aan Tor/bridge; tydsberekening/volume | Relays sien elk 'n beperkte gedeelte | Tor-exit, blaaierdata | Stadiger; rekening-/endpoint-/korrelasierisiko's | Matig/stadig |
| Tails/Whonix | Soortgelyke Tor-pad, met sterker roeteringsgrense | Dieselfde Tor-beperkings | Tor-exit/toepassingsdata | Operasionele foute en host/hardeware bly | Matig/stadig |
| Openbare gas-Wi-Fi + HTTPS | Lokaaletoestel-/tydsberekening en bestemmings sigbaar vir lokaal | Lokaal se ISP sien metadata | Gas se publieke IP | Fisiese/captive-portal-/toestelkorrelasie | Vinnig/veranderlik |
| Sellulêre hotspot | Draer sien intekenaar/toestel/ligging en bestemmings | VPN/Tor indien gebruik | Draer-, VPN- of Tor-uitgangs-IP | Mobiele intekening en ligging is duursame identifiseerders | Vinnig/veranderlik |
| Mixnet | Toegang sien mixnet-gebruik; tydsberekening/volume | Veelvuldige mixing nodes | Gateway/uitgang | Ontluikende ekosisteem; koste in latency en bandwydte | Stadigste |

HTTPS beskerm inhoud onderweg, maar nie alle metadata nie. EFF merk op dat domein, tyd en verkeersgrootte vir tussengangers sigbaar kan bly selfs wanneer bladsy-paaie, geloofsbriewe en boodskappe geënkripteer is.<sup>[[1]](#references)</sup>

## VPNs: vinnige privaatheid met gekonsentreerde vertroue

'n VPN is nuttig om bestemmingmetadata vir die toegangs-ISP te versteek, 'n eerste hop op 'n onvertroude netwerk te beskerm, 'n stabiele engagement-uitgangsadres te bied, of toegang tot 'n private netwerk te verkry. Dit maak 'n gebruiker **nie** anoniem nie. Die VPN sien die bronverbinding en kan bestemmingmetadata waarneem; rekeninge, cookies, GPS, fingerprints en betalingsinligting bly bestaan.<sup>[[1]](#references)</sup>

### Kontrolelys vir verskafferevaluering

1. **Eienaarskap en jurisdiksie:** identifiseer die regsentiteit, moedermaatskappy, bedryfslande, infrastruktuur-onderaannemers en toepaslike regsproses.
2. **Versamelde data:** onderskei tussen rekening-/fakturering-, bron-IP-, verbindingstydstempel-, bandwydte-, crash-telemetry-, DNS-navraag- en bestemmingslogboeke. “No browsing logs” beteken nie “no data” nie.
3. **Bewaring en verwydering:** vind presiese tydperke en of rugsteune, fraudestelsels en verwerkers dieselfde skedule volg.
4. **Bewyse:** verkies openbare audits met omvang, datum, bevindings en herstelmaatreëls; reproduceerbare/open clients; deursigtigheidsverslae; en gedokumenteerde insidente.
5. **Protokol en client:** Ondersteunde WireGuard, OpenVPN of 'n ander nagegane protokol; outomatiese opdaterings; DNS- en IPv6-hantering; kill switch; en per-platform leak-toetse.
6. **Besigheidsmodel:** verstaan hoe 'n gratis of gesubsidieerde diens befonds word. Blote teenwoordigheid in 'n app store is nie bewys van betroubare bedryf nie.
7. **Betalingsgeskiktheid:** alternatiewe betaling kan faktureringsopenbaarmaking aan die VPN verminder, maar verwyder nie die bron-IP wat by elke verbinding waargeneem word nie.

### Stel 'n VPN op en verifieer dit

1. Installeer die verskaffer/organisasie se ondertekende client vanaf die amptelike bron.
2. Kies **full tunnel** tensy 'n gedokumenteerde roete dit moet omseil. Split tunneling skep korrelasie- en leak-paaie.
3. Aktiveer fail-closed/always-on-gedrag en blokkeer verkeer tydens herverbinding.
4. Stuur DNS deur die tunnel en toets beide IPv4 en IPv6. Deaktiveer 'n protokol slegs indien dit nie veilig getunnel kan word nie en die verlies aan funksionaliteit aanvaar word.
5. Toets slaap/wakker word, netwerkwisseling, captive-portal-aanmelding, tunnel-crash en hotspot-tethering. NCSC waarsku dat getetherde clients op sommige platforms 'n foon se VPN kan omseil.<sup>[[2]](#references)</sup>
6. Gebruik 'n organisasie-beheerde toets-endpoint om waargenome IPv4, IPv6, DNS-resolver en verbindingstydsberekening aan te teken. Moenie 'n sensitiewe engagement aan willekeurige “leak test”-werwe blootstel nie.
7. Toets weer ná client-, OS-, netwerk- of beleidsveranderinge.

## Tor Browser: sterker web-onkoppelbaarheid

Tor bou 'n circuit deur veelvuldige relays sodat geen enkele relay normaalweg beide bron en bestemming ken nie. Die bestemming sien 'n Tor-exit eerder as die gebruiker se IP; die plaaslike netwerk sien normaalweg 'n Tor-verbinding.<sup>[[3]](#references)</sup> Tor is ontwerp vir lae-latency TCP-toepassings, en is dus stadiger en kan nie beskerming waarborg teen 'n adversary wat albei kante kan korreleer nie.<sup>[[4]](#references)</sup>

### Veilige Tor Browser-werkvloei

1. Laai Tor Browser slegs van die Tor Project of 'n amptelike mirror af en verifieer die signature waar moontlik.
2. Gebruik **Tor Browser**, nie 'n gewone blaaier wat na 'n Tor SOCKS-port wys nie. Gewone blaaiers kan DNS/WebRTC en identifiserende state leks.<sup>[[5]](#references)</sup>
3. Behou die verstekgrootte, fonts, extensions en privaatheidinstellings. Bykomende add-ons kan die blaaier meer uniek maak.<sup>[[6]](#references)</sup>
4. Kies die **Safer** of **Safest**-sekuriteitsvlak wanneer die verhoogde onversoenbaarheid aanvaarbaar is.
5. Gebruik 'n bridge wanneer direkte Tor geblokkeer word of wanneer gewone relay-IP's onaanvaarbare plaaslike sigbaarheid sou skep. Bridges verminder maklike herkenning; hulle elimineer nie traffic analysis nie.<sup>[[7]](#references)</sup>
6. Moenie by 'n identifiserende rekening aanmeld, identifiserende inligting verskaf of afgelaaide aktiewe dokumente in 'n eksterne netwerktoepassing oopmaak nie.
7. Gebruik 'n aparte sessie/konteks vir elke identiteit. “New circuit” is nie dieselfde as om blaaier-/toepassingsidentiteit uit te wis nie; gebruik **New Identity** of herbegin die geïsoleerde omgewing soos toepaslik.
8. Verkies geauthentiseerde HTTPS of 'n geauthentiseerde onion service. 'n Tor-exit kan ongeënkripteerde HTTP-verkeer waarneem.

### Tor plus VPN

Die kombinasie is nie outomaties veiliger nie. 'n VPN voor Tor kan direkte Tor-relayverbindings vir 'n ISP versteek terwyl die VPN die bron sien; Tor voor 'n VPN gee die VPN 'n stabiele beeld van aktiwiteit ná Tor en kan die anonymity set verklein. Wankonfigurasie kan leaks veroorsaak. Tor Project beveel sulke kombinasies slegs aan vir gevorderde, eksplisiete threat models.<sup>[[8]](#references)</sup>

## Openbare en gas-Wi-Fi

Moderne HTTPS beteken dat passiewe bure gewoonlik nie behoorlik geënkripteerde webinhoud kan lees nie, maar gas-Wi-Fi is nie anonimiteit nie. Die lokaal kan assosiasietye, toestelidentifiseerders, captive-portal-data, bestemmings en DHCP-besonderhede aanteken; kameras, aankope, vervoer en fisiese waarneming kan die gebruiker identifiseer. 'n Vals hotspot met 'n soortgelyke naam kan ook portal-geloofsbriewe vaslê of ongeënkripteerde verkeer manipuleer.<sup>[[9]](#references)</sup>

### Wettige gasnetwerk-werkvloei

1. Gebruik slegs 'n netwerk wat vir gaste aangebied word of waarvoor die eienaar uitdruklike toestemming verleen het. Vra personeel vir die presiese SSID en portalprosedure.
2. Dateer die endpoint en travel router op voor aankoms. Deaktiveer lêer-/drukkerdeling, inkomende discovery, auto-join en probing vir gestoorde netwerke.
3. Aktiveer die OS se private/randomized Wi-Fi-adres. Huidige Apple-stelsels kan roterende adresse op oop/swakkere netwerke gebruik; moderne Android-randomization is gewoonlik persistent per SSID. Dit verminder slegs een plaaslike identifiseerder.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Verkies 'n organisasie-beheerde travel router of low-trust bridge-toestel tussen 'n geprivilegeerde werkstasie en die gasnetwerk. Dit sentraliseer firewall/VPN-beleid, maar versteek nie die router vir die lokaal nie.<sup>[[12]](#references)</sup>
5. Voltooi 'n captive portal slegs deur die aangewese low-trust-toestel/-blaaier. Moet nooit persoonlike of hergebruikte geloofsbriewe vir 'n sogenaamd anonieme konteks invoer nie. Sluit die portalblaaier nadat verbinding gevestig is.
6. Begin 'n full-tunnel VPN of Tor voor sensitiewe aktiwiteit en bevestig fail-closed-gedrag.
7. Vergeet die netwerk ná gebruik en hersien die portal se rekening-/dataretensiebeleid.

{% hint style="danger" %}
Om 'n buurman se Wi-Fi te crack, 'n portal te omseil, gelekte gasgeloofsbriewe te gebruik, 'n ander gas se toegang te kloon of 'n Raspberry Pi in 'n kafee weg te steek, is ongemagtigde aktiwiteit—nie 'n privaatheidstegniek nie. Die veilige ekwivalente is 'n wettige gasnetwerk, 'n client-goedgekeurde terrein of 'n gedokumenteerde drop node wat met die eiendomseienaar se skriftelike toestemming geplaas en teruggekry word.
{% endhint %}

## Travel routers

'n Travel router kan 'n werkstasie van vyandige plaaslike broadcasts isoleer, 'n firewall afdwing, 'n konsekwente interne SSID bied en 'n VPN outomaties herverbind. Dit is **nie** anoniem nie: die upstream sien sy radio-identiteit en verkeerstydsberekening, en sy VPN-verskaffer sien die tunnelsource.

- Gebruik ondersteunde OpenWrt/vendor-firmware en verwyder ongebruikte dienste.
- Administreer oor Ethernet of 'n toegewyde bestuurs-SSID met 'n unieke wagwoord.
- Deaktiveer WAN-side administration, UPnP, WPS, lêerdeling en ongevraagde inkomende verkeer.
- Gebruik 'n gerandomiseerde/private WAN MAC slegs waar dit ondersteun en toegelaat word.
- Dwing VPN-beleid op die router af, insluitend DNS en IPv6, en blokkeer egress wanneer die tunnel faal.
- Moenie aanvaar dat 'n foon-hotspot getetherde toestelle deur die foon se VPN tonnel nie; toets dit.

## Sellulêr, SIMs en eSIMs

Sellulêr is gerieflik maar nie anoniem nie. Operateurs hou intekenaar-/toestelidentifiseerders en ligging af wat van netwerkhegting afgelei word; 'n eSIM is steeds 'n mobiele intekening. Prepaid beteken nie betroubaar ongeregistreerd nie—vereistes verskil per land en verander.<sup>[[13]](#references)</sup>

Operasioneel:

- Gebruik 'n aparte, ondersteunde toestel om blootstelling van persoonlike data te verminder, nie om 'n fiktiewe intekenaar te skep nie.
- Moenie 'n “aparte” toestel voortdurend saam met 'n persoonlike foon dra as mede-ligging deel van die threat model is nie.
- Deaktiveer ongebruikte sellulêre, Wi-Fi-, Bluetooth- en liggingtoegang; afskakeling is 'n sterker radiogrens as UI-toggles.
- Plaas sensitiewe verkeer binne die goedgekeurde VPN/Tor-pad, terwyl jy erken dat die draer steeds die intekening/toestelligging en tunnel-endpoint ken.
- Verifieer huidige registrasie- en retensiereëls by die nasionale reguleerder of plaaslike regsadviseur; moenie staatmaak op aanlynlyste van “anonymous SIM countries” nie.

## DNS- en TLS-metadata

- **DoH/DoT/DoQ** enkripteer DNS tussen client en resolver, wat eenvoudige plaaslike lees of wysiging voorkom, maar die resolver sien steeds navrae en transport identifiers. Hulle verskuif vertroue; hulle bied nie anonimiteit nie.<sup>[[14]](#references)</sup>
- **ODoH** voeg 'n proxy by sodat die resolver nie die client-IP hoef te leer nie, met die aanname dat proxy en target nie saamspan nie. Traffic analysis is uitdruklik buite omvang.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** kan die inner server name in 'n TLS-handshake beskerm wanneer client, DNS en server dit ondersteun. Bestemming-IP, tydsberekening, volume en die endpoint bly sigbaar.<sup>[[16]](#references)</sup>
- Met 'n korrek gekonfigureerde VPN- of Tor-omgewing behoort DNS die ondersteunde roete van daardie omgewing te volg. Die byvoeging van 'n aparte resolver kan 'n nuwe waarnemer of fingerprint skep.

### Encrypted-DNS/ECH-verifikasiewerkvloei

1. Besluit of DNS deur die VPN/Tor-omgewing, die OS of die toepassing beheer word. Konfigureer dit in **een** bedoelde laag eerder as om onverwante resolvers te stapel.
2. Kies 'n resolver volgens sy gepubliseerde privaatheids-/retensiebeleid en aktiveer strict encrypted mode waar die platform dit ondersteun. Opportunistic fallback kan stilweg na plaintext terugkeer.
3. Doen navraag oor 'n unieke subdomein onder 'n authoritative test zone wat jy beheer; bevestig dat die authoritative log die bedoelde recursive resolver sien.
4. Capture slegs die toetstoestel se verkeer met magtiging. Bevestig dat die toegangsnetwerk nie plaintext DNS kan lees nie, terwyl jy erken dat dit die encrypted resolver/tunnel-endpoint kan sien.
5. Toets 'n geblokkeerde/onbereikbare encrypted resolver. Die slaagvoorwaarde is die gekose fail-closed- of gedokumenteerde fallback-gedrag—nie 'n toevallige clear query nie.
6. Gebruik vir ECH 'n beheerde ECH-enabled host en inspekteer client/server-diagnostics om te bevestig dat die **inner** ClientHello aanvaar is. Om bloot 'n HTTPS-record aan te bied, bewys nie dat ECH geslaag het nie.
7. Herhaal ná netwerkveranderinge, captive portals, blaaieropdaterings en VPN-herverbindings. Teken aan watter komponent DNS/ECH besit sodat latere administrators nie 'n bypass skep nie.

## Mixnets

Mixnets soos Nym of Katzenpost voeg vaste-grootte-pakkette, delay, reordering en cover traffic by om timing correlation te weerstaan. Hierdie eienskappe kos latency en bandwydte, en onafhanklike bewyse op ontplooiingskaal is beperk. Behandel huidige consumer mixnets as **emerging/high-latency options**, nie as vinniger of gewaarborgde plaasvervangers vir Tor/VPNs nie.<sup>[[17]](#references)</sup>

### Evaluasiewerkvloei

1. Identifiseer 'n onderhoude client en die presiese ondersteunde toepassing; moenie arbitrêre blaaier-/stelselverkeer deur 'n ongedokumenteerde proxy forseer nie.
2. Lees die huidige threat model vir entry, mix nodes, gateway, bestemming en collusion-aannames.
3. Installeer vanaf die amptelike ondertekende bron in 'n aparte test compartment en gebruik slegs 'n goedaardige endpoint wat jy besit.
4. Meet afleweringslatency, boodskapgroottebeperkings, betroubaarheid, retransmission en wat gebeur wanneer die gateway onbeskikbaar is.
5. Inspekteer plaaslike verkeer en die endpoint wat jy besit om die bedoelde pad en bron te bevestig. Kontroleer of antwoorde dieselfde privaatheidsontwerp gebruik.
6. Toets shutdown/failure: die toepassing moet nie stilweg na direkte Internet-toegang terugval nie.
7. Moenie cover traffic deaktiveer, delays verminder of ongewone vaste roetes kies bloot vir spoed nie; hierdie veranderinge kan die verklaarde anonymity model ongeldig maak.
8. Hou dit eksperimenteel totdat die spesifieke ontplooiing, onafhanklike ontleding en operasionele betroubaarheid by die consequence level pas.

## Netwerk-preflight-kontrolelys

- [ ] Magtiging dek die toegangsnetwerk, target, datums en broninfrastruktuur.
- [ ] Die endpoint bevat geen onverwante identiteite of aktiewe sync-sessies nie.
- [ ] IPv4, IPv6, DNS en reconnect-gedrag stem met die plan ooreen.
- [ ] Die bestemming sien slegs die verwagte egress.
- [ ] Captive-portal- en hotspot-gedrag is sonder sensitiewe verkeer getoets.
- [ ] Plaaslike sharing/discovery en outomatiese netwerkjoining is gedeaktiveer.
- [ ] Die waarnemerstabel en oorblywende traffic-correlation risk word aanvaar.
- [ ] Verskafferbeleid, retensie en noodkontak is op datum.

Vir split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P en disposable remote browsers, gaan voort na [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Choosing the VPN That's Right for You](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — The privacy and anonymity protections Tor offers](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — A short introduction to Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Using Tor with other browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins and add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Are Public Wi-Fi Networks Safe?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy with Apple devices](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implement MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principles for Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recommendations for DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
