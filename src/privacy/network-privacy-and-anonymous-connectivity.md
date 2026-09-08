# Netwerkprivaatheid & Anonieme Verbinding

{{#include ../banners/hacktricks-training.md}}

Netwerkprivaatheid is 'n roetebesluit, nie 'n volledige identiteit nie. Kies 'n pad deur te vra wie nie die **bron**, **bestemming**, **inhoud** en **tydsberekening** behoort te kan verbind nie.

Vir die genormaliseerde inventaris—`Pros`, `Cons`, stap-vir-stap `Procedure`, en `Detection` vir elke toegangs-padfamilie—begin met die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Hierdie blad brei die algemene implementeerbare opsies uit.

## Wat elke waarnemer gewoonlik kan sien

| Pad | Plaaslike netwerk / ISP | Tussenganger | Bestemming | Belangrikste beperking | Relatiewe spoed |
|---|---|---|---|---|---|
| Direct HTTPS | Bron-, bestemmingmetadata, tydsberekening/volume | Hosting/CDN sien verbinding | Bron-IP, blaaier-/appdata | Geen bron-IP-privaatheid nie | Vinnigste |
| Commercial VPN | Bron gekoppel aan VPN; nie gewone bestemmingmetadata nie | VPN sien bron- en bestemmingmetadata | VPN-egress-IP | Een verskaffer word 'n korrelasiepunt | Gewoonlik vinnig |
| Self-hosted VPN/VPS | Bron gekoppel aan VPS | Gasheer-/rekening-/betaling-/beheerlaag-logboeke | VPS-egress-IP | Maklik aan die gehuurde bediener/rekening gekoppel | Gewoonlik vinnig |
| Tor Browser | Bron gekoppel aan Tor/bridge; tydsberekening/volume | Relays sien elk 'n beperkte gedeelte | Tor-exit, blaaierdata | Stadiger; rekening-/endpoint-/korrelasierisiko's | Matig/stadig |
| Tails/Whonix | Soortgelyke Tor-pad, met sterker roetebeperkings | Dieselfde Tor-beperkings | Tor-exit/toepassingsdata | Operasionele foute en gasheer/hardeware bly oor | Matig/stadig |
| Public guest Wi-Fi + HTTPS | Lokaal toestel en tydsberekening, plus bestemmings | Venue-ISP sien metadata | Guest-public-IP | Fisiese/kaptive-portaal-/toestelkorrelasie | Vinnig/veranderlik |
| Cellular hotspot | Draer sien intekenaar/toestel/ligging en bestemmings | VPN/Tor indien gebruik | Draer-, VPN- of Tor-egress-IP | Mobiele intekening en ligging is duursame identifiseerders | Vinnig/veranderlik |
| Mixnet | Toegang sien mixnet-gebruik; tydsberekening/volume | Veelvuldige mixing nodes | Gateway/egress | Ontluikende ekosisteem; latensie- en bandwydtekoste | Stadigste |

HTTPS beskerm inhoud tydens oordrag, maar nie alle metadata nie. EFF merk op dat domein, tyd en verkeersgrootte vir tussengangers sigbaar kan bly, selfs wanneer bladsy-paaie, geloofsbriewe en boodskappe geïnkripteer is.<sup>[[1]](#references)</sup>

## VPNs: vinnige privaatheid met gekonsentreerde vertroue

'n VPN is nuttig om bestemmingmetadata vir die toegangs-ISP te verberg, 'n eerste hop op 'n onbetroubare netwerk te beskerm, 'n stabiele engagement-egress-adres te bied, of 'n private netwerk te bereik. Dit maak 'n gebruiker **nie** anoniem nie. Die VPN sien die bronverbinding en kan bestemmingmetadata waarneem; rekeninge, cookies, GPS, fingerprints en betalingsinligting bly bestaan.<sup>[[1]](#references)</sup>

### Kontrolelys vir verskafferevaluering

1. **Eienaarskap en jurisdiksie:** identifiseer die wettige entiteit, moedermaatskappy, bedryfslande, infrastruktuur-subkontrakteurs en toepaslike regsproses.
2. **Versamelde data:** onderskei tussen rekening-/faktureringdata, bron-IP, verbindingstydstempels, bandwydte, crash-telemetrie, DNS-navrae en bestemmingslogboeke. “No browsing logs” beteken nie “no data” nie.
3. **Bewaring en uitvee:** vind presiese tydsduur en of backups, fraudestelsels en verwerkers dieselfde skedule volg.
4. **Bewyse:** verkies openbare audits met omvang, datum, bevindings en remediëring; reproduceerbare/open clients; deursigtigheidsverslae; en gedokumenteerde insidente.
5. **Protokol en client:** onderhoude WireGuard, OpenVPN of 'n ander beoordeelde protokol; outomatiese updates; DNS- en IPv6-hantering; kill switch; en leak-toetse per platform.
6. **Besigheidsmodel:** verstaan hoe 'n gratis of gesubsidieerde diens befonds word. Teenwoordigheid in 'n app store is op sigself nie bewys van betroubare bedryf nie.
7. **Betalingsgeskiktheid:** alternatiewe betaling kan faktureringsopenbaarmaking aan die VPN verminder, maar verwyder nie die bron-IP wat by elke verbinding waargeneem word nie.

### Konfigureer en verifieer 'n VPN

1. Installeer die verskaffer/organisasie se ondertekende client vanaf sy amptelike bron.
2. Kies **full tunnel**, tensy 'n gedokumenteerde roete dit moet omseil. Split tunneling skep korrelasie- en leak-paaie.
3. Aktiveer fail-closed/always-on-gedrag en blokkeer verkeer tydens herverbinding.
4. Stuur DNS deur die tunnel en toets beide IPv4 en IPv6. Deaktiveer 'n protokol slegs indien dit nie veilig deur die tunnel gestuur kan word nie en die verlies aan funksionaliteit aanvaar word.
5. Toets slaap/wakker-word, netwerkwisseling, captive-portal-aanmelding, tunnel-crash en hotspot-tethering. NCSC waarsku dat getetherde clients op sommige platforms 'n foon se VPN kan omseil.<sup>[[2]](#references)</sup>
6. Gebruik 'n organisasie-beheerde toets-endpoint om waargenome IPv4, IPv6, DNS-resolver en verbindingstydsberekening aan te teken. Moenie 'n sensitiewe engagement aan willekeurige “leak test”-webwerwe blootstel nie.
7. Toets weer na client-, OS-, netwerk- of beleidsveranderings.

## Tor Browser: sterker web-onkoppelbaarheid

Tor bou 'n circuit deur veelvuldige relays sodat geen enkele relay normaalweg beide bron en bestemming ken nie. Die bestemming sien 'n Tor-exit eerder as die gebruiker se IP; die plaaslike netwerk sien normaalweg 'n Tor-verbinding.<sup>[[3]](#references)</sup> Tor is ontwerp vir TCP-toepassings met lae latensie, dus is dit stadiger en kan dit nie beskerming waarborg teen 'n teenstander wat albei kante kan korreleer nie.<sup>[[4]](#references)</sup>

### Veilige Tor Browser-werksvloei

1. Laai Tor Browser slegs van die Tor Project of 'n amptelike mirror af en verifieer die signature wanneer moontlik.
2. Gebruik **Tor Browser**, nie 'n gewone blaaier wat na 'n Tor SOCKS-port wys nie. Gewone blaaiers kan DNS/WebRTC en identifiserende state laat lek.<sup>[[5]](#references)</sup>
3. Behou die verstekgrootte, fonts, extensions en privaatheidinstellings. Bykomende add-ons kan die blaaier meer uniek maak.<sup>[[6]](#references)</sup>
4. Kies die **Safer**- of **Safest**-sekuriteitsvlak wanneer die verhoogde breakage aanvaarbaar is.
5. Gebruik 'n bridge wanneer direkte Tor geblokkeer word of wanneer gewone relay-IP's onaanvaarbare plaaslike sigbaarheid sou skep. Bridges verminder maklike herkenning; hulle skakel traffic analysis nie uit nie.<sup>[[7]](#references)</sup>
6. Moenie by 'n identifiserende rekening aanmeld, identifiserende inligting verskaf of afgelaaide aktiewe dokumente in 'n eksterne netwerktoepassing oopmaak nie.
7. Gebruik 'n aparte session/context vir elke identiteit. “New circuit” is nie dieselfde as om blaaier-/toepassingsidentiteit uit te vee nie; gebruik **New Identity** of herbegin die geïsoleerde omgewing soos toepaslik.
8. Verkies geauthentiseerde HTTPS of 'n geauthentiseerde onion service. 'n Tor-exit kan ongeënkripteerde HTTP-verkeer waarneem.

### Tor plus VPN

Die kombinasie is nie outomaties veiliger nie. 'n VPN voor Tor kan direkte Tor-relay-verbindings vir 'n ISP verberg terwyl die VPN die bron sien; Tor voor 'n VPN gee die VPN 'n stabiele beeld van aktiwiteit ná Tor en kan die anonymity set verklein. Wankonfigurasie kan leaks veroorsaak. Tor Project beveel sulke kombinasies slegs vir gevorderde, eksplisiete threat models aan.<sup>[[8]](#references)</sup>

## Openbare en guest-Wi-Fi

Moderne HTTPS beteken dat passiewe bure gewoonlik nie behoorlik geënkripteerde webinhoud kan lees nie, maar guest-Wi-Fi is nie anonimiteit nie. Die venue kan assosiasietye, toestel-identifiseerders, captive-portal-data, bestemmings en DHCP-besonderhede aanteken; kameras, aankope, vervoer en fisiese waarneming kan die gebruiker identifiseer. 'n Vals hotspot met 'n soortgelyke naam kan ook portal-geloofsbriewe vaslê of ongeënkripteerde verkeer manipuleer.<sup>[[9]](#references)</sup>

### Wettige guest-netwerk-werksvloei

1. Gebruik slegs 'n netwerk wat vir gaste aangebied word of waarvoor die eienaar uitdruklike toestemming verleen het. Vra personeel vir die presiese SSID en portal-prosedure.
2. Dateer die endpoint en travel router voor aankoms op. Deaktiveer lêer-/drukkerdeling, inbound discovery, auto-join en probing van onthoude netwerke.
3. Aktiveer die OS se private/randomized Wi-Fi-adres. Huidige Apple-stelsels kan roterende adresse op oop/swakkere netwerke gebruik; moderne Android-randomization is gewoonlik persistent per SSID. Dit verminder slegs een plaaslike identifiseerder.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Verkies 'n organisasie-beheerde travel router of low-trust bridge-toestel tussen 'n bevoorregte workstation en die guest-netwerk. Dit sentraliseer firewall/VPN-beleid, maar verberg nie die router vir die venue nie.<sup>[[12]](#references)</sup>
5. Voltooi 'n captive portal slegs deur die aangewese low-trust-toestel/-blaaier. Moet nooit persoonlike of hergebruikte geloofsbriewe vir 'n sogenaamd anonieme context invoer nie. Sluit die portal-blaaier nadat verbinding gevestig is.
6. Begin 'n full-tunnel VPN of Tor voor sensitiewe aktiwiteit en bevestig fail-closed-gedrag.
7. Vergeet die netwerk ná gebruik en hersien die portal-rekening-/dataretensiebeleid.

{% hint style="danger" %}
Om 'n buurman se Wi-Fi te crack, 'n portal te omseil, gelekte guest-geloofsbriewe te gebruik, 'n ander gas se toegang te clone, of 'n Raspberry Pi in 'n kafee te versteek, is ongemagtigde aktiwiteit—nie 'n privaatheidstegniek nie. Die veilige ekwivalente is 'n wettige guest-netwerk, 'n client-goedgekeurde terrein, of 'n gedokumenteerde drop node wat met die eiendomseienaar se skriftelike toestemming geplaas en teruggevind word.
{% endhint %}

## Travel routers

'n Travel router kan 'n workstation van vyandige plaaslike broadcasts isoleer, 'n firewall afdwing, 'n konsekwente interne SSID verskaf en 'n VPN outomaties herverbind. Dit is **nie** anoniem nie: die upstream sien sy radio-identiteit en verkeerstydsberekening, en sy VPN-verskaffer sien die tunnelbron.

- Gebruik ondersteunde OpenWrt/vendor-firmware en verwyder ongebruikte dienste.
- Administreer oor Ethernet of 'n toegewyde management-SSID met 'n unieke wagwoord.
- Deaktiveer WAN-side administration, UPnP, WPS, file sharing en ongevraagde inbound traffic.
- Gebruik slegs 'n randomized/private WAN MAC waar dit ondersteun en toegelaat word.
- Dwing VPN-beleid op die router af, insluitend DNS en IPv6, en blokkeer egress wanneer die tunnel faal.
- Moenie aanvaar dat 'n phone hotspot getetherde toestelle deur die foon se VPN stuur nie; toets dit.

## Cellular, SIMs en eSIMs

Cellular is gerieflik maar nie anoniem nie. Operators hou intekenaar-/toestel-identifiseerders en ligging by wat van netwerk-aanhegting afgelei word; 'n eSIM is steeds 'n mobiele intekening. Prepaid beteken nie betroubaar ongeregistreerd nie—vereistes verskil per land en verander.<sup>[[13]](#references)</sup>

Operasioneel:

- Gebruik 'n aparte, ondersteunde toestel om blootstelling van persoonlike data te verminder, nie om 'n fiktiewe intekenaar te skep nie.
- Moenie voortdurend 'n “aparte” toestel langs 'n persoonlike foon dra indien ko-ligging deel van die threat model is nie.
- Deaktiveer ongebruikte cellular, Wi-Fi, Bluetooth en location access; afskakeling bied 'n sterker radio-grens as UI-toggles.
- Plaas sensitiewe verkeer binne die goedgekeurde VPN/Tor-pad, terwyl jy erken dat die draer steeds die intekening/toestelligging en tunnel-endpoint ken.
- Verifieer huidige registrasie- en retensiereëls met die nasionale regulator of plaaslike regsadviseur; moenie op aanlynlyste van “anonymous SIM countries” staatmaak nie.

## DNS en TLS-metadata

- **DoH/DoT/DoQ** enkripteer DNS tussen client en resolver, wat eenvoudige plaaslike lees of wysiging voorkom, maar die resolver sien steeds navrae en transport-identifiseerders. Hulle verskuif vertroue; hulle verskaf nie anonimiteit nie.<sup>[[14]](#references)</sup>
- **ODoH** voeg 'n proxy by sodat die resolver nie die client-IP hoef te leer nie, mits proxy en target nie collude nie. Traffic analysis is uitdruklik buite omvang.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** kan die inner server name in 'n TLS-handshake beskerm wanneer client, DNS en server dit ondersteun. Bestemming-IP, tydsberekening, volume en die endpoint bly sigbaar.<sup>[[16]](#references)</sup>
- Met 'n korrek gekonfigureerde VPN- of Tor-omgewing behoort DNS die omgewing se ondersteunde roete te volg. Die byvoeging van 'n aparte resolver kan 'n nuwe waarnemer of fingerprint skep.

### Encrypted-DNS/ECH-verifikasiewerksvloei

1. Besluit of DNS deur die VPN/Tor-omgewing, die OS of die toepassing beheer word. Konfigureer dit in **een** beoogde laag in plaas daarvan om onverwante resolvers te stapel.
2. Kies 'n resolver volgens sy gepubliseerde privaatheids-/retensiebeleid en aktiveer streng encrypted mode waar die platform dit ondersteun. Opportunistic fallback kan stilweg na plaintext terugkeer.
3. Doen navraag oor 'n unieke subdomein onder 'n authoritative test zone wat jy beheer; bevestig dat die authoritative log die beoogde recursive resolver sien.
4. Capture slegs die toets-toestel se verkeer met authorization. Bevestig dat die toegangsnetwerk nie plaintext DNS kan lees nie, terwyl jy erken dat dit die encrypted resolver-/tunnel-endpoint kan sien.
5. Toets 'n geblokkeerde/onbereikbare encrypted resolver. Die slaagvoorwaarde is die gekose fail-closed- of gedokumenteerde fallback-gedrag—nie 'n toevallige clear query nie.
6. Gebruik vir ECH 'n beheerde ECH-enabled host en inspekteer client-/server-diagnostics om te bevestig dat die **inner** ClientHello aanvaar is. Die blote aanbieding van 'n HTTPS-record bewys nie dat ECH geslaag het nie.
7. Herhaal ná netwerkveranderings, captive portals, blaaierupdates en VPN-herverbindings. Teken aan watter komponent DNS/ECH besit sodat latere administrators nie 'n bypass skep nie.

## Mixnets

Mixnets soos Nym of Katzenpost voeg vaste-grootte pakkette, vertraging, herordening en cover traffic by om tydsberekeningskorrelasie te weerstaan. Hierdie eienskappe kos latensie en bandwydte, en onafhanklike bewyse op deployment-skaal is beperk. Behandel huidige consumer mixnets as **emerging/high-latency options**, nie as vinniger of gewaarborgde plaasvervangers vir Tor/VPNs nie.<sup>[[17]](#references)</sup>

### Evalueringswerksvloei

1. Identifiseer 'n onderhoude client en die presiese ondersteunde toepassing; moenie arbitrêre blaaier-/stelselverkeer deur 'n ongedokumenteerde proxy forseer nie.
2. Lees die huidige threat model vir entry, mix nodes, gateway, bestemming en collusion-aannames.
3. Installeer vanaf die amptelike ondertekende bron in 'n aparte test compartment en gebruik slegs 'n onskadelike endpoint wat jy besit.
4. Meet afleweringslatensie, boodskapgroottebeperkings, betroubaarheid, retransmission en wat gebeur wanneer die gateway onbeskikbaar is.
5. Inspekteer plaaslike verkeer en die endpoint wat jy besit om die beoogde pad en bron te bevestig. Kontroleer of antwoorde dieselfde privaatheidsontwerp gebruik.
6. Toets shutdown/failure: die toepassing mag nie stilweg na direkte Internet-toegang terugval nie.
7. Moenie cover traffic deaktiveer, vertragings verminder of ongewone vaste roetes kies bloot vir spoed nie; hierdie veranderinge kan die verklaarde anonymity model ongeldig maak.
8. Hou dit eksperimenteel totdat die spesifieke deployment, onafhanklike analise en operasionele betroubaarheid by die consequence level pas.

## Netwerk-preflight-kontrolelys

- [ ] Authorization dek die toegangsnetwerk, target, datums en broninfrastruktuur.
- [ ] Die endpoint bevat geen onverwante identiteite of aktiewe sync sessions nie.
- [ ] IPv4, IPv6, DNS en reconnect-gedrag stem met die plan ooreen.
- [ ] Die bestemming sien slegs die verwagte egress.
- [ ] Captive-portal- en hotspot-gedrag is sonder sensitiewe verkeer getoets.
- [ ] Plaaslike sharing/discovery en outomatiese netwerkjoining is gedeaktiveer.
- [ ] Die observer table en oorblywende traffic-correlation risk word aanvaar.
- [ ] Verskafferbeleid, retensie en noodkontak is op datum.

Vir split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P en disposable remote browsers, gaan voort na [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Die keuse van die regte VPN vir jou](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Toestelsekuriteitsriglyne: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Die privaatheids- en anonimiteitsbeskerming wat Tor bied](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — 'n Kort inleiding tot Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Gebruik Tor met ander blaaiers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins en add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Ontblokkering van Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Gebruik Tor Browser met 'n VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Is openbare Wi-Fi-netwerke veilig?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi-privaatheid met Apple-toestelle](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementeer MAC-randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Beginsels vir Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Verpligte SIM-registrasie: beleids- en regulatoriese perspektiewe](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Aanbevelings vir DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
