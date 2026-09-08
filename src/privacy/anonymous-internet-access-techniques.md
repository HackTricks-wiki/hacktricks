# Katalog tehnika anonimnog pristupa Internetu

{{#include ../banners/hacktricks-training.md}}

Ovo je kanonski inventar pristupnih putanja. Obuhvata **familije** protokola i operacija, a ne svaki naziv dobavljača. Nijedna Internet putanja ne garantuje anonimnost: nalog, browser, endpoint, vremenska korelacija, plaćanje, cloud-control-plane i fizički dokazi mogu razotkriti čak i putanju koja izgleda savršeno.

Svaki unos koristi ista polja. „Procedura” znači zakonitu implementaciju ili emulaciju u laboratoriji koja je u vašem vlasništvu. Kada stvarna tehnika zavisi od kompromitovanja rutera, krađe pristupa ili zloupotrebe posrednika koji na to nije pristao, reprodukcija koristi sisteme u vlasništvu vežbe.

## Matrica pokrivenosti

| Familija | Odredište vidi | Najjače svojstvo | Brzina | Tretman |
|---|---|---|---|---|
| Shared NAT/CGNAT | deljenu javnu adresu | neodređenost među pretplatnicima | visoka | primenljivo |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay adresu | brzo razdvajanje izvorne adrese | visoka | primenljivo |
| Multi-hop/split relay, MASQUE | krajnji proxy | podeljeno znanje ili full-IP tunel | visoka/umerena | primenljivo uz pouzdane relaye |
| Tor, bridge, onion service | exit ili onion identitet | putanja sa više učesnika i standardni browser | umerena | primenljivo |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay ili otpornost na vremensku analizu | niska/promjenljiva | specifično za aplikaciju |
| OHTTP/ODoH, Private Relay | gateway/egress | razdvajanje izvora i zahteva | visoka | samo podržane aplikacije |
| Public Wi-Fi, travel router | adresa lokacije/tunela | promena lokacije/pristupne putanje | visoka | potrebna dozvola |
| Cellular/eSIM, satellite | adresa operatora/provajdera | nezavisan fizički uplink | visoka/promjenljiva | pretplatnik/provajder posmatra |
| Remote browser/jump host | udaljeni workspace | razdvajanje endpointa i egress-a | visoka | primenljivo |
| Residential/mobile proxy | consumer/carrier adresa | izgled consumer mreže | visoka | pristanak/poreklo su kritični |
| ORB/compromised relay | adresa druge žrtve | prikrivanje porekla i pozajmljena reputacija | visoka | samo reprodukcija u vlasničkoj laboratoriji |
| CDN/fronting/redirector | CDN/front adresa | zaštita back-end infrastrukture | visoka | potrebna saglasnost provajdera/vlasnika |
| Fast flux/DGA/dead drop | rotirajući node/service | otpornost na otkrivanje infrastrukture | promenljiva | samo reprodukcija u vlasničkoj laboratoriji |
| Drop/nearest-neighbor | lokalna adresa uz cilj | prelazak geografske/mrežne granice | visoka | samo laboratorija na lokaciji u vlasništvu |
| Store-and-forward/offline | gateway ili fizički prijemnik | smanjenje interaktivne vremenske korelacije | niska | specifično za aplikaciju |
| Pluggable/refraction transport | Tor entry ili saradnički diversion proxy | dostupnost otporna na cenzuru | promenljiva | podržani client ili istraživačka laboratorija |
| IPFS gateway/PIR/remote fetcher | gateway ili application service | razdvajanje publish/query/request uloga | promenljiva | ograničena aplikacija |
| Anycast/QUIC/MPTCP | stabilni broker ili više podtokova | rendezvous i kontinuitet sesije | visoka | dostupnost, ne anonimnost |
| CI/CD automation runner | adresa hostovanog runnera | privremeni odgovorni egress | visoka | samo vlasnički workflow |
| Non-IP local first hop | gateway organizacije | uklanjanje Internet stack-a sa senzora | niska | implementacija uz odobrenje vlasnika |

## Direct shared NAT i carrier-grade NAT

**Mehanika:** više korisnika deli jednu javnu adresu; access provider mapira adrese i portove na strani pretplatnika u javni tuple.

**Prednosti:** brzo; nije potreban poseban client; IP na strani odredišta može identifikovati samo domaćinstvo, lokaciju ili carrier pool.

**Nedostaci:** provajder može čuvati mape pretplatnika, portova i vremena; nalozi i fingerprint-i ostaju; drugi korisnici mogu narušiti reputaciju adrese.

**Procedura:** (1) potvrdite da li odobreni pristup koristi NAT/CGNAT; (2) zabeležite tačnu javnu IP adresu i source port na endpointu u vlasništvu organizacije; (3) razdvojite identitete aplikacija; (4) ne tretirajte deljenu adresu kao privacy kontrolu; (5) koristite jaču putanju ako ISP ne sme da sazna odredišta.

**Detekcija:** odredišta treba da čuvaju source port i precizno vreme, a ne samo IP. Provajderi povezuju NAT allocation logove; istražitelji spajaju dokaze o nalogu, uređaju i browseru.

## Commercial VPN

**Mehanika:** šifrovana full-tunnel veza završava se na VPN-u; odredišta vide njegov egress. VPN obično može povezati izvor, vreme i odredišta.

**Prednosti:** brzo; jednostavno; štiti od lokalnog pasivnog posmatranja; stabilni ili deljeni exit-i; pogodno za kontrolisani red-team egress.

**Nedostaci:** koncentrisano poverenje; telemetry o naplati i prijavljivanju; greške kill-switch/DNS/IPv6; deljeni exit-i često imaju lošu reputaciju i blokirani su.

**Procedura:** (1) utvrdite provajdera, vlasnika, jurisdikciju, retention i assessment policy; (2) instalirajte potpisani zvanični client; (3) uključite full tunnel, always-on i fail-closed ponašanje; (4) namerno usmerite DNS i IPv6; (5) proverite posmatrani IPv4/IPv6/DNS na endpointu u vlasništvu organizacije; (6) prekinite i ponovo uspostavite tunnel i potvrdite da nema nešifrovanog fallback-a.<sup>[[1]](#references)</sup>

**Detekcija:** lokalne mreže vide dugotrajan šifrovan tok ka VPN infrastrukturi; provajderi imaju zapise autentikacije i konekcije; odredišta koriste ASN/reputaciju zajedno sa korelacijom naloga, TLS/browsera i ponašanja.

## Self-hosted VPN ili rented VPS egress

**Mehanika:** operator kontroliše WireGuard/OpenVPN gateway ili prosleđuje saobraćaj kroz rented server.

**Prednosti:** predvidljiva velika brzina; fiksna adresa pogodna za allowlist; prilagođeni logging/firewall; dobra kontrola incidenta.

**Nedostaci:** mali anonymity set; cloud tenant, plaćanje, source login, API i image istorija povezuju operatora; karakterističan nov server lako se grupiše.

**Procedura:** (1) kreirajte organization-specific engagement project; (2) provision-ujte podržani image i fiksnu adresu; (3) ograničite management na MFA/key-based administraciju; (4) podesite full-tunnel egress i DNS; (5) gde je praktično, dozvolite samo definisana odredišta; (6) testirajte leak/failure ponašanje; (7) zadržite controller audit zapise; (8) uništite credentials i resurse pri uklanjanju.

**Detekcija:** povežite hosting ASN, prvi put viđenu adresu, fingerprint sertifikata/service-a i scanning ponašanje; cloud vlasnici koriste control-plane, console, billing i flow logove.

## HTTP CONNECT, SOCKS i SSH forwarding

**Mehanika:** aplikacija traži od proxy-ja da otvori TCP stream; SOCKS može prenositi i name resolution i UDP, zavisno od verzije; SSH prosleđuje stream-ove unutar jedne šifrovane sesije.

**Prednosti:** lagano; po aplikaciji; brzo; korisno za chaining i pristup segmentiranim mrežama.

**Nedostaci:** aplikacije mogu zaobići proxy; DNS može procureti; proxy vidi susedne endpoint-e; stanje browsera ostaje; open proxy-ji mogu biti zamke ili kompromitovani sistemi.

**Procedura:** (1) postavite proxy na hostu u vlasništvu organizacije; (2) zahtevajte autentikaciju i ograničite izvor/odredište; (3) konfigurišite jedan disposable application profile; (4) obezbedite remote DNS resolution kada je potrebno; (5) proverite pomoću DNS/HTTP endpointa u vlasništvu organizacije; (6) blokirajte direktan egress za workload; (7) pregledajte i rotirajte proxy credentials.

**Detekcija:** identifikujte procese sposobne za tunneling, CONNECT/SOCKS negotiation, duge SSH sesije i odredišta koja nisu u skladu sa aplikacijom; proxy logovi rekonstruišu stream-ove.

## URL-rewriting web proxy i browser proxy extension

**Mehanika:** website preuzima odredište i prepisuje linkove/forms kroz sopstveni origin, ili extension usmerava browser zahteve ka proxy-ju. Odredište vidi service, dok service može videti plaintext nakon TLS termination-a i ubaciti ili zadržati sadržaj.

**Prednosti:** nije potreban system-wide client; brzo za jednostavno browsing iskustvo; radi kada VPN instalacija nije moguća.

**Nedostaci:** proxy može čitati credentials/content, menjati download-e i fingerprint-ovati korisnike; scripts/WebSockets/download-i mogu zaobići proxy; browser extension ima široke privilegije; mali anonymity set i često blokiranje.

**Procedura:** (1) koristite samo proxy kojim upravlja organizacija, za odobreno testiranje; (2) izolujte ga u disposable browseru bez ličnih naloga; (3) zabranite unos password-a i osetljive download-e; (4) proverite da svaki subresource na stranici u vlasništvu organizacije ide kroz proxy; (5) testirajte WebSocket, download i form ponašanje; (6) uklonite extension/profile nakon upotrebe.

**Detekcija:** odredište loguje proxy; enterprise proxy/DNS i inventory extension-a identifikuju service; content-security/reporting ili canary subresources u vlasništvu organizacije otkrivaju direktni bypass; proxy logovi mapiraju user session na target-e.

## Multi-hop proxy ili provider multi-hop VPN

**Mehanika:** entry vidi izvor, dok ga jedan ili više traversal relay-a razdvaja od exit-a koji vidi odredište.

**Prednosti:** nijedan uobičajeni relay ne mora videti oba kraja; kvar ili zaplena jednog node-a otkriva manje; fleksibilna geografija.

**Nedostaci:** deljena administracija/logovi poništavaju razdvajanje; latencija; vremenska korelacija; više mogućih kvarova i DNS putanja; isti nalog/plaćanje može povezati svaki hop.

**Procedura:** (1) definišite koji observer uklanja svaki hop; (2) koristite nezavisno administrirane relay-e u vlasništvu organizacije ili odobrene relay-e kada je razdvajanje važno; (3) nametnite samo entry pristup iz workload-a; (4) obezbedite da svaki relay može dosegnuti samo sledeći hop; (5) proverite logove na svakom sloju; (6) zaustavite svaki hop i potvrdite fail-closed ponašanje. Reprodukujte pomoću [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detekcija:** povežite susedne NetFlow vremenske obrasce/volumen, ponovljene proxy handshake-ove i zajedničku controller infrastrukturu; ne zaključujte geografiju operatora na osnovu exit-a.

## Split-knowledge application relay i OHTTP

**Mehanika:** client šifruje stateless HTTP poruku ka gateway-u i šalje je kroz relay. Relay vidi client IP, ali ne i zahtev; gateway vidi zahtev, ali obično samo relay IP.

**Prednosti:** snažna, proverljiva privacy podela za podržane zahteve; manji overhead od opštih anonymity mreža.

**Nedostaci:** nije proizvoljno browsing iskustvo; cookies/authentication mogu ponovo povezati zahtev; relay/gateway collusion i traffic analysis ostaju; aplikacija mora implementirati ovu funkciju.

**Procedura:** (1) izaberite aplikaciju koja izričito podržava RFC 9458; (2) proverite gateway ključeve preko zvaničnog configuration path-a; (3) izbegavajte stabilna polja po korisniku; (4) šaljite samo podržani stateless request; (5) uporedite relay, gateway i target logove; (6) testirajte key rotation/failure bez direktnog fallback-a.<sup>[[2]](#references)</sup>

**Detekcija:** enterprise endpoint-i otkrivaju initiating process i OHTTP relay; gateway-i detektuju neispravan/replay-ovan saobraćaj; vreme i stabilna payload/account polja mogu povezati zahteve.

## MASQUE CONNECT-UDP/CONNECT-IP i HTTP privacy proxy-ji

**Mehanika:** HTTP Extended CONNECT preko TLS/QUIC prenosi UDP ili IP pakete kroz proxy. Može implementirati moderan VPN-like tunnel i uklopiti transport u HTTP/3, ali proxy ostaje observer.<sup>[[3]](#references)</sup>

**Prednosti:** efikasno multiplexing/roaming ponašanje; podrška za UDP ili full IP; deployment kroz modernu HTTP infrastrukturu.

**Nedostaci:** nije anonymity network; proxy/account vidi izvor i odredišta; QUIC/HTTP fingerprint-i i poznate putanje vidljivi su endpoint-ima/provajderima.

**Procedura:** (1) koristite client/service koji dokumentuje podršku za RFC 9298/9484; (2) autentikujte proxy sertifikat/configuration; (3) definišite dozvoljene target route-ove; (4) uključite encrypted DNS unutar putanje; (5) proverite UDP, TCP, IPv6 i failover prema endpoint-ima u vlasništvu organizacije; (6) pregledajte proxy request i flow logove.

**Detekcija:** endpoint-i vide client process i virtual interface; mreže mogu klasifikovati dugotrajan QUIC/TLS ka proxy-ju; proxy logovi otkrivaju CONNECT target/path.

## Tor Browser

**Mehanika:** Tor bira guard, middle i exit relay-e; slojevito šifrovanje ograničava pogled svakog relay-a. Tor Browser dodaje standardizovani browser namenjen otpornosti na fingerprinting.

**Prednosti:** veliki javni anonymity set; nijedan uobičajeni relay ne zna oba kraja; unlinkability odredišta bez pokretanja sopstvenih servera.

**Nedostaci:** sporije; fokusirano na TCP; exit reputacija/blokiranje; logini i otkrivanje identiteta identifikuju korisnika; low-latency timing correlation ostaje.

**Procedura:** (1) preuzmite i proverite Tor Browser iz projekta; (2) zadržite podrazumevana podešavanja i izbegavajte extensions; (3) izaberite odgovarajući security level; (4) kreirajte odvojeni identity/session; (5) izbegavajte identifikujuće naloge i spoljne aktivne dokumente; (6) koristite HTTPS ili authenticated onion services; (7) proverite exit samo pomoću endpointa u vlasništvu organizacije.<sup>[[4]](#references)</sup>

**Detekcija:** lokalne mreže mogu identifikovati poznat guard saobraćaj ako se ne koristi bridge/transport; odredišta vide exit-e i Tor Browser ponašanje; end-to-end observer-i povezuju vreme/volumen.

## Tor bridges i pluggable transports

**Mehanika:** nejavni bridge zamenjuje javni guard; obfs4, Snowflake ili WebTunnel menjaju transport prvog hop-a radi otpornosti na jednostavno blokiranje/probing.

**Prednosti:** zaobilazi cenzuru i prikriva očigledna odredišta javnih relay-a; zadržava Tor circuit nakon ulaska.

**Nedostaci:** transportni obrasci/otkrivanje bridge-a i dalje su mogući; promenljive performanse; ne dodaje zaštitu od naloga ili globalnog timing-a.

**Procedura:** (1) prvo pokušajte direktan Tor; (2) u Tor Browser Connection settings izaberite ugrađeni podržani transport ili zatražite zvanični bridge; (3) ne koristite nasumične binaries/lists; (4) povežite se i izvršite benigni test; (5) testirajte reconnect i clock; (6) zadržite sva druga browser podešavanja standardnim.<sup>[[5]](#references)</sup>

**Detekcija:** censors koriste destination discovery, protocol/flow classification i active probing; defenders treba da razlikuju korišćenje circumvention-a od kompromitovanja i da se oslone na endpoint process/context.

## VPN before Tor i Tor before VPN

**Mehanika:** VPN-before-Tor skriva direktnu upotrebu Tor-a od access ISP-a, ali source izlaže VPN-u. Tor-before-VPN daje VPN-u post-Tor saobraćaj i često stabilan customer/tunnel identitet.

**Prednosti:** uklanja određenog observer-a kada je pravilno projektovano; može dosegnuti mreže koje blokiraju jedan sloj.

**Nedostaci:** složenost, neuobičajen fingerprint, leak-ovi, manji anonymity set i lažni osećaj sigurnosti; Tor Project ove kombinacije tretira kao napredne.<sup>[[6]](#references)</sup>

**Procedura:** (1) zapišite kog observer-a uklanjate i kog novog uvodite; (2) koristite disposable environment; (3) uspostavite samo predviđenu spoljnu putanju; (4) nametnite firewall route-ove; (5) proverite DNS/IPv4/IPv6 i redosled svakog failure-a; (6) uporedite vidljivost oba provajdera; (7) napustite stack ako nema merljivu prednost.

**Detekcija:** lokalni/VPN/Tor observer-i vide različite susedne slojeve; timing ostaje end-to-end; neuobičajeni nested-tunnel fingerprint-i i provider account-i mogu povezati sesije.

## Onion service

**Mehanika:** client i service grade Tor circuit-e do rendezvous-a, skrivajući service IP i izbegavajući exit.

**Prednosti:** zaštita lokacije izvora i service-a; end-to-end onion autentikacija; nema javnog inbound port-a; opciona client authorization.

**Nedostaci:** origin leak kroz update-e/analytics/errors; onion key je kritičan; identitet aplikacije/timing i kompromitovanje host-a ostaju.

**Procedura:** (1) izolujte aplikaciju i vežite je samo za loopback/socket; (2) instalirajte podržani Tor; (3) konfigurišite v3 onion service prema zvaničnim uputstvima; (4) zaštitite/backup-ujte njegov key samo ako je potrebna stabilna identifikacija; (5) dodajte client authorization za zatvorenu upotrebu; (6) uklonite third-party fetches; (7) spolja proverite da origin nije dostupan.<sup>[[7]](#references)</sup>

**Detekcija:** host/network defenders pronalaze Tor process/configuration i outbound circuits; application errors, DNS, sertifikati ili third-party resursi mogu otkriti origin.

## I2P internal services

**Mehanika:** I2P koristi odvojene jednosmerne inbound/outbound tunnel-e za destination-e unutar overlay-a; outproxy-ji ka javnom Internetu uvode tačku poverenja.

**Prednosti:** decentralizovano interno objavljivanje; nema zavisnosti od zvaničnog exit-a; odvojene inbound/outbound putanje.

**Nedostaci:** nije opšta zamena za web; manji ekosistem; dugotrajno ponašanje peer-ova; outproxy može posmatrati javno browsing iskustvo.

**Procedura:** (1) instalirajte iz zvaničnog izvora; (2) koristite dedicated context; (3) dozvolite integration/bandwidth stabilizaciju; (4) pristupite I2P-native service-u u vlasništvu organizacije; (5) izbegavajte outproxy-je osim ako su izričito potrebni; (6) proverite da shutdown ne daje direktan fallback; (7) pregledajte lokalne peer i service logove.<sup>[[8]](#references)</sup>

**Detekcija:** lokalne mreže vide dugotrajan peer saobraćaj i bootstrap ponašanje; endpoint-i otkrivaju router/application procese; outproxy-ji loguju exit-e.

## Mixnets

**Mehanika:** paketi fiksne veličine, batching, kašnjenje, reordering i cover traffic smanjuju vremensku korelaciju; gateway-i povezuju aplikacije.

**Prednosti:** bolja otpornost na timing analysis od low-latency proxy-ja; korisno za asinhrone poruke/transakcije.

**Nedostaci:** latencija, bandwidth overhead, manji deployment i ograničenja aplikacije; gateway/account metadata može ostati.

**Procedura:** (1) izaberite održavani client i podržanu aplikaciju; (2) pročitajte stvarni threat model; (3) instalirajte u odvojenom compartment-u; (4) pošaljite benigne podatke endpointu u vlasništvu organizacije; (5) izmerite latenciju/pouzdanost i reply path; (6) testirajte gateway failure; (7) nikada ne isključujte delay/cover traffic samo zbog brzine.<sup>[[9]](#references)</sup>

**Detekcija:** endpoint-i identifikuju client; access mreže mogu klasifikovati gateway-e/packet cadence; gateway-i i exit-i vide susedne uloge, dok šira korelacija zahteva duže statističke prozore.

## GNUnet anonymous file sharing

**Mehanika:** GNUnet može rutirati publish/search/download zahteve kroz peer-ove i dodati cover traffic u skladu sa anonymity level-om. Njegova dokumentacija upozorava da podrazumevani level 1 ne zahteva cover traffic i da moćna traffic analysis može identifikovati origin.<sup>[[10]](#references)</sup>

**Prednosti:** decentralizovano, application-native anonymous sharing; podesiv zahtev za cover traffic.

**Nedostaci:** nije uobičajen anonymous web access; trošak performansi/storage-a; ograničenja peer-ova i traffic analysis; GNUnet VPN dokumentacija navodi da njegov IP overlay ne pruža dobru anonimnost.

**Procedura:** (1) instalirajte održavani official build; (2) izolujte test peer; (3) ograničite bandwidth/storage; (4) objavite bezopasan, jedinstven test file sa izabranim anonymity level-om; (5) preuzmite ga sa drugog peer-a u vlasništvu organizacije; (6) zabeležite cover traffic i latency; (7) ne tvrdite da IP VPN component pruža jednaku anonimnost.

**Detekcija:** peer bootstrap, overlay saobraćaj, lokalni datastore/process i file identifiers; široki observer može analizirati volumen saobraćaja u odnosu na cover traffic.

## Encrypted DNS, ODoH i ECH

**Mehanika:** DoH/DoT/DoQ šifruju komunikaciju do resolver-a; ODoH razdvaja client adresu od query-ja između proxy-ja i resolver-a; ECH šifruje unutrašnji TLS ClientHello/server name.

**Prednosti:** uklanja plaintext DNS/SNI od nekih lokalnih observer-a; ODoH deli znanje o izvoru i query-ju.

**Nedostaci:** nije IP-anonymity path; resolver/proxy/server zadržavaju svoje uloge; destination IP/timing/volume i endpoint ostaju; fallback može procureti.

**Procedura:** (1) izaberite da li OS, aplikacija ili tunnel kontroliše DNS; (2) uključite strict encrypted mode ili podržani ODoH; (3) testirajte jedinstveni domain u vlasništvu organizacije; (4) lokalno capture-ujte saobraćaj da potvrdite odsustvo clear query-ja; (5) oborite resolver i proverite očekivano ponašanje; (6) za ECH potvrdite da server diagnostics prikazuje prihvatanje inner ClientHello.<sup>[[11]](#references)</sup>

**Detekcija:** endpoint/resolver logovi otkrivaju query-je; mreže identifikuju endpoint-e encrypted resolver-a i destination flow-ove; ECH stanje je vidljivo endpoint-ima/CDN-u čak i kada je sakriveno na putanji.

## Split-provider privacy relay

**Mehanika:** proizvodi kao iCloud Private Relay koriste ingress koji zna client i nezavisno operisan egress koji zna odredište, uz grubo određivanje regiona.

**Prednosti:** privacy podela uz malo trenja; brzo; integrisana DNS/web zaštita za podržani saobraćaj.

**Nedostaci:** obim proizvoda/aplikacije je ograničen; account/platform provider i dalje identifikuje customer-a; nije proizvoljna system anonymity; collusion/legal i timing rizici.

**Procedura:** (1) potvrdite tačne podržane aplikacije i tipove saobraćaja; (2) uključite feature u dedicated platform context-u kada je prikladno; (3) izaberite ponašanje regiona; (4) odvojeno testirajte Safari/DNS i nepodržane aplikacije; (5) pregledajte destination address; (6) testirajte promenu mreže/failure.<sup>[[12]](#references)</sup>

**Detekcija:** access vidi ingress; odredište vidi egress; platform/relay logovi i account records pokrivaju svoje slojeve; nepodržane aplikacije otkrivaju standardne putanje.

## Remote browser, VDI, RDP ili organization jump host

**Mehanika:** browsing/tool execution odvija se na udaljenom sistemu; odredište vidi njegov egress, dok workspace provider vidi operator connection i control plane.

**Prednosti:** brzo; izoluje rizičan sadržaj; stabilan kontrolisani egress; disposable state i snažan organizational audit.

**Nedostaci:** provider/admin može posmatrati sesiju/nalog; screen/clipboard/file channels cure; remote browser fingerprint može biti jedinstven; niste anonimni prema vlasniku workspace-a.

**Procedura:** (1) kreirajte jedan organization-owned workspace po engagement-u; (2) zahtevajte MFA i ograničite administraciju; (3) isključite ili ograničite clipboard/upload/download; (4) usmerite saobraćaj kroz odobreni fiksni egress; (5) ne koristite lični IdP/sync; (6) izvezite samo pregledane dokaze; (7) uništite workspace i credentials prema rasporedu.

**Detekcija:** provider i IdP logovi mapiraju korisnika na sesiju; odredišta grupišu workspace egress/browser; enterprise defenders identifikuju remote-control protokole i anomalne cloud sesije.

## Public ili guest Wi-Fi

**Mehanika:** saobraćaj izlazi kroz venue NAT ili tunnel pokrenut na toj lokaciji.

**Prednosti:** velika brzina i deljena adresa koja nije kućna; nema dedicated infrastrukture.

**Nedostaci:** venue association/DHCP/portal, kamere, kupovine i lokacijski dokazi; neprijateljski peer-ovi/AP-ovi; uslovi korišćenja; fizički rizik.

**Procedura:** (1) pribavite pristup ponuđen gostima i proverite SSID sa osobljem; (2) koristite patched low-trust uređaj; (3) isključite sharing/auto-join i uključite private MAC; (4) završite portal bez ponovljene identifikacije; (5) pokrenite fail-closed VPN/Tor path; (6) proverite tethered saobraćaj; (7) zaboravite mrežu.

**Detekcija:** venue povezuje AP, MAC, DHCP, portal i vreme; odredište vidi venue/tunnel; istražitelji kombinuju fizičke i device dokaze. Nikada ne zaobilazite access control.

## Travel router

**Mehanika:** router u vlasništvu operatora povezuje se na venue Wi-Fi/Ethernet i pruža izolovanu internu mrežu sa nametnutom tunnel politikom.

**Prednosti:** izoluje workstation-e; centralni kill switch/DNS; konzistentna client mreža; štiti privilegovane endpoint-e od lokalnih broadcast-a.

**Nedostaci:** router postaje stabilan radio/DHCP fingerprint; dodaje attack surface; captive portal-i i tethering mogu zaobići tunnel.

**Procedura:** (1) ažurirajte podržani firmware; (2) podesite jedinstvene management credentials i isključite WAN admin/WPS/UPnP; (3) konfigurišite private upstream MAC gde je dozvoljeno; (4) kreirajte odvojeni internal SSID; (5) nametnite full-tunnel DNS/IPv6 firewall policy; (6) testirajte portal, reconnect i tunnel failure.

**Detekcija:** venue vidi router association i oblik saobraćaja; lokalni RF/DHCP fingerprinting ga identifikuje; VPN provider vidi venue source.

## Cellular, prepaid SIM i eSIM

**Mehanika:** modem koristi carrier radio access i obično carrier NAT; VPN/Tor sloj može promeniti exit vidljiv odredištu.

**Prednosti:** nezavisno od lokalne wired/Wi-Fi mreže; mobilno; velika brzina; korisno kao backhaul za odobrene drop-ove.

**Nedostaci:** carrier zna subscriber/eSIM, IMSI, IMEI, cells, vreme i dodeljene portove; zakoni o registraciji se razlikuju; zajednička lokacija sa ličnim telefonom povezuje uređaje.

**Procedura:** (1) zakonito pribavite service sa tačnim zahtevanim podacima; (2) koristite odvojeni modem/device u vlasništvu organizacije; (3) evidentirajte ga kod exercise controller-a; (4) isključite nepovezane radio-interfejse/naloge; (5) uspostavite odobreni tunnel; (6) testirajte da li tethered clients zaista prate tunnel; (7) proverite pretpostavke o provajderu i retention-u pre putovanja.<sup>[[13]](#references)</sup>

**Detekcija:** carrier records i RF lokacija; enterprise USB/PCI/MDM inventory i rogue-hotspot surveys; destination/tunnel timing.

## Satellite Internet i satellite downlink abuse

**Mehanika:** normalni service koristi registrovani terminal/provajder. Stariji one-way DVB-S abuse omogućavao je prijemniku unutar beam-a da posmatra nešifrovan downlink saobraćaj namenjen legitimnom pretplatniku, dok je koristio drugu putanju za outbound requests.

**Prednosti:** široka pokrivenost; nezavisan last mile; istorijski one-way abuse mogao je pogrešno pripisati C2 geografiji pretplatnika.

**Nedostaci:** equipment/RF/provider records; latency i coverage; moderni bidirectional systems se razlikuju; outbound path i asymmetric routing ostaju dokazi.

**Procedura:** za zakonit pristup registrujte terminal u vlasništvu organizacije i tunelujte saobraćaj prema potrebi. Za emulaciju istorijskog Turla ponašanja, reprodukujte sintetičke one-way packet captures u RF-free laboratoriji i testirajte da li analitičari otkrivaju reply hostu koji nije poslao zahtev; ne presrećite živi satellite saobraćaj.<sup>[[14]](#references)</sup>

**Detekcija:** provider/terminal telemetry, RF direction finding, nemoguć/asimetričan flow, RTT/routing inconsistency i malware configuration.

## Residential/mobile proxy ili consented proxyware

**Mehanika:** backconnect gateway dodeljuje consumer broadband/mobile exit-e, sticky ili rotirajuće. Supply može biti zasnovan na pristanku, obmanjujuće uključen u paket ili zlonameran.

**Prednosti:** velika brzina; geografski izbor; consumer ASN izbegava neke hosting block-ove; veliki pool-ovi.

**Nedostaci:** rizik porekla/pristanka i zakonitosti; broker vidi customer-a; infected exit-i štete žrtvama; rotacija stvara anomalije; skupo i nepouzdano.

**Procedura:** koristite samo dokumentovane, informisano odobrene agent-e u vlasništvu organizacije za emulaciju: (1) enroll-ujte test endpoint-e; (2) evidentirajte vlasnike/IP adrese; (3) konfigurišite gateway; (4) rotirajte sticky/per-request režime; (5) šaljite samo ka targetu u vlasništvu organizacije; (6) uporedite gateway/exit/target logove; (7) uklonite svaki agent.

**Detekcija:** nemoguće kretanje, stabilan browser/account kroz brze promene IP/ASN-a, backconnect protokoli, proxyware process/network artefakti i broker/controller odnosi.

## ORB, botnet i compromised edge-device relay-i

**Mehanika:** iznajmljeni ili kompromitovani router-i/IoT/serveri formiraju access, traversal i exit uloge kojima se upravlja kao flotom. Više APT customer-a može deliti flotu.

**Prednosti:** pozajmljena reputacija/geografija; kratkotrajni exit-i; otporna multi-hop mesh mreža; slaba direktna veza actor-to-IP.

**Nedostaci:** kriminalna viktimizacija; implant/controller i fleet obrasci; zaplena posrednika; neujednačene performanse; operator/customer service records.

**Procedura:** nikada ne kompromitujte stvarne uređaje. Koristite [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) kreirajte izolovane entry/transit/target mreže; (2) priključite relay container-e sa dve mrežne kartice u vlasništvu organizacije; (3) prosledite samo jedan test port; (4) pošaljite benigni zahtev; (5) proverite da target vidi samo exit; (6) rotirajte exit; (7) uklonite sve imenovane asset-e.<sup>[[15]](#references)</sup>

**Detekcija:** pratite topologiju, portove/service-e, controller odnose, implant fingerprint-e i lifecycle node-ova; centralizujte edge configuration/flow/integrity telemetry; ne poistovećujte exit IP sa actor-om.

## CDN redirector, domain fronting i domainless fronting

**Mehanika:** javni edge prosleđuje samo saobraćaj koji odgovara grammar-u; fronting postavlja benigni spoljašnji SNI i drugi unutrašnji HTTP authority, ili prazan SNI, kada intermediary to dozvoljava.

**Prednosti:** skriva/štiti back-end; brz globalni edge; odredište se stapa sa deljenim service-om; brz cutover.

**Nedostaci:** CDN vidi svo routing i tenant; mnogi provajderi zabranjuju cross-tenant fronting; SNI/Host/process/flow i account artefakti; ponovno korišćenje configuration-a grupiše campaign-e.

**Procedura:** reprodukujte samo na reverse proxy-ju u vlasništvu organizacije pomoću [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): kreirajte lokalni sertifikat/edge, usmerite jedan mismatch-ovani Host ka targetu u vlasništvu organizacije, logujte SNI i Host, pošaljite normalne/mismatch-ovane zahteve, zatim uklonite container-e.<sup>[[16]](#references)</sup>

**Detekcija:** uporedite SNI/ECH/Host/`:authority` na endpointu ili terminating edge-u; povežite initiating process, tenant/origin, request grammar i flow cadence.

## Dynamic DNS, DGA, fast flux i double flux

**Mehanika:** DDNS ažurira stabilno ime; DGA izvodi promenljiva kandidatna imena; fast flux rotira service adrese sa niskim TTL-om; double flux rotira i name server-e.

**Prednosti:** otporno otkrivanje; brza zamena infrastrukture; controller je sakriven iza više node-ova.

**Nedostaci:** DNS stvara centralizovanu telemetry; entropy/NXDOMAIN/churn; nizak TTL i široki ASN obrasci; registracija i authoritative infrastruktura ostaju.

**Procedura:** koristite [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): poslužite zone u vlasništvu organizacije koja vraća RFC 5737 adrese sa TTL-om od pet sekundi, upitujte je ponavljano, promenite sintetički epoch i proverite analytics. Nikada ne usmeravajte test records ka trećim stranama.<sup>[[17]](#references)</sup>

**Detekcija:** jedinstveni odgovori/ASN-ovi u kliznom prozoru, median TTL, geografija, authoritative churn, DGA NXDOMAIN/lexical/temporal klasteri i process follow-on; legitimne CDN-ove isključite na osnovu konteksta.

## Legitimate web service, dead-drop resolver i one-way tasking

**Mehanika:** javni post, repository, document, object ili feed sadrži kodirani trenutni endpoint ili task. Client može vratiti rezultate drugim kanalom.

**Prednosti:** dozvoljen service sa dobrom reputacijom; TLS; rotacija endpoint-a bez promene binary-ja; asinhroni tasking otežava jednostavnu flow korelaciju.

**Nedostaci:** stabilni object/account/API identifikatori; provider records; endpoint decode/follow-on sequence; sadržaj može biti zaplenjen ili promenjen.

**Procedura:** koristite [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): host-ujte kodirani pointer na jednom container-u u vlasništvu organizacije, preuzmite/dekodirajte ga sa short-lived client-a, kontaktirajte drugi service u vlasništvu organizacije, sačuvajte oba loga, zatim uklonite okruženje.

**Detekcija:** povežite neobičan process → čitanje stabilnog object-a → decode → novo odredište; hash-ujte/sačuvajte content i zadržite pune object path-ove, ne samo domain.

## Serverless, ephemeral container i cloud-NAT egress

**Mehanika:** functions/short-lived jobs rade iza provider NAT-a ili front-a; logical service ostaje stabilan dok se instance i adrese rotiraju.

**Prednosti:** brzo postavljanje/uklanjanje; shared egress na nivou provajdera; malo lokalnog diska; elastično regionalno rutiranje.

**Nedostaci:** tenant, role, API, image, secret, invocation, billing i front-to-origin logovi su trajni; cold-start i platform fingerprint-i; provider policy.

**Procedura:** (1) koristite organization-owned exercise tenant; (2) deploy-ujte benignu function koja zahteva samo endpoint u vlasništvu organizacije; (3) zabeležite project/role/image/config; (4) izvršite je kroz više instance-a; (5) uporedite target IP adrese sa audit/request ID-jevima; (6) testirajte retention logova; (7) uklonite function, role i secrets.

**Detekcija:** cloud audit/invocation logovi, neobično kreiranje role-a, shared egress sa stabilnim request grammar-om, image/layer i secret reuse, kao i front-origin korelacija.

## Authorized on-site drop

**Mehanika:** inventarisani mali računar koristi lokalni wired/Wi-Fi i outbound VPN/cellular rendezvous, predstavljajući lokalni source.

**Prednosti:** realističan test internal origin-a; velika brzina; može testirati NAC, fizički inventory i egress kontrole.

**Nedostaci:** fizičko otkrivanje/krađa; serial/MAC/USB/DHCP/PoE/RF i camera dokazi; gubitak može otkriti credentials.

**Procedura:** pratite [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) pribavite tačno pisano odobrenje za postavljanje; (2) zabeležite serial, MAC, fotografiju, lokaciju i vreme preuzimanja; (3) koristite potpisani minimalni image i short-lived mutual credentials; (4) ograničite outbound-only destinations/capabilities; (5) dodajte server-side quarantine i bandwidth limits; (6) testirajte SOC visibility i reakciju na gubitak; (7) preuzmite uređaj, sačuvajte zahtevane dokaze, zatim ga sanitizujte prema dogovorenoj lifecycle policy. Nikada ga ne skrivajte na lokaciji čiji vlasnik nije pristao.

**Detekcija:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera i fizička inspekcija.

## Nearest-neighbor wireless pivot

**Mehanika:** actor kontroliše host u radio dometu targeta, a zatim koristi target Wi-Fi credentials da daljinski pređe granicu. APT28 je na ovaj način koristio obližnje kompromitovane organizacije.<sup>[[18]](#references)</sup>

**Prednosti:** nema putovanja operatora; target vidi lokalni radio source; zaobilazi kontrole koje se primenjuju samo na Internet entry.

**Nedostaci:** potreban je nearby compromised/owned dual-radio host i validan access; RADIUS/NAC/AP i neighbor endpoint dokazi; signal/device anomalies.

**Procedura:** reprodukujte samo pomoću [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): pridružite owned pivot neighbor i target lab SSID-ovima, prosledite samo jedan service, prikupite oba AP/pivot loga, zatim uključite EAP-TLS/device posture i potvrdite da drugi pokušaj ne uspe.

**Detekcija:** povežite RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login i fizičko prisustvo; tražite nearby endpoint-e sa istovremenim radio-interfejsima, forwarding-om i tunnel-ima.

## Community mesh, delay-tolerant i offline store-and-forward

**Mehanika:** saobraćaj prolazi kroz lokalne peer-ove, asinhrone gateway-e, removable media ili zakazane queue-ove umesto kroz jednu interaktivnu Internet sesiju.

**Prednosti:** radi tokom prekida/cenzure; odložena/batch-ovana isporuka slabi jednostavnu timing korelaciju; nema centralnog last mile-a za lokalnu komunikaciju.

**Nedostaci:** velika latencija; mali anonymity set; custody/fizički metadata; zlonamerni peer-ovi; podaci na kraju stižu do gateway-a koji ih posmatra.

**Procedura:** (1) napravite izolovanu mesh mrežu ili file queue sa tri node-a u vlasništvu organizacije; (2) end-to-end šifrujte i autentikujte sadržaj; (3) uklonite direktne Internet route-ove iz origin-a; (4) prosledite benigni file nakon kontrolisanog kašnjenja; (5) proverite da samo gateway kontaktira target u vlasništvu organizacije; (6) uporedite custody/timestamps; (7) sačuvajte zahtevane dokaze, zatim sanitizujte privremene medije/queue-ove tokom odobrenog zatvaranja.

**Detekcija:** endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity i content identifiers. Duži correlation windows zamenjuju analizu interaktivnog flow-a.

## TURN relay i forced-relay WebRTC

**Mehanika:** Traversal Using Relays around NAT (TURN) dodeljuje javnu relay adresu i prenosi UDP, TCP ili TLS saobraćaj između client-a i peer-ova. ICE policy može nametnuti relay umesto izlaganja direktnog candidate-a. TURN rešava reachability, ne opštu anonimnost: server autentikuje client i vidi allocations, peer-ove, vreme i volumen.<sup>[[19]](#references)</sup>

**Prednosti:** široka implementacija; radi sa restriktivnim NAT-om; podržava mobile WebRTC; peer ne dobija direktnu transport adresu client-a kada je relay-only policy pravilno nametnut.

**Nedostaci:** TURN operator vidi obe susedne strane; application identity, media fingerprint i signaling ostaju; relay-only troši bandwidth i latency; pogrešna konfiguracija i dalje može prikupljati host ili server-reflexive candidates.

**Procedura:** (1) deploy-ujte organization-owned TURN service sa TLS-om i short-lived credentials; (2) ograničite realm-e, peer-ove, portove, quota-e i expiration; (3) podesite test application na relay-only ICE; (4) pozovite peer u vlasništvu organizacije; (5) pregledajte `getStats()` i packet capture da potvrdite da su samo relay candidates nosili media; (6) oborite relay i potvrdite da nema direktnog fallback-a; (7) zadržite allocation logove za engagement.

**Detekcija:** signaling, browser process i TURN allocations povezuju session sa relay-em; mreže vide dugotrajne flow-ove ka TURN portovima ili TLS endpoint-ima; peer vidi dodeljeni relay. **Captured node:** application state i ephemeral TURN credentials mogu otkriti realm i rendezvous service. Smanjite izloženost pomoću short-lived credentials po uređaju i zadržite operator authentication samo na controller-u.

## Outbound-only rendezvous ili reverse overlay

**Mehanika:** node iza NAT-a pokreće authenticated connection ka brokeru kojim upravlja organizacija. Operator se odvojeno autentikuje na brokeru, koji odobrava uzak management channel; nisu potrebni inbound port forwarding ni direktna operator-to-node putanja.

**Prednosti:** stabilno iza NAT-a i captive last mile-a; centralna revokacija i audit; promene adrese field node-a ne zahtevaju operator discovery; čisto razdvaja operator identity od node credential-a.

**Nedostaci:** broker postaje correlation point visoke vrednosti; periodični keepalive-i su prepoznatljivi; široki tunnel može postati nesiguran pivot; gubitak broker-a prekida management.

**Procedura:** pratite [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): izdajte jedan scoped device identity, dozvolite samo owned broker i odobreni management service, koristite authenticated keepalive, nametnite fail-closed routing, testirajte promene adrese i oporavak nakon reboot-a i revoke-ujte identity tokom loss drill-a. WireGuard dokumentuje 25-sekundni persistent keepalive kao široko koristan NAT interval kada je zaista potreban.<sup>[[20]](#references)</sup>

**Detekcija:** broker i identity-provider logovi mapiraju obe strane; access mreža vidi ponovljeno šifrovano odredište/cadence; endpoint inventory prikazuje overlay agent. **Captured node:** pretpostavite da su njegov device key, broker name, tunnel adrese i cached task data otkriveni. Ne sme sadržati operator private key, personal account ili reusable controller token.

## Pull mailbox, message queue ili object-store rendezvous

**Mehanika:** field workload periodično proverava authenticated mailbox za signed, pre-approved jobs i objavljuje ograničene rezultate. Operator piše u queue kroz odvojeni control plane; između njih nema interaktivnog socket-a.

**Prednosti:** podnosi povremene veze; razdvaja timing i addressing; quota-e i schema-i mogu ograničiti capability; jednostavan centralizovani audit i revocation.

**Nedostaci:** polling cadence i stabilna object/queue imena fingerprint-uju sistem; provider logovi spajaju producer-a i consumer-a; odložena kontrola; zaplenjeni queued data mogu otkriti vežbu.

**Procedura:** (1) kreirajte jedan engagement queue i jedan device identity; (2) definišite signed schema benignih, izričito ograničenih job-ova; (3) podesite message TTL, maksimalnu veličinu rezultata i rate; (4) dozvolite node-u da čita samo svoj queue i piše samo u svoj result prefix; (5) testirajte offline accumulation, duplicate delivery i revocation; (6) centralizujte immutable access logove; (7) obrišite queue nakon ispunjenja retention zahteva.

**Detekcija:** tražite periodične API calls neobičnog process-a, stabilne bucket/object/queue path-ove, isti user-agent ili TLS ponašanje i fetch-then-new-connection sequence. **Captured node:** lokalni cache može otkriti pending jobs i object names; držite cache šifrovanim, ograničenim i disposable, uz očuvanje authoritative controller logova.

## Dual-uplink failover i connection migration

**Mehanika:** odobreni field node ima dva nezavisna uplink-a—na primer venue Ethernet/Wi-Fi i organization cellular—and održava control session kroz overlay ili message broker dok se route-ovi menjaju. Ovo je availability engineering, ne anonimnost.

**Prednosti:** preživljava kvar jednog provajdera, AP-a ili captive portal-a; podržava planirano održavanje; omogućava brzu izolaciju sumnjive putanje.

**Nedostaci:** dva provajdera stvaraju dve lokacijske/account evidencije; istovremena upotreba olakšava korelaciju; route i DNS leak-ovi tokom failover-a; cellular co-location dokazi ostaju.

**Procedura:** (1) registrujte oba organization-owned interfejsa i provajdera; (2) dodelite determinističke route priorities i health checks ka owned endpoint-ima; (3) vežite DNS i management za overlay; (4) sprečite sekundarnu putanju da prihvata inbound traffic; (5) isključite svaku putanju i proverite session recovery, source policy i odsustvo direktnog destination access-a; (6) upozorite na neplaniranu promenu putanje; (7) dokumentujte upotrebu podataka i roaming limits.

**Detekcija:** povežite isti device certificate, request grammar i timing kroz ASN-ove; lokalni inventory vidi oba radio-interfejsa; carrier-i/venue-i zadržavaju sopstvene records. **Captured node:** oba SIM/device identifier-a i poznati SSID-ovi mogu biti vidljivi; koristite organization assets i nikada ne povezujte node sa ličnim uređajima.

## Organization private APN ili managed cellular tunnel

**Mehanika:** carrier private APN smešta enrolled SIM-ove u private routed domain ili tuneluje saobraćaj do enterprise gateway-a. Razdvaja uređaj od javnog mobile Internet-a, ali ga ne skriva od carrier-a ili contracting organization-a.

**Prednosti:** stabilno private addressing; carrier-level enrollment i traffic policy; izbegava javnu inbound exposure; korisno za odobrene udaljene appliance-e.

**Nedostaci:** subscriber, IMSI/IMEI, cell i billing attribution su jaki; procurement lead time i trošak; carrier/gateway outage; nije anonimno prema operatoru.

**Procedura:** (1) ugovorite APN u ime assessment organizacije; (2) whitelist-ujte samo registrovane SIM-ove i gateway prefix-e; (3) dodajte application-layer mutual authentication; (4) ograničite APN route na rendezvous i update services; (5) testirajte SIM removal, roaming, public-Internet breakout i revocation; (6) pratite carrier i gateway records; (7) otkažite ili quarantine-ujte svaki SIM pri završetku.

**Detekcija:** carrier inventory i cell telemetry, APN gateway flows, SIM/IMEI mismatch i enterprise asset records. **Captured node:** SIM i modem identifikuju contract čak i kada je storage šifrovan; capture resilience zato znači brzu suspenziju i usku autorizaciju, a ne mogućnost poricanja.

## Long-range point-to-point wireless bridge

**Mehanika:** directional Wi-Fi ili drugi licencirani/nekoordinisani point-to-point radio povezuje dve owner-approved lokacije, sa Internet egress-om na udaljenoj lokaciji. Može pomeriti prividnu IP lokaciju bez commercial proxy-ja.

**Prednosti:** veliki throughput; nezavisno od posrednih wired carrier-a; kontrolisani RF i routing; korisno za testiranje segmentacije i remote-site monitoring-a.

**Nedostaci:** line-of-sight, spectrum, landlord i regulatorna ograničenja; karakteristične RF emisije i hardware; oba endpoint-a su fizički dokazi; vreme/napajanje/alignment utiču na stabilnost.

**Procedura:** (1) pribavite pisanu dozvolu za obe lokacije i proverite spectrum/power pravila; (2) ispitajte putanju bez emitovanja izvan odobrenih parametara; (3) koristite authenticated encryption i management VLAN; (4) ograničite bridge na owned rendezvous ili test subnet; (5) testirajte failover, alignment, power recovery i RF containment; (6) označite i inventarišite oba radija; (7) uklonite ih i proverite reset configuration-a nakon vežbe.

**Detekcija:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic i remote-site egress logovi. **Captured node:** configuration otkriva peer i management domain; koristite jedinstvene exercise credentials, bez ličnih management naloga i uz brzu revocation peer key-a.

## Consented cooperative ili community exit

**Mehanika:** volonteri ili partnerske organizacije svesno pokreću relay-e prema objavljenoj policy. Saobraćaj izlazi iz deljenog community pool-a, dok coordination layer vodi evidenciju zloupotreba i revocation-a.

**Prednosti:** raznovrsne non-cloud mreže; izričit pristanak je bezbedniji od proxyware-a; shared governance može distribuirati poverenje; korisno za istraživanja i studije otpornosti na cenzuru.

**Nedostaci:** mali pool-ovi i membership records smanjuju anonimnost; exit operator-i primaju pritužbe i vide traffic metadata; zlonamerni učesnici, promenljiva dostupnost i razlike u jurisdikcijama.

**Procedura:** (1) objavite acceptable-use i logging policy; (2) pribavite informisani opt-in svakog operatora; (3) izdajte jedinstveni relay identity i ograničite destinations/rates; (4) obezbedite abuse handling i one-action revocation; (5) tokom testiranja šaljite samo odobreni saobraćaj ka endpoint-ima u vlasništvu organizacije; (6) merite churn i correlation exposure; (7) uredno uklonite relay kada pristanak prestane.

**Detekcija:** membership/control-plane records, relay certificates, common software fingerprint i exit ponašanje identifikuju pool. **Captured node:** relay configuration može identifikovati cooperative, ali ne treba da sadrži client identities; accountability između client-a i session-a čuvajte na authorized controller-u uz access control.

## IPv6 temporary addresses i prefix rotation

**Mehanika:** IPv6 privacy extensions stvaraju privremene interface identifier-e kako se stabilna adresa ne bi koristila za svaku outbound konekciju. Promene provider prefix-a mogu dodati rotaciju, ali delegated prefix, subscriber record i upper-layer fingerprint ostaju.<sup>[[21]](#references)</sup>

**Prednosti:** smanjuje pasivno dugoročno praćenje stabilnim interface identifier-om; ugrađeno u uobičajene operativne sisteme; nema relay overhead-a.

**Nedostaci:** nije source anonymity; ISP i lokalna mreža i dalje znaju prefix/device; DNS, nalozi i browser state povezuju sesije; address churn komplikuje allowlists i logging.

**Procedura:** (1) pregledajte trenutne stable i temporary adrese na client-u u vlasništvu organizacije; (2) uključite OS-supported privacy-address default umesto third-party spoofing-a; (3) ponavljano zahtevajte owned IPv6 endpoint kroz više address lifetime-a; (4) potvrdite da se inbound services bind-uju samo za namenjene stable adrese; (5) zadržite DHCPv6/RA/neighbor i precizne endpoint logove; (6) testirajte VPN/firewall ponašanje za svaku IPv6 adresu.

**Detekcija:** povežite delegated prefix, layer-2 identity, neighbor discovery, account i endpoint telemetry umesto tretiranja jedne adrese kao jednog uređaja. **Captured node:** network profiles i interface identifiers ostaju; temporary addressing sprečava jedan pasivni identifier, ne forenzičku atribuciju.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 i meek

**Mehanika:** pluggable transport menja način na koji se prva Tor konekcija prikazuje ili način na koji dolazi do bridge-a. Snowflake koristi short-lived volunteer WebRTC proxy-je, WebTunnel liči na običan HTTPS, obfs4 se opire jednostavnoj identifikaciji protokola i active probing-u, a meek prosleđuje kroz podržanu web infrastrukturu. To su transporti za zaobilaženje cenzure do Tor-a, ne dodatni end-to-end anonymity slojevi.<sup>[[22]](#references)</sup>

**Prednosti:** korisno kada su direktan Tor ili poznati relay-i blokirani; Snowflake izbegava stabilnu javnu bridge adresu; integrisano je u održavane Tor client-e; odredište i dalje dobija uobičajena Tor svojstva.

**Nedostaci:** niže ili promenljive performanse; broker/front/bridge i lokalna mreža posmatraju različite metadata; transport fingerprint-i i blocking i dalje su mogući; volunteer proxy ne zamenjuje Tor i ne treba mu verovati application plaintext.

**Procedura:** (1) instalirajte i proverite zvanični Tor Browser ili podržani Tor client; (2) izaberite ugrađeni transport u Connection/Bridges; (3) povežite se samo sa owned diagnostic page; (4) potvrdite da page vidi Tor exit, a ne Snowflake/WebTunnel peer; (5) uporedite bootstrap i performance; (6) oborite transport i potvrdite da se client ne povezuje tiho direktno; (7) vratite se na standardnu podržanu configuration nakon testa.

**Detekcija:** censor može kombinovati destination allowlists, TLS/WebRTC ponašanje, broker discovery i flow analysis; endpoint-i otkrivaju Tor i transport configuration. **Capture-resilient OPSEC:** koristite standardni client, nikada ne kopirajte lični browser state u njega i pretpostavite da je bridge/broker history obnovljiv. **Monitoring:** pratite Tor bootstrap logove, neočekivane direct DNS/connection attempts i controller-side owned-page observations; transport failure nije dokaz otkrivanja.

## Refraction networking ili decoy routing

**Mehanika:** cooperating network operator detektuje covert signal u saobraćaju koji je naizgled adresiran ka dozvoljenom decoy-ju i preusmerava flow ka circumvention proxy-ju. Deployment zahteva infrastrukturu na mrežnoj putanji; client to ne može napraviti samo izborom bezazlenog website-a.<sup>[[23]](#references)</sup>

**Prednosti:** prividno odredište može biti teško blokirati bez kolateralne štete; nije potrebno distribuirati javnu bridge adresu; koristan istraživački model za on-path-assisted circumvention.

**Nedostaci:** specijalizovano ISP/transit učešće; deployability i performance zavise od routing-a; client-to-decoy flow i proxy-side activity ostaju; globalni ili cooperating observer može povezati timing.

**Procedura:** ne signalizujte kroz mreže koje nisu uključene. Reprodukujte arhitekturu u izolovanoj laboratoriji: (1) kreirajte owned client, router, decoy i proxy namespace-ove; (2) koristite benigni tagged test request; (3) dozvolite owned router-u da samo taj tag preusmeri ka proxy-ju; (4) logujte pre/post-routing tuple-ove i request ID-jeve; (5) uporedite obične i signaled flow-ove; (6) testirajte false positives i uklanjanje; (7) uništite lab route-ove.

**Detekcija:** ovlašćeni network operator-i mogu pregledati routing divergence, neobično client hello/tag ponašanje i razlike između decoy i back-end flow-ova. **Capture-resilient OPSEC:** research client treba da sadrži samo test keys i documentation addresses. **Monitoring:** uporedite signed lab-router decisions sa proxy arrivals; ne probajte production transit provajdere da biste utvrdili da li su detektovali signaling.

## Content-addressed gateway ili cached peer retrieval

**Mehanika:** HTTP gateway preuzima IPFS content identifier (CID), moguće iz svog cache-a ili od peer-ova, i vraća proverljiv sadržaj client-u. Originalni publisher može videti gateway ili druge peer-ove umesto krajnjeg čitaoca; gateway vidi reader IP i zahtevani CID. Native peer-to-peer retrieval izlaže client peer-ovima i DHT/routing učesnicima.<sup>[[24]](#references)</sup>

**Prednosti:** publisher i reader mogu biti razdvojeni cache-ovima; immutable content proverljiv je hash-om; replicirani podaci preživljavaju gubitak jednog host-a; HTTP client-ima nije potreban native peer stack.

**Nedostaci:** javni CID-ovi i gateway logovi otkrivaju interesovanja; timing prvog preuzimanja može povezati publisher-a i reader-a; malicious web content i path-style same-origin opasnosti; javni gateway-i su best-effort i zabranjuju abuse.

**Procedura:** (1) objavite bezopasan test file na owned private IPFS swarm-u ili owned gateway-u; (2) zabeležite CID; (3) preuzmite ga kroz odvojeni owned HTTP gateway koristeći subdomain isolation; (4) proverite bytes prema CID-u; (5) ponovite nakon caching-a; (6) uporedite publisher, peer i gateway logove; (7) unpin-ujte i uklonite test content kada retention istekne.

**Detekcija:** gateway-i loguju source/CID; DHT i peer konekcije otkrivaju retrieval; endpoint history i file hashes identifikuju content. **Capture-resilient OPSEC:** ne čuvajte private publishing key na read-only field client-u i šifrujte osetljiv sadržaj pre content addressing-a. **Monitoring:** upozorite na neočekivano pinning, promenu peer-set-a, CID request-e izvan allowlist-e ili gateway account notices.

## Private information retrieval service

**Mehanika:** Private Information Retrieval (PIR) omogućava client-u da preuzme jedan record iz baze dok se selected index kriptografski skriva od servera prema navedenom single- ili multi-server threat model-u. Štiti izbor query-ja za ograničeni dataset; nije opšti web access niti IP anonymity.<sup>[[25]](#references)</sup>

**Prednosti:** snažna application-specific query privacy; merljiv leakage model; korisno za key directories, blocklists ili male javne baze; može smanjiti potrebu otkrivanja tačnih lookup terms.

**Nedostaci:** computation/bandwidth overhead; server saznaje connection time/IP ako se ne kombinuje sa relay-em; dataset version, response size i application state mogu razdvajati korisnike; zrelost implementacije varira.

**Procedura:** (1) deploy-ujte audited PIR implementation nad synthetic owned database-om; (2) objavite dataset version i parameters; (3) preuzmite više index-a kroz request-e iste veličine; (4) lokalno proverite ispravnost; (5) uporedite server logove i potvrdite da index nije prisutan; (6) testirajte malicious/truncated responses i version mismatch; (7) dokumentujte tačnu privacy pretpostavku umesto nazivanja anonymous browsing-om.

**Detekcija:** mreže vide service use i volume; endpoint telemetry otkriva client i final record use; kompromitovan server može menjati datasets ili timing. **Capture-resilient OPSEC:** na client-u čuvajte samo javne database parameters i ograničeni cache. **Monitoring:** proveravajte signed dataset roots, fiksne request shapes, promene error rate-a i server-key rotations.

## Constrained server-side fetcher, preview ili rendering service

**Mehanika:** udaljeni service preuzima ili renderuje URL i vraća screenshot, metadata ili sanitizovani sadržaj. Odredište vidi fetcher address; service vidi requester-a, URL i rezultat. Zloupotreba link-preview bot-ova, security scanner-a ili third-party URL fetcher-a nije odobrena proxy upotreba.

**Prednosti:** izoluje active content od workstation-a; odredište dobija kontrolisani fetcher fingerprint; mogu se nametnuti ograničenja tipa file-a, veličine, odredišta i renderovanja; disposable execution environment.

**Nedostaci:** service ima potpuno znanje o zahtevu; account/API/billing records; SSRF i data-exfiltration rizik; scripts, authentication i interaktivni sajtovi možda neće raditi; jedinstveni URL-ovi povezuju requester-a i fetch.

**Procedura:** (1) deploy-ujte organization-owned fetcher sa strogim allowlist-om owned test domain-a; (2) blokirajte private, link-local, metadata i redirect-to-unapproved adrese; (3) ograničite methods, redirects, bytes i render time; (4) uklonite credentials/cookies; (5) pošaljite owned URL; (6) uporedite requester, fetcher i target logove; (7) uništite render instance i zadržite centralni audit prema policy.

**Detekcija:** target vidi service ASN/fingerprint; provider i controller logovi mapiraju requester-a na URL; endpoint process/API calls prikazuju submission. **Capture-resilient OPSEC:** koristite jedan short-lived project token bez authority-ja nad proizvoljnim destination-ima. **Monitoring:** upozorite na allowlist denials, redirect violations, fetches bez controller job ID-ja i provider abuse notices.

## Anycast rendezvous pool

**Mehanika:** više organization-controlled node-ova oglašava ili predstavlja jednu stabilnu service adresu, a routing bira bližu instancu. Anycast poboljšava dostupnost i skriva pojedinačni back-end od client-a, ali operator i dalje kontroliše sve instance, a service address je stabilna.<sup>[[26]](#references)</sup>

**Prednosti:** otporan regionalni ingress; nema field reconfiguration kada jedna instanca otkaže; DDoS/load distribution; centralna policy može premeštati sesije između poznatih node-ova.

**Nedostaci:** BGP/CDN i provider records identifikuju organizaciju; promene putanje mogu prekinuti stateful sessions; monitoring se razlikuje prema lokaciji client-a; jedna stabilna adresa se lako blokira ili grupiše po reputaciji.

**Procedura:** koristite provider-supported organization project ili isolated routing lab: (1) deploy-ujte dva identična authenticated health endpoint-a; (2) izložite jednu dokumentovanu service address; (3) čuvajte session state na brokeru, ne na edge-u; (4) povucite jedan node i proverite reconnect; (5) testirajte certificate, policy i log consistency; (6) upozorite na unauthorized origin/region; (7) uklonite advertisements i credentials pri zatvaranju.

**Detekcija:** BGP/RPKI/history, provider tenancy, sertifikati i identično service ponašanje identifikuju pool. **Capture-resilient OPSEC:** edge sadrži samo regional service identity i nijedan operator ili fleet-enrollment key. **Monitoring:** sondirajte svaki region iz authorized monitors, uporedite route origin i configuration digest i tretirajte neočekivani origin kao incident.

## QUIC migration i Multipath TCP continuity

**Mehanika:** QUIC connection IDs mogu održati client session kroz NAT rebinding ili promene adrese; Multipath TCP može prenositi jedan pouzdan byte stream kroz više subflow-ova. Poboljšavaju kontinuitet tokom Wi-Fi/cellular prelaza, ali zajednički peer vidi stare i nove putanje, pa cross-path correlation može biti lakša.<sup>[[27]](#references)</sup>

**Prednosti:** brži oporavak tokom uplink promena; application session ne mora početi iznova; MPTCP može kombinovati otpornost i throughput; vredno za odobrene field node-ove.

**Nedostaci:** nije anonimnost; peer vidi migration/subflows; connection identifiers i simultani saobraćaj povezuju putanje; podrška middlebox/carrier-a varira; duplirani provider records povećavaju izloženost.

**Procedura:** (1) uključite podržani transport samo između owned field client-a i rendezvous-a; (2) autentikujte aplikaciju nezavisno od IP-a; (3) započnite ograničen transfer na odobrenom Wi-Fi-ju; (4) pređite na organization cellular; (5) potvrdite path validation, data integrity i odsustvo clear/direct fallback-a; (6) testirajte idle timeout i povratak; (7) zadržite broker records svake promene putanje.

**Detekcija:** peer direktno vidi address migration ili MPTCP subflows; access providers vide svoj deo; connection IDs, TLS identity i timing povezuju oba. **Capture-resilient OPSEC:** čuvajte samo device-scoped session material i brzo ističite resumable state. **Monitoring:** upozorite na nemoguće promene putanje, istovremene neodobrene mreže, migration storms i resumption nakon quarantine-a.

## Managed CI/CD ili ephemeral automation runner egress

**Mehanika:** organization-owned workflow izvršava ograničenu network proveru na hosted runner-u. Odredište vidi cloud runner address, dok platforma zadržava repository, actor, workflow, token, log i billing attribution. Ovo je remote execution sa accountable egress-om, ne anonimnost od provajdera.<sup>[[28]](#references)</sup>

**Prednosti:** disposable clean environment; reproducible job definition; nema inbound connection-a; korisno za geografski distribuirane availability checks; snažan controller audit.

**Nedostaci:** platforma i organizacija identifikuju initiator-a; široki workflow token-i i untrusted pull request-ovi su opasni; shared IP reputation; logovi/artifacts mogu zadržati secrets ili target data.

**Procedura:** (1) kreirajte private organization repository i environment za assessment; (2) dozvolite samo ručno odobrene, fiksne benigne job-ove ka owned endpoint-ima; (3) koristite minimalne read-only workflow permissions i bez production secrets; (4) pokrenite proveru; (5) uporedite workflow, provider i target records; (6) proverite da artifacts ne sadrže credentials; (7) obrišite environment token i zadržite zahtevani audit.

**Detekcija:** provider audit i workflow logovi daju direktnu atribuciju; target-i identifikuju runner ASN/range-ove i stabilan request grammar. **Capture-resilient OPSEC:** nikada ne stavljajte field-device, signing, wallet ili cloud-administrator secrets u runner variables. **Monitoring:** zahtevajte branch/environment approval i upozorite na workflow edits, fork execution, secret reads i neočekivana odredišta.

## Non-IP local first hop do owned gateway-a

**Mehanika:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio ili serial/optical link prenosi ograničene poruke od nearby senzora do owner-approved Internet gateway-a. Field device sam nema Internet route; gateway je jedini egress. Radio range i protokolarna ograničenja čine ovo telemetry/store-and-forward dizajnom, ne interaktivnim anonimnim Internetom.

**Prednosti:** uklanja Internet stack i credentials sa najmanjeg field device-a; mala potrošnja energije; gateway centralizuje policy; može premostiti privremene dead zone-ove.

**Nedostaci:** RF/fizičko otkrivanje, pairing i device identifiers; mali bandwidth i range; gateway i dalje povezuje sve poruke; spectrum i encryption restrictions variraju; capture može otkriti queued data.

**Procedura:** (1) pribavite site i spectrum approval; (2) uparite jedan owned sensor sa jednim owned gateway-em pomoću jedinstvenih ključeva; (3) definišite signed fixed-size message types, TTL i rate; (4) senzoru ne dajte default IP route; (5) dozvolite gateway-u da prosleđuje samo ka owned collector-u; (6) testirajte replay, gubitak dometa i gateway outage; (7) inventarišite i preuzmite oba uređaja.

**Detekcija:** RF survey, pairing database, fizička inspekcija i gateway process/flow logovi otkrivaju putanju. **Capture-resilient OPSEC:** sensor sadrži samo svoj pairwise key i ograničeni encrypted queue, nikada operator, Wi-Fi, cellular ili controller credentials. **Monitoring:** upozorite na nove peer-ove, sequence rollback, key failure, neuobičajen RF rate i poruke pristigle kroz neregistrovani gateway.

## Matrica izloženosti pri capture/compromise

Ova tabela primenjuje capture-resilience proveru na svaku prethodnu familiju. „Minimizovati” znači smanjiti secrets i blast radius na odobrenim asset-ima; nikada ne znači brisati dokaze ili skrivati se od istrage.

| Familija tehnike | Šta captured endpoint/relay može otkriti | Minimalna odobrena kontrola |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | poznate mreže, DHCP/portal history, MAC adrese, tunnel peer | odvojen organization device; private MAC gde je podržan; bez ličnih naloga; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames, ključevi, route-ovi, logovi i susedni hop | jedan identity po engagement-u; kratak TTL; uske putanje; broker-side revocation; bez master keys |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers i cached requests | minimizujte payload identifiers; pin-ujte odobreni config; bounded cache; strogi no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | instalirani software, bridge/onion material, local state i peer history | standardni client; odvojeni service keys; encrypted minimal state; rotirajte kompromitovani service identity |
| Remote browser/VDI/jump host | workspace token, clipboard/files i remote tenant | phishing-resistant MFA na gateway-u; onemogućeni transfer channels; brza session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider i približna lokacija | organization contract; bez personal co-location; uska APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | samo consented/owned node-ovi; signed agent; credential po node-u; controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment i billing references | dedicated project; least-privilege role; short-lived deploy token; provider audit centralno zadržan |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results i custody data | signed bounded jobs; TTL; encrypted cache; odvojeni producer identity; immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, artifacts fizičkog postavljanja | pisano odobrenje; jedinstveni device identity; bez operator secret-a; tamper/state telemetry; revoke i recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route i uplink profiles | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed paths |
| IPv6 temporary addressing | profiles, prefix history i endpoint/application state | tretirajte samo kao anti-tracking; čuvajte network logs; kombinujte sa endpoint compartmentation |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state i research keys | standardni client ili isolated lab; bez personal browser state-a; bez production signaling-a |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway ili service token | encrypted bounded cache; public-only parameters; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state i sve poznate putanje | samo regional identity; kratak resumption lifetime; centralna route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs i artifacts | least-privilege workflow; bez production/field/wallet secrets; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages i gateway identity | jedinstveni pairwise key; fixed message schema; bez Wi-Fi/cellular/operator credential |

## Monitoring mogućeg otkrivanja za svaku access familiju

Nijedan client-side test ne dokazuje da investigator ili defender posmatra saobraćaj. Pratite promene na sistemima u vlasništvu engagement-a, potvrdite ih preko controller/client-a i zaustavite se umesto probing-a observer-a. Redovi ispod pokrivaju svaku prethodnu tehniku; kombinujte ih sa [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Obuhvaćene tehnike | Bezbedni controller-side signali | Uslov za quarantine/stop |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | neodobrena mreža/SIM/device, neobjašnjeno premeštanje ili provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, novi admin/API event, complaint | duplicate/stolen credential, nepoznati administrator, direct fallback ili egress izvan obima |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer ili provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health i owned canary page | personal-account crossover, neočekivana non-Tor konekcija ili kompromitovan service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association i content hash | unknown peer/gateway, sequence rollback, unauthorized content ili missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export i cloud audit | unknown login/workflow edit, secret read, neočekivano odredište ili project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature i TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape iz lab-a |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use ili site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation i broker session | impossible migration, simultaneous unapproved paths ili session resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root ili provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Izbor i testiranje putanje

1. Navedite observer-a kog želite ukloniti i podatke koje želite sakriti.
2. Izaberite najmanje složenu familiju koja ga uklanja.
3. Nacrtajte source, entry, traversal, exit, DNS, account i payment observer-e.
4. Koristite odvojeni endpoint/application identity.
5. Proverite IPv4, IPv6, DNS, WebRTC/application bypass i pogled odredišta.
6. Prekinite svaki hop i potvrdite da je failure zatvoren.
7. Uporedite logove svake komponente koju kontrolišete.
8. Zabeležite preostale timing, provider, endpoint i fizičke veze.

## References

- [1] [EFF — Izbor odgovarajućeg VPN-a](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor zaštite](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Deblokiranje Tor-a](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Korišćenje Tor Browser-a sa VPN-om](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Pregled onion services](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Obavezna registracija SIM-a](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
{{#include ../banners/hacktricks-training.md}}
