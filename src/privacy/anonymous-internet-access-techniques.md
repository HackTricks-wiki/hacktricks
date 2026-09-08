# Katalog tehnika za anoniman pristup Internetu

Ovo je kanonski inventar pristupnih putanja. Obuhvata **familije** protokola i operativnih postupaka, a ne naziv svakog vendora. Nijedna Internet putanja ne garantuje anonimnost: dokazi o nalogu, browseru, endpointu, vremenu, plaćanju, cloud-control-plane-u i fizičkom okruženju mogu razotkriti i savršeno izvedenu putanju.

Svaki unos koristi ista polja. „Procedura“ znači zakonitu implementaciju ili emulaciju u sopstvenoj laboratoriji. Kada stvarna tehnika zavisi od kompromitovanja routera, krađe pristupa ili zloupotrebe posrednika koji na to nije pristao, reprodukcija koristi sisteme u vlasništvu vežbe.

## Matrica pokrivenosti

| Familija | Odredište vidi | Najjače svojstvo | Brzina | Tretman |
|---|---|---|---|---|
| Deljeni NAT/CGNAT | deljenu javnu adresu | neodređenost među pretplatnicima | visoka | može se implementirati |
| VPN, VPS, SOCKS/HTTP/SSH proxy | adresu relay-a | brzo razdvajanje izvorne adrese | visoka | može se implementirati |
| Višestruki hop/split relay, MASQUE | krajnji proxy | podeljeno znanje ili puni IP tunnel | visoka/umerena | može se implementirati uz pouzdane relay-e |
| Tor, bridge, onion service | exit ili onion identitet | višestrana putanja i zajednički browser | umerena | može se implementirati |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay ili otpornost na analizu vremena | niska/promjenljiva | specifično za aplikaciju |
| OHTTP/ODoH, Private Relay | gateway/egress | podela izvora i zahteva | visoka | samo podržane aplikacije |
| Javni Wi-Fi, travel router | adresu lokacije/tunnel-a | promena lokacije/pristupne putanje | visoka | potrebna dozvola |
| Cellular/eSIM, satellite | adresu carrier-a/provajdera | nezavisna fizička uplink veza | visoka/promjenljiva | subscription/provajder posmatra |
| Remote browser/jump host | udaljeni workspace | razdvajanje endpointa i egress-a | visoka | može se implementirati |
| Residential/mobile proxy | consumer/carrier adresu | izgled consumer mreže | visoka | saglasnost/poreklo su kritični |
| ORB/kompromitovani relay | adresu druge žrtve | prikrivanje porekla i pozajmljena reputacija | visoka | samo laboratorijska reprodukcija |
| CDN/fronting/redirector | CDN/front adresu | zaštita back-end infrastrukture | visoka | potrebna saglasnost provajdera/vlasnika |
| Fast flux/DGA/dead drop | rotirajući node/service | otpornost na otkrivanje infrastrukture | promenljiva | samo laboratorijska reprodukcija |
| Drop/nearest-neighbor | adresu blizu cilja | prelazak geografske/mrežne granice | visoka | samo laboratorija na sopstvenim lokacijama |
| Store-and-forward/offline | gateway ili fizičkog primaoca | smanjenje interaktivne vremenske povezanosti | niska | specifično za aplikaciju |
| Pluggable/refraction transport | Tor entry ili cooperating diversion proxy | dostupnost otporna na cenzuru | promenljiva | podržani klijent ili istraživačka laboratorija |
| IPFS gateway/PIR/remote fetcher | gateway ili application service | podela izdavaoca/upita/zahteva | promenljiva | ograničeno na aplikaciju |
| Anycast/QUIC/MPTCP | stabilnog broker-a ili više podtokova | rendezvous i kontinuitet sesije | visoka | dostupnost, ne anonimnost |
| CI/CD automation runner | adresu hosted runner-a | privremeni odgovorni egress | visoka | samo sopstveni workflow |
| Non-IP local first hop | gateway organizacije | uklanjanje Internet stack-a sa senzora | niska | implementacija uz odobrenje vlasnika |

## Direktni deljeni NAT i carrier-grade NAT

**Mehanika:** više korisnika deli jednu javnu adresu; access provider mapira adrese i portove na strani pretplatnika na javni tuple.

**Prednosti:** brzo; nije potreban poseban klijent; IP na strani odredišta može identifikovati samo domaćinstvo, lokaciju ili carrier pool.

**Nedostaci:** provajder može čuvati mape pretplatnika, portova i vremena; nalozi i fingerprint-i i dalje ostaju; drugi korisnici mogu narušiti reputaciju adrese.

**Procedura:** (1) potvrditi da autorizovani pristup koristi NAT/CGNAT; (2) zabeležiti tačan javni IP i izvorni port na endpointu u vlasništvu organizacije; (3) razdvojiti identitete aplikacija; (4) ne tretirati deljenu adresaciju kao privacy kontrolu; (5) koristiti jaču putanju ako ISP ne sme da sazna odredišta.

**Detekcija:** odredišta treba da čuvaju izvorni port i precizno vreme, a ne samo IP. Provajderi povezuju NAT allocation logove; istražitelji spajaju dokaze o nalogu, uređaju i browseru.

## Komercijalni VPN

**Mehanika:** šifrovana full-tunnel veza završava se na VPN-u; odredišta vide njegov egress. VPN obično može povezati izvor, vreme i odredišta.

**Prednosti:** brz; jednostavan; štiti od lokalnog pasivnog posmatranja; stabilni ili deljeni exit-i; dobar za kontrolisani red-team egress.

**Nedostaci:** koncentrisano poverenje; billing/login telemetry; kvarovi kill-switch/DNS/IPv6 funkcija; deljeni exit-i često imaju lošu reputaciju i blokirani su.

**Procedura:** (1) utvrditi provajdera, vlasnika, jurisdikciju, retention i assessment policy; (2) instalirati potpisani zvanični klijent; (3) uključiti full tunnel, always-on i fail-closed ponašanje; (4) namerno konfigurisati DNS i IPv6; (5) proveriti posmatrani IPv4/IPv6/DNS na endpointu u vlasništvu organizacije; (6) zaustaviti i ponovo uspostaviti tunnel i potvrditi da nema fallback-a u čistom tekstu.<sup>[[1]](#references)</sup>

**Detekcija:** lokalne mreže vide dugotrajan šifrovan tok ka VPN infrastrukturi; provajderi imaju authentication/connection records; odredišta koriste ASN/reputation, nalog, TLS/browser i korelaciju ponašanja.

## VPN u sopstvenoj infrastrukturi ili VPS egress

**Mehanika:** operator kontroliše WireGuard/OpenVPN gateway ili prosleđuje saobraćaj kroz iznajmljeni server.

**Prednosti:** predvidiva velika brzina; stabilna adresa pogodna za allowlist; prilagođeni logging/firewall; dobra kontrola incidenta.

**Nedostaci:** mali anonymity set; cloud tenant, plaćanje, izvorni login, API i istorija image-a povezuju operatora; karakterističan novi server lako se grupiše.

**Procedura:** (1) kreirati organization project namenjen engagement-u; (2) provision-ovati podržani image i stabilnu adresu; (3) ograničiti management na MFA/key-based administraciju; (4) konfigurisati full-tunnel egress i DNS; (5) gde je praktično, dozvoliti samo ciljna odredišta; (6) testirati leak/failure ponašanje; (7) čuvati controller audit records; (8) uništiti credentials i resurse pri teardown-u.

**Detekcija:** korelisati hosting ASN, adresu koja je prvi put viđena, certificate/service fingerprint i scanning ponašanje; cloud vlasnici koriste control-plane, console, billing i flow logove.

## HTTP CONNECT, SOCKS i SSH forwarding

**Mehanika:** aplikacija traži od proxy-ja da otvori TCP stream; SOCKS može proslediti i name resolution i UDP, u zavisnosti od verzije; SSH prosleđuje stream-ove unutar jedne šifrovane sesije.

**Prednosti:** lagano; po aplikaciji; brzo; korisno za chaining i pristup segmentiranim mrežama.

**Nedostaci:** aplikacije mogu zaobići proxy; DNS može leak-ovati; proxy vidi susedne endpoint-e; browser stanje ostaje; open proxy-ji mogu biti zamke ili kompromitovani sistemi.

**Procedura:** (1) postaviti proxy na hostu u vlasništvu organizacije; (2) zahtevati authentication i ograničiti source/destination; (3) konfigurisati jedan disposable application profile; (4) po potrebi obezbediti remote DNS resolution; (5) proveriti pomoću DNS/HTTP endpointa u vlasništvu organizacije; (6) blokirati direktni egress za workload; (7) pregledati i rotirati proxy credentials.

**Detekcija:** identifikovati procese koji podržavaju tunnel, CONNECT/SOCKS negotiation, duge SSH sesije i odredišta koja nisu u skladu sa aplikacijom; proxy logovi rekonstruišu stream-ove.

## Web proxy sa prepisivanjem URL-ova i browser proxy ekstenzija

**Mehanika:** web sajt preuzima odredište i prepisuje linkove/forms kroz sopstveni origin, ili ekstenzija usmerava browser zahteve ka proxy-ju. Odredište vidi service, dok service može videti plaintext posle TLS termination-a i ubacivati ili zadržavati sadržaj.

**Prednosti:** nema system-wide klijenta; brzo za jednostavno browsovanje; radi tamo gde VPN instalacija nije moguća.

**Nedostaci:** proxy može čitati credentials/content, menjati download-e i fingerprint-ovati korisnike; skripte/WebSocket-i/download-i mogu zaobići proxy; browser extension ima široke privilegije; mali anonymity set i često blokiranje.

**Procedura:** (1) koristiti samo proxy kojim upravlja organizacija za autorizovano testiranje; (2) izolovati ga u disposable browser-u bez ličnih naloga; (3) zabraniti unos lozinki i osetljiva preuzimanja; (4) proveriti da se svaki subresource na stranici u vlasništvu organizacije učitava kroz proxy; (5) testirati WebSocket, download i form ponašanje; (6) ukloniti ekstenziju/profile posle upotrebe.

**Detekcija:** odredište loguje proxy; enterprise proxy/DNS i inventar ekstenzija identifikuju service; content-security/reporting ili canary subresources u vlasništvu organizacije otkrivaju direktni bypass; proxy logovi povezuju korisničku sesiju sa ciljevima.

## Višestruki proxy ili provider multi-hop VPN

**Mehanika:** entry vidi izvor, dok jedan ili više traversal relay-a razdvajaju izvor od exit-a koji vidi odredište.

**Prednosti:** nijedan uobičajeni relay ne mora znati oba kraja; kvar ili zaplena jednog node-a otkriva manje; fleksibilna geografija.

**Nedostaci:** zajednička administracija/logovi poništavaju podelu; latencija; timing correlation; više mogućnosti za kvar i DNS rute; isti nalog/plaćanje može povezati sve hop-ove.

**Procedura:** (1) definisati kog posmatrača svaki hop uklanja; (2) koristiti nezavisno administrirane relay-e u vlasništvu organizacije ili odobrene relay-e kada je razdvajanje važno; (3) zahtevati samo entry pristup iz workload-a; (4) obezbediti da svaki relay može doći samo do sledećeg hop-a; (5) proveriti logove na svakom sloju; (6) zaustaviti svaki hop i potvrditi fail-closed ponašanje. Reprodukovati pomoću [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detekcija:** korelisati susedne NetFlow timing/volume podatke, ponovljene proxy handshake-e i zajedničku controller infrastrukturu; ne zaključivati geografiju operatora na osnovu exit-a.

## Application relay sa podeljenim znanjem i OHTTP

**Mehanika:** klijent šifruje stateless HTTP poruku ka gateway-u i šalje je kroz relay. Relay vidi IP klijenta, ali ne i zahtev; gateway vidi zahtev, ali obično samo IP relay-a.

**Prednosti:** snažna, proverljiva privacy podela za podržane zahteve; manji overhead od opštih anonymity mreža.

**Nedostaci:** nije proizvoljno browsovanje; cookies/authentication mogu ponovo povezati sesije; collusion relay-a i gateway-a i traffic analysis ostaju; aplikacija mora ovo podržavati.

**Procedura:** (1) izabrati aplikaciju koja izričito podržava RFC 9458; (2) proveriti gateway ključeve kroz zvanični configuration path; (3) izbegavati stabilna polja po korisniku; (4) slati samo podržani stateless zahtev; (5) uporediti relay, gateway i target logove; (6) testirati key rotation/failure bez direktnog fallback-a.<sup>[[2]](#references)</sup>

**Detekcija:** enterprise endpoint-i otkrivaju proces koji inicira zahtev i OHTTP relay; gateway-i otkrivaju malformed/replayed traffic; vreme i stabilna payload/account polja mogu povezati zahteve.

## MASQUE CONNECT-UDP/CONNECT-IP i HTTP privacy proxy-ji

**Mehanika:** HTTP Extended CONNECT preko TLS/QUIC prenosi UDP ili IP pakete kroz proxy. Može implementirati moderan VPN-like tunnel i uklopiti transport sa HTTP/3, ali proxy i dalje ostaje posmatrač.<sup>[[3]](#references)</sup>

**Prednosti:** efikasno multiplexing/roaming ponašanje; podrška za UDP ili puni IP; implementacija kroz modernu HTTP infrastrukturu.

**Nedostaci:** nije anonymity network; proxy/nalog vide izvor i odredišta; QUIC/HTTP fingerprint-i i poznate putanje vidljivi su endpoint-ima/provajderima.

**Procedura:** (1) koristiti klijent/service koji dokumentuje RFC 9298/9484 podršku; (2) autentifikovati proxy certificate/configuration; (3) definisati dozvoljene target routes; (4) uključiti encrypted DNS unutar putanje; (5) proveriti UDP, TCP, IPv6 i failover prema endpoint-ima u vlasništvu organizacije; (6) pregledati proxy request i flow logove.

**Detekcija:** endpoint-i vide klijentski proces i virtual interface; mreže mogu klasifikovati trajni QUIC/TLS ka proxy-ju; proxy logovi otkrivaju CONNECT target/path i dodeljene rute.

## Tor Browser

**Mehanika:** Tor bira guard, middle i exit relay-e; layered encryption ograničava ono što svaki relay može videti. Tor Browser dodaje standardizovani browser namenjen otpornosti na fingerprinting.

**Prednosti:** veliki javni anonymity set; nijedan obični relay ne zna oba kraja; unlinkability odredišta bez pokretanja servera.

**Nedostaci:** sporiji; pretežno TCP; exit reputacija/blokade; login-i i otkrivanje podataka identifikuju korisnika; low-latency timing correlation i dalje postoji.

**Procedura:** (1) preuzeti i verifikovati Tor Browser iz projekta; (2) zadržati podrazumevana podešavanja i izbegavati ekstenzije; (3) izabrati odgovarajući security level; (4) kreirati odvojeni identity/session; (5) izbegavati identifikujuće naloge i spoljne aktivne dokumente; (6) koristiti HTTPS ili autentifikovane onion services; (7) proveriti exit samo pomoću endpointa u vlasništvu organizacije.<sup>[[4]](#references)</sup>

**Detekcija:** lokalne mreže mogu identifikovati poznati guard traffic ako se ne koristi bridge/transport; odredišta vide exit-e i Tor Browser ponašanje; end-to-end posmatrači korelišu vreme i količinu saobraćaja.

## Tor bridge-ovi i pluggable transport-i

**Mehanika:** ne-javni bridge zamenjuje javni guard; obfs4, Snowflake ili WebTunnel menjaju transport prvog hop-a radi otpornosti na jednostavno blokiranje/probing.

**Prednosti:** zaobilazi cenzuru i skriva očigledna javna relay odredišta; zadržava Tor circuit nakon ulaska.

**Nedostaci:** transport pattern-i/otkrivanje bridge-a i dalje su mogući; promenljiva performansa; ne štiti od naloga ili globalnog timing-a.

**Procedura:** (1) prvo pokušati direktni Tor; (2) u Tor Browser Connection settings izabrati ugrađeni podržani transport ili zatražiti zvanični bridge; (3) ne koristiti nasumične binary-je/liste; (4) povezati se i pokrenuti bezopasan test; (5) testirati reconnect i clock; (6) zadržati sva ostala browser podešavanja standardnim.<sup>[[5]](#references)</sup>

**Detekcija:** censors koriste discovery odredišta, protocol/flow classification i active probing; defenders treba da razlikuju korišćenje zaobilaženja od kompromitovanja i da se oslone na endpoint process/context.

## VPN pre Tor-a i Tor pre VPN-a

**Mehanika:** VPN-before-Tor skriva direktno korišćenje Tor-a od access ISP-a, ali izvor izlaže VPN-u. Tor-before-VPN daje VPN-u saobraćaj posle Tor-a i često stabilan customer/tunnel identitet.

**Prednosti:** uklanja određenog posmatrača kada je pravilno projektovano; može pristupiti mrežama koje blokiraju jedan sloj.

**Nedostaci:** složenost, neuobičajen fingerprint, leak-ovi, manji anonymity set i lažna sigurnost; Tor Project ove kombinacije smatra naprednim.<sup>[[6]](#references)</sup>

**Procedura:** (1) napisati kog posmatrača uklanjate i kog novog uvodite; (2) koristiti disposable environment; (3) uspostaviti samo namenjenu spoljnu putanju; (4) primeniti firewall routes; (5) proveriti DNS/IPv4/IPv6 i redosled svakog kvara; (6) uporediti vidljivost oba provajdera; (7) napustiti stack ako nema merljivu prednost.

**Detekcija:** lokalni/VPN/Tor posmatrači vide različite susedne slojeve; timing ostaje end-to-end; neuobičajeni nested tunnel fingerprint-i i provider accounts mogu povezati sesije.

## Onion service

**Mehanika:** i klijent i service grade Tor circuit-e do rendezvous-a, skrivajući IP service-a i izbegavajući exit.

**Prednosti:** zaštita lokacije izvora i service-a; end-to-end onion authentication; nema javnog inbound port-a; opcioni client authorization.

**Nedostaci:** origin može leak-ovati kroz update-e/analytics/errors; onion key je kritičan; identitet aplikacije/timing i kompromitovanje hosta ostaju rizici.

**Procedura:** (1) izolovati aplikaciju i bind-ovati je samo na loopback/socket; (2) instalirati podržani Tor; (3) konfigurisati v3 onion service prema zvaničnim uputstvima; (4) zaštititi/backup-ovati ključ samo ako je potreban stabilan identitet; (5) dodati client authorization za zatvorenu upotrebu; (6) ukloniti third-party fetch-ove; (7) eksterno proveriti da origin nije dostupan.<sup>[[7]](#references)</sup>

**Detekcija:** host/network defenders pronalaze Tor proces/konfiguraciju i outbound circuit-e; application errors, DNS, certificates ili third-party resources mogu otkriti origin.

## I2P internal services

**Mehanika:** I2P koristi odvojene jednosmerne inbound/outbound tunnel-e za destinations unutar overlay-a; public-Internet outproxy-ji dodaju trust point.

**Prednosti:** decentralizovano interno objavljivanje; nema zavisnosti od zvaničnog exit-a; odvojene inbound/outbound putanje.

**Nedostaci:** nije zamena za opšti web; manji ekosistem; dugotrajno peer ponašanje; outproxy može posmatrati javno browsovanje.

**Procedura:** (1) instalirati iz zvaničnog izvora; (2) koristiti dedicated context; (3) dozvoliti integration/bandwidth stabilization; (4) pristupiti I2P-native service-u u vlasništvu organizacije; (5) izbegavati outproxy-je osim ako su izričito potrebni; (6) proveriti da shutdown ne daje direktni fallback; (7) pregledati lokalne peer i service logove.<sup>[[8]](#references)</sup>

**Detekcija:** lokalne mreže vide dugotrajni peer traffic i bootstrap ponašanje; endpoint-i otkrivaju router/application procese; outproxy-ji loguju exit-e.

## Mixnet-i

**Mehanika:** fixed-size paketi, batching, kašnjenje, reorderovanje i cover traffic smanjuju timing correlation; gateway-i povezuju aplikacije.

**Prednosti:** bolja otpornost na timing analysis od low-latency proxy-ja; korisno za asinhrone poruke/transakcije.

**Nedostaci:** latencija, bandwidth overhead, manja implementacija i application limits; gateway/account metadata mogu ostati.

**Procedura:** (1) izabrati održavan klijent i podržanu aplikaciju; (2) pročitati stvarni threat model; (3) instalirati u odvojenom compartment-u; (4) poslati bezopasne podatke endpointu u vlasništvu organizacije; (5) izmeriti latenciju/pouzdanost i reply path; (6) testirati gateway failure; (7) nikada ne isključivati delays/cover traffic samo radi brzine.<sup>[[9]](#references)</sup>

**Detekcija:** endpoint-i identifikuju klijent; access mreže mogu klasifikovati gateway-e/packet cadence; gateway-i i exit-i vide susedne uloge, dok šira korelacija zahteva duže statističke prozore.

## GNUnet anonymous file sharing

**Mehanika:** GNUnet može usmeravati publish/search/download zahteve kroz peer-ove i dodavati cover traffic u skladu sa anonymity level-om. Njegova dokumentacija upozorava da podrazumevani level 1 ne zahteva cover traffic i da snažna traffic analysis može identifikovati izvor.<sup>[[10]](#references)</sup>

**Prednosti:** decentralizovano, application-native anonimno deljenje; podesiv zahtev za cover traffic.

**Nedostaci:** nije običan anoniman web pristup; trošak performansi/storage-a; ograničenja peer-ova i traffic analysis; GNUnet VPN dokumentacija navodi da njegov IP overlay ne pruža dobru anonimnost.

**Procedura:** (1) instalirati održavanu zvaničnu verziju; (2) izolovati test peer; (3) ograničiti bandwidth/storage; (4) objaviti bezopasan jedinstveni test file sa izabranim anonymity level-om; (5) preuzeti ga sa drugog peer-a u vlasništvu organizacije; (6) zabeležiti cover traffic i latenciju; (7) ne tvrditi da IP VPN komponenta pruža jednaku anonimnost.

**Detekcija:** peer bootstrap, overlay traffic, lokalni datastore/proces i file identifiers; široki posmatrač može analizirati količinu saobraćaja u odnosu na cover traffic.

## Encrypted DNS, ODoH i ECH

**Mehanika:** DoH/DoT/DoQ šifruju vezu do resolver-a; ODoH deli adresu klijenta i query između proxy-ja i resolver-a; ECH šifruje unutrašnji TLS ClientHello/server name.

**Prednosti:** uklanja plaintext DNS/SNI od nekih lokalnih posmatrača; ODoH deli znanje o izvoru i query-ju.

**Nedostaci:** nije IP-anonymity path; resolver/proxy/server zadržavaju svoje uloge; destination IP/timing/volume i endpoint ostaju; fallback može leak-ovati.

**Procedura:** (1) odlučiti da li DNS kontroliše OS, aplikacija ili tunnel; (2) uključiti strict encrypted mode ili podržani ODoH; (3) testirati jedinstveni domen u vlasništvu organizacije; (4) lokalno snimiti saobraćaj i potvrditi da nema čistog query-ja; (5) onesposobiti resolver i proveriti predviđeno ponašanje; (6) za ECH potvrditi da server diagnostics prikazuje prihvatanje unutrašnjeg ClientHello-a.<sup>[[11]](#references)</sup>

**Detekcija:** endpoint/resolver logovi otkrivaju query-je; mreže identifikuju encrypted-resolver endpoint-e i destination flows; ECH stanje vidljivo je endpoint-ima/CDN-u čak i kada je skriveno na putanji.

## Privacy relay sa podeljenim provajderima

**Mehanika:** proizvodi kao iCloud Private Relay koriste ingress koji zna klijenta i nezavisno upravljani egress koji zna odredište, uz grubu regionalnu obradu.

**Prednosti:** jednostavna podela znanja; brzo; integrisana DNS/web zaštita za podržani saobraćaj.

**Nedostaci:** ograničen scope proizvoda/aplikacije; account/platform provider i dalje identifikuje korisnika; nije opšta system anonymity; collusion/legal i timing rizici.

**Procedura:** (1) potvrditi tačne aplikacije i tipove saobraćaja koji su podržani; (2) omogućiti funkciju u dedicated platform context-u gde je odgovarajuće; (3) izabrati regionalno ponašanje; (4) odvojeno testirati Safari/DNS i nepodržane aplikacije; (5) pregledati destination address; (6) testirati promenu mreže/failure.<sup>[[12]](#references)</sup>

**Detekcija:** access vidi ingress; destination vidi egress; platform/relay logovi i account records obuhvataju svoje slojeve; nepodržane aplikacije izlažu uobičajene putanje.

## Remote browser, VDI, RDP ili organization jump host

**Mehanika:** browsovanje/izvršavanje alata odvija se na udaljenom sistemu; odredište vidi njegov egress, dok workspace provider vidi vezu operatora i control plane.

**Prednosti:** brzo; izoluje rizičan sadržaj; stabilan kontrolisani egress; disposable stanje i jaka organizaciona revizija.

**Nedostaci:** provider/admin može posmatrati sesiju/nalog; screen/clipboard/file kanali mogu leak-ovati; remote browser fingerprint može biti jedinstven; nije anoniman za vlasnika workspace-a.

**Procedura:** (1) kreirati jedan organization-owned workspace po engagement-u; (2) zahtevati MFA i ograničiti administraciju; (3) onemogućiti ili ograničiti clipboard/upload/download; (4) usmeriti saobraćaj kroz odobreni stabilni egress; (5) ne koristiti lični IdP/sync; (6) izvoziti samo pregledane dokaze; (7) uništiti workspace i credentials prema rasporedu.

**Detekcija:** provider i IdP logovi povezuju korisnika sa sesijom; odredišta grupišu workspace egress/browser; enterprise defenders identifikuju remote-control protokole i anomalne cloud sesije.

## Javni ili guest Wi-Fi

**Mehanika:** saobraćaj izlazi kroz venue NAT ili tunnel pokrenut na lokaciji.

**Prednosti:** velika brzina i deljena adresa koja nije kućna; nema posebne infrastrukture.

**Nedostaci:** venue association/DHCP/portal, kamere, kupovina i lokacijski dokazi; neprijateljski peer-ovi/AP-ovi; uslovi korišćenja; fizički rizik.

**Procedura:** (1) dobiti pristup ponuđen gostima i potvrditi SSID sa osobljem; (2) koristiti zakrpljen low-trust uređaj; (3) isključiti sharing/auto-join i uključiti private MAC; (4) završiti portal bez ponovo korišćenog identiteta; (5) pokrenuti fail-closed VPN/Tor path; (6) proveriti tethered saobraćaj; (7) zaboraviti mrežu.

**Detekcija:** venue povezuje AP, MAC, DHCP, portal i vreme; destination vidi venue/tunnel; istražitelji kombinuju fizičke i device dokaze. Nikada ne zaobilaziti access control.

## Travel router

**Mehanika:** router u vlasništvu operatora priključuje se na venue Wi-Fi/Ethernet i obezbeđuje izolovanu internu mrežu sa enforced tunnel policy.

**Prednosti:** izoluje workstations; centralni kill switch/DNS; konzistentna client network; štiti privilegovane endpoint-e od lokalnih broadcast-a.

**Nedostaci:** router postaje stabilan radio/DHCP fingerprint; dodaje attack surface; captive portal-i i tethering mogu zaobići tunnel.

**Procedura:** (1) ažurirati podržani firmware; (2) postaviti jedinstvene management credentials i isključiti WAN admin/WPS/UPnP; (3) konfigurisati private upstream MAC gde je dozvoljeno; (4) kreirati odvojeni interni SSID; (5) primeniti full-tunnel DNS/IPv6 firewall policy; (6) testirati portal, reconnect i tunnel failure.

**Detekcija:** venue vidi association routera i oblik saobraćaja; lokalni RF/DHCP fingerprinting ga identifikuje; VPN provider vidi izvor venue-a.

## Cellular, prepaid SIM i eSIM

**Mehanika:** modem koristi carrier radio access i obično carrier NAT; VPN/Tor sloj može promeniti exit koji vidi odredište.

**Prednosti:** nezavisno od lokalne wired/Wi-Fi mreže; mobilno; velika brzina; koristan backhaul za autorizovane drop-ove.

**Nedostaci:** carrier zna subscriber/eSIM, IMSI, IMEI, ćelije, vreme i dodeljene portove; registracioni zakoni se razlikuju; zajednička lokacija sa ličnim telefonom povezuje uređaje.

**Procedura:** (1) zakonito nabaviti service sa tačnim traženim podacima; (2) koristiti odvojeni modem/uređaj u vlasništvu organizacije; (3) evidentirati ga kod exercise controller-a; (4) isključiti nepovezane radio-veze/naloge; (5) uspostaviti odobreni tunnel; (6) testirati da li tethered klijenti zaista koriste tunnel; (7) proveriti pretpostavke o provajderu i retention-u pre putovanja.<sup>[[13]](#references)</sup>

**Detekcija:** carrier records i RF location; enterprise USB/PCI/MDM inventar i rogue-hotspot surveys; destination/tunnel timing.

## Satellite Internet i zloupotreba satelitskog downlink-a

**Mehanika:** normalni service koristi registrovani terminal/provajder. Starija zloupotreba jednosmernog DVB-S omogućavala je prijemniku unutar beam-a da posmatra nešifrovani downlink saobraćaj namenjen legitimnom pretplatniku, dok se za outbound zahteve koristila druga putanja.

**Prednosti:** široka pokrivenost; nezavisan last mile; istorijska jednosmerna zloupotreba mogla je pogrešno pripisati C2 geografiji pretplatnika.

**Nedostaci:** equipment/RF/provider records; latencija i pokrivenost; moderni bidirectional sistemi su drugačiji; outbound path i asymmetric routing ostaju dokazi.

**Procedura:** za zakonit pristup registrovati terminal u vlasništvu organizacije i po potrebi tunnel-ovati saobraćaj. Za emulaciju istorijskog Turla ponašanja reprodukovati synthetic one-way packet captures u RF-free laboratoriji i testirati da li analitičari otkrivaju odgovor hostu koji nije poslao zahtev; ne presretati live satellite traffic.<sup>[[14]](#references)</sup>

**Detekcija:** provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency i malware configuration.

## Residential/mobile proxy ili consented proxyware

**Mehanika:** backconnect gateway dodeljuje consumer broadband/mobile exit-e, sticky ili rotirajuće. Poreklo može biti zasnovano na saglasnosti, obmanjujućem bundlovanju ili zlonamernom softveru.

**Prednosti:** velika brzina; geografski izbor; consumer ASN izbegava neke hosting blokade; veliki pool-ovi.

**Nedostaci:** rizik porekla/saglasnosti i zakonitosti; broker vidi klijenta; kompromitovani exit-i oštećuju žrtve; rotacija stvara anomalije; skupo i nepouzdano.

**Procedura:** koristiti samo dokumentovane agent-e sa informisanom saglasnošću, u vlasništvu organizacije, za emulaciju: (1) uključiti test endpoint-e; (2) evidentirati vlasnike/IP adrese; (3) konfigurisati gateway; (4) rotirati sticky/per-request režime; (5) slati samo ka target-u u vlasništvu organizacije; (6) uporediti gateway/exit/target logove; (7) ukloniti svaki agent.

**Detekcija:** impossible travel, stabilan browser/nalog kroz brze promene IP/ASN-a, backconnect protokoli, proxyware process/network artefakti i broker/controller odnosi.

## ORB, botnet i relay-i kompromitovanih edge uređaja

**Mehanika:** iznajmljeni ili kompromitovani router-i/IoT/serveri formiraju access, traversal i exit uloge kojima se upravlja kao fleet-om. Više APT korisnika može deliti istu infrastrukturu.

**Prednosti:** pozajmljena reputacija/geografija; kratkotrajni exit-i; otporna multi-hop mesh mreža; slaba direktna veza actor-to-IP.

**Nedostaci:** kriminalna viktimizacija; implant/controller i fleet obrasci; zaplena posrednika; neujednačena performansa; operator/customer service records.

**Procedura:** nikada ne kompromitovati stvarne uređaje. Koristiti [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) kreirati izolovane entry/transit/target mreže; (2) priključiti owned dual-homed relay containers; (3) prosleđivati samo jedan test port; (4) poslati bezopasan zahtev; (5) proveriti da target vidi samo exit; (6) rotirati exit; (7) ukloniti sva imenovana sredstva.<sup>[[15]](#references)</sup>

**Detekcija:** pratiti topology, portove/services, controller odnose, implant fingerprints i životni ciklus node-ova; centralizovati edge configuration/flow/integrity telemetry; ne izjednačavati exit IP sa actor-om.

## CDN redirector, domain fronting i domainless fronting

**Mehanika:** javni edge prosleđuje samo saobraćaj koji odgovara grammar-u; fronting postavlja benigni spoljašnji SNI i drugačiji unutrašnji HTTP authority, ili prazan SNI, kada intermediary to dozvoljava.

**Prednosti:** skriva/štiti back-end; brz globalni edge; odredište se meša sa deljenim service-om; brzo prebacivanje.

**Nedostaci:** CDN vidi svako routing pravilo i tenant; mnogi provajderi zabranjuju cross-tenant fronting; SNI/Host/process/flow i account artefakti; ponovno korišćenje konfiguracije grupiše kampanje.

**Procedura:** reprodukovati samo na owned reverse proxy-ju pomoću [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): kreirati lokalni certificate/edge, usmeriti jedan mismatched Host ka target-u u vlasništvu organizacije, logovati SNI i Host, poslati normalne/mismatched zahteve, zatim ukloniti containers.<sup>[[16]](#references)</sup>

**Detekcija:** uporediti SNI/ECH/Host/`:authority` na endpointu ili terminating edge-u; povezati initiating process, tenant/origin, request grammar i flow cadence.

## Dynamic DNS, DGA, fast flux i double flux

**Mehanika:** DDNS ažurira stabilno ime; DGA izvodi promenljiva kandidat-imena; fast flux rotira service adrese sa kratkim TTL-om; double flux dodatno rotira name server-e.

**Prednosti:** otporna discovery funkcija; brza zamena infrastrukture; controller je skriven iza mnogo node-ova.

**Nedostaci:** DNS stvara centralizovanu telemetry; entropy/NXDOMAIN/churn; nizak TTL i široki ASN obrasci; registraciona i authoritative infrastruktura ostaju.

**Procedura:** koristiti [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): servirati owned zone koja vraća RFC 5737 adrese sa TTL-om od pet sekundi, ponavljano je query-ovati, promeniti sintetičku epohu i proveriti analytics. Nikada ne usmeravati test records ka trećim stranama.<sup>[[17]](#references)</sup>

**Detekcija:** sliding-window jedinstveni odgovori/ASN-ovi, median TTL, geografija, authoritative churn, DGA NXDOMAIN/lexical/temporal klasteri i process follow-on; legitimne CDN-ove isključiti na osnovu konteksta.

## Legitimni web service, dead-drop resolver i one-way tasking

**Mehanika:** javna objava, repository, dokument, object ili feed sadrži kodirani trenutni endpoint ili task. Klijent može vraćati rezultate drugim kanalom.

**Prednosti:** dozvoljen service sa dobrom reputacijom; TLS; rotacija endpoint-a bez promene binary-ja; asimetrični tasking otežava jednostavnu flow correlation.

**Nedostaci:** stabilni object/account/API identifiers; provider records; endpoint decode/follow-on sequence; sadržaj može biti zaplenjen ili promenjen.

**Procedura:** koristiti [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): host-ovati kodirani pointer na jednom owned container-u, preuzeti/dekodirati ga sa short-lived client-a, kontaktirati drugi owned service, sačuvati oba loga i zatim izvršiti teardown.

**Detekcija:** korelisati neobičan process → čitanje stabilnog object-a → decode → novo odredište; hash-ovati/sačuvati sadržaj i zadržati pune object paths, a ne samo domen.

## Serverless, ephemeral container i cloud-NAT egress

**Mehanika:** funkcije/kratkotrajni job-ovi izvršavaju se iza provider NAT-a ili front-a; logički service ostaje stabilan dok se instance i adrese rotiraju.

**Prednosti:** brzo pokretanje/uništavanje; shared egress na nivou provajdera; malo lokalnog diska; elastično regionalno routiranje.

**Nedostaci:** tenant, role, API, image, secret, invocation, billing i front-to-origin logovi su trajni; cold-start i platform fingerprint-i; provider policy.

**Procedura:** (1) koristiti organization-owned exercise tenant; (2) deploy-ovati benign function koja zahteva samo endpoint u vlasništvu organizacije; (3) zabeležiti project/role/image/config; (4) izvršavati kroz više instanci; (5) uporediti target IP adrese sa audit/request ID-jevima; (6) testirati retention logova; (7) ukloniti function, roles i secrets.

**Detekcija:** cloud audit/invocation logovi, neobično kreiranje role-a, shared egress sa stabilnim request grammar-om, image/layer i secret reuse, i front-origin korelacija.

## Autorizovani on-site drop

**Mehanika:** inventarisani mali računar koristi lokalni wired/Wi-Fi i outbound VPN/cellular rendezvous, predstavljajući lokalni izvor.

**Prednosti:** realistično testiranje porekla unutar mreže; velika brzina; mogućnost testiranja NAC-a, fizičkog inventara i egress kontrola.

**Nedostaci:** fizičko otkrivanje/krađa; serial/MAC/USB/DHCP/PoE/RF i camera dokazi; gubitak može otkriti credentials.

**Procedura:** pratiti [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) dobiti preciznu pisanu dozvolu za postavljanje; (2) zabeležiti serial, MAC, fotografiju, lokaciju i vreme preuzimanja; (3) koristiti signed minimal image i short-lived mutual credentials; (4) ograničiti outbound-only destinacije/capabilities; (5) dodati server-side quarantine i bandwidth limits; (6) testirati SOC visibility i response na gubitak; (7) preuzeti uređaj, sačuvati potrebne dokaze i zatim ga sanitizovati prema dogovorenoj lifecycle policy. Nikada ga ne skrivati na lokaciji koja nije dala saglasnost.

**Detekcija:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera i fizička inspekcija.

## Nearest-neighbor wireless pivot

**Mehanika:** actor kontroliše host u radio dometu cilja, a zatim koristi Wi-Fi credentials cilja za daljinski prelazak granice. APT28 je na ovaj način koristio obližnje kompromitovane organizacije.<sup>[[18]](#references)</sup>

**Prednosti:** operator ne mora putovati; target vidi lokalni radio izvor; zaobilaze se kontrole primenjene samo na Internet entry.

**Nedostaci:** potreban je obližnji kompromitovani/owned dual-radio host i validan access; RADIUS/NAC/AP i neighbor endpoint dokazi; signal/device anomalije.

**Procedura:** reprodukovati samo pomoću [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): priključiti owned pivot na neighbor i target lab SSID-ove, prosleđivati samo jedan service, prikupiti oba AP/pivot loga, zatim uključiti EAP-TLS/device posture i potvrditi da drugi pokušaj neuspešno završava.

**Detekcija:** korelisati RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login i fizičko prisustvo; tražiti nearby endpoint-e sa istovremenim radio vezama, forwarding-om i tunnel-ima.

## Community mesh, delay-tolerant i offline store-and-forward

**Mehanika:** saobraćaj prolazi kroz lokalne peer-ove, asinhrone gateway-e, removable media ili zakazane queue-ove umesto jedne interaktivne Internet sesije.

**Prednosti:** radi tokom prekida/cenzure; odložena/batch isporuka slabi jednostavni timing; nema centralnog last mile-a za lokalnu komunikaciju.

**Nedostaci:** velika latencija; mali anonymity set; custody/fizički metadata; zlonamerni peer-ovi; podaci na kraju stižu do gateway-a koji ih posmatra.

**Procedura:** (1) izgraditi izolovanu owned three-node mesh ili file queue; (2) šifrovati/autentifikovati sadržaj end-to-end; (3) ukloniti direktne Internet rute iz izvora; (4) proslediti bezopasan file nakon kontrolisanog kašnjenja; (5) proveriti da samo gateway kontaktira target u vlasništvu organizacije; (6) uporediti custody/timestamps; (7) sačuvati potrebne dokaze, zatim sanitizovati privremene medije/queue-ove pri odobrenom završetku.

**Detekcija:** endpoint file/process activity, peer-radio linkovi, removable-media audit, queue/gateway periodičnost i content identifiers. Duži correlation windows zamenjuju analizu interaktivnog flow-a.

## TURN relay i forced-relay WebRTC

**Mehanika:** Traversal Using Relays around NAT (TURN) dodeljuje javnu relay adresu i prenosi UDP, TCP ili TLS saobraćaj između klijenta i peer-ova. ICE policy može zahtevati korišćenje relay-a umesto izlaganja direktnog kandidata. TURN rešava reachability, a ne opštu anonimnost: server autentifikuje klijenta i vidi allocations, peer-ove, vreme i količinu saobraćaja.<sup>[[19]](#references)</sup>

**Prednosti:** široko implementirano; radi sa restriktivnim NAT-om; podržava mobilni WebRTC; peer ne dobija direktnu transport adresu klijenta kada je relay-only policy pravilno primenjen.

**Nedostaci:** TURN operator vidi obe susedne strane; application identity, media fingerprint i signaling ostaju; relay-only troši bandwidth i povećava latenciju; pogrešna konfiguracija i dalje može prikupiti host ili server-reflexive candidates.

**Procedura:** (1) deploy-ovati organization-owned TURN service sa TLS-om i short-lived credentials; (2) ograničiti realms, peer-ove, portove, quotas i expiration; (3) podesiti testnu aplikaciju na relay-only ICE; (4) pozvati owned peer; (5) pregledati `getStats()` i packet capture kako bi se potvrdilo da su samo relay candidates prenosili media; (6) oboriti relay i potvrditi da nema direct fallback-a; (7) zadržati allocation logove za engagement.

**Detekcija:** signaling, browser process i TURN allocations povezuju sesiju sa relay-em; mreže vide trajne tokove ka TURN portovima ili TLS endpoint-ima; peer vidi dodeljeni relay. **Captured node:** application state i ephemeral TURN credentials mogu otkriti realm i rendezvous service. Smanjiti izloženost korišćenjem short-lived credentials po uređaju i čuvati operator authentication samo na controller-u.

## Outbound-only rendezvous ili reverse overlay

**Mehanika:** node iza NAT-a pokreće autentifikovanu vezu ka broker-u kojim upravlja organizacija. Operator se zasebno autentifikuje kod broker-a, koji odobrava uzak management channel; nisu potrebni ni inbound port forwarding ni direktna operator-to-node ruta.

**Prednosti:** stabilno iza NAT-a i captive last mile-ova; centralna revocation i audit; promene adrese field node-a ne zahtevaju discovery od operatora; jasno razdvaja identitet operatora od credentials node-a.

**Nedostaci:** broker postaje tačka visoke vrednosti za korelaciju; periodični keepalive-i su prepoznatljivi; široki tunnel može postati nebezbedan pivot; gubitak broker-a prekida management.

**Procedura:** pratiti [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): izdati jedan scoped device identity, dozvoliti samo owned broker i approved management service, koristiti authenticated keepalive, primeniti fail-closed routing, testirati promenu adrese i reboot recovery i opozvati identity tokom loss drill-a. WireGuard dokumentuje persistent keepalive od 25 sekundi kao široko koristan NAT interval kada je zaista potreban.<sup>[[20]](#references)</sup>

**Detekcija:** broker i identity-provider logovi povezuju obe strane; access network vidi ponovljeno šifrovano odredište/cadence; endpoint inventory prikazuje overlay agent. **Captured node:** pretpostaviti da su device key, broker name, tunnel addresses i cached task data otkriveni. Ne sme sadržati operator private key, personal account ili reusable controller token.

## Pull mailbox, message queue ili object-store rendezvous

**Mehanika:** field workload anketira autentifikovani mailbox za potpisane, unapred odobrene job-ove i objavljuje ograničene rezultate. Operator upisuje u queue kroz odvojeni control plane; između njih nema interaktivnog socket-a.

**Prednosti:** podnosi povremene veze; razdvaja vreme i adresiranje; quotas i schemas mogu ograničiti capabilities; laka centralna revocation i audit.

**Nedostaci:** polling cadence i stabilna object/queue imena fingerprint-uju sistem; provider logovi povezuju producer i consumer; odložena kontrola; uhvaćeni queued podaci mogu otkriti vežbu.

**Procedura:** (1) kreirati jedan engagement queue i jedan device identity; (2) definisati signed schema benignih, izričito ograničenih job-ova; (3) postaviti message TTL, maksimalnu veličinu rezultata i rate; (4) dozvoliti node-u da čita samo svoj queue i piše samo u svoj result prefix; (5) testirati offline accumulation, duplicate delivery i revocation; (6) centralizovati immutable access logove; (7) obrisati queue nakon isteka retention zahteva.

**Detekcija:** tražiti periodične API pozive neobičnog procesa, stabilne bucket/object/queue paths, identičan user-agent ili TLS ponašanje i sekvencu fetch-then-new-connection. **Captured node:** lokalni cache može otkriti pending jobs i object names; cache držati šifrovanim, ograničenim i disposable, uz očuvanje authoritative controller logova.

## Dual-uplink failover i connection migration

**Mehanika:** odobreni field node ima dva nezavisna uplink-a—kao venue Ethernet/Wi-Fi i organization cellular—i održava control session kroz overlay ili message broker dok se rute menjaju. Ovo je availability engineering, a ne anonimnost.

**Prednosti:** preživljava kvar jednog provajdera, AP-a ili captive portal-a; podržava planirano održavanje; omogućava brzo izolovanje sumnjive putanje.

**Nedostaci:** dva provajdera stvaraju dve lokacijske/account evidencije; istovremena upotreba olakšava korelaciju; route i DNS leak-ovi tokom failover-a; cellular co-location dokazi ostaju.

**Procedura:** (1) registrovati oba organization-owned interfejsa i provajdera; (2) dodeliti determinističke route priorities i health checks ka owned endpoint-ima; (3) vezati DNS i management za overlay; (4) sprečiti sekundarnu putanju da prihvata inbound traffic; (5) isključiti svaku putanju i proveriti session recovery, source policy i odsustvo direktnog pristupa odredištu; (6) alarmirati na neplaniranu promenu putanje; (7) dokumentovati upotrebu podataka i roaming limits.

**Detekcija:** korelisati isti device certificate, request grammar i timing kroz različite ASN-ove; lokalni inventar vidi oba radija; carrier-i/venue-i čuvaju sopstvene zapise. **Captured node:** oba SIM/device identifikatora i poznati SSID-ovi mogu biti vidljivi; koristiti organizational assets i nikada ne povezivati node sa ličnim uređajima.

## Organization private APN ili managed cellular tunnel

**Mehanika:** carrier private APN stavlja enrolled SIM-ove u privatni routed domain ili tunnel-uje saobraćaj do enterprise gateway-a. Razdvaja uređaj od javnog mobilnog Interneta, ali ga ne skriva od carrier-a ili contracting organization.

**Prednosti:** stabilno privatno adresiranje; carrier-level enrollment i traffic policy; izbegavanje javne inbound exposure; korisno za autorizovane udaljene uređaje.

**Nedostaci:** subscriber, IMSI/IMEI, cell i billing attribution su snažni; vreme i troškovi nabavke; carrier/gateway outage; nije anoniman za operatora.

**Procedura:** (1) ugovoriti APN na ime assessment organization; (2) whitelist-ovati samo registrovane SIM-ove i gateway prefixes; (3) dodati application-layer mutual authentication; (4) ograničiti APN rutu na rendezvous i update services; (5) testirati SIM removal, roaming, public-Internet breakout i revocation; (6) nadzirati carrier i gateway records; (7) otkazati ili staviti u quarantine svaki SIM pri closeout-u.

**Detekcija:** carrier inventory i cell telemetry, APN gateway flows, SIM/IMEI mismatch i enterprise asset records. **Captured node:** SIM i modem identifikuju ugovor čak i kada je storage šifrovan; capture resilience zato znači brzu suspenziju i usku autorizaciju, a ne poricanje.

## Long-range point-to-point wireless bridge

**Mehanika:** directional Wi-Fi ili drugi licencirani/nelicencirani point-to-point radio povezuje dve lokacije uz odobrenje vlasnika, sa Internet egress-om na udaljenoj lokaciji. Može promeniti prividnu IP lokaciju bez komercijalnog proxy-ja.

**Prednosti:** veliki throughput; nezavisnost od posrednih wired carrier-a; kontrolisani RF i routing; korisno za testiranje segmentacije i nadzora udaljene lokacije.

**Nedostaci:** line-of-sight, spectrum, landlord i regulatorna ograničenja; karakteristične RF emisije i hardware; oba endpoint-a su fizički dokazi; vreme/power/alignment utiču na stabilnost.

**Procedura:** (1) pribaviti pisanu dozvolu za obe lokacije i proveriti spectrum/power pravila; (2) ispitati putanju bez emitovanja izvan odobrenih parametara; (3) koristiti authenticated encryption i management VLAN; (4) ograničiti bridge na owned rendezvous ili test subnet; (5) testirati failover, alignment, power recovery i RF containment; (6) označiti/inventarisati oba radija; (7) ukloniti ih i proveriti reset konfiguracije po završetku vežbe.

**Detekcija:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic i remote-site egress logovi. **Captured node:** konfiguracija otkriva peer i management domain; koristiti jedinstvene exercise credentials, bez ličnih management naloga i uz brzu revocation peer key-a.

## Consented cooperative ili community exit

**Mehanika:** volonteri ili partnerske organizacije svesno pokreću relay-e prema objavljenoj policy. Saobraćaj izlazi iz deljenog community pool-a, dok coordination layer vodi evidenciju zloupotreba i revocation-a.

**Prednosti:** raznovrsne non-cloud mreže; izričita saglasnost je bezbednija od proxyware-a; shared governance može raspodeliti poverenje; korisno za istraživanja i studije otpornosti na cenzuru.

**Nedostaci:** mali pool-ovi i membership records smanjuju anonimnost; exit operator-i primaju pritužbe i vide traffic metadata; zlonamerni učesnici, promenljiva dostupnost i različite jurisdikcije.

**Procedura:** (1) objaviti acceptable-use i logging policy; (2) dobiti informisani opt-in svakog operatora; (3) izdati jedinstveni relay identity i ograničiti destinations/rates; (4) obezbediti abuse handling i one-action revocation; (5) tokom testiranja slati samo autorizovani saobraćaj ka owned endpoint-ima; (6) meriti churn i correlation exposure; (7) čisto ukloniti relay kada saglasnost prestane.

**Detekcija:** membership/control-plane records, relay certificates, common software fingerprint i exit behavior identifikuju pool. **Captured node:** relay configuration može identifikovati cooperative, ali ne treba sadržati client identities; client-to-session accountability čuvati na autorizovanom controller-u uz access control.

## IPv6 privremene adrese i rotacija prefix-a

**Mehanika:** IPv6 privacy extensions kreiraju privremene interface identifiers tako da se stabilna adresa ne koristi za svaku outbound vezu. Promene provider prefix-a mogu dodati rotaciju, ali delegated prefix, subscriber record i upper-layer fingerprint ostaju.<sup>[[21]](#references)</sup>

**Prednosti:** smanjuje pasivno dugoročno praćenje pomoću stabilnog interface identifier-a; ugrađeno u uobičajene operativne sisteme; nema relay overhead-a.

**Nedostaci:** nije source anonymity; ISP i lokalna mreža i dalje znaju prefix/device; DNS, nalozi i browser stanje povezuju sesije; address churn otežava allowlist-e i logging.

**Procedura:** (1) pregledati trenutne stable i temporary addresses na owned client-u; (2) uključiti OS-supported privacy-address default umesto third-party spoofing-a; (3) više puta zatražiti owned IPv6 endpoint tokom životnog veka adrese; (4) potvrditi da se inbound services bind-uju samo na namenjene stable addresses; (5) čuvati DHCPv6/RA/neighbor i precizne endpoint logove; (6) testirati VPN/firewall ponašanje za svaku IPv6 adresu.

**Detekcija:** korelisati delegated prefix, layer-2 identity, neighbor discovery, account i endpoint telemetry umesto tretiranja jedne adrese kao jednog uređaja. **Captured node:** network profiles i interface identifiers ostaju; temporary addressing sprečava jedan pasivni identifier, ali ne i forensic attribution.

## Tor pluggable transport-i: Snowflake, WebTunnel, obfs4 i meek

**Mehanika:** pluggable transport menja izgled prve Tor veze ili način dolaska do bridge-a. Snowflake koristi short-lived volunteer WebRTC proxy-je, WebTunnel liči na običan HTTPS, obfs4 se opire jednostavnoj identifikaciji protokola i active probing-u, a meek prosleđuje kroz podržanu web infrastrukturu. To su censorship-circumvention transport-i ka Tor-u, a ne dodatni end-to-end slojevi anonimnosti.<sup>[[22]](#references)</sup>

**Prednosti:** korisno kada su direktni Tor ili poznati relay-i blokirani; Snowflake izbegava stabilnu javnu bridge adresu; integrisano je u održavane Tor klijente; destination i dalje dobija uobičajene Tor karakteristike.

**Nedostaci:** niže ili promenljive performanse; broker/front/bridge i lokalna mreža vide različite metadata; transport fingerprint-i i blokiranje su i dalje mogući; volunteer proxy ne zamenjuje Tor i ne treba mu verovati sa application plaintext-om.

**Procedura:** (1) instalirati i verifikovati zvanični Tor Browser ili podržani Tor client; (2) izabrati ugrađeni transport u Connection/Bridges; (3) povezati se samo na owned diagnostic page; (4) potvrditi da stranica vidi Tor exit, a ne Snowflake/WebTunnel peer; (5) uporediti bootstrap i performanse; (6) oboriti transport i potvrditi da se klijent ne povezuje tiho direktno; (7) nakon testa vratiti standardnu podržanu konfiguraciju.

**Detekcija:** censor može kombinovati destination allowlists, TLS/WebRTC behavior, broker discovery i flow analysis; endpoint-i otkrivaju Tor i transport configuration. **Capture-resilient OPSEC:** koristiti standardni client, nikada ne kopirati lično browser stanje u njega i pretpostaviti da je bridge/broker istorija dostupna. **Monitoring:** pratiti Tor bootstrap logove, neočekivane direktne DNS/connection pokušaje i observations na controller-side owned page-u; transport failure nije dokaz discovery-ja.

## Refraction networking ili decoy routing

**Mehanika:** cooperating network operator otkriva covert signal u saobraćaju koji je prividno adresiran ka dozvoljenom decoy-ju i preusmerava flow ka circumvention proxy-ju. Implementacija zahteva infrastrukturu na mrežnoj putanji; klijent je ne može kreirati samo izborom bezopasnog web sajta.<sup>[[23]](#references)</sup>

**Prednosti:** prividno odredište može biti teško blokirati bez kolateralne štete; nije potrebno distribuirati javnu bridge adresu; koristan istraživački model za on-path-assisted circumvention.

**Nedostaci:** specijalizovano ISP/transit učešće; deployability i performanse zavise od routinga; client-to-decoy flow i proxy-side activity ostaju; globalni ili cooperating observer može korelisati timing.

**Procedura:** ne signalizirati kroz nepovezane mreže. Reprodukovati arhitekturu u izolovanoj laboratoriji: (1) kreirati owned client, router, decoy i proxy namespaces; (2) koristiti benign tagged test request; (3) dozvoliti owned router-u da preusmeri samo taj tag ka proxy-ju; (4) logovati pre/post-routing tuples i request IDs; (5) uporediti ordinary i signaled flows; (6) testirati false positives i removal; (7) uništiti lab routes.

**Detekcija:** autorizovani network operator-i mogu pregledati routing divergence, neuobičajeno client hello/tag ponašanje i razlike između decoy i back-end flow-ova. **Capture-resilient OPSEC:** research client treba da sadrži samo test keys i documentation addresses. **Monitoring:** uporediti signed lab-router odluke sa proxy arrival-ima; ne ispitivati production transit provajdere da bi se utvrdilo da li su detektovali signaling.

## Content-addressed gateway ili cached peer retrieval

**Mehanika:** HTTP gateway preuzima IPFS content identifier (CID), moguće iz cache-a ili peer-ova, i vraća proverljiv sadržaj klijentu. Originalni publisher može videti gateway ili druge peer-ove umesto krajnjeg čitaoca; gateway vidi IP čitaoca i traženi CID. Native peer-to-peer retrieval izlaže klijenta peer-ovima i DHT/routing učesnicima.<sup>[[24]](#references)</sup>

**Prednosti:** publisher i reader mogu biti razdvojeni cache-ovima; immutable content proverljiv je hash-om; replicated data preživljava gubitak jednog hosta; HTTP klijenti ne zahtevaju native peer stack.

**Nedostaci:** javni CID-ovi i gateway logovi otkrivaju interesovanja; timing prvog preuzimanja može povezati publisher-a i reader-a; malicious web content i path-style same-origin rizici; javni gateway-i su best-effort i zabranjuju zloupotrebu.

**Procedura:** (1) objaviti bezopasan test file na owned private IPFS swarm-u ili owned gateway-u; (2) zabeležiti CID; (3) preuzeti ga kroz odvojeni owned HTTP gateway uz subdomain isolation; (4) proveriti bytes prema CID-u; (5) ponoviti nakon caching-a; (6) uporediti publisher, peer i gateway logove; (7) unpin-ovati i ukloniti test content kada retention istekne.

**Detekcija:** gateway-i loguju source/CID; DHT i peer connections otkrivaju retrieval; endpoint history i file hashes identifikuju sadržaj. **Capture-resilient OPSEC:** ne čuvati private publishing key na read-only field client-u i šifrovati osetljiv sadržaj pre content addressing-a. **Monitoring:** alarmirati na neočekivano pinning, promenu peer set-a, CID requests izvan allowlist-e ili gateway account notices.

## Private information retrieval service

**Mehanika:** Private Information Retrieval (PIR) omogućava klijentu da preuzme jedan record iz baze tako da server kriptografski ne sazna izabrani index, prema navedenom single- ili multi-server threat model-u. Štiti izbor query-ja za ograničen dataset; nije opšti web access niti IP anonymity.<sup>[[25]](#references)</sup>

**Prednosti:** jaka application-specific query privacy; merljiv leakage model; korisno za key directories, blocklists ili male javne baze; može smanjiti potrebu za otkrivanjem tačnih lookup terms.

**Nedostaci:** computation/bandwidth overhead; server saznaje vreme/IP veze ako se ne kombinuje sa relay-em; dataset version, response size i application state mogu podeliti korisnike; zrelost implementacije varira.

**Procedura:** (1) deploy-ovati audited PIR implementation protiv synthetic owned database; (2) objaviti dataset version i parameters; (3) preuzeti više indices sa identičnim request sizes; (4) lokalno proveriti ispravnost; (5) uporediti server logove i potvrditi da index nije prisutan; (6) testirati malicious/truncated responses i version mismatch; (7) dokumentovati tačnu privacy assumption umesto nazivanja ovoga anonymous browsing-om.

**Detekcija:** mreže vide korišćenje service-a i volume; endpoint telemetry otkriva client i final record use; kompromitovani server može menjati datasets ili timing. **Capture-resilient OPSEC:** na client-u čuvati samo javne database parameters i ograničeni cache. **Monitoring:** proveravati signed dataset roots, fixed request shapes, promene error rate-a i server-key rotations.

## Ograničeni server-side fetcher, preview ili rendering service

**Mehanika:** udaljeni service preuzima ili renderuje URL i vraća screenshot, metadata ili sanitizovani sadržaj. Odredište vidi adresu fetcher-a; service vidi requestera, URL i rezultat. Zloupotreba link-preview botova, security scanner-a ili third-party URL fetcher-a nije autorizovano korišćenje proxy-ja.

**Prednosti:** izoluje aktivni sadržaj od workstation-a; destination dobija kontrolisani fetcher fingerprint; mogu se primeniti ograničenja tipa file-a, veličine, odredišta i rendering-a; disposable execution environment.

**Nedostaci:** service ima potpuno znanje o zahtevu; account/API/billing records; SSRF i data-exfiltration rizik; skripte, authentication i interaktivni sajtovi možda neće raditi; jedinstveni URL-ovi povezuju requestera i fetch.

**Procedura:** (1) deploy-ovati organization-owned fetcher sa strogim allowlist-om owned test domena; (2) blokirati private, link-local, metadata i redirect-to-unapproved adrese; (3) ograničiti methods, redirects, bytes i render time; (4) ukloniti credentials/cookies; (5) poslati owned URL; (6) uporediti requester, fetcher i target logove; (7) uništiti render instance i centralni audit zadržati prema policy.

**Detekcija:** target vidi service ASN/fingerprint; provider i controller logovi povezuju requestera sa URL-om; endpoint process/API calls prikazuju submission. **Capture-resilient OPSEC:** koristiti jedan short-lived project token bez arbitrary destination authority. **Monitoring:** alarmirati na allowlist denials, redirect violations, fetches bez controller job ID-a i provider abuse notices.

## Anycast rendezvous pool

**Mehanika:** više organization-controlled node-ova oglašava ili front-uje jednu stabilnu service adresu, a routing bira najbližu instancu. Anycast poboljšava dostupnost i skriva pojedinačni back-end od klijenta, ali operator i dalje kontroliše sve instance, a service address je stabilna.<sup>[[26]](#references)</sup>

**Prednosti:** otporan regionalni ingress; nije potrebna field reconfiguration kada jedna instanca otkaže; DDoS/load distribution; central policy može premeštati sesije između poznatih node-ova.

**Nedostaci:** BGP/CDN i provider records identifikuju organizaciju; promene putanje mogu prekinuti stateful sessions; monitoring se razlikuje po lokaciji klijenta; jedna stabilna adresa lako se blokira ili grupiše po reputaciji.

**Procedura:** koristiti provider-supported organization project ili isolated routing lab: (1) deploy-ovati dva identična authenticated health endpoint-a; (2) izložiti jednu dokumentovanu service address; (3) session state držati kod broker-a, a ne na edge-u; (4) povući jedan node i proveriti reconnect; (5) testirati certificate, policy i log consistency; (6) alarmirati na unauthorized origin/region; (7) ukloniti advertisements i credentials pri closeout-u.

**Detekcija:** BGP/RPKI/history, provider tenancy, certificates i identično service behavior identifikuju pool. **Capture-resilient OPSEC:** edge sadrži samo regional service identity, bez operator ili fleet-enrollment key-a. **Monitoring:** probe-ovati svaki region iz authorized monitor-a, uporediti route origin i configuration digest i neočekivani origin tretirati kao incident.

## QUIC migration i Multipath TCP continuity

**Mehanika:** QUIC connection IDs mogu održati client session kroz NAT rebinding ili promene adrese; Multipath TCP može prenositi jedan pouzdani byte stream kroz više subflow-ova. Poboljšavaju kontinuitet pri prelasku između Wi-Fi/cellular mreža, ali zajednički peer vidi stare i nove putanje, pa cross-path correlation može biti lakši.<sup>[[27]](#references)</sup>

**Prednosti:** brži oporavak pri promeni uplink-a; application session ne mora početi ispočetka; MPTCP može kombinovati otpornost i throughput; vredno za odobrene field node-ove.

**Nedostaci:** nije anonimnost; peer vidi migration/subflows; connection identifiers i simultani saobraćaj povezuju putanje; middlebox/carrier support varira; duplirani provider records povećavaju izloženost.

**Procedura:** (1) uključiti podržani transport samo između owned field client-a i rendezvous-a; (2) autentifikovati aplikaciju nezavisno od IP-a; (3) započeti ograničeni transfer na approved Wi-Fi-ju; (4) preći na organization cellular; (5) potvrditi path validation, data integrity i odsustvo clear/direct fallback-a; (6) testirati idle timeout i povratak; (7) čuvati broker records svake path transition.

**Detekcija:** peer direktno vidi address migration ili MPTCP subflows; access providers vide svoj deo; connection IDs, TLS identity i timing povezuju oba. **Capture-resilient OPSEC:** čuvati samo device-scoped session material i brzo isticanje resumable state-a. **Monitoring:** alarmirati na impossible path changes, simultane neodobrene mreže, migration storms i resumption nakon revoke-a.

## Managed CI/CD ili ephemeral automation runner egress

**Mehanika:** organization-owned workflow izvršava ograničenu network proveru na hosted runner-u. Odredište vidi cloud runner address, dok platforma zadržava repository, actor, workflow, token, log i billing attribution. Ovo je remote execution sa odgovornim egress-om, a ne anonimnost od provajdera.<sup>[[28]](#references)</sup>

**Prednosti:** disposable clean environment; reproducible job definition; nema inbound connection; korisno za geografski distribuirane availability checks; jak controller audit.

**Nedostaci:** platforma i organizacija identifikuju inicijatora; široki workflow tokens i untrusted pull requests su opasni; shared IP reputation; logovi/artifacts mogu zadržati secrets ili target data.

**Procedura:** (1) kreirati private organization repository i environment za assessment; (2) dozvoliti samo ručno odobrene, fiksne benigne job-ove prema owned endpoint-ima; (3) koristiti minimalne read-only workflow permissions i bez production secrets; (4) pokrenuti proveru; (5) uporediti workflow, provider i target records; (6) proveriti da artifacts ne sadrže credentials; (7) obrisati environment token i zadržati potrebni audit.

**Detekcija:** provider audit i workflow logovi daju direktnu atribuciju; target-i identifikuju runner ASN/range i stabilan request grammar. **Capture-resilient OPSEC:** nikada ne stavljati field-device, signing, wallet ili cloud-administrator secrets u runner variables. **Monitoring:** zahtevati branch/environment approval i alarmirati na workflow edits, fork execution, secret reads i neočekivana odredišta.

## Non-IP lokalni first hop do owned gateway-a

**Mehanika:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio ili serial/optical link prenosi ograničene poruke sa obližnjeg senzora do Internet gateway-a uz odobrenje vlasnika. Field device sam nema Internet rutu; gateway je jedini egress. Radio range i protokolarna ograničenja čine ovo telemetry/store-and-forward dizajnom, a ne interaktivnim anonimnim Internetom.

**Prednosti:** uklanja Internet stack i credentials sa najmanjeg field device-a; mala potrošnja; gateway centralizuje policy; može premostiti privremene dead zone-ove.

**Nedostaci:** RF/fizičko otkrivanje, pairing i device identifiers; mali bandwidth i domet; gateway i dalje povezuje sve poruke; spectrum i encryption restrictions variraju; capture može otkriti queued data.

**Procedura:** (1) dobiti site i spectrum approval; (2) upariti jedan owned sensor sa jednim owned gateway-om pomoću jedinstvenih keys; (3) definisati signed fixed-size message types, TTL i rate; (4) senzoru ne dati default IP route; (5) dozvoliti gateway-u da prosleđuje samo do owned collector-a; (6) testirati replay, range loss i gateway outage; (7) inventarisati i preuzeti oba uređaja.

**Detekcija:** RF survey, pairing database, fizička inspekcija i gateway process/flow logovi otkrivaju putanju. **Capture-resilient OPSEC:** senzor sadrži samo pairwise key i ograničeni encrypted queue, nikada operator, Wi-Fi, cellular ili controller credentials. **Monitoring:** alarmirati na nove peer-ove, sequence rollback, key failure, neuobičajen RF rate i poruke koje stižu preko neregistrovanog gateway-a.

## Matrica izloženosti pri capture-u/kompromitovanju

Ova tabela primenjuje proveru otpornosti na capture na svaku prethodnu familiju. „Minimizovati“ znači smanjiti secrets i blast radius na autorizovanim sredstvima; nikada ne znači brisati dokaze ili skrivati se od istrage.

| Familija tehnike | Captured endpoint/relay može otkriti | Minimalna autorizovana kontrola |
|---|---|---|
| NAT/CGNAT, javni Wi-Fi, travel router | poznate mreže, DHCP/portal history, MAC-ove, tunnel peer | odvojeni organization device; private MAC gde je podržan; bez ličnih naloga; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provajdere/hostname-ove, keys, routes, logove i susedni hop | jedan identity po engagement-u; short TTL; uske rute; broker-side revocation; bez master keys |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway konfiguraciju, application identifiers i cached requests | minimizovati payload identifiers; pin approved config; bounded cache; striktan no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | instalirani software, bridge/onion material, local state i peer history | standard client; odvojeni service keys; minimalno šifrovano stanje; rotirati kompromitovani service identity |
| Remote browser/VDI/jump host | workspace token, clipboard/files i remote tenant | phishing-resistant MFA na gateway-u; disabled transfer channels; brza session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider i približnu lokaciju | organization contract; bez personal co-location; narrow APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | samo consented/owned node-ovi; signed agent; credential po node-u; participant mapping kod controller-a |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment i billing reference | dedicated project; least-privilege role; short-lived deploy token; provider audit centralno zadržan |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results i custody data | signed bounded jobs; TTL; encrypted cache; odvojeni producer identity; immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artefacts | pisana dozvola; unique device identity; bez operator secret-a; tamper/state telemetry; revoke and recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route i uplink profiles | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed paths |
| IPv6 temporary addressing | profiles, prefix history i endpoint/application state | tretirati samo kao anti-tracking; čuvati network logs; kombinovati sa endpoint compartmentation |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state i research keys | standard client ili isolated lab; bez personal browser state-a; bez production signaling-a |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway ili service token | encrypted bounded cache; public-only parameters; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state i sve poznate putanje | regional identity only; kratak resumption lifetime; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs i artifacts | least-privilege workflow; bez production/field/wallet secrets; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages i gateway identity | unique pairwise key; fixed message schema; bez Wi-Fi/cellular/operator credentials |

## Monitoring mogućeg otkrivanja za svaku access familiju

Nijedan client-side test ne dokazuje da investigator ili defender posmatra saobraćaj. Pratiti promene u sistemima koje engagement poseduje, potvrđivati ih pomoću controller/client-a i zaustaviti rad umesto ispitivanja posmatrača. Redovi ispod obuhvataju sve prethodne tehnike; kombinovati ih sa [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Obuhvaćene tehnike | Bezbedni controller-side signali | Uslov za quarantine/stop |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | neodobrena mreža/SIM/device, neobjašnjena relokacija ili provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback ili out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer ili provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health i owned canary page | personal-account crossover, unexpected non-Tor connection ili compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association i content hash | unknown peer/gateway, sequence rollback, unauthorized content ili missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export i cloud audit | unknown login/workflow edit, secret read, unexpected destination ili project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature i TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape iz lab-a |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use ili site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation i broker session | impossible migration, simultaneous unapproved paths ili session resumption posle revoke-a |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root ili provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Izbor i testiranje putanje

1. Navesti posmatrača koji treba ukloniti i podatke koje treba sakriti.
2. Izabrati najmanje složenu familiju koja ga uklanja.
3. Nacrtati posmatrače izvora, entry-ja, traversal-a, exit-a, DNS-a, naloga i plaćanja.
4. Koristiti odvojeni endpoint/application identity.
5. Proveriti IPv4, IPv6, DNS, WebRTC/application bypass i prikaz na odredištu.
6. Prekinuti svaki hop i potvrditi da je failure zatvoren.
7. Uporediti logove svake komponente pod kontrolom organizacije.
8. Zabeležiti preostale vremenske, provider, endpoint i fizičke veze.

## References

- [1] [EFF — Izbor odgovarajućeg VPN-a za vas](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
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
