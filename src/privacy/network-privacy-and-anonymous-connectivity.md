# Privatnost mreže i anonimno povezivanje

{{#include ../banners/hacktricks-training.md}}

Privatnost mreže je odluka o rutiranju, a ne potpuni identitet. Putanju birajte tako što ćete se zapitati ko ne bi trebalo da može da poveže **source**, **destination**, **content** i **timing**.

Za normalizovani inventar — `Pros`, `Cons`, detaljnu `Procedure` i `Detection` za svaku porodicu pristupnih putanja — počnite od [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Ova stranica proširuje uobičajene opcije koje se mogu primeniti.

## Šta svaki posmatrač obično može da vidi

| Putanja | Lokalna mreža / ISP | Posrednik | Odredište | Glavno ograničenje | Relativna brzina |
|---|---|---|---|---|---|
| Direktan HTTPS | Source, metapodaci odredišta, timing/obim | Hosting/CDN vidi konekciju | Source IP, podaci browsera/aplikacije | Nema privatnosti source IP adrese | Najbrže |
| Commercial VPN | Source povezan sa VPN-om; uobičajeno ne vidi metapodatke odredišta | VPN vidi source i metapodatke odredišta | VPN egress IP | Jedan provajder postaje tačka korelacije | Obično brzo |
| Self-hosted VPN/VPS | Source povezan sa VPS-om | Host/account/payment/control-plane logovi | VPS egress IP | Lako se povezuje sa iznajmljenim serverom/account-om | Obično brzo |
| Tor Browser | Source povezan sa Tor/bridge; timing/obim | Svaki relay vidi ograničeni deo | Tor exit, podaci browsera | Sporije; rizici account-a/endpoint-a/korelacije | Umereno/sporo |
| Tails/Whonix | Slična Tor putanja, sa jačim granicama rutiranja | Ista Tor ograničenja | Tor exit/podaci aplikacije | Operativne greške i host/hardware ostaju | Umereno/sporo |
| Javni guest Wi-Fi + HTTPS | Lokacija vidi lokalni uređaj/timing i odredišta | ISP lokacije vidi metapodatke | Guest javni IP | Fizička korelacija sa lokacijom/captive portalom/uređajem | Brzo/promenljivo |
| Cellular hotspot | Carrier vidi subscriber/uređaj/lokaciju i odredišta | VPN/Tor ako se koristi | Carrier, VPN ili Tor egress IP | Mobilna pretplata i lokacija su trajni identifikatori | Brzo/promenljivo |
| Mixnet | Access vidi korišćenje mixnet-a; timing/obim | Više mixing node-ova | Gateway/egress | Ekosistem u nastajanju; cena u vidu latencije i bandwidth-a | Najsporije |

HTTPS štiti content tokom prenosa, ali ne i sve metapodatke. EFF navodi da domen, vreme i veličina saobraćaja mogu ostati vidljivi posrednicima čak i kada su putanje stranica, kredencijali i poruke šifrovani.<sup>[[1]](#references)</sup>

## VPN-ovi: brza privatnost sa koncentrisanim poverenjem

VPN je koristan za skrivanje metapodataka odredišta od access ISP-a, zaštitu prvog hop-a na nepouzdanoj mreži, korišćenje stabilne engagement egress adrese ili pristup privatnoj mreži. On **ne** čini korisnika anonimnim. VPN vidi source konekciju i može da posmatra metapodatke odredišta; account-i, cookies, GPS, fingerprints i payment informacije ostaju.<sup>[[1]](#references)</sup>

### Kontrolna lista za procenu provajdera

1. **Vlasništvo i jurisdikcija:** utvrdite pravno lice, matičnu kompaniju, zemlje poslovanja, podizvođače infrastrukture i važeći pravni postupak.
2. **Prikupljeni podaci:** razlikujte account/billing, source IP, timestamps konekcija, bandwidth, crash telemetry, DNS queries i destination logove. „No browsing logs“ ne znači „no data“.
3. **Čuvanje i brisanje:** pronađite precizna trajanja i proverite da li backups, fraud sistemi i processors prate isti raspored.
4. **Dokazi:** prednost dajte javnim auditima sa obimom, datumom, nalazima i remediation-om; reproducible/open klijentima; transparency reports i dokumentovanim incidentima.
5. **Protocol i client:** održavani WireGuard, OpenVPN ili drugi pregledani protocol; automatic updates; DNS i IPv6 handling; kill switch; i per-platform leak testovi.
6. **Business model:** razumite kako se besplatna ili subvencionisana usluga finansira. Samo prisustvo u app store-u nije dokaz pouzdanog rada.
7. **Payment fit:** alternativni payment može da smanji disclosure billing podataka VPN-u, ali ne uklanja source IP koji se posmatra pri svakoj konekciji.

### Konfigurisanje i verifikacija VPN-a

1. Instalirajte potpisani client provajdera/organizacije iz njegovog zvaničnog izvora.
2. Izaberite **full tunnel**, osim ako dokumentovana ruta mora da ga zaobiđe. Split tunneling stvara putanje za korelaciju i leak.
3. Omogućite fail-closed/always-on ponašanje i blokirajte saobraćaj tokom ponovnog povezivanja.
4. Šaljite DNS kroz tunnel i testirajte IPv4 i IPv6. Isključite protocol samo ako se ne može bezbedno tunelovati i ako je prihvaćen gubitak funkcionalnosti.
5. Testirajte sleep/wake, promenu mreže, captive-portal login, pad tunnela i hotspot tethering. NCSC upozorava da tethered klijenti na nekim platformama mogu zaobići VPN na telefonu.<sup>[[2]](#references)</sup>
6. Koristite testni endpoint pod kontrolom organizacije da zabeležite uočene IPv4, IPv6, DNS resolver i timing konekcije. Ne izlažite osetljiv engagement nasumičnim „leak test“ sajtovima.
7. Ponovite testiranje nakon promena client-a, OS-a, mreže ili policy-ja.

### Bypasses rutiranja na hostile LAN-u

VPN može ostati vidljivo „povezan“ dok odabrani paketi zaobilaze VPN, jer operativni sistem bira rutu **pre** nego što VPN šifruje paket. TunnelCrack je pokazao dva načina zloupotrebe uobičajenih routing izuzetaka: **LocalNet** čini da Internet odredište izgleda kao da je na direktno povezanoj podmreži, dok **ServerIP** spoof-uje VPN-gateway resolution tako da ciljna adresa nasledi clear-network izuzetak potreban VPN transportu. Ovo su client/routing greške, a ne propusti u WireGuard-u, OpenVPN-u, IPsec-u ili TLS-u; HTTPS payload-i ostaju end-to-end šifrovani, ali lokalni posmatrač može da povrati metapodatke odredišta/timinga i sve cleartext protocol podatke.<sup>[[18]](#references)</sup>

TunnelVision primenjuje isti primitive pre šifrovanja pomoću DHCP option 121. Zlonamerni ili kompromitovani DHCP server može da instalira classless rutu koja je specifičnija od VPN catch-all rute i da izabere fizički interface za proizvoljni host ili opseg. VPN control channel može ostati aktivan, pa se kill switch koji se pokreće samo pri prekidu tunnela možda neće aktivirati, dok jedna javna provera „IP leak“-a može propustiti selektivne bypass-e.<sup>[[19]](#references)</sup>

Packet-filter kill switch koji na fizičkom interface-u dozvoljava samo DHCP i autentifikovani VPN transport trebalo bi da ovo pretvori u fail-closed ponašanje, ali ciljano ubacivanje ruta i dalje može da stvori selective-denial side channel. Za Linux workload-e sa visokim posledicama prednost dajte snažnijem [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), gde application namespace nema fizički interface ni clear-network default rutu.<sup>[[19]](#references)</sup>

#### Verifikacija u sopstvenom labu

Testirajte tačan client/OS/version na sopstvenom AP-u, DHCP serveru, VPN endpoint-u i odredištu; tvrdnje o celom proizvodu brzo zastarevaju jer su implementacije rutiranja i packet-filter-a specifične za platformu. Hvatajte saobraćaj i na samom endpoint-u i na testnom serveru — sam sajt za proveru egress IP adrese ne dokazuje da svako odredište prati tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Povežite VPN, zabeležite adresu VPN servera i sačuvajte svaku IPv4/IPv6 routing tabelu i policy-routing pravilo. Na Windows-u koristite `route print`; na macOS-u `netstat -rn`; na Linux-u koristite komande ispod.
2. Proverite izabranu rutu za nekoliko IP adresa odredišta pod vašom kontrolom. Next hop/interface mora biti tunnel, osim dokumentovanog VPN transport endpoint-a.
3. Za TunnelVision obnovite lease na kontrolisanoj DHCP mreži i instalirajte option 121 rutu **samo za testno odredište pod vašom kontrolom**. Prolaz znači da je saobraćaj i dalje tunelovan ili blokiran — nikada ne sme biti emitovan kao saobraćaj odredišta preko fizičkog interface-a.
4. Za LocalNet dodelite klijentu lab-only javnu documentation podmrežu, kao što je `203.0.113.0/24`, i smestite testno odredište pod vašom kontrolom unutar nje. Proverite da omogućavanje LAN pristupa ne dovodi do toga da odredišta Internet klase zaobiđu tunnel.
5. Za ServerIP, pre VPN konekcije podesite da kontrolisani DNS razreši kontrolisani VPN hostname u testno odredište pod vašom kontrolom, dok lab gateway prosleđuje VPN transport stvarnom VPN endpoint-u pod vašom kontrolom. Klijent ne sme da izuzme nepovezan application saobraćaj prema spoof-ovanoj adresi.
6. Ponovite test sa uključenim i isključenim „local network access“, nakon reconnect-a, sleep/wake-a, promene mreže i pada VPN procesa. IPv4, IPv6 i DNS testirajte nezavisno.
7. Pregledajte capture na fizičkom interface-u. Trebalo bi da sadrži DHCP i šifrovane pakete prema VPN serveru, a ne pakete direktno adresirane na testno odredište pod vašom kontrolom. Takođe potvrdite da odbijeni bypass ne može neprimetno da se aktivira nakon user prompt-a ili popravke konektivnosti.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: jača nepovezivost na vebu

Tor gradi circuit kroz više relay-a tako da nijedan pojedinačni relay obično ne zna i izvor i odredište. Odredište vidi Tor exit, a ne IP adresu korisnika; lokalna mreža obično vidi Tor konekciju.<sup>[[3]](#references)</sup> Tor je dizajniran za TCP aplikacije sa malim kašnjenjem, pa je sporiji i ne može garantovati zaštitu od adversary-ja koji može korelisati oba kraja.<sup>[[4]](#references)</sup>

### Bezbedan Tor Browser workflow

1. Preuzimajte Tor Browser samo sa Tor Project-a ili zvaničnog mirror-a i proverite potpis kad god je to moguće.
2. Koristite **Tor Browser**, a ne običan browser usmeren na Tor SOCKS port. Obični browser-i mogu da naprave DNS/WebRTC leak i da otkriju identifikujuće stanje.<sup>[[5]](#references)</sup>
3. Zadržite podrazumevanu veličinu, fontove, ekstenzije i privacy settings. Dodatni add-on-i mogu učiniti browser jedinstvenijim.<sup>[[6]](#references)</sup>
4. Izaberite nivo bezbednosti **Safer** ili **Safest** kada je prihvatljivo povećano narušavanje funkcionalnosti.
5. Koristite bridge kada je direktan Tor blokiran ili kada bi uobičajene relay IP adrese stvorile neprihvatljivu lokalnu vidljivost. Bridge-evi otežavaju jednostavno prepoznavanje; ne uklanjaju traffic analysis.<sup>[[7]](#references)</sup>
6. Ne prijavljujte se na nalog koji otkriva identitet, ne pružajte identifikujuće informacije i ne otvarajte preuzete aktivne dokumente u eksternoj umreženoj aplikaciji.
7. Koristite odvojenu sesiju/kontekst za svaki identitet. „New circuit“ nije isto što i brisanje browser/application identiteta; koristite **New Identity** ili ponovo pokrenite izolovano okruženje kada je to prikladno.
8. Dajte prednost autentifikovanom HTTPS-u ili autentifikovanom onion service-u. Tor exit može posmatrati nešifrovan HTTP saobraćaj.

### Tor plus VPN

Kombinovanje nije automatski bezbednije. VPN pre Tor-a može sakriti direktne Tor relay konekcije od ISP-a, dok VPN vidi izvor; Tor pre VPN-a daje VPN-u stabilan uvid u aktivnost nakon Tor-a i može smanjiti anonymity set. Pogrešna konfiguracija može uvesti leak-ove. Tor Project preporučuje ovakve kombinacije samo za napredne, eksplicitne threat model-e.<sup>[[8]](#references)</sup>

## Javni i guest Wi-Fi

Moderni HTTPS znači da pasivni susedi obično ne mogu da čitaju pravilno šifrovan veb sadržaj, ali guest Wi-Fi nije anonymity. Mesto može beležiti vremena povezivanja, identifikatore uređaja, podatke captive portal-a, odredišta i DHCP detalje; kamere, kupovine, prevoz i fizičko posmatranje mogu identifikovati korisnika. Lažna pristupna tačka sa sličnim nazivom takođe može preuzeti akreditive portal-a ili manipulisati nešifrovanim saobraćajem.<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. Koristite samo mrežu ponuđenu gostima ili mrežu za koju je vlasnik dao izričitu dozvolu. Pitajte osoblje za tačan SSID i proceduru portal-a.
2. Ažurirajte endpoint i travel router pre dolaska. Onemogućite deljenje datoteka/štampača, inbound discovery, automatsko povezivanje i proveravanje zapamćenih mreža.
3. Omogućite privatnu/randomizovanu Wi-Fi adresu operativnog sistema. Aktuelni Apple sistemi mogu koristiti rotirajuće adrese na otvorenim/slabim mrežama; moderni Android obično koristi randomizaciju trajnu po SSID-u. Ovo smanjuje samo jedan lokalni identifikator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Dajte prednost travel router-u ili low-trust bridge uređaju pod kontrolom organizacije između privilegovane radne stanice i guest mreže. Ovo centralizuje firewall/VPN policy, ali ne skriva router od mesta.<sup>[[12]](#references)</sup>
5. Captive portal završite samo preko određenog low-trust uređaja/browser-a. Nikada ne unosite lične ili ponovo korišćene akreditive za navodno anoniman kontekst. Zatvorite portal browser nakon uspostavljanja konekcije.
6. Pokrenite full-tunnel VPN ili Tor pre osetljive aktivnosti i potvrdite fail-closed ponašanje.
7. Zaboravite mrežu nakon korišćenja i pregledajte policy naloga portal-a/zadržavanja podataka.

{% hint style="danger" %}
Cracking Wi-Fi mreže komšije, zaobilaženje portal-a, korišćenje leaked guest akreditiva, kloniranje pristupa drugog gosta ili skrivanje Raspberry Pi-ja u kafiću predstavljaju neovlašćenu aktivnost — ne tehniku za zaštitu privatnosti. Bezbedne alternative su zakonita guest mreža, lokacija odobrena od klijenta ili dokumentovani drop node postavljen i uklonjen uz pisanu saglasnost vlasnika objekta.
{% endhint %}

## Travel router-i

Travel router može izolovati radnu stanicu od neprijateljskih lokalnih broadcast-a, primeniti firewall, obezbediti konzistentan interni SSID i automatski ponovo uspostaviti VPN. On **nije** anoniman: upstream vidi njegov radio identitet i vreme saobraćaja, a VPN provider vidi izvor tunnel-a.

- Koristite podržani OpenWrt/vendor firmware i uklonite nekorišćene servise.
- Administrirajte preko Ethernet-a ili posebnog management SSID-a sa jedinstvenom lozinkom.
- Onemogućite WAN-side administraciju, UPnP, WPS, deljenje datoteka i neželjeni inbound saobraćaj.
- Koristite randomizovani/private WAN MAC samo gde je podržan i dozvoljen.
- Primenite VPN policy na router-u, uključujući DNS i IPv6, i blokirajte egress kada tunnel otkaže.
- Ne pretpostavljajte da phone hotspot usmerava tethered uređaje kroz VPN telefona; testirajte to.

## Cellular, SIM-ovi i eSIM-ovi

Cellular je praktičan, ali nije anoniman. Operateri čuvaju identifikatore pretplatnika/uređaja i lokaciju izvedenu iz priključivanja na mrežu; eSIM je i dalje mobilna pretplata. Prepaid pouzdano ne znači neregistrovan — zahtevi se razlikuju po državama i menjaju se.<sup>[[13]](#references)</sup>

Operativno:

- Koristite odvojen, podržan uređaj da biste smanjili izlaganje ličnih podataka, a ne da biste stvorili izmišljenog pretplatnika.
- Ne nosite „odvojen“ uređaj stalno pored ličnog telefona ako je co-location deo threat model-a.
- Onemogućite nekorišćeni cellular, Wi-Fi, Bluetooth i pristup lokaciji; isključivanje napajanja predstavlja jaču radio granicu od UI prekidača.
- Osetljiv saobraćaj usmerite kroz odobreni VPN/Tor path, uz svest da carrier i dalje zna lokaciju pretplate/uređaja i endpoint tunnel-a.
- Proverite aktuelna pravila registracije i zadržavanja podataka kod nacionalnog regulatora ili lokalnog pravnog savetnika; ne oslanjajte se na online spiskove „anonymous SIM countries“.

## DNS i TLS metadata

- **DoH/DoT/DoQ** šifruju DNS između klijenta i resolver-a, sprečavajući jednostavno lokalno čitanje ili izmene, ali resolver i dalje vidi upite i transportne identifikatore. Oni pomeraju poverenje; ne obezbeđuju anonymity.<sup>[[14]](#references)</sup>
- **ODoH** dodaje proxy tako da resolver ne mora da sazna IP adresu klijenta, pod pretpostavkom da proxy i target ne sarađuju. Traffic analysis je izričito van opsega.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** može zaštititi unutrašnje ime servera u TLS handshake-u kada ga podržavaju klijent, DNS i server. Destination IP, vreme, obim i endpoint ostaju vidljivi.<sup>[[16]](#references)</sup>
- U pravilno konfigurisanom VPN ili Tor okruženju, DNS treba da prati podržani route tog okruženja. Dodavanje zasebnog resolver-a može stvoriti novog observer-a ili fingerprint.

### Encrypted-DNS/ECH verification workflow

1. Odredite da li DNS kontroliše VPN/Tor okruženje, OS ili aplikacija. Konfigurišite ga u **jednom** predviđenom layer-u umesto naslagivanja nepovezanih resolver-a.
2. Izaberite resolver na osnovu njegove objavljene privacy/retention policy i omogućite strogi encrypted mode tamo gde ga platforma podržava. Opportunistic fallback može nečujno vratiti saobraćaj na plaintext.
3. Pošaljite upit za jedinstveni subdomain u okviru authoritative test zone koju kontrolišete; potvrdite da authoritative log vidi predviđeni recursive resolver.
4. Uz autorizaciju snimite samo saobraćaj testnog uređaja. Potvrdite da access network ne može čitati plaintext DNS, uz svest da može videti encrypted resolver/tunnel endpoint.
5. Testirajte blokiran/nedostupan encrypted resolver. Uslov prolaza je izabrano fail-closed ili dokumentovano fallback ponašanje — ne slučajni clear query.
6. Za ECH koristite kontrolisani ECH-enabled host i pregledajte client/server dijagnostiku da potvrdite da je **inner** ClientHello prihvaćen. Samo nuđenje HTTPS record-a ne dokazuje da je ECH uspeo.
7. Ponovite test nakon promena mreže, captive portal-a, ažuriranja browser-a i ponovnog povezivanja VPN-a. Zabeležite koja komponenta upravlja DNS/ECH-om kako kasniji administratori ne bi napravili bypass.

## Mixnets

Mixnet-i kao što su Nym ili Katzenpost dodaju pakete fiksne veličine, kašnjenje, promenu redosleda i cover traffic radi otpora timing correlation-u. Ove osobine zahtevaju latency i bandwidth, a nezavisni dokazi na skali deployment-a su ograničeni. Trenutne consumer mixnet-e tretirajte kao **emerging/high-latency options**, a ne kao brže ili garantovane zamene za Tor/VPN.<sup>[[17]](#references)</sup>

### Evaluation workflow

1. Identifikujte održavan client i tačno podržanu aplikaciju; ne usmeravajte proizvoljan browser/system saobraćaj kroz nedokumentovani proxy.
2. Pročitajte aktuelni threat model za entry, mix node-ove, gateway, destination i pretpostavke o collusion-u.
3. Instalirajte iz zvaničnog potpisanog izvora u zasebnom testnom compartment-u i koristite samo benigni endpoint koji posedujete.
4. Izmerite delivery latency, ograničenja veličine poruke, pouzdanost, retransmission i ponašanje kada gateway nije dostupan.
5. Pregledajte lokalni saobraćaj i endpoint koji posedujete da biste potvrdili predviđeni path i source. Proverite da li replies koriste isti privacy design.
6. Testirajte shutdown/failure: aplikacija ne sme nečujno preći na direktan Internet access.
7. Ne onemogućavajte cover traffic, ne smanjujte delays i ne birajte neuobičajene fixed routes samo radi brzine; ove izmene mogu obezvrediti navedeni anonymity model.
8. Zadržite rešenje u eksperimentalnoj fazi dok konkretni deployment, nezavisna analiza i operativna pouzdanost ne budu u skladu sa nivoom posledica.

## Network preflight checklist

- [ ] Authorization obuhvata access network, target, datume i source infrastructure.
- [ ] Endpoint ne sadrži nepovezane identitete ili aktivne sync sesije.
- [ ] IPv4, IPv6, DNS i reconnect ponašanje odgovaraju planu.
- [ ] Kontrolisani DHCP/local-subnet route injection ne može preusmeriti testni saobraćaj na fizički interfejs.
- [ ] Destination vidi samo očekivani egress.
- [ ] Captive portal i hotspot ponašanje testirani su bez osetljivog saobraćaja.
- [ ] Lokalno deljenje/discovery i automatsko pridruživanje mrežama su onemogućeni.
- [ ] Observer tabela i preostali rizik traffic correlation-a su prihvaćeni.
- [ ] Provider policy, retention i emergency contact su aktuelni.

Za split-knowledge relay-e, route-enforced workloads, pluggable transports, onion services, I2P i disposable remote browser-e nastavite na [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Izbor VPN-a koji vam odgovara](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Smernice za bezbednost uređaja: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Zaštite privatnosti i anonymity-ja koje Tor pruža](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Kratak uvod u Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Korišćenje Tor-a sa drugim browser-ima](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins i add-on-i u Tor Browser-u](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Deblokiranje Tor-a](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Korišćenje Tor Browser-a sa VPN-om](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Da li su javne Wi-Fi mreže bezbedne?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privatnost sa Apple uređajima](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementacija MAC randomizacije](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principi za bezbedne privilegovane access workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Obavezna SIM registracija: policy i regulatorne perspektive](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Preporuke za operatere DNS Privacy Service-a](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Zaobilaženje tunnel-a: Leaking VPN Client Traffic zloupotrebom Routing Tables](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Kako napadači mogu otkriti routing-based VPN-ove radi potpunog VPN leak-a](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
