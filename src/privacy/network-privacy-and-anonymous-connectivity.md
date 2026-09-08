# Privatnost mreže i anonimno povezivanje

Privatnost mreže je odluka o rutiranju, a ne potpuni identitet. Izaberite putanju tako što ćete pitati ko ne bi trebalo da može da poveže **izvor**, **odredište**, **sadržaj** i **vreme**.

Za normalizovani inventar — `Pros`, `Cons`, detaljnu `Procedure` i `Detection` za svaku porodicu pristupnih putanja — počnite od [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Ova stranica proširuje najčešće primenljive opcije.

## Šta svaki posmatrač obično može da vidi

| Putanja | Lokalna mreža / ISP | Posrednik | Odredište | Glavno ograničenje | Relativna brzina |
|---|---|---|---|---|---|
| Direktni HTTPS | Izvor, metapodaci odredišta, vreme/obim | Hosting/CDN vidi vezu | Izvorna IP adresa, podaci browsera/aplikacije | Nema privatnosti izvorne IP adrese | Najbrže |
| Komercijalni VPN | Izvor povezan sa VPN-om; ne uobičajene metapodatke odredišta | VPN vidi metapodatke izvora i odredišta | Izlazna IP adresa VPN-a | Jedan provajder postaje tačka korelacije | Obično brzo |
| Samostalno hostovani VPN/VPS | Izvor povezan sa VPS-om | Logovi hosta/naloga/plaćanja/control-plane-a | Izlazna IP adresa VPS-a | Lako ga je povezati sa iznajmljenim serverom/nalogom | Obično brzo |
| Tor Browser | Izvor povezan sa Tor-om/bridge-om; vreme/obim | Svaki relay vidi ograničen deo | Tor exit, podaci browsera | Sporije; rizici naloga/endpointa/korelacije | Umereno/sporo |
| Tails/Whonix | Slična Tor putanja, sa snažnijim granicama rutiranja | Ista Tor ograničenja | Tor exit/podaci aplikacije | Operativne greške i host/hardver ostaju | Umereno/sporo |
| Javni guest Wi-Fi + HTTPS | Mesto vidi lokalni uređaj/vreme i odredišta | ISP mesta vidi metapodatke | Javna IP adresa gosta | Korelacija fizičkog prisustva/portal uređaja | Brzo/promenljivo |
| Cellular hotspot | Operater vidi pretplatnika/uređaj/lokaciju i odredišta | VPN/Tor ako se koristi | IP adresa operatera, VPN-a ili Tor exit-a | Mobilna pretplata i lokacija su trajni identifikatori | Brzo/promenljivo |
| Mixnet | Pristup vidi korišćenje mixnet-a; vreme/obim | Više mixing node-ova | Gateway/izlaz | Ekosistem u razvoju; trošak latencije i bandwidth-a | Najsporije |

HTTPS štiti sadržaj tokom prenosa, ali ne i sve metapodatke. EFF navodi da domen, vreme i veličina saobraćaja mogu ostati vidljivi posrednicima čak i kada su putanje stranica, akreditivi i poruke šifrovani.<sup>[[1]](#references)</sup>

## VPN-ovi: brza privatnost sa koncentrisanim poverenjem

VPN je koristan za skrivanje metapodataka odredišta od pristupnog ISP-a, zaštitu prvog skoka na nepouzdanoj mreži, predstavljanje stabilne izlazne adrese za engagement ili pristup privatnoj mreži. On **ne** čini korisnika anonimnim. VPN vidi izvornu vezu i može da posmatra metapodatke odredišta; nalozi, kolačići, GPS, fingerprint-i i podaci o plaćanju ostaju.<sup>[[1]](#references)</sup>

### Kontrolna lista za procenu provajdera

1. **Vlasništvo i jurisdikcija:** utvrdite pravno lice, matičnu kompaniju, zemlje poslovanja, podizvođače infrastrukture i primenljive pravne procedure.
2. **Prikupljeni podaci:** razlikujte podatke o nalogu/naplati, izvornu IP adresu, vremenske oznake konekcije, bandwidth, crash telemetriju, DNS upite i logove odredišta. „Bez browsing logova“ ne znači „bez podataka“.
3. **Čuvanje i brisanje:** pronađite precizne rokove i proverite da li backup-i, sistemi za prevenciju prevara i procesori prate isti raspored.
4. **Dokazi:** prednost dajte javnim audit-ima sa obimom, datumom, nalazima i otklanjanjem problema; reproducibilnim/open client-ima; izveštajima o transparentnosti; i dokumentovanim incidentima.
5. **Protokol i client:** održavani WireGuard, OpenVPN ili drugi pregledani protokol; automatska ažuriranja; DNS i IPv6 rukovanje; kill switch; i leak testovi za svaku platformu.
6. **Poslovni model:** razumite kako se finansira besplatna ili subvencionisana usluga. Prisustvo u app store-u samo po sebi nije dokaz pouzdanog rada.
7. **Kompatibilnost plaćanja:** alternativno plaćanje može smanjiti otkrivanje podataka o naplati VPN-u, ali ne uklanja izvornu IP adresu zabeleženu pri svakoj konekciji.

### Konfigurisanje i provera VPN-a

1. Instalirajte potpisani client provajdera/organizacije iz zvaničnog izvora.
2. Izaberite **full tunnel**, osim ako dokumentovana ruta mora da ga zaobiđe. Split tunneling stvara putanje za korelaciju i leak.
3. Omogućite fail-closed/always-on ponašanje i blokirajte saobraćaj tokom ponovnog povezivanja.
4. Šaljite DNS kroz tunnel i testirajte IPv4 i IPv6. Isključite protokol samo ako ne može bezbedno da se tuneluje i ako je prihvaćen gubitak funkcionalnosti.
5. Testirajte sleep/wake, promenu mreže, captive-portal prijavljivanje, pad tunnel-a i hotspot tethering. NCSC upozorava da tethered client-i na nekim platformama mogu zaobići VPN telefona.<sup>[[2]](#references)</sup>
6. Koristite testni endpoint pod kontrolom organizacije da zabeležite uočeni IPv4, IPv6, DNS resolver i vreme konekcije. Ne izlažite osetljivi engagement nasumičnim sajtovima za „leak test“.
7. Ponovite test nakon promena client-a, OS-a, mreže ili politike.

## Tor Browser: snažnija web nepovezivost

Tor gradi circuit kroz više relay-a tako da nijedan pojedinačni relay obično ne zna i izvor i odredište. Odredište vidi Tor exit umesto korisničke IP adrese; lokalna mreža obično vidi Tor konekciju.<sup>[[3]](#references)</sup> Tor je projektovan za TCP aplikacije sa malom latencijom, pa je sporiji i ne može garantovati zaštitu od napadača koji može da koreliše oba kraja.<sup>[[4]](#references)</sup>

### Bezbedan Tor Browser workflow

1. Preuzmite Tor Browser samo sa Tor Project-a ili zvaničnog mirror-a i, kada je moguće, proverite potpis.
2. Koristite **Tor Browser**, a ne običan browser usmeren na Tor SOCKS port. Obični browser-i mogu da izazovu DNS/WebRTC leak i odaju identifikujuće stanje.<sup>[[5]](#references)</sup>
3. Zadržite podrazumevanu veličinu, fontove, ekstenzije i privacy settings. Dodatni add-on-i mogu učiniti browser jedinstvenijim.<sup>[[6]](#references)</sup>
4. Izaberite nivo bezbednosti **Safer** ili **Safest** kada je prihvatljivo povećano narušavanje funkcionalnosti.
5. Koristite bridge kada je direktni Tor blokiran ili kada bi uobičajene relay IP adrese stvorile neprihvatljivu lokalnu vidljivost. Bridge-ovi otežavaju prepoznavanje; ne uklanjaju traffic analysis.<sup>[[7]](#references)</sup>
6. Ne prijavljujte se na identifikujući nalog, ne unosite identifikujuće podatke i ne otvarajte preuzete aktivne dokumente u eksternoj mrežnoj aplikaciji.
7. Koristite odvojenu sesiju/kontekst za svaki identitet. „New circuit“ nije isto što i brisanje identiteta browsera/aplikacije; koristite **New Identity** ili po potrebi ponovo pokrenite izolovano okruženje.
8. Dajte prednost autentifikovanom HTTPS-u ili autentifikovanom onion service-u. Tor exit može posmatrati nešifrovan HTTP saobraćaj.

### Tor i VPN zajedno

Kombinovanje nije automatski bezbednije. VPN pre Tor-a može sakriti direktne konekcije ka Tor relay-ima od ISP-a, dok VPN vidi izvor; Tor pre VPN-a daje VPN-u stabilan pregled aktivnosti nakon Tor-a i može smanjiti anonymity set. Pogrešna konfiguracija može uvesti leak. Tor Project preporučuje takve kombinacije samo za napredne, eksplicitne threat model-e.<sup>[[8]](#references)</sup>

## Javni i guest Wi-Fi

Savremeni HTTPS znači da pasivni susedi obično ne mogu čitati pravilno šifrovan web sadržaj, ali guest Wi-Fi nije anonimnost. Mesto može beležiti vremena povezivanja, identifikatore uređaja, podatke captive portal-a, odredišta i DHCP detalje; kamere, kupovine, prevoz i fizičko posmatranje mogu identifikovati korisnika. Lažni hotspot sa sličnim nazivom takođe može prikupljati akreditive portala ili manipulisati nešifrovanim saobraćajem.<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. Koristite samo mrežu ponuđenu gostima ili mrežu za koju je vlasnik dao izričitu dozvolu. Od osoblja zatražite tačan SSID i proceduru portala.
2. Ažurirajte endpoint i travel router pre dolaska. Isključite deljenje fajlova/štampača, inbound discovery, auto-join i probing zapamćenih mreža.
3. Omogućite privatnu/randomizovanu Wi-Fi adresu OS-a. Aktuelni Apple sistemi mogu koristiti rotirajuće adrese na otvorenim/slabim mrežama; moderna Android randomizacija je obično trajna po SSID-u. Ovo smanjuje samo jedan lokalni identifikator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Dajte prednost travel router-u pod kontrolom organizacije ili bridge uređaju sa niskim poverenjem između privilegovane radne stanice i guest mreže. Ovo centralizuje firewall/VPN politiku, ali ne skriva router od mesta.<sup>[[12]](#references)</sup>
5. Captive portal završite samo preko određenog uređaja/browsera sa niskim poverenjem. Nikada ne unosite lične ili ponovo korišćene akreditive za navodno anoniman kontekst. Zatvorite browser portala nakon uspostavljanja konekcije.
6. Pokrenite full-tunnel VPN ili Tor pre osetljive aktivnosti i potvrdite fail-closed ponašanje.
7. Zaboravite mrežu nakon upotrebe i pregledajte politiku naloga portala/čuvanja podataka.

{% hint style="danger" %}
Cracking Wi-Fi mreže suseda, zaobilaženje portala, korišćenje procurelih guest akreditiva, kloniranje pristupa drugog gosta ili skrivanje Raspberry Pi-ja u kafiću predstavlja neovlašćenu aktivnost — ne tehniku privatnosti. Bezbedne alternative su zakonita guest mreža, site odobren od klijenta ili dokumentovani drop node postavljen i preuzet uz pisanu saglasnost vlasnika objekta.
{% endhint %}

## Travel router-i

Travel router može izolovati radnu stanicu od neprijateljskih lokalnih broadcast-a, primeniti firewall, obezbediti dosledan interni SSID i automatski ponovo uspostaviti VPN. On **nije** anoniman: upstream vidi njegov radio identitet i vreme saobraćaja, a njegov VPN provajder vidi izvor tunnel-a.

- Koristite podržani OpenWrt/vendor firmware i uklonite nekorišćene servise.
- Administrirajte preko Ethernet-a ili posebnog management SSID-a sa jedinstvenom lozinkom.
- Isključite WAN-side administraciju, UPnP, WPS, deljenje fajlova i neželjeni inbound saobraćaj.
- Koristite randomizovani/private WAN MAC samo tamo gde je podržan i dozvoljen.
- Primenite VPN politiku na router-u, uključujući DNS i IPv6, i blokirajte egress kada tunnel otkaže.
- Ne pretpostavljajte da phone hotspot tuneluje tethered uređaje kroz VPN telefona; testirajte to.

## Cellular, SIM-ovi i eSIM-ovi

Cellular je praktičan, ali nije anoniman. Operateri čuvaju identifikatore pretplatnika/uređaja i lokaciju izvedenu iz povezivanja na mrežu; eSIM je i dalje mobilna pretplata. Prepaid pouzdano ne znači neregistrovan — zahtevi se razlikuju po zemljama i menjaju se.<sup>[[13]](#references)</sup>

Operativno:

- Koristite odvojen, podržan uređaj da biste smanjili izlaganje ličnih podataka, a ne da biste kreirali izmišljenog pretplatnika.
- Ne nosite „odvojeni“ uređaj neprekidno uz lični telefon ako je zajednička lokacija deo threat model-a.
- Isključite nekorišćene cellular, Wi-Fi, Bluetooth i location funkcije; gašenje uređaja predstavlja snažniju radio granicu od UI prekidača.
- Osetljiv saobraćaj usmerite kroz odobrenu VPN/Tor putanju, uz svest da operater i dalje zna lokaciju pretplate/uređaja i endpoint tunnel-a.
- Proverite aktuelna pravila registracije i čuvanja podataka kod nacionalnog regulatora ili lokalnog pravnog savetnika; ne oslanjajte se na online spiskove „anonimnih SIM zemalja“.

## DNS i TLS metapodaci

- **DoH/DoT/DoQ** šifruju DNS između client-a i resolver-a, sprečavajući jednostavno lokalno čitanje ili izmene, ali resolver i dalje vidi upite i transportne identifikatore. Oni pomeraju poverenje; ne obezbeđuju anonimnost.<sup>[[14]](#references)</sup>
- **ODoH** dodaje proxy tako da resolver ne mora saznati IP adresu client-a, pod pretpostavkom da proxy i target ne sarađuju. Traffic analysis je izričito van opsega.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** može zaštititi unutrašnje ime servera u TLS handshake-u kada ga podržavaju client, DNS i server. Odredišna IP adresa, vreme, obim i endpoint ostaju vidljivi.<sup>[[16]](#references)</sup>
- U pravilno konfigurisanim VPN ili Tor okruženjima, DNS treba da prati podržanu putanju tog okruženja. Dodavanje zasebnog resolver-a može stvoriti novog posmatrača ili fingerprint.

### Workflow za proveru Encrypted-DNS/ECH

1. Odlučite da li DNS kontroliše VPN/Tor okruženje, OS ili aplikacija. Konfigurišite ga u **jednom** predviđenom sloju umesto da slažete nepovezane resolver-e.
2. Izaberite resolver na osnovu njegove objavljene privacy/retention politike i omogućite strict encrypted mode tamo gde ga platforma podržava. Opportunistic fallback može neprimetno vratiti saobraćaj na plaintext.
3. Pošaljite upit za jedinstveni subdomain unutar authoritative test zone pod vašom kontrolom; potvrdite da authoritative log vidi predviđeni recursive resolver.
4. Uz ovlašćenje uhvatite samo saobraćaj testnog uređaja. Potvrdite da pristupna mreža ne može čitati plaintext DNS, uz svest da može videti encrypted resolver/tunnel endpoint.
5. Testirajte blokirani/nedostupni encrypted resolver. Uslov prolaza je izabrano fail-closed ili dokumentovano fallback ponašanje — ne slučajni clear query.
6. Za ECH koristite kontrolisani ECH-enabled host i pregledajte client/server dijagnostiku da potvrdite da je **inner** ClientHello prihvaćen. Samo nuđenje HTTPS record-a ne dokazuje da je ECH uspeo.
7. Ponovite test nakon promena mreže, captive portal-a, ažuriranja browsera i VPN reconnect-a. Zabeležite koja komponenta poseduje DNS/ECH kako kasniji administratori ne bi napravili bypass.

## Mixnet-ovi

Mixnet-ovi kao što su Nym ili Katzenpost dodaju pakete fiksne veličine, kašnjenje, promenu redosleda i cover traffic radi otpornosti na timing correlation. Ova svojstva imaju cenu u latenciji i bandwidth-u, a nezavisni dokazi na nivou deployment-a su ograničeni. Trenutne consumer mixnet-ove tretirajte kao **emerging/high-latency options**, a ne kao brže ili garantovane zamene za Tor/VPN-ove.<sup>[[17]](#references)</sup>

### Workflow za procenu

1. Identifikujte održavani client i tačnu podržanu aplikaciju; ne usmeravajte proizvoljan browser/system saobraćaj kroz nedokumentovani proxy.
2. Pročitajte aktuelni threat model za entry, mix node-ove, gateway, odredište i pretpostavke o saradnji.
3. Instalirajte iz zvaničnog potpisanog izvora u odvojenom testnom compartment-u i koristite samo benigni endpoint koji posedujete.
4. Izmerite latenciju isporuke, ograničenja veličine poruka, pouzdanost, retransmisiju i ponašanje kada gateway nije dostupan.
5. Pregledajte lokalni saobraćaj i endpoint koji posedujete kako biste potvrdili predviđenu putanju i izvor. Proverite da li odgovori koriste isti privacy dizajn.
6. Testirajte gašenje/otkazivanje: aplikacija ne sme neprimetno preći na direktan pristup Internetu.
7. Ne isključujte cover traffic, ne smanjujte kašnjenja i ne birajte neuobičajene fiksne rute samo radi brzine; ove izmene mogu poništiti navedeni anonymity model.
8. Držite ga u eksperimentalnom statusu dok konkretni deployment, nezavisna analiza i operativna pouzdanost ne budu u skladu sa nivoom posledica.

## Network preflight checklist

- [ ] Authorization obuhvata pristupnu mrežu, target, datume i source infrastrukturu.
- [ ] Endpoint ne sadrži nepovezane identitete ili aktivne sync sesije.
- [ ] IPv4, IPv6, DNS i reconnect ponašanje odgovaraju planu.
- [ ] Odredište vidi samo očekivani egress.
- [ ] Captive portal i hotspot ponašanje testirani su bez osetljivog saobraćaja.
- [ ] Lokalno deljenje/discovery i automatsko povezivanje na mreže su isključeni.
- [ ] Tabela posmatrača i preostali rizik od traffic correlation su prihvaćeni.
- [ ] Politika provajdera, retention i emergency kontakt su aktuelni.

Za split-knowledge relay-e, route-enforced workload-e, pluggable transport-e, onion service-e, I2P i disposable remote browser-e nastavite na [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Izbor VPN-a koji vam odgovara](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Smernice za bezbednost uređaja: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Zaštite privatnosti i anonimnosti koje Tor pruža](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Kratak uvod u Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Korišćenje Tor-a sa drugim browser-ima](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins i add-on-i u Tor Browser-u](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Deblokiranje Tor-a](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Korišćenje Tor Browser-a sa VPN-om](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Da li su javne Wi-Fi mreže bezbedne?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privatnost sa Apple uređajima](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementacija MAC randomizacije](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principi za bezbedne privilegovane pristupne radne stanice](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Obavezna SIM registracija: perspektive politike i regulative](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Preporuke za operatere DNS Privacy Service-a](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
