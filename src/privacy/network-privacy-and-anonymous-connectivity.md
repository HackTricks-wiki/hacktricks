# Privatnost mreže i anonimna povezanost

{{#include ../banners/hacktricks-training.md}}

Privatnost mreže je odluka o rutiranju, a ne potpuni identitet. Putanju izaberite tako što ćete se zapitati ko ne bi trebalo da može da poveže **izvor**, **odredište**, **sadržaj** i **vreme**.

Za standardizovani pregled — `Pros`, `Cons`, korak-po-korak `Procedure` i `Detection` za svaku porodicu pristupnih putanja — počnite od [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Ova stranica proširuje najčešće primenljive opcije.

## Šta svaki posmatrač obično može da vidi

| Putanja | Lokalna mreža / ISP | Posrednik | Odredište | Glavno ograničenje | Relativna brzina |
|---|---|---|---|---|---|
| Direct HTTPS | Izvor, metapodaci odredišta, vreme/obim | Hosting/CDN vidi konekciju | Izvorna IP adresa, podaci browsera/aplikacije | Nema privatnosti izvorne IP adrese | Najbrža |
| Commercial VPN | Izvor povezan sa VPN-om; ne i uobičajeni metapodaci odredišta | VPN vidi metapodatke izvora i odredišta | Izlazna IP adresa VPN-a | Jedan provajder postaje tačka korelacije | Obično brza |
| Self-hosted VPN/VPS | Izvor povezan sa VPS-om | Host/account/payment/control-plane logovi | Izlazna IP adresa VPS-a | Lako povezivanje sa iznajmljenim serverom/account-om | Obično brza |
| Tor Browser | Izvor povezan sa Tor-om/bridge-om; vreme/obim | Svaki relay vidi ograničeni deo | Tor exit, podaci browsera | Sporiji; rizici account-a/endpoint-a/korelacije | Umerena/spora |
| Tails/Whonix | Slična Tor putanja, sa jačim granicama rutiranja | Ista Tor ograničenja | Tor exit/podaci aplikacije | Operativne greške i host/hardware ostaju | Umerena/spora |
| Public guest Wi-Fi + HTTPS | Lokacija vidi lokalni uređaj/vreme i odredišta | ISP lokacije vidi metapodatke | Javna IP adresa gosta | Fizička/kaptive-portal/device korelacija | Brza/promenljiva |
| Cellular hotspot | Operator vidi pretplatnika/uređaj/lokaciju i odredišta | VPN/Tor ako se koristi | Carrier, VPN ili Tor izlazna IP adresa | Mobilna pretplata i lokacija su trajni identifikatori | Brza/promenljiva |
| Mixnet | Pristup vidi korišćenje mixnet-a; vreme/obim | Više mixing čvorova | Gateway/egress | Ekosistem u razvoju; cena u kašnjenju i bandwidth-u | Najsporija |

HTTPS štiti sadržaj tokom prenosa, ali ne i sve metapodatke. EFF navodi da domen, vreme i veličina saobraćaja mogu ostati vidljivi posrednicima čak i kada su putanje stranica, credential-i i poruke šifrovani.<sup>[[1]](#references)</sup>

## VPN-ovi: brza privatnost sa koncentrisanim poverenjem

VPN je koristan za skrivanje metapodataka odredišta od pristupnog ISP-a, zaštitu prvog hop-a na nepouzdanoj mreži, predstavljanje stabilne engagement egress adrese ili pristup privatnoj mreži. On **ne** čini korisnika anonimnim. VPN vidi izvornu konekciju i može da posmatra metapodatke odredišta; account-i, cookies, GPS, fingerprints i payment informacije ostaju.<sup>[[1]](#references)</sup>

### Kontrolna lista za procenu provajdera

1. **Vlasništvo i jurisdikcija:** identifikujte pravno lice, matičnu kompaniju, zemlje poslovanja, podugovarače infrastrukture i primenljive pravne procedure.
2. **Prikupljeni podaci:** razlikujte account/billing, source IP, vremenske oznake konekcija, bandwidth, crash telemetry, DNS queries i destination logs. „No browsing logs” ne znači „no data”.
3. **Čuvanje i brisanje:** pronađite precizna trajanja i proverite da li backups, fraud systems i processors prate isti raspored.
4. **Dokazi:** prednost dajte javnim auditima sa obimom, datumom, nalazima i otklanjanjem problema; reproducible/open clients; transparency reports; i dokumentovanim incidentima.
5. **Protokol i client:** održavani WireGuard, OpenVPN ili drugi provereni protokol; automatska ažuriranja; DNS i IPv6 rukovanje; kill switch; i leak testovi za svaku platformu.
6. **Poslovni model:** razumite kako se finansira besplatna ili subvencionisana usluga. Samo prisustvo u app store-u nije dokaz pouzdanog rada.
7. **Payment prikladnost:** alternativni payment može da smanji otkrivanje billing podataka VPN-u, ali ne briše source IP koji se beleži pri svakoj konekciji.

### Konfigurisanje i proveravanje VPN-a

1. Instalirajte potpisani client provajdera/organizacije iz njegovog zvaničnog izvora.
2. Izaberite **full tunnel** osim ako dokumentovana ruta mora da ga zaobiđe. Split tunneling stvara putanje za korelaciju i leak.
3. Omogućite fail-closed/always-on ponašanje i blokirajte saobraćaj tokom ponovnog povezivanja.
4. Šaljite DNS kroz tunnel i testirajte IPv4 i IPv6. Onemogućite protokol samo ako se ne može bezbedno tunelovati i ako je prihvaćen gubitak funkcionalnosti.
5. Testirajte sleep/wake, promenu mreže, captive-portal login, pad tunnel-a i hotspot tethering. NCSC upozorava da tethered clients na nekim platformama mogu zaobići VPN telefona.<sup>[[2]](#references)</sup>
6. Koristite endpoint za testiranje pod kontrolom organizacije da zabeležite uočene IPv4, IPv6, DNS resolver i vreme konekcije. Ne izlažite osetljivi engagement nasumičnim „leak test” sajtovima.
7. Ponovite test nakon promena client-a, OS-a, mreže ili policy-ja.

## Tor Browser: jača web unlinkability

Tor gradi circuit kroz više relay-a tako da nijedan pojedinačni relay obično ne zna istovremeno izvor i odredište. Odredište vidi Tor exit umesto korisničke IP adrese; lokalna mreža obično vidi Tor konekciju.<sup>[[3]](#references)</sup> Tor je projektovan za TCP aplikacije sa malim kašnjenjem, pa je sporiji i ne može garantovati zaštitu od adversary-ja koji može da koreliše oba kraja.<sup>[[4]](#references)</sup>

### Bezbedan Tor Browser workflow

1. Preuzmite Tor Browser samo sa Tor Project-a ili zvaničnog mirror-a i proverite signature kada je moguće.
2. Koristite **Tor Browser**, a ne običan browser usmeren na Tor SOCKS port. Obični browser-i mogu da izazovu DNS/WebRTC leak i otkriju identifying state.<sup>[[5]](#references)</sup>
3. Zadržite podrazumevanu veličinu, fonts, extensions i privacy settings. Dodatni add-ons mogu učiniti browser jedinstvenijim.<sup>[[6]](#references)</sup>
4. Izaberite nivo bezbednosti **Safer** ili **Safest** kada je prihvatljivo povećano narušavanje funkcionalnosti.
5. Koristite bridge kada je direktan Tor blokiran ili kada bi obične relay IP adrese stvorile neprihvatljivu lokalnu vidljivost. Bridges otežavaju jednostavno prepoznavanje; ne uklanjaju traffic analysis.<sup>[[7]](#references)</sup>
6. Ne prijavljujte se na identifying account, ne pružajte identifying information i ne otvarajte preuzete aktivne dokumente u eksternoj umreženoj aplikaciji.
7. Koristite odvojenu session/context za svaki identity. „New circuit” nije isto što i brisanje browser/application identity; koristite **New Identity** ili ponovo pokrenite izolovano okruženje prema potrebi.
8. Prednost dajte authenticated HTTPS-u ili authenticated onion service-u. Tor exit može da posmatra nešifrovan HTTP saobraćaj.

### Tor i VPN zajedno

Njihovo kombinovanje nije automatski bezbednije. VPN pre Tor-a može sakriti direktne Tor relay konekcije od ISP-a, dok VPN vidi izvor; Tor pre VPN-a daje VPN-u stabilan prikaz aktivnosti nakon Tor-a i može smanjiti anonymity set. Pogrešna konfiguracija može uvesti leak. Tor Project preporučuje takve kombinacije samo za napredne, eksplicitne threat model-e.<sup>[[8]](#references)</sup>

## Javni i guest Wi-Fi

Moderni HTTPS znači da pasivni susedi obično ne mogu da čitaju pravilno šifrovan web sadržaj, ali guest Wi-Fi nije anonimnost. Lokacija može beležiti vremena povezivanja, identifikatore uređaja, podatke captive portal-a, odredišta i DHCP detalje; kamere, kupovine, prevoz i fizičko posmatranje mogu identifikovati korisnika. Lažna hotspot mreža sa sličnim nazivom takođe može prikupiti portal credentials ili manipulisati nešifrovanim saobraćajem.<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. Koristite samo mrežu ponuđenu gostima ili mrežu za koju je vlasnik dao izričitu dozvolu. Pitajte osoblje za tačan SSID i proceduru portal-a.
2. Ažurirajte endpoint i travel router pre dolaska. Onemogućite file/printer sharing, inbound discovery, auto-join i probing zapamćenih mreža.
3. Omogućite privatnu/randomized Wi-Fi adresu OS-a. Aktuelni Apple sistemi mogu koristiti rotirajuće adrese na otvorenim/slabim mrežama; moderni Android randomization je obično trajan po SSID-u. Ovo smanjuje samo jedan lokalni identifikator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Prednost dajte organization-controlled travel router-u ili low-trust bridge uređaju između privileged workstation-a i guest mreže. Ovo centralizuje firewall/VPN policy, ali ne skriva router od lokacije.<sup>[[12]](#references)</sup>
5. Captive portal završite samo kroz određeni low-trust uređaj/browser. Nikada ne unosite lične ili ponovo korišćene credentials za navodno anoniman context. Zatvorite portal browser nakon uspostavljanja konekcije.
6. Pokrenite full-tunnel VPN ili Tor pre osetljive aktivnosti i potvrdite fail-closed ponašanje.
7. Zaboravite mrežu nakon korišćenja i pregledajte policy portal account-a/čuvanja podataka.

{% hint style="danger" %}
Cracking Wi-Fi mreže suseda, zaobilaženje portal-a, korišćenje leaked guest credentials, kloniranje pristupa drugog gosta ili skrivanje Raspberry Pi-ja u kafiću predstavljaju neovlašćenu aktivnost — ne tehniku privatnosti. Bezbedne alternative su lawful guest network, client-approved site ili dokumentovani drop node postavljen i preuzet uz pisanu saglasnost vlasnika objekta.
{% endhint %}

## Travel router-i

Travel router može izolovati workstation od hostile local broadcasts, primeniti firewall, obezbediti dosledan interni SSID i automatski ponovo uspostaviti VPN. On **nije** anoniman: upstream vidi njegov radio identity i vreme saobraćaja, a VPN provajder vidi izvor tunnel-a.

- Koristite podržani OpenWrt/vendor firmware i uklonite nekorišćene servise.
- Administrirajte preko Ethernet-a ili posebnog management SSID-a sa jedinstvenom lozinkom.
- Onemogućite WAN-side administration, UPnP, WPS, file sharing i unsolicited inbound traffic.
- Koristite randomized/private WAN MAC samo kada je podržan i dozvoljen.
- Primenite VPN policy na router-u, uključujući DNS i IPv6, i blokirajte egress kada tunnel otkaže.
- Ne pretpostavljajte da phone hotspot tuneluje tethered devices kroz VPN telefona; testirajte to.

## Cellular, SIM-ovi i eSIM-ovi

Cellular je praktičan, ali nije anoniman. Operator održava subscriber/device identifiers i lokaciju izvedenu iz priključenja na mrežu; eSIM je i dalje mobilna pretplata. Prepaid pouzdano ne znači neregistrovano — zahtevi se razlikuju po državama i menjaju se.<sup>[[13]](#references)</sup>

Operativno:

- Koristite odvojen, podržan uređaj da smanjite izlaganje ličnih podataka, a ne da kreirate izmišljenog pretplatnika.
- Ne nosite „odvojen” uređaj neprekidno zajedno sa ličnim telefonom ako je co-location deo threat model-a.
- Onemogućite nekorišćene cellular, Wi-Fi, Bluetooth i location access funkcije; isključivanje napajanja predstavlja jaču radio granicu od UI toggle-a.
- Osetljiv saobraćaj stavite u odobreni VPN/Tor path, uz svest da carrier i dalje zna subscription/device lokaciju i tunnel endpoint.
- Proverite aktuelna pravila registracije i čuvanja podataka kod nacionalnog regulatora ili lokalnog pravnog savetnika; ne oslanjajte se na online liste „anonymous SIM countries”.

## DNS i TLS metapodaci

- **DoH/DoT/DoQ** šifruju DNS između client-a i resolver-a, sprečavajući jednostavno lokalno čitanje ili izmenu, ali resolver i dalje vidi queries i transport identifiers. Oni pomeraju poverenje; ne pružaju anonimnost.<sup>[[14]](#references)</sup>
- **ODoH** dodaje proxy tako da resolver ne mora da sazna client IP, pod pretpostavkom da proxy i target ne sarađuju. Traffic analysis je izričito van obima.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** može zaštititi unutrašnje ime servera u TLS handshake-u kada ga podržavaju client, DNS i server. Destination IP, vreme, obim i endpoint ostaju vidljivi.<sup>[[16]](#references)</sup>
- U pravilno konfigurisanim VPN ili Tor okruženjima, DNS treba da prati podržanu rutu tog okruženja. Dodavanje odvojenog resolver-a može stvoriti novog posmatrača ili fingerprint.

### Encrypted-DNS/ECH verification workflow

1. Odredite da li DNS kontroliše VPN/Tor environment, OS ili aplikacija. Konfigurišite ga u **jednom** predviđenom sloju umesto kombinovanja nepovezanih resolver-a.
2. Izaberite resolver na osnovu njegove objavljene privacy/retention policy i omogućite strict encrypted mode tamo gde ga platforma podržava. Opportunistic fallback može neprimetno vratiti plaintext.
3. Pošaljite query ka jedinstvenom subdomain-u u authoritative test zone-u pod vašom kontrolom; potvrdite da authoritative log vidi predviđeni recursive resolver.
4. Snimite samo saobraćaj testnog uređaja uz ovlašćenje. Potvrdite da pristupna mreža ne može da čita plaintext DNS, uz svest da može videti encrypted resolver/tunnel endpoint.
5. Testirajte blokirani/nedostupni encrypted resolver. Uslov prolaska je izabrano fail-closed ili dokumentovano fallback ponašanje — ne slučajan clear query.
6. Za ECH koristite kontrolisani ECH-enabled host i pregledajte client/server diagnostics da potvrdite da je **inner** ClientHello prihvaćen. Samo nuđenje HTTPS record-a ne dokazuje da je ECH uspeo.
7. Ponovite test nakon promena mreže, captive portal-a, ažuriranja browser-a i VPN reconnect-a. Zabeležite koja komponenta poseduje DNS/ECH da kasniji administratori ne bi napravili bypass.

## Mixnet-ovi

Mixnet-ovi kao što su Nym ili Katzenpost dodaju pakete fiksne veličine, kašnjenje, promenu redosleda i cover traffic radi otpornosti na timing correlation. Ove osobine imaju cenu u kašnjenju i bandwidth-u, a nezavisni dokazi na skali primene su ograničeni. Trenutne consumer mixnet-ove tretirajte kao **emerging/high-latency options**, a ne kao brže ili garantovane zamene za Tor/VPN.<sup>[[17]](#references)</sup>

### Evaluation workflow

1. Identifikujte održavani client i tačno podržanu aplikaciju; ne usmeravajte proizvoljan browser/system traffic kroz nedokumentovani proxy.
2. Pročitajte aktuelni threat model za entry, mix nodes, gateway, destination i pretpostavke o collusion-u.
3. Instalirajte iz zvaničnog signed source-a u odvojenom test compartment-u i koristite samo benigni owned endpoint.
4. Izmerite delivery latency, ograničenja veličine poruka, pouzdanost, retransmission i ponašanje kada gateway nije dostupan.
5. Pregledajte lokalni saobraćaj i owned endpoint da potvrdite predviđenu putanju i izvor. Proverite da li replies koriste isti privacy design.
6. Testirajte shutdown/failure: aplikacija ne sme neprimetno da pređe na direktan Internet pristup.
7. Ne onemogućavajte cover traffic, ne smanjujte kašnjenja i ne birajte neobične fixed routes samo radi brzine; ove promene mogu poništiti navedeni anonymity model.
8. Ostavite sistem eksperimentalnim dok konkretna primena, nezavisna analiza i operativna pouzdanost ne dostignu nivo posledica.

## Network preflight checklist

- [ ] Authorization obuhvata pristupnu mrežu, target, datume i source infrastructure.
- [ ] Endpoint ne sadrži nepovezane identitete ili aktivne sync sessions.
- [ ] IPv4, IPv6, DNS i reconnect ponašanje odgovaraju planu.
- [ ] Destination vidi samo očekivani egress.
- [ ] Captive portal i hotspot ponašanje testirani su bez osetljivog saobraćaja.
- [ ] Local sharing/discovery i automatsko pridruživanje mrežama su onemogućeni.
- [ ] Observer table i preostali rizik traffic correlation-a su prihvaćeni.
- [ ] Provider policy, retention i emergency contact su ažurni.

Za split-knowledge relay-e, route-enforced workloads, pluggable transports, onion services, I2P i disposable remote browser-e, nastavite na [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Izbor odgovarajućeg VPN-a](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Smernice za bezbednost uređaja: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Zaštita privatnosti i anonimnosti koju Tor pruža](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Kratak uvod u Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Korišćenje Tor-a sa drugim browser-ima](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins i add-ons u Tor Browser-u](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Deblokiranje Tor-a](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Korišćenje Tor Browser-a sa VPN-om](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Da li su javne Wi-Fi mreže bezbedne?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privatnost sa Apple uređajima](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementacija MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principi za bezbedne Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Obavezna SIM registracija: policy i regulatorne perspektive](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Preporuke za operatore DNS Privacy Service-a](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
