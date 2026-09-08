# Napredne arhitekture mrežne privatnosti

Kompleksnost je korisna samo kada uklanja konkretnog posmatrača ili scenario otkaza. Jedinstveni stack tunela, prilagođeni oblik paketa, redak user agent ili infrastruktura koja se često rotira mogu postati jači fingerprint od standardne konfiguracije koju koriste hiljade ljudi.

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) obezbeđuje uobičajenu šemu `Pros`/`Cons`/`Procedure`/`Detection`. Ova stranica proširuje složenije arhitekture i granice poverenja.

Napredni cilj je zato **razdvajanje znanja**: nijedna uobičajena komponenta ne bi trebalo istovremeno da poseduje identitet korisnika, odredište, plaintext i dugoročnu istoriju aktivnosti. Ovo nije nevidljivost, a koluzija, pravni postupak, kompromitovanje endpointa ili end-to-end korelacija saobraćaja i dalje mogu rekonstruisati putanju.

## Izbor arhitekture

| Obrazac | Dobijena osobina | Novo poverenje/otkaz | Pogodna upotreba |
|---|---|---|---|
| Standardni Tor Browser | Zajednički browser fingerprint i putanja kroz više relay-a | Mala latencija omogućava korelaciju saobraćaja | Opšte anonimno pregledanje weba |
| Tor bridge + pluggable transport | Otežava direktno blokiranje/klasifikaciju Tor-a | Bridge/transport i dalje mogu biti detektovani; bridge saznaje izvor | Cenzurisane mreže |
| Onion service | Sakriva IP adresu servisa; izbegava exit; potvrđuje onion identitet | Onion ključ i server endpoint postaju kritična sredstva | Privatno objavljivanje, prijem podataka ili administracija |
| Nezavisni ingress + egress relay-i | Nijedan pojedinačni relay obično ne vidi izvor i odredište | Operateri mogu koludirati; tajming prolazi kroz oba | Aplikacije visokih performansi sa podrškom |
| Oblivious HTTP | Razdvaja izvornu IP adresu od šifrovanog stateless HTTP zahteva | Zahteva podršku aplikacije, relay-a i gateway-a | Telemetrija, upiti, slanja bez stanja sesije |
| VPN-only namespace radnog opterećenja | Kernel nametnut izostanak rute ka clear-network-u | VPN i dalje vidi oba kraja; host/root ostaje pouzdan | Alati za autorizovane angažmane i fiksni egress |
| Disposable remote browser | Odredište je izolovano od lokalnog browsera/endpointa | Workspace provajder vidi aktivnost i identitet za prijavljivanje | Nepouzdani sajtovi/fajlovi i kontrolisano istraživanje |
| Interni I2P servis | Odvojeni inbound/outbound overlay tuneli; nema zvaničnih exit-a | Manji/drugačiji ekosistem; ponašanje peer-ova tokom dužeg vremena | Servisi izvorni za I2P, a ne zamena za običan web |
| Mixnet/asynchronous delivery | Kašnjenje, grupisanje i cover saobraćaj pružaju otpor analizi tajminga | Visoka latencija, ograničene aplikacije i zrelost | Poruke/zadaci kojima nije potrebna interakcija |

## Split-knowledge relay-i

Obrazac relay-a sa dva operatera može nadmašiti single VPN za usku aplikaciju:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay je implementiran primer: Apple upravlja ingress-om, dok drugi content provider upravlja egress-om, tako da nijedan od njih uobičajeno ne vidi i IP adresu klijenta i odredište pregledanja.<sup>[[1]](#references)</sup> Ovo je proizvodno-specifična Safari/DNS privacy usluga, a ne anonymity network za sve uređaje, i namerno čuva grubi region.

Oblivious HTTP (OHTTP) standardizuje uži obrazac na nivou aplikacije. Relay vidi klijenta i šifrovani saobraćaj ka gateway-u; gateway dešifruje HTTP poruku, ali vidi relay, a ne klijenta. RFC 9458 upozorava da su potrebni saradnja relay/gateway strana, da je ovo najbolje koristiti za zahteve bez kolačića/authentication/session state podataka i da traffic analysis nije obuhvaćen garancijama.<sup>[[2]](#references)</sup>

### Kontrolna lista dizajna

1. Definišite tačne poruke aplikacije koje treba zaštititi; nemojte neprimetno proxy-ovati proizvoljne authenticated web sesije.
2. Koristite nezavisno upravljane ingress i egress organizacije sa odvojenom administracijom, credentials podacima, logging-om i pravnom kontrolom gde je moguće.
3. Šifrujte zahtev aplikacije prema gateway-u tako da ingress ne može da ga pročita.
4. Uklonite forwarding headere izvedene iz podataka klijenta, TLS identifikatore i stabilne per-user tokene na odgovarajućem sloju.
5. Izbegavajte jedinstvene ključeve, kolačiće ili payload polja koja omogućavaju gateway-u da ponovo poveže zahteve uprkos razdvajanju transporta.
6. Agregirajte, minimizujte i pravovremeno brišite logove na obe strane; dokumentujte rizik od koluzije i prinudnog otkrivanja podataka.
7. Dodajte padding ili batch-ujte samo prema pregledanom protokolu. Ručno napravljeno oblikovanje saobraćaja može stvoriti jedinstven potpis, a da ne spreči korelaciju.
8. Testirajte pomoću kontrolisanih canary zahteva i uporedite šta svaki od klijenta, ingress-a, gateway-a i target-a beleži.

Za obično interaktivno pregledanje koristite Tor Browser umesto izmišljanja privatnog OHTTP proxy-ja. OHTTP štiti podržanu transakciju aplikacije, a ne kompletan browser identitet.

## Enforce-ujte rutu po workload-u

Kill switch zasnovan samo na promenljivim host rutama može otkazati tokom DHCP obnove, sleep/wake ciklusa, IPv6 promena ili pada tunela. Robusniji Linux obrazac daje container-u ili network namespace-u samo loopback interfejs i tunnel interfejs. WireGuard dokumentuje da interfejs može biti kreiran u fizičkom namespace-u, premešten u workload namespace i da njegov šifrovani UDP socket može ostati u originalnom namespace-u.<sup>[[3]](#references)</sup>

### Obrazac deployment-a

1. Ovo prvo izgradite na disposable/local-console host-u; greške u namespace-u mogu ukloniti remote pristup.
2. Stavite fizički Ethernet/Wi-Fi interfejs i DHCP/supplicant u **physical** namespace.
3. Tamo kreirajte WireGuard interfejs kako bi njegov šifrovani transportni socket imao pristup fizičkoj mreži.
4. Prebacite samo WireGuard interfejs u **workload** namespace i postavite ga kao jedinu default rutu.
5. Dodelite workload-u resolver specifičan za namespace, dostupan samo kroz tunnel. Eksplicitno obuhvatite IPv6.
6. Pokrenite browser/tool container u tom namespace-u bez host networking-a, privileged capability-ja, deljenog browser direktorijuma ili personal credential agent-a.
7. Zaustavite tunnel i proverite da workload ne može da razreši ili uspostavi vezu sa kontrolisanim IPv4 ili IPv6 endpoint-om.
8. Testirajte endpoint roaming, DHCP obnovu, suspend/resume i captive-portal handling izvan workload namespace-a.
9. Zabeležite hash namespace/tunnel konfiguracije i odobrenu egress adresu radi accountability-ja angažmana.

Ovo obezbeđuje **enforcement rute**, a ne anonymity od VPN-a ili engagement bastion-a. Compromised host/root može da pregleda ili promeni namespace-ove.

## Tor bridges i pluggable transports

Bridges su nejavni Tor entry relay-i. Pluggable transports menjaju saobraćaj prvog hop-a tako da je jednostavno blokiranje ili klasifikacija protokola otežana. Oni ne dodaju anonymous relay slojeve nakon ulaska i ne nadjačavaju observer-a sposobnog za širu timing korelaciju.

| Transport | Pristup prvom hop-u | Praktični kompromis |
|---|---|---|
| **obfs4** | Čini da saobraćaj izgleda nasumično i pruža otpor aktivnom probing-u | Poznata bridge adresa i dalje može biti blokirana |
| **Snowflake** | Koristi kratkotrajne volunteer WebRTC proxy-je za pristup bridge-u | Performanse variraju; postoje broker/STUN/WebRTC obrasci |
| **WebTunnel** | Prenosi bridge saobraćaj u HTTPS-like WebSocket tunnel-u | Zavisi od dostupnog web front-a i i dalje može biti klasifikovan |

Tor Project opisuje Snowflake i WebTunnel kao transport-e za zaobilaženje cenzure, a ne kao savršenu neodvojivost od drugih saobraćaja.<sup>[[4]](#references)</sup>

### Bezbedan workflow

1. Počnite sa direktnom vezom Tor Browser-a. Dodajte bridge samo kada blokiranje ili vidljivost u lokalnom observer modelu to opravdavaju.
2. Koristite ugrađene transport-e ili bridge linije dobijene kroz Tor Project kanale. Nemojte preuzimati nasumične transport binary-je ili javne bridge liste sa foruma.
3. Isprobajte najmanje složenu podržanu opciju koja se pouzdano povezuje; zabeležite zašto je izabrana.
4. Tor Browser u ostalom ostavite standardnim. Bridge ne čini custom ekstenzije, prijavljivanje na naloge ili neobična browser podešavanja bezbednim.
5. Testirajte ponovno povezivanje i ispravnost sata. Nemojte uzastopno menjati transport-e na način koji istom lokalnom observer-u šalje prepoznatljiv niz.
6. Ponovo procenite situaciju ako se censor ili network policy promeni; korišćenje samo po sebi može biti osetljivo ili ograničeno na nekim lokacijama.

## Onion services kao privatni rendezvous

Onion service uspostavlja outbound Tor circuits do introduction point-ova i rendezvous relay-a, pa mu nije potreban javni inbound port i ne otkriva IP adresu servera kroz onion protokol. Saobraćaj između klijenta i service-a ostaje unutar Tor-a, a onion adresa autentifikuje service key.<sup>[[5]](#references)</sup>

Za zakonit intake portal, privatni repository, administrativni interfejs ili engagement evidence drop:

1. Pokrenite aplikaciju na namenskom host-u/VM-u i bind-ujte je na loopback ili izolovani Unix socket.
2. Instalirajte Tor iz njegovog zvaničnog repository-ja i pratite zvanično podešavanje v3 onion service-a; nikada ne koristite zastarela v2 uputstva.
3. Zaštitite private key onion service-a kao TLS/signing key. Napravite backup samo ako je potreban stabilan identitet.
4. Dodajte onion-service client authorization za zatvorenu grupu i dostavite credentials kroz nezavisno autentifikovan kanal.<sup>[[6]](#references)</sup>
5. Sprečite origin da preuzima third-party fontove, analytics, updates ili webhooks koji otkrivaju njegov javni IP ili operator account.
6. Authentication i authorization postavite i u samu aplikaciju; posedovanje onion adrese nije access control.
7. Patch-ujte, ograničite rate i nadgledajte service bez ugrađivanja third-party telemetry-ja.
8. Iz zasebnog test konteksta potvrdite da DNS, email, error pages, file metadata i response headers ne otkrivaju origin.
9. Za red-team korišćenje navedite service, owner-a, svrhu i vreme gašenja u ROE. Nemojte ga koristiti za prikrivanje out-of-scope C2.

## Remote browser i disposable workspace

Remote browser premešta rendering i rizičan sadržaj dalje od lokalnog endpoint-a i može da predstavi engagement-specific cloud egress. On štiti lokalni uređaj od određenog sadržaja i persistence-a; ne čini operator-a anonymous u odnosu na workspace provider-a. AWS, na primer, dokumentuje prikupljanje portal, identity, policy, preference i session-log podataka iako se disposable browser instance odbacuje na kraju sesije.<sup>[[7]](#references)</sup>

Koristite po jedan workspace pod kontrolom organizacije za svaki engagement, ograničite downloads/uploads/clipboard, isključite personal identity provider-e, usmerite njegov fiksni egress kroz odobreni bastion i istek workspace-a izvršite nakon export-a dokaza. Konzolu provider-a, IdP i administrator-a tretirajte kao observer-e.

## I2P i internal overlays

I2P gradi odvojene jednosmerne inbound i outbound tunnel-e i nema zvanične exits na nivou mreže; prvenstveno je namenjen service-ima unutar I2P-a.<sup>[[8]](#references)</sup> Nije drop-in brži način za pregledanje javnog Interneta. Outproxy-ji uvode trust point, a zvanični threat model izričito zahteva dodatno istraživanje i ne tvrdi da pruža savršenu anonymity.

I2P koristite samo kada ga oba kraja namerno podržavaju, izolujte njegov dugotrajni router od personal applications i imajte na umu da peers/lokalne mreže mogu posmatrati učešće u I2P-u. Nemojte povećavati broj hop-ova niti podešavati izbor peer-ova bez dokaza: neuobičajena podešavanja mogu smanjiti performanse i anonymity set.

## Operacije otporne na korelaciju

- Dajte prednost uobičajenoj, podržanoj konfiguraciji klijenta u odnosu na jedinstveni build.
- Razdvojite identitete na endpoint-u; nijedna routing topologija ne popravlja account, payment, recovery ili content reuse.
- Za non-interactive tasks dajte prednost pregledanom asynchronous protocol/mixnet-u u odnosu na ručno dodavanje sleep intervala ili lažnog saobraćaja.
- Izbegavajte upravljanje navodno odvojenim identitetima u sinhronizovanom obrascu iz istog fizičkog konteksta.
- Koristite one-way export gate: untrusted content ulazi u disposable renderer; samo pregledan, sanitized rezultat izlazi.
- Održavajte tačnost satova radi protocol security-ja, ali uklonite nepotrebne precizne timestamps iz objavljenih artefakata.
- Svedite trajanje sesije i zastarelu infrastrukturu na minimum bez brze „fast-flux“ rotacije, koja je upadljiva i narušava accountability.

## Tehnike koje ne mogu koristiti nepovezane third party-je

Ovo su stvarne adversary tehnike, a ne imaginarne ili nevažne. Njihova mehanika i detekcija obrađene su u [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) i [APT case studies](government-and-apt-case-studies.md). Tokom autorizovane vežbe reprodukujte njihovo uočljivo ponašanje pomoću substitutes pod vašom kontrolom:

- modelujte residential/mobile exit churn pomoću kontrolisanih relay pool-ova, nikada pomoću marketa sa nejasnim consent-om;
- modelujte open proxy-je, compromised router-e i botnet-e pomoću VM-ova/router-a pod vašom kontrolom;
- modelujte ukradene cloud naloge pomoću određenog exercise tenant-a i synthetic victim identity-ja;
- modelujte domain fronting na reverse proxy-ju pod vašom kontrolom, a ne preko CDN-a koji nije pristao;
- modelujte third-party Wi-Fi pomoću dva izolovana AP-a u vlasništvu laboratorije;
- custom encryption, multi-VPN chains i identifier rotation tretirajte kao test hipoteze čiji flow, account i endpoint artefakti ostaju detektabilni.

Za autorizovani red team, svaki pokušaj da se saobraćaj učini manje prepoznatljivim mora biti eksplicitan detection objective u ROE-u, imati attribution map koju čuva controller i uključivati stop/deconfliction mehanizam.

## Matrica verifikacije

| Test | Očekivani rezultat | Neuspeh znači |
|---|---|---|
| Tunnel/bridge zaustavljen | Workload nema direktan IPv4/IPv6/DNS path | Route enforcement je nepotpun |
| Target log pregledan | Pojavljuje se samo planirani egress/application identity | Header, route ili account leak |
| Ingress log pregledan | Source je prisutan; jasan target/request nije | Trust split je neuspešan na ingress-u |
| Egress log pregledan | Relay/request je prisutan; source identity nije | Trust split je neuspešan na egress-u |
| Onion origin eksterno skeniran | Nijedna javna origin service nije dostupna/povezana | Origin je leak-ovan ili je dual-homed |
| Disposable sesija završena | Stanje instance je uklonjeno; odobreni dokazi su zasebno sačuvani | Persistence granica je neuspešna |
| Controller lookup izvršen | Aktivnost se pravovremeno povezuje sa engagement/operator-om | Red-team accountability je neuspešan |

## References

- [1] [Apple Platform Security — iCloud Private Relay bezbednost](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing i Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake i pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Kako Onion Services rade](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Napredna podešavanja Onion Service-a i client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Šifrovanje podataka u Amazon WorkSpaces Secure Browser-u](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
