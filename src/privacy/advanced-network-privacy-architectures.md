# Napredne arhitekture mrežne privatnosti

{{#include ../banners/hacktricks-training.md}}

Složenost je korisna samo kada uklanja konkretnog posmatrača ili režim otkaza. Jedinstveni tunnel stack, prilagođeni oblik paketa, redak user agent ili infrastruktura koja se često rotira mogu postati jači fingerprint od standardne konfiguracije koju koristi na hiljade ljudi.

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) obezbeđuje uobičajenu šemu `Pros`/`Cons`/`Procedure`/`Detection`. Ova stranica proširuje složenije arhitekture i granice poverenja.

Napredni cilj je zato **razdvajanje znanja**: nijedna uobičajena komponenta ne bi trebalo istovremeno da poseduje identitet korisnika, odredište, plaintext i dugoročnu istoriju aktivnosti. Ovo nije nevidljivost, a koluzija, pravni postupak, kompromitovanje endpointa ili end-to-end korelacija saobraćaja i dalje mogu rekonstruisati putanju.

## Izbor arhitekture

| Obrazac | Dobijeno svojstvo | Novo poverenje/otkaz | Pogodna upotreba |
|---|---|---|---|
| Standardni Tor Browser | Zajednički browser fingerprint i putanja kroz više relay-a | Mala latencija omogućava korelaciju saobraćaja | Opšte anonimno pregledanje weba |
| Tor bridge + pluggable transport | Otežava direktno blokiranje/klasifikaciju Tor-a | Bridge/transport se i dalje može detektovati; bridge saznaje izvor | Cenzurisane mreže |
| Onion service | Sakriva IP adresu servisa; izbegava exit; autentifikuje onion identitet | Onion ključ i server endpoint postaju kritična sredstva | Privatno objavljivanje, prijem ili administracija |
| Nezavisni ingress + egress relay-i | Nijedan pojedinačni relay obično ne vidi izvor i odredište | Operateri mogu koludirati; timing prolazi kroz oba | Podržane aplikacije visokih performansi |
| Oblivious HTTP | Razdvaja izvornu IP adresu od šifrovanog stateless HTTP zahteva | Zahteva podršku aplikacije, relay-a i gateway-a | Telemetrija, upiti, slanja bez stanja sesije |
| Namespace workload-a koji koristi samo VPN | Kernel primenom obezbeđeno odsustvo rute ka čistoj mreži | VPN i dalje vidi oba kraja; host/root i dalje ostaju pouzdani | Alati za autorizovane angažmane i fiksni egress |
| Disposable remote browser | Odredište je izolovano od lokalnog browser-a/endpointa | Workspace provajder vidi aktivnost i identitet za prijavljivanje | Nepouzdani sajtovi/fajlovi i kontrolisano istraživanje |
| Interni I2P service | Odvojeni inbound/outbound overlay tunnel-i; nema zvaničnih exit-a | Manji/drugačiji ecosystem; ponašanje peer-ova tokom dugog rada | Servisi izvorni za I2P, ne zamena za običan web |
| Mixnet/asynchronous delivery | Kašnjenje, grupisanje i cover saobraćaj pružaju otpor timing analizi | Velika latencija, ograničene aplikacije i zrelost | Poruke/zadaci kojima nije potrebna interakcija |

## Relay-i sa podeljenim znanjem

Obrazac sa relay-ima kojima upravljaju dva operatera može biti bolji od jednog VPN-a za usku aplikaciju:
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
Apple Private Relay je primer u produkciji: Apple upravlja ingress-om, dok drugi content provider upravlja egress-om, tako da nijedan od njih obično ne vidi istovremeno i IP adresu klijenta i odredište browsinga.<sup>[[1]](#references)</sup> Ovo je product-specific Safari/DNS privacy service, a ne anonymity network za sve uređaje, i namerno zadržava grubi region.

Oblivious HTTP (OHTTP) standardizuje uži application pattern. Relay vidi klijenta i enkriptovani saobraćaj ka gateway-u; gateway dekriptuje HTTP poruku, ali vidi relay, a ne klijenta. RFC 9458 upozorava da su potrebni willing relay/gateway support, da je ovo najbolje za zahteve bez cookies/authentication/session state podataka i da traffic analysis nije obuhvaćen garancijama.<sup>[[2]](#references)</sup>

### Kontrolna lista za dizajn

1. Definišite tačne application poruke koje treba zaštititi; nemojte neprimetno proxy-jevati proizvoljne authenticated web sessions.
2. Koristite nezavisno operisane ingress i egress organizacije sa odvojenim administration, credentials, logging i legal control procesima, gde je moguće.
3. Enkriptujte application request ka gateway-u tako da ingress ne može da ga pročita.
4. Uklonite client-derived forwarding headers, TLS identifiers i stabilne per-user tokene na odgovarajućem sloju.
5. Izbegavajte jedinstvene keys, cookies ili payload fields koji omogućavaju gateway-u da ponovo poveže zahteve uprkos transport separation-u.
6. Agregirajte, minimizujte i ističite logs na obe strane; dokumentujte collusion i compelled-disclosure rizik.
7. Padujte ili batch-ujte samo u skladu sa reviewed protocol-om. Ručno napravljeno traffic shaping može stvoriti jedinstven signature, a da ne spreči correlation.
8. Testirajte pomoću kontrolisanih canary requests i uporedite šta svaki od client-a, ingress-a, gateway-a i target-a beleži.

Za uobičajeni interactive browsing koristite Tor Browser umesto izmišljanja privatnog OHTTP proxy-ja. OHTTP štiti podržanu application transaction, a ne kompletan browser identity.

## Enforce-ujte route po workload-u

Kill switch zasnovan samo na promenljivim host routes može otkazati tokom DHCP renewal-a, sleep/wake ciklusa, IPv6 promena ili pada tunnel-a. Robusniji Linux pattern daje container-u ili network namespace-u samo loopback interface i tunnel interface. WireGuard dokumentuje da interface može biti kreiran u physical namespace-u, premešten u workload namespace i zadržati svoj enkriptovani UDP socket u originalnom namespace-u.<sup>[[3]](#references)</sup>

### Deployment pattern

1. Prvo ovo izgradite na disposable/local-console host-u; greške u namespace-u mogu ukloniti remote access.
2. Stavite physical Ethernet/Wi-Fi interface i DHCP/supplicant u **physical** namespace.
3. Tamo kreirajte WireGuard interface, tako da njegov encrypted transport socket ima pristup fizičkoj mreži.
4. Prebacite samo WireGuard interface u **workload** namespace i postavite ga kao jedinu default route.
5. Dajte workload-u namespace-specific resolver koji je dostupan samo kroz tunnel. Eksplicitno obuhvatite IPv6.
6. Pokrenite browser/tool container u tom namespace-u bez host networking-a, privileged capability-ja, shared browser directory-ja ili personal credential agent-a.
7. Zaustavite tunnel i proverite da workload ne može da razreši ili uspostavi vezu sa kontrolisanim IPv4 ili IPv6 endpoint-om.
8. Testirajte endpoint roaming, DHCP renewal, suspend/resume i captive-portal handling izvan workload namespace-a.
9. Zabeležite namespace/tunnel configuration hash i odobrenu egress adresu radi engagement accountability-ja.

Ovo obezbeđuje **route enforcement**, a ne anonymity od VPN-a ili engagement bastion-a. Kompromitovani host/root može pregledati ili izmeniti namespace-ove.

## Tor bridges i pluggable transports

Bridges su nejavni Tor entry relays. Pluggable transports menjaju saobraćaj prvog hop-a tako da je jednostavno blocking ili protocol classification teže. Oni ne dodaju anonymous relay layers nakon entry-ja i ne sprečavaju observer-a sposobnog za širu timing correlation.

| Transport | Pristup prvom hop-u | Praktičan kompromis |
|---|---|---|
| **obfs4** | Čini da saobraćaj izgleda nasumično i pruža otpor active probing-u | Poznata bridge adresa i dalje može biti blokirana |
| **Snowflake** | Koristi kratkotrajne volunteer WebRTC proxies za pristup bridge-u | Performanse variraju; postoje broker/STUN/WebRTC patterns |
| **WebTunnel** | Prenosi bridge saobraćaj kroz HTTPS-like WebSocket tunnel | Zavisi od dostupnog web front-a i i dalje može biti klasifikovan |

Tor Project opisuje Snowflake i WebTunnel kao censorship-circumvention transports, a ne kao savršenu indistinguishability.<sup>[[4]](#references)</sup>

### Bezbedan workflow

1. Počnite sa direktnom vezom Tor Browser-a. Dodajte bridge samo kada blocking ili visibility u lokalnom observer modelu to opravdavaju.
2. Koristite ugrađene transports ili bridge lines dobijene kroz Tor Project kanale. Ne preuzimajte nasumične transport binaries ili javne bridge lists sa foruma.
3. Isprobajte najmanje složenu podržanu opciju koja se pouzdano povezuje; zabeležite razlog izbora.
4. Tor Browser inače ostavite standardnim. Bridge ne čini custom extensions, account logins ili neobična browser settings bezbednim.
5. Testirajte reconnect i ispravnost clock-a. Nemojte uzastopno menjati transports na način koji istom lokalnom observer-u šalje prepoznatljivu sekvencu.
6. Ponovo procenite situaciju ako se censor ili network policy promene; korišćenje samo po sebi može biti osetljivo ili ograničeno na nekim lokacijama.

## Onion services kao privatni rendezvous

Onion service uspostavlja outbound Tor circuits ka introduction points i rendezvous relays, tako da mu nije potreban javni inbound port i ne otkriva IP adresu servera kroz onion protocol. Saobraćaj između klijenta i service-a ostaje unutar Tor-a, a onion address autentifikuje service key.<sup>[[5]](#references)</sup>

Za lawful intake portal, private repository, administrative interface ili engagement evidence drop:

1. Pokrenite application na dedicated host/VM-u i bind-ujte ga na loopback ili izolovani Unix socket.
2. Instalirajte Tor iz njegovog official repository-ja i pratite official v3 onion-service setup; nikada ne koristite zastarela v2 uputstva.
3. Zaštitite onion service private key kao TLS/signing key. Napravite backup samo ako je potreban stabilan identity.
4. Dodajte onion-service client authorization za zatvorenu grupu i dostavite credentials kroz nezavisno autentifikovan channel.<sup>[[6]](#references)</sup>
5. Sprečite da origin preuzima third-party fonts, analytics, updates ili webhooks koji otkrivaju njegov public IP ili operator account.
6. Authentication i authorization postavite i u application; posedovanje onion address-a nije access control.
7. Patch-ujte, rate-limit-ujte i nadzirite service bez ugrađivanja third-party telemetry-ja.
8. Iz zasebnog test context-a potvrdite da DNS, email, error pages, file metadata i response headers ne otkrivaju origin.
9. Za red-team upotrebu navedite service, owner-a, purpose i shutdown time u ROE-u. Nemojte ga koristiti za skrivanje out-of-scope C2.

## Remote browser i disposable workspace

Remote browser premešta rendering i rizičan sadržaj dalje od lokalnog endpoint-a i može obezbediti engagement-specific cloud egress. On štiti lokalni uređaj od određenog sadržaja i persistence-a; ne čini operator-a anonymous prema workspace provider-u. AWS, na primer, dokumentuje prikupljanje portal, identity, policy, preference i session-log podataka čak i kada se disposable browser instance odbacuje na kraju session-a.<sup>[[7]](#references)</sup>

Koristite po jedan organization-controlled workspace za svaki engagement, ograničite downloads/uploads/clipboard, onemogućite personal identity providers, pošaljite njegov fixed egress kroz odobreni bastion i isteknite workspace nakon export-a dokaza. Provider console, IdP i administrator tretirajte kao observers.

## I2P i internal overlays

I2P gradi odvojene unidirectional inbound i outbound tunnels i nema official network-layer exits; prvenstveno je namenjen services unutar I2P-a.<sup>[[8]](#references)</sup> Nije drop-in brži način za browsing javnog Interneta. Outproxies uvode trust point, a official threat model izričito zahteva dodatno istraživanje i ne tvrdi da pruža savršenu anonymity.

I2P koristite samo kada ga obe strane namerno podržavaju, izolujte njegov long-lived router od personal applications i shvatite da peers/local networks mogu posmatrati I2P participation. Nemojte povećavati hop counts ili podešavati peer selection bez dokaza: neuobičajena podešavanja mogu smanjiti performanse i anonymity set.

## Operations otporne na correlation

- Dajte prednost uobičajenoj, podržanoj client configuration umesto jedinstvenog build-a.
- Razdvojite identities na endpoint-u; nijedna routing topology ne popravlja account, payment, recovery ili content reuse.
- Za non-interactive tasks dajte prednost reviewed asynchronous protocol/mixnet-u u odnosu na ručno dodavanje sleeps ili fake traffic-a.
- Izbegavajte upravljanje navodno odvojenim identities u sinhronizovanom obrascu iz istog fizičkog context-a.
- Koristite one-way export gate: untrusted content ulazi u disposable renderer; samo reviewed, sanitized result izlazi.
- Održavajte tačne clocks radi protocol security-ja, ali uklonite nepotrebne precizne timestamps iz objavljenih artifacts.
- Minimizujte trajanje session-a i zastarelu infrastrukturu bez brze “fast-flux” rotacije, koja je upadljiva i narušava accountability.

## Techniques koje ne mogu koristiti nepovezane third parties

Ovo su stvarne adversary techniques, a ne imaginarne ili nevažne tehnike. Njihova mehanika i detekcija obrađene su u [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) i [APT case studies](government-and-apt-case-studies.md). Tokom authorized exercise-a reprodukujte njihovo observable behavior pomoću substitutes u vašem vlasništvu:

- modelujte residential/mobile exit churn pomoću kontrolisanih relay pools, nikada marketa sa nejasnim consent-om;
- modelujte open proxies, compromised routers i botnets pomoću owned VMs/routers;
- modelujte stolen cloud accounts pomoću designated exercise tenant-a i synthetic victim identity-ja;
- modelujte domain fronting na owned reverse proxy-ju umesto na unwilling CDN-u;
- modelujte third-party Wi-Fi pomoću dva isolated AP-a u vlasništvu lab-a;
- custom encryption, multi-VPN chains i identifier rotation tretirajte kao test hypotheses čiji flow, account i endpoint artifacts ostaju detektabilni.

Za authorized red team, svaki pokušaj da se saobraćaj učini manje prepoznatljivim mora biti eksplicitan detection objective u ROE-u, imati attribution map koju čuva controller i uključivati stop/deconfliction mechanism.

## Verification matrix

| Test | Očekivani rezultat | Failure znači |
|---|---|---|
| Tunnel/bridge zaustavljen | Workload nema direktan IPv4/IPv6/DNS path | Route enforcement je nepotpun |
| Target log pregledan | Pojavljuje se samo planirani egress/application identity | Header, route ili account leak |
| Ingress log pregledan | Source je prisutan; jasan target/request nije prisutan | Trust split je otkazao na ingress-u |
| Egress log pregledan | Relay/request je prisutan; source identity nije prisutan | Trust split je otkazao na egress-u |
| Onion origin eksterno skeniran | Nijedan public origin service nije dostupan/povezan | Origin je leak-ovan ili dual-homed |
| Disposable session završen | Instance state je nestao; odobreni dokazi su zasebno sačuvani | Persistence boundary je otkazao |
| Controller lookup testiran | Aktivnost se pravovremeno mapira na engagement/operator-a | Red-team accountability je otkazao |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
