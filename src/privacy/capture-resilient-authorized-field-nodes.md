# Terenski čvorovi sa otpornošću na zaplenu

{{#include ../banners/hacktricks-training.md}}

Raspberry Pi, mini-PC, travel router ili cellular appliance postavljen na lokaciji može ovlašćenom red team-u pružiti trajan vantage point. Takođe predstavlja verovatnu tačku otkrivanja, krađe i atribucije. Pravi cilj dizajna je zato **stabilan, kontrolisan pristup sa malo privilegija na terenskom čvoru**, a ne implant koji se ne može pratiti.

Ovaj vodič se odnosi isključivo na opremu postavljenu uz pisano odobrenje vlasnika lokacije. Kafić, komšija, hotel ili zajednička zgrada nisu obuhvaćeni samo zato što je njihova mreža dostupna. Ne skrivajte hardver na lokaciji čiji vlasnik nije dao saglasnost, ne zaobilazite captive portal, ne koristite tuđe akreditive, ne ometajte monitoring i ne pokušavajte da obrišete dokaze nakon otkrivanja.

{% hint style="warning" %}
Ne postoji pouzdano podešavanje „bez tragova“. Zapisi o radio asocijaciji, DHCP/NAT-u, carrier-u, kamerama, kupovini, uređaju, provider-u, controller-u i odredištima mogu preživeti uređaj. Odgovoran red team umesto toga uklanja **lične i nepovezane tajne** sa čvora, zadržava zaštićenu atribuciju na strani controller-a i omogućava da se posledice zaplene lako ograniče.
{% endhint %}

## Prednosti i nedostaci

**Prednosti:** realističan izvor unutar ciljne mreže ili u njenoj neposrednoj blizini; stabilno testiranje velikom brzinom; validira NAC, egress, fizički inventar i pokrivenost SOC-a; može nastaviti rad i nakon promene operatorove adrese; ograničen pristup može se centralno opozvati.

**Nedostaci:** fizičko postavljanje stvara snažne dokaze; gubitak može otkriti akreditive uređaja, mrežne profile i prikupljene podatke; ponavljajući control saobraćaj je uočljiv; napajanje, portali i promene radio-mreže smanjuju pouzdanost; širok tunnel može postati nekontrolisani pivot.

## Model pretnji i invarijante dizajna

Pretpostavite da pronalazač može ukloniti storage, pregledati firmware, kopirati svaku tajnu koju softver čuva, posmatrati kasnije mrežno ponašanje i predati uređaj klijentu ili organima za sprovođenje zakona. Full-disk encryption štiti isključen uređaj samo u okviru svog definisanog modela pretnji; aktivni, otključani čvor i ključevi učitani u memoriju predstavljaju drugačije slučajeve.

| Invarijanta | Praktična posledica |
|---|---|
| Nema direktnog identiteta između operatora i čvora | Operator se prijavljuje na gateway organizacije; čvor ima drugačiji identitet uređaja |
| Nema materijala sa lične radne stanice | Nema ličnog SSH ključa, browser profila, email-a, password manager-a, uparivanja telefona niti cache-a cloud CLI-ja |
| Nema glavne tajne controller-a | Jedan čvor ne može registrovati drugi, promeniti policy niti dešifrovati druge engagement-e |
| Samo odlazna i ograničena komunikacija | Terenska mreža ne prihvata management listener; čvor pristupa samo imenovanim rendezvous/update/time servisima |
| Kratkotrajne privilegije ograničenog opsega | Svaki credential ima jedan uređaj, audience, servis, rok isteka i neposredan način opoziva |
| Minimalna količina lokalnih podataka | Rezultati se prosleđuju controller-u; cache-ovi su encrypted, ograničeni po veličini/TTL-u i nisu autoritativni |
| Odgovornost controller-a preživljava zaplenu | Mapiranje asset-a na engagement, odobrenja, pristup operatora i komande čuvaju se centralno i pristup im je kontrolisan |
| Gubitak zaustavlja rad | Otkrivanje ili neobjašnjena promena stanja pokreće zaustavljanje, opoziv, obaveštavanje i očuvanje dokaza—not remote destruction |

NIST-ov IoT baseline objedinjuje identifikaciju uređaja, konfiguraciju, zaštitu podataka, logički pristup, secure software update i svest o stanju cybersecurity-ja kao osnovne mogućnosti. On posebno tretira svest o stanju i event zapise van uređaja kao podršku istrazi kompromitacije.<sup>[[1]](#references)</sup>

## Referentna arhitektura
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
Gateway mora znati koji je imenovani operator pristupio kom imenovanom uređaju. Terenskom čvoru je za rendezvous potrebna samo credential za uređaj. On nikada ne saznaje izvornu adresu operatora niti authentication secret, a operator na njega nikada ne kopira privatni management key. Time se smanjuje lična veza koja se može rekonstruisati **iz terenskog skladišta**, bez uništavanja odgovornosti u okviru vežbe.

Za veći fleet, sistem workload identity može izdavati kratkotrajne X.509 identitete i automatski rotirati ključeve. SPIFFE preporučuje X.509 SVIDs gde je to moguće i opisuje kratke životne vekove i čestu rotaciju kao mere za ograničavanje izloženosti usled kompromitovanja ključa.<sup>[[2]](#references)</sup> Mali tim može primeniti ista svojstva pomoću privatnog CA-a i automatizovanih certificates po uređaju; instaliranje SPIRE-a nije potrebno samo da bi se ispunio ovaj obrazac.

## Step 1: authorize and register the placement

1. Zabeležite vlasnika, lokaciju, tačno dozvoljenu zonu postavljanja, dozvoljene mreže, period procene, dozvoljena odredišta/radnje i kontakte za hitne slučajeve.
2. Zabeležite model, serijski broj, serijski broj storage-a, žične/bežične MAC adrese, modem IMEI/eSIM ili SIM ICCID, napajanje i aktuelnu fotografiju.
3. Dodelite uređaju nepersonalni engagement identifier, na primer `E2026-014-DROP03`. Nemojte u broadcast hostnames ili SSIDs kodirati ime klijenta.
4. Obavestite kontrolora vežbe i najmanju neophodnu grupu za fizičku bezbednost/SOC zaduženu za dekonflikciju o tome šta za ovaj test znače „izgubljen“, „pomerен“ i „otkriven“.
5. Unapred dogovorite ko sme da ga preuzme i kako pronalazač može da prijavi njegov pronalazak. Safety label može izostaviti osetljive detalje o klijentu, a ipak pružiti kontrolisani callback.
6. Postavite automatski istek authorization-a. Nastavak povezivanja nakon završetka scope-a ne sme produžiti dozvolu.

## Step 2: build a minimal recoverable image

Koristite podržanu OS image, proverite njen potpis/checksum kroz dokumentovani kanal vendora, instalirajte security updates i održavajte reproducible build manifest. Dajte prednost read-only ili immutable osnovi sa malom writable data particijom, tamo gde to software dozvoljava.

1. Uklonite podrazumevane naloge, demo services, compilere i packages koji nisu potrebni za authorized workload.
2. Onemogućite lokalni GUI, Bluetooth, discovery protocols, file sharing, Wi-Fi P2P i inbound administration, osim ako vežba izričito zahteva neku od tih funkcija.
3. Omogućite secure boot i measured boot/TPM-backed key release ako ih hardware zaista podržava; nemojte tvrditi da Raspberry Pi konfiguracija ima PC-class measured boot bez provere tačnog modela.
4. Šifrujte lokalno writable stanje i konfigurišite strogu maksimalnu veličinu i vreme zadržavanja. Encryption je kontrola odlaganja/ograničavanja, a ne dokaz da aktivni čvor ne otkriva ništa.
5. Šaljite važne logove van uređaja. Ograničite lokalne journals da biste sprečili iscrpljivanje storage-a, ali nemojte konfigurisati brisanje logova ili anti-forensic deletion.
6. Čuvajte image manifest, verzije packages, configuration hash i recovery instructions kod kontrolora.
7. Ponovo kreirajte image na rezervnom uređaju koristeći manifest i pokrenite isti health test. Dizajn koji može da oporavi samo njegov tvorac nije spreman za teren.

## Step 3: issue identities with one-way trust

Kreirajte tri različita identiteta:

- **device identity**, koju prihvata samo rendezvous za ovaj uređaj;
- **operator identity**, koju prihvata organization gateway i koja je zaštićena phishing-resistant MFA; i
- **controller/deployment identity**, koja se koristi za potpisivanje odobrenih jobs ili configuration-a i čuva se izvan operatora i terenskog čvora.

Čvor treba da ima javni ključ potreban za verifikaciju potpisanih jobs, a nikada signing key. Captured device credential ne sme omogućiti authentication na cloud consoles, source repositories, payment accounts, other nodes ili client production.

Koristite kratke certificate lifetimes tamo gde je automatic renewal pouzdan. Kada je dugotrajni WireGuard key operativno neophodan, tretirajte njegov public key kao revocation handle i ograničite ga peer-specific tunnel address-om, firewall policy-jem i broker authorization-om. Održavajte testiranu controller action koja odmah uklanja tog peera.

## Step 4: stable outbound rendezvous

Sledeći obrazac iz owned lab-a pruža stabilan management kroz NAT bez izlaganja inbound service-a. To je uobičajeno WireGuard networking, a ne covert reverse shell. Koristite documentation addresses i zamenite ih samo endpoint-ima u vlasništvu organizacije.

Na organization rendezvous-u dodelite `10.77.0.1/32`; terenskom čvoru dodelite `10.77.0.20/32`. Gateway peer entry treba da prihvata samo jednu adresu čvora:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Čvor uspostavlja izlaznu vezu ka rendezvous tački i zadržava NAT mapping samo kada je to potrebno:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard dokumentuje 25 sekundi kao razuman interval keepalive-a kroz mnoge NAT/firewall implementacije kada je potrebna perzistencija; ostavljanje ove opcije onemogućenom je poželjno kada nije potrebna.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` namerno čini ovo management putanjom, a ne pivotom podrazumevane rute.

Zatim primenite kontrole izvan WireGuard-a:

1. Razrešite `vpn.redteam.example` kroz odobreni bootstrap DNS put i evidentirajte očekivani endpoint organizacije u deployment zapisima.
2. Na node-u dozvolite izlazni DHCP/RA, neophodne DNS/NTP zahteve, rendezvous endpoint i minimalni odobreni update put. Odbijte neželjeni dolazni saobraćaj na svakom uplinku.
3. Na rendezvous-u dozvolite da `10.77.0.20` dosegne samo broker/health servis potreban za vežbu. Nemojte ga opšte prosleđivati u client mrežu.
4. Stavite interaktivni operatorski pristup iza gateway-a organizacije. Izbegavajte izlaganje SSH-a sa node-a kroz tunnel ako signed pull-job interfejs zadovoljava assessment.
5. Konfigurišite service manager da pokrene tunnel nakon uspostavljanja mreže, da ga restartuje nakon greške uz ograničeni backoff i da pošalje alert nakon ponovljenih grešaka. Restart loop ne sme preopteretiti lokaciju niti sakriti osnovni kvar.
6. Proverite poslednji handshake peera, ali nemojte koristiti „handshake postoji” kao dokaz da uređaj nije kompromitovan.

TURN može obezbediti samo relay reachability za namenski WebRTC control plane, a message queue može tolerisati povremenu nedostupnost servisa. TURN eksplicitno daje client-u javnu relay adresu iza NAT-a; njegov server ostaje posmatrač.<sup>[[4]](#references)</sup> Izaberite jednu control arhitekturu umesto slaganja tunnel-a bez jasno navedenog posmatrača ili koristi po pitanju pouzdanosti.

## Korak 5: stabilnost uplinka bez ličnih linkova

Za autorizovani venue node, prednost dajte sledećem redosledu:

1. žičana veza koju obezbeđuje client ili namenski test VLAN;
2. enterprise/guest Wi-Fi profil koji je odobrio vlasnik;
3. cellular/private APN fallback koji je ugovorila organizacija.

Nikada ga nemojte inicijalno povezivati preko ličnog phone hotspot-a, kućnog SSID-a, ličnog eSIM-a, ličnog Apple/Google naloga ili Wi-Fi profila izvezenog sa svakodnevnog laptopa. To su upravo artefakti kojima će se capture pridružiti.

Za svaki odobreni uplink:

- zabeležite SSID/BSSID ili switch/VLAN i očekivano ponašanje captive portal-a;
- postavite deterministički prioritet i health check ka endpoint-u u vlasništvu organizacije;
- obezbedite da failover menja samo underlay; identiteti uređaja i operatora ostaju kod broker-a;
- obezbedite da DNS, IPv6 i application saobraćaj tokom tranzicije ne zaobiđu rendezvous;
- pošaljite alert na nepoznati SSID/BSSID, promenu SIM-a, novi default gateway, promenu javnog IP/ASN-a ili istovremene uplinkove;
- pre deployment-a testirajte gubitak napajanja, DHCP renewal, restart AP-a, promenu javnog IP-a, 24-časovni idle, gubitak tunnel-a i oporavak primary-to-secondary-to-primary.

Privatno MAC adresiranje može smanjiti usputno praćenje između mreža, ali je stabilan MAC po mreži često potreban za autorizovani NAC. Zabeležite šta odabrani OS zaista radi i nemojte rotirati MAC oko access control-a vlasnika.

## Korak 6: ograničite rad i podatke

Bezbedan field node ne bi trebalo da prihvata proizvoljan shell tekst iz mailbox-a. Definišite signed tipove job-ova kao što su `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` ili neku drugu akciju izričito navedenu u rules of engagement. Ponovo validirajte destination, trajanje, rate, output size i scope na samom node-u.

1. Dodelite svakom job-u jedinstveni ID, device audience, vreme izdavanja, expiry, scope reference i maksimalni output.
2. Potpišite ga controller/deployment identitetom.
3. Odbijte nepoznata polja, istekle/replayed job-ove i job-ove namenjene drugom uređaju.
4. Stream-ujte rezultate ka collector-u u vlasništvu organizacije; šifrujte i postavite TTL za svaki neizbežni lokalni spool.
5. Zabeležite prihvaćeni/odbijeni job ID i hash rezultata na controller-u. Nemojte stavljati osetljive command parametre u javni monitoring channel.
6. Obustavite obradu kada authorization istekne, identity rotation ne uspe ili controller označi uređaj kao quarantined.

## Monitoring za otkrivanje, gubitak ili kompromitaciju

Monitoring može controller-u pokazati da se posmatrano stanje promenilo. Ne može pouzdano dokazati da su „istražitelji pronašli uređaj”, a pokušaj nadziranja respondera ili probing-a njihovih sistema premašio bi opseg autorizovanog assessment-a.

### Prikupljajte stanje van uređaja

Šaljite controller-u signed health record malog obima u nasumičnom, ali ograničenom operativnom intervalu. Uključite samo ono što je controller-u potrebno:

- device ID, boot ID/counter i monotonic uptime;
- hash configuration/image-a i verziju softvera;
- serial device certificate-a i stanje renewal-a;
- klasu uplinka, interfejs, BSSID ili switch context kada je odobreno, hash default gateway-a i javni IP/ASN koji je uočio service u vlasništvu organizacije;
- starost tunnel handshake-a, packet counter-e i queue depth;
- stanje enclosure switch-a ili hardware-tamper-a ako je vlasnik odobrio senzor;
- disk pressure, temperaturu, procenu clock offset-a i ID poslednjeg uspešnog job-a;
- sequence number i signature radi otkrivanja replay-a ili praznina.

Centralizujte gateway authentication, policy decisions, operator access, job submission, hash-eve rezultata, provider audit events i alert-e. CISA preporučuje centralizaciju logova, zaštitu od brisanja, uspostavljanje baseline-a normalne aktivnosti i određivanje kontakata za incident response.<sup>[[5]](#references)</sup>

### Indikatori otkrivanja/kompromitacije

| Signal | Moguća objašnjenja | Akcija controller-a |
|---|---|---|
| Heartbeat nedostaje | kvar napajanja/mreže, promena portala, oštećenje, namerno blokiranje ili uklanjanje | potvrdite stanje kod provider-a/lokacije; nemojte se ponovo povezivati preko neodobrenog puta |
| Boot counter se neočekivano promenio | prekid napajanja, crash, uklanjanje ili održavanje | stavite job-ove u quarantine; uporedite vreme i događaje na lokaciji |
| Config/image hash se promenio | greška update-a, kvar skladišta ili tampering | obustavite rad; revoke-ujte ako release nije odobrio controller |
| Novi uplink/BSSID/gateway/ASN | zamena AP-a, roaming, pomeren uređaj ili interception | uporedite sa odobrenim inventory-jem; stavite neobjašnjivu tranziciju u quarantine |
| Ponovljeni odbijeni job/signature | corruption, replay ili neovlašćeni controller | obustavite obradu i istražite gateway/controller logove |
| Credential uređaja korišćen dvaput ili sa nekompatibilnih putanja | cloned key, reuse snapshot-a ili network transition | odmah revoke-ujte; sačuvajte oba session record-a |
| Neočekivani lokalni login, interface, process ili privilege event | održavanje ili kompromitacija | izolujte kroz broker policy; sačuvajte dokaze |
| Promena enclosure switch/state-a | servis, pomeranje ili otkrivanje | obavestite imenovani kontakt na lokaciji; nemojte pokretati destruktivnu akciju |
| Provider abuse notice/account query ili SOC alert | detekcija, pogrešna konfiguracija ili saobraćaj van scope-a | obustavite aktivnost i pokrenite deconfliction/incident process |
| Sentinel credential korišćen | neko je pročitao decoy secret bez privilegija, jedinstven za ovaj node | revoke-ujte stvarni identitet uređaja i sačuvajte trag alert-a |

Sentinel credential ne sme davati **nikakav pristup**, sme pozivati samo alert service u vlasništvu organizacije i mora biti naveden u rules of engagement. To je tripwire za neovlašćeno čitanje, a ne beacon za praćenje osobe koja je pronašla opremu.

### Pragovi za alert-e

Koristite stateful rules, a ne jedan dramatičan alarm „caught”:

- **warning:** jedan propušteni interval, normalna promena adrese ili rast queue-a;
- **degraded:** tri uzastopna propuštena intervala, kašnjenje renewal-a, gubitak primary uplinka ili ponovljeni restart;
- **quarantine:** neodobrena promena hash-a/boot-a/uplinka, duplicate credential, korišćenje sentinel-a ili neočekivani privileged event;
- **confirmed discovery/loss:** izveštaj lokacije/controller-a, nepodudaranje fizičkog inventory-ja, recovery uređaja od strane neplanirane osobe ili validirana eskalacija provider-a/SOC-a.

Testirajte isporuku alert-a kroz channel nezavisan od field node-a. Izbegavajte slanje osetljivih podataka o client-u/uređaju na lične messaging ili consumer push naloge.

## Runbook za sumnjivo otkrivanje ili capture

1. **Stop:** suspendujte nove job-ove i operatorske session-e. Nemojte slati probe „proveri da li nas posmatraju”.
2. **Quarantine:** podesite broker da odbije identitet uređaja i njegove rute, uz zadržavanje postojećih logova.
3. **Revoke:** revoke-ujte device certificate/key, queue token, update credential i svaki service token za jednokratnu namenu. Suspendujte SIM organizacije kada je fizički gubitak verovatan.
4. **Preserve:** napravite snapshot controller, gateway, provider i alert zapisa; zabeležite pouzdano vreme, ko je postupao i poslednju poznatu konfiguraciju. Nemojte brisati niti remote wipe-ovati node.
5. **Notify:** kontaktirajte exercise controller, client incident contact i pravne/privacy kontakte definisane u authorization-u. Ako ga je pronašla treća strana, koristite unapred dogovoreni recovery process.
6. **Assess:** pretpostavite da su svaki secret i keširani rezultat na node-u izloženi. Precizno navedite čemu je svaki secret mogao da pristupi i da li je korišćen nakon sumnjivog događaja.
7. **Contain downstream:** rotirajte pogođene service credential-e, invalidate-ujte pending job-ove i pregledajte logove ciljeva/provider-a u vlasništvu organizacije zbog neočekivanog ponašanja.
8. **Recover safely:** preuzmite uređaj samo preko autorizovane osobe; fotografišite/upišite ga u paket, zabeležite custody i pribavite forensic dokaze prema uputstvima client-a.
9. **Resume with a new identity:** nikada nemojte nečujno ponovo omogućiti captured credential. Ponovo izgradite sistem iz poznatog manifest-a, otklonite control failure i pribavite izričito odobrenje.

NIST-ove aktuelne smernice za incident response integrišu preparation, detection, response i recovery u organization-wide cybersecurity risk management; prvo sačuvajte podatke kako bi client mogao da utvrdi šta se dogodilo i izabere odgovarajuću reakciju.<sup>[[6]](#references)</sup>

## Capture drill pre deployment-a

Predajte otključanu testnu jedinicu ili kopiju njenog storage-a nezavisnom reviewer-u i zatražite da popiše:

1. identifikatore uređaja/lokacije/engagement-a;
2. imena operatora, lične naloge, kućne/workstation mreže i recovery kontakte;
3. controller/broker destinacije i credential-e;
4. client network profile-e i keširane rezultate;
5. druge uređaje/projekte dostupne pomoću svakog secret-a;
6. payment credential-e ili vrednosti;
7. šta controller može da revoke-uje i koliko brzo;
8. koja aktivnost ostaje attributable iz centralnih logova.

Kriterijumi prolaza: nula ličnih naloga/workstation key-eva; nula cross-engagement ili enrollment authority; nema payment credential-a; ograničeni encrypted cache; jedna dokumentovana device-revocation akcija; potpuna odgovornost na strani controller-a. Svaki neočekivani lični link ili lateral capability tretirajte kao blocker za release.

## Zatvaranje

1. Zaustavite job-ove i onemogućite broker route po završetku scope-a.
2. Preuzmite i uskladite tačan inventory; prijavite sve što nedostaje.
3. Sačuvajte logove/rezultate i, ako je potrebno, forensic image prema retention plan-u engagement-a.
4. Revoke-ujte device, SIM, queue, update i service identitete čak i kada je hardware vraćen.
5. Tek nakon preservation/acceptance-a, sanitizujte ili uništite media kroz owner-ov odobreni data-disposal process i zabeležite završetak. Ovo je lifecycle management, a ne concealment.
6. Uklonite venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules i privremene kontakte.
7. Dokumentujte uočenu detekciju, propuštenu telemetriju, vreme do quarantine-a i svaki artefakt koji je capture izložio.

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
