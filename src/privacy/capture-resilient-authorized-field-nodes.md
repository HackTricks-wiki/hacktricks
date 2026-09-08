# Capture-Resilient Authorized Field Nodes

Raspberry Pi, mini-PC, travel router ili cellular appliance postavljen na lokaciji može ovlašćenom red teamu pružiti trajnu poziciju za pristup. Takođe je verovatna tačka otkrivanja, krađe i atribucije. Pravi cilj dizajna je zato **stabilan, kontrolisan pristup uz malo ovlašćenja na field node-u**, a ne implant koji se ne može povezati sa odgovornim licem.

Ovaj vodič se odnosi isključivo na opremu postavljenu uz pisano ovlašćenje vlasnika lokacije. Kafić, komšija, hotel ili zajednička zgrada nisu obuhvaćeni samo zato što je njihova mreža dostupna. Ne skrivajte hardver na mestu čiji vlasnik nije dao saglasnost, ne zaobilazite captive portal, ne koristite tuđe akreditive, ne ometajte monitoring i ne pokušavajte da obrišete dokaze nakon otkrivanja.

{% hint style="warning" %}
Ne postoji pouzdano podešavanje „bez tragova“. Radio association, DHCP/NAT, carrier, kamera, kupovina, uređaj, provider, kontroler i destination zapisi mogu preživeti uređaj. Odgovoran red team zato uklanja **lične i nepovezane tajne** sa node-a, zadržava zaštićenu atribuciju na strani kontrolera i omogućava da se capture jeftino ograniči.
{% endhint %}

## Prednosti i nedostaci

**Prednosti:** realističan izvor iz interne mreže ili u blizini cilja; stabilno testiranje velikom brzinom; proverava NAC, egress, fizički inventar i SOC pokrivenost; može nastaviti rad nakon promene operatorove adrese; ograničen pristup može se centralno opozvati.

**Nedostaci:** fizičko postavljanje stvara snažne dokaze; gubitak može otkriti akreditive uređaja, mrežne profile i prikupljene podatke; ponavljani control saobraćaj može biti otkriven; napajanje, portali i promene radio okruženja umanjuju pouzdanost; širok tunnel može postati nekontrolisani pivot.

## Model pretnji i invarijante dizajna

Pretpostavite da pronalazač može ukloniti storage, pregledati firmware, kopirati svaku tajnu sačuvanu u softveru, posmatrati kasnije ponašanje na mreži i predati uređaj klijentu ili law enforcement-u. Full-disk encryption štiti isključen uređaj samo u okviru svog navedenog modela pretnji; pokrenut i otključan node i ključevi učitani u memoriju predstavljaju različite slučajeve.

| Invarijanta | Praktična posledica |
|---|---|
| Nema direktnog identiteta operatora prema node-u | Operator se prijavljuje na gateway organizacije; node ima drugačiji identitet uređaja |
| Nema materijala sa lične radne stanice | Nema ličnog SSH ključa, browser profila, email-a, password manager-a, uparivanja sa telefonom ili cache-a cloud CLI-ja |
| Nema master secret-a kontrolera | Jedan node ne može da enroluje drugi, menja policy ili dešifruje druge engagements |
| Samo outbound i ograničeno | Field mreža ne prihvata management listener; node pristupa samo imenovanim rendezvous/update/time servisima |
| Kratkotrajno i ograničeno ovlašćenje | Svaki credential ima jedan uređaj, audience, servis, rok važenja i neposredan put za revocation |
| Minimalna količina lokalnih podataka | Rezultati se stream-uju kontroleru; cache-ovi su šifrovani, ograničeni po veličini/TTL-u i nisu authoritative |
| Odgovornost kontrolera preživljava capture | Mapiranje asset-a i engagement-a, odobrenja, pristup operatora i komande čuvaju se centralno i kontroliše se pristup |
| Gubitak zaustavlja rad | Otkrivanje ili neobjašnjena promena stanja pokreće zaustavljanje, revoke, obaveštavanje i očuvanje dokaza—not remote destruction |

NIST-ov IoT baseline grupiše identifikaciju uređaja, konfiguraciju, zaštitu podataka, logical access, secure software update i awareness o stanju cybersecurity-ja kao osnovne mogućnosti. On posebno tretira awareness o stanju i event zapise van uređaja kao podršku istrazi kompromitovanja.<sup>[[1]](#references)</sup>

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
Gateway mora da zna koji imenovani operator je pristupio kom uređaju sa imenom. Field node-u je za rendezvous potrebna samo credential za uređaj. On nikada ne saznaje izvornu adresu operatora niti authentication secret, a operator na njega nikada ne kopira privatni management key. Ovo smanjuje ličnu vezu koja se može rekonstruisati **iz field storage-a**, bez uništavanja odgovornosti za vežbu.

Za veću flotu, workload-identity sistem može izdavati kratkotrajne X.509 identitete i automatski rotirati ključeve. SPIFFE preporučuje X.509 SVIDs gde god je to moguće i opisuje kratke životne vekove i čestu rotaciju kao mere koje ograničavaju izloženost usled kompromitovanja ključa.<sup>[[2]](#references)</sup> Mali tim može primeniti ista svojstva pomoću privatnog CA-a i automatizovanih sertifikata po uređaju; instaliranje SPIRE-a nije potrebno samo da bi se ispoštovao ovaj obrazac.

## Step 1: autorizujte i registrujte postavljanje

1. Zabeležite vlasnika, lokaciju, tačno dozvoljenu zonu postavljanja, dozvoljene mreže, vremenski okvir procene, dozvoljena odredišta/radnje i kontakte za hitne slučajeve.
2. Zabeležite model, serijski broj, serijski broj storage-a, žične/bežične MAC adrese, modem IMEI/eSIM ili SIM ICCID, napajanje i aktuelnu fotografiju.
3. Dodelite uređaju nepersonalni engagement identifier, na primer `E2026-014-DROP03`. Nemojte kodirati ime klijenta u broadcast hostname-ovima ili SSID-ovima.
4. Obavestite exercise controller i najmanju neophodnu grupu za fizičku bezbednost/SOC deconfliction o tome šta za ovaj test znače „izgubljen“, „pomer en“ i „pronađen“.
5. Unapred se dogovorite ko sme da ga preuzme i kako pronalazač može da prijavi pronalazak. Safety label može izostaviti osetljive detalje o klijentu, uz obezbeđivanje kontrolisanog callback-a.
6. Podesite automatski istek autorizacije. Nastavak povezivanja nakon završetka scope-a ne sme produžiti dozvolu.

## Step 2: napravite minimalni recoverable image

Koristite podržani OS image, proverite njegov potpis/checksum kroz dokumentovani kanal proizvođača, instalirajte security updates i održavajte reproducible build manifest. Dajte prednost read-only ili immutable osnovi sa malom writable data particijom, tamo gde software to podržava.

1. Uklonite podrazumevane naloge, demo servise, compilere i pakete koji nisu potrebni za autorizovani workload.
2. Onemogućite lokalni GUI, Bluetooth, discovery protokole, file sharing, Wi-Fi P2P i inbound administration, osim ako vežba izričito zahteva neku od tih funkcija.
3. Omogućite secure boot i measured boot/TPM-backed key release ako ih hardware zaista podržava; nemojte tvrditi da Raspberry Pi konfiguracija ima PC-class measured boot bez provere tačnog modela.
4. Enkriptujte lokalno writable stanje i podesite strogu maksimalnu veličinu i vreme zadržavanja. Encryption je kontrola odlaganja/ograničavanja, a ne dokaz da aktivni node ne otkriva ništa.
5. Šaljite važne logove van uređaja. Ograničite lokalne journale da biste sprečili iscrpljivanje storage-a, ali nemojte podešavati brisanje logova ili anti-forensic deletion.
6. Čuvajte image manifest, verzije paketa, hash konfiguracije i uputstva za oporavak kod controller-a.
7. Ponovo image-ujte rezervni uređaj na osnovu manifesta i pokrenite isti health test. Dizajn koji može da oporavi samo njegov tvorac nije spreman za field.

## Step 3: izdajte identitete sa one-way trust

Napravite tri različita identiteta:

- **device identity**, koji prihvata samo rendezvous za ovaj uređaj;
- **operator identity**, koji prihvata organization gateway i štiti ga phishing-resistant MFA; i
- **controller/deployment identity**, koji se koristi za potpisivanje odobrenih job-ova ili konfiguracije i čuva se izvan operator-a i field node-a.

Node treba da ima public key potreban za verifikaciju potpisanih job-ova, nikada signing key. Zarobljeni device credential ne sme da omogući authentication ka cloud konzolama, source repository-jima, payment account-ima, drugim node-ovima ili klijentskoj produkciji.

Koristite kratke životne vekove sertifikata tamo gde je automatsko obnavljanje pouzdano. Kada je dugotrajni WireGuard key operativno neophodan, tretirajte njegov public key kao revocation handle i ograničite ga pomoću peer-specific tunnel address-a, firewall policy-ja i broker authorization-a. Održavajte testiranu controller akciju koja odmah uklanja tog peer-a.

## Step 4: stabilni outbound rendezvous

Sledeći owned-lab obrazac obezbeđuje stabilan management kroz NAT bez izlaganja inbound service-a. To je uobičajeno WireGuard umrežavanje, a ne covert reverse shell. Koristite documentation adrese i zamenite ih samo endpoint-ima u vlasništvu organizacije.

Na organization rendezvous-u dodelite `10.77.0.1/32`; field node-u dodelite `10.77.0.20/32`. Gateway peer entry treba da prihvata samo jednu adresu node-a:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Čvor usmerava saobraćaj ka rendezvous tački i održava NAT mapiranje samo kada je potrebno:
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
WireGuard navodi 25 sekundi kao razuman interval za keepalive kroz mnoge NAT/firewall implementacije kada je potrebna perzistencija; ostavljanje ove opcije isključenom je poželjno kada nije potrebna.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` namerno definiše ovo kao putanju za upravljanje, a ne kao pivot ka podrazumevanoj ruti.

Zatim primenite kontrole izvan WireGuard-a:

1. Razrešite `vpn.redteam.example` kroz odobreni bootstrap DNS put i zabeležite očekivanu organizacionu krajnju tačku u deployment zapisima.
2. Na nodu dozvolite izlazni DHCP/RA, neophodni DNS/NTP, rendezvous krajnju tačku i minimalnu odobrenu putanju za update. Odbijte neželjeni ulazni saobraćaj na svakom uplinku.
3. Na rendezvous-u dozvolite da `10.77.0.20` pristupa samo broker/health servisu potrebnom za vežbu. Nemojte ga generalno prosleđivati u client mrežu.
4. Interaktivni operatorski pristup postavite iza organizacionog gateway-a. Izbegavajte izlaganje SSH-a sa noda kroz tunel ako signed pull-job interfejs zadovoljava procenu.
5. Podesite service manager da pokrene tunel nakon uspostavljanja mreže, da ga ponovo pokrene nakon greške uz ograničeni backoff i da pošalje alert nakon ponovljenih grešaka. Restart loop ne sme da preoptereti lokaciju ili prikrije osnovni kvar.
6. Proverite poslednji handshake peer-a, ali nemojte koristiti činjenicu da „handshake postoji” kao dokaz da uređaj nije kompromitovan.

TURN može obezbediti samo relay dostupnost za namenski WebRTC control plane, a message queue može tolerisati povremene prekide servisa. TURN eksplicitno daje client-u javnu relay adresu iza NAT-a; njegov server ostaje posmatrač.<sup>[[4]](#references)</sup> Izaberite jednu control arhitekturu umesto slaganja tunela bez jasno navedenog posmatrača ili koristi u pogledu pouzdanosti.

## Step 5: stabilnost uplinka bez ličnih linkova

Za odobreni venue node, prednost dajte sledećim opcijama:

1. žična veza koju obezbeđuje client ili namenski test VLAN;
2. enterprise/guest Wi-Fi profil koji je odobrio owner;
3. fallback preko cellular/private APN-a koji je ugovorila organizacija.

Nikada ga nemojte opremati personalnim phone hotspot-om, kućnim SSID-om, personalnim eSIM-om, personalnim Apple/Google account-om ili Wi-Fi profilom izvezenim sa svakodnevnog laptopa. To su upravo artifact-i kojima će se capture pridružiti.

Za svaki odobreni uplink:

- zabeležite SSID/BSSID ili switch/VLAN i očekivano ponašanje captive portal-a;
- podesite deterministički prioritet i health check ka endpoint-u u vlasništvu organizacije;
- obezbedite da failover menja samo underlay; identiteti uređaja i operatora ostaju kod broker-a;
- obezbedite da DNS, IPv6 i application saobraćaj tokom prelaza ne zaobilaze rendezvous;
- pošaljite alert za nepoznati SSID/BSSID, promenu SIM-a, novi default gateway, promenu javnog IP/ASN-a ili istovremene uplink-e;
- pre deployment-a testirajte gubitak napajanja, DHCP renewal, restart AP-a, promenu javnog IP-a, 24-časovni idle, gubitak tunela i oporavak primary-to-secondary-to-primary.

Private MAC addressing može smanjiti neformalno praćenje između mreža, ali je stabilan MAC po mreži često potreban za odobreni NAC. Zabeležite šta izabrani OS zaista radi i nemojte rotirati MAC oko access control-a owner-a.

## Step 6: ograničite rad i podatke

Bezbedan field node ne bi trebalo da prihvata proizvoljan shell tekst iz mailbox-a. Definišite signed job tipove kao što su `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` ili drugu akciju izričito navedenu u pravilima angažmana. Ponovo proverite odredište, trajanje, rate, veličinu izlaza i scope na samom nodu.

1. Dodelite svakom job-u jedinstveni ID, device audience, vreme izdavanja, rok važenja, scope referencu i maksimalni izlaz.
2. Potpišite ga identitetom controller/deployment-a.
3. Odbijte nepoznata polja, istekle/replayed job-ove i job-ove namenjene drugom uređaju.
4. Stream-ujte rezultate ka collector-u u vlasništvu organizacije; encrypt-ujte i ograničite TTL svakog neizbežnog lokalnog spool-a.
5. Zabeležite prihvaćeni/odbijeni job ID i hash rezultata na controller-u. Nemojte stavljati osetljive command parametre u javni monitoring kanal.
6. Zaustavite obradu kada authorization istekne, rotacija identiteta ne uspe ili controller označi uređaj kao quarantined.

## Monitoring za discovery, gubitak ili compromise

Monitoring može obavestiti controller da se posmatrano stanje promenilo. Ne može pouzdano dokazati da su „istražitelji pronašli uređaj”, a pokušaj nadgledanja respondera ili probe njihovih sistema prevazišao bi granice odobrene procene.

### Prikupljanje stanja van uređaja

Šaljite controller-u signed health zapis malog obima u nasumičnom, ali ograničenom operativnom intervalu. Uključite samo ono što je controller-u potrebno:

- device ID, boot ID/counter i monotonic uptime;
- hash konfiguracije/image-a i verziju software-a;
- serijski broj device-certificate-a i stanje renewal-a;
- klasu uplinka, interfejs, BSSID ili switch context kada je odobreno, hash default gateway-a i javni IP/ASN koji je zabeležio service u vlasništvu organizacije;
- starost tunnel handshake-a, packet counters i queue depth;
- stanje enclosure switch-a ili hardware-tamper-a ako je owner odobrio senzor;
- opterećenje diska, temperaturu, procenu clock-offset-a i ID poslednjeg uspešnog job-a;
- sequence number i signature radi otkrivanja replay-a ili praznina.

Centralno čuvajte gateway authentication, odluke policy-ja, operatorski pristup, submission job-ova, hash-eve rezultata, provider audit događaje i alert-e. CISA preporučuje centralizaciju logova, zaštitu od brisanja, uspostavljanje baseline-a normalne aktivnosti i određivanje kontakata za incident-response.<sup>[[5]](#references)</sup>

### Indikatori discovery/compromise-a

| Signal | Moguća objašnjenja | Akcija controller-a |
|---|---|---|
| Heartbeat nedostaje | kvar napajanja/mreže, promena portal-a, oštećenje, namerno blokiranje ili uklanjanje | potvrdite stanje kod provider-a/lokacije; nemojte se ponovo povezivati sa neodobrenog puta |
| Boot counter se neočekivano promenio | prekid napajanja, crash, uklanjanje ili održavanje | stavite job-ove u quarantine; uporedite vreme i događaje na lokaciji |
| Hash konfiguracije/image-a se promenio | greška pri update-u, kvar storage-a ili tampering | zaustavite rad; revoke-ujte ako release nije odobrio controller |
| Novi uplink/BSSID/gateway/ASN | zamena AP-a, roaming, premešten uređaj ili interception | uporedite sa odobrenim inventory-jem; stavite neobjašnjivu promenu u quarantine |
| Ponovljeni odbijeni job/signature | korupcija, replay ili neovlašćeni controller | zaustavite obradu i istražite gateway/controller logove |
| Credential uređaja korišćen je dvaput ili sa nekompatibilnih putanja | cloned key, ponovno korišćen snapshot ili promena mreže | odmah revoke-ujte; sačuvajte oba session zapisa |
| Neočekivani lokalni login, interfejs, proces ili privilege događaj | održavanje ili compromise | izolujte kroz broker policy; sačuvajte dokaze |
| Promena enclosure switch-a/stanja | servis, pomeranje ili discovery | obavestite imenovani kontakt na lokaciji; nemojte pokretati destruktivnu akciju |
| Provider abuse notice/account query ili SOC alert | detekcija, pogrešna konfiguracija ili saobraćaj van scope-a | zaustavite aktivnost i pokrenite deconfliction/incident proces |
| Sentinel credential je korišćen | neko je pročitao decoy secret bez privilegija, jedinstven za ovaj node | revoke-ujte stvarni identitet uređaja i sačuvajte trag alert-a |

Sentinel credential mora davati **nikakav pristup**, pozivati samo alert service u vlasništvu organizacije i biti naveden u pravilima angažmana. To je tripwire za neovlašćeno čitanje, a ne beacon za praćenje osobe koja je pronašla opremu.

### Pragovi za alert-e

Koristite stateful pravila, a ne jedan dramatični alarm „caught”:

- **warning:** jedan propušten interval, normalna promena adrese ili rast queue-a;
- **degraded:** tri uzastopna propuštena intervala, kašnjenje renewal-a, gubitak primary uplinka ili ponovljeni restart;
- **quarantine:** neodobrena promena hash-a/boot-a/uplinka, duplicate credential, korišćenje sentinel-a ili neočekivani privilegovani događaj;
- **confirmed discovery/loss:** izveštaj lokacije/controller-a, nepodudaranje fizičkog inventory-ja, recovery uređaja od strane neplanirane osobe ili potvrđena provider/SOC eskalacija.

Testirajte dostavu alert-a kroz kanal nezavisan od field node-a. Izbegavajte slanje osetljivih podataka o client-u/uređaju na personal messaging ili consumer push account-e.

## Runbook za sumnju na discovery ili capture

1. **Stop:** suspendujte nove job-ove i operatorske session-e. Nemojte slati probe „proveri da li te nadgledaju”.
2. **Quarantine:** podesite broker da odbija identitet uređaja i njegove rute, uz zadržavanje postojećih logova.
3. **Revoke:** revoke-ujte device certificate/key, queue token, update credential i svaki service token namenjen jednoj svrsi. Suspendujte organization SIM kada je fizički gubitak moguć.
4. **Preserve:** napravite snapshot controller, gateway, provider i alert zapisa; zabeležite pouzdano vreme, osobu koja je postupila i poslednju poznatu konfiguraciju. Nemojte brisati podatke niti raditi remote wipe noda.
5. **Notify:** kontaktirajte exercise controller, client incident kontakt i pravne/privacy kontakte definisane u authorization-u. Ako ga je pronašla treća strana, primenite unapred dogovoreni recovery proces.
6. **Assess:** pretpostavite da su svaki secret i cached rezultat na nodu izloženi. Precizno popišite čemu je svaki secret mogao da pristupi i da li je korišćen nakon sumnjivog događaja.
7. **Contain downstream:** rotirajte pogođene service credential-e, invalidate-ujte pending job-ove i pregledajte logove target/provider sistema u vlasništvu organizacije radi neočekivanog ponašanja.
8. **Recover safely:** preuzimanje obavite samo preko ovlašćene osobe; fotografišite i zapakujte uređaj, zabeležite chain of custody i pribavite forensic dokaze prema uputstvima client-a.
9. **Resume with a new identity:** nikada nemojte nečujno ponovo omogućiti captured credential. Ponovo izgradite sistem iz poznatog manifesta, ispravite control grešku i pribavite eksplicitno odobrenje.

NIST-ove aktuelne smernice za incident-response integrišu preparation, detection, response i recovery u upravljanje cybersecurity rizikom na nivou organizacije; prvo sačuvajte podatke kako bi client mogao da utvrdi šta se dogodilo i izabere odgovarajući odgovor.<sup>[[6]](#references)</sup>

## Capture drill pre deployment-a

Predajte otključani testni uređaj ili kopiju njegovog storage-a odvojenom reviewer-u i zatražite da popiše:

1. identifikatore uređaja/lokacije/angažmana;
2. imena operatora, personal account-e, kućne/workstation mreže i recovery kontakte;
3. controller/broker destinacije i credential-e;
4. client network profile-e i cached rezultate;
5. druge uređaje/projekte kojima se može pristupiti svakim secret-om;
6. value ili payment credential-e;
7. šta controller može da revoke-uje i koliko brzo;
8. koja aktivnost ostaje pripisiva na osnovu centralnih logova.

Kriterijumi prolaza: nula personal account-a/workstation key-eva; nula cross-engagement ili enrollment authority-ja; bez payment credential-a; ograničen encrypted cache; jedna dokumentovana akcija za device-revocation; potpuna odgovornost na strani controller-a. Svaki neočekivani lični link ili lateral capability tretirajte kao blocker za release.

## Closeout

1. Zaustavite job-ove i onemogućite broker rutu po završetku scope-a.
2. Preuzmite i uskladite tačan inventory; prijavite sve što nedostaje.
3. Sačuvajte logove/rezultate i, ako je potrebno, forensic image prema retention plan-u angažmana.
4. Revoke-ujte device, SIM, queue, update i service identitete čak i kada je hardware vraćen.
5. Tek nakon preservation/acceptance, sanitizujte ili uništite media kroz owner-ov odobreni proces za disposal podataka i zabeležite završetak. Ovo je lifecycle management, a ne prikrivanje.
6. Uklonite venue NAC/DHCP rezervacije, broker rute, DNS, cloud role, alert pravila i privremene kontakte.
7. Dokumentujte uočenu detekciju, propuštenu telemetriju, vreme do quarantine-a i svaki artifact koji je capture izložio.

## References

- [1] [NIST — Katalog mogućnosti cybersecurity-ja IoT uređaja](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Koncepti i short-lived workload identiteti](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Kratki vodič: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Korišćenje logging-a na poslovnim sistemima](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Preporuke i razmatranja za Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
