# Atribucija, detekcija i protivmere

Infrastruktura za izbegavanje atribucije projektovana je tako da pojedinačni indikatori budu potrošni. Defenders treba da sačuvaju sirove dokaze, modeluju odnose i tragaju za ponašanjem koje opstaje nakon promene IP adrese, domena ili persone.

## Hijerarhija dokaza

| Dokaz | Koristan za | Glavna ograničenja |
|---|---|---|
| Source IP/ASN/geolokacija | lociranje vidljivog izlaza i provajdera | izlaz može biti relay, NAT ili žrtva; geolokacija je približna |
| Pasivni DNS/registracija | istoriju infrastrukture i co-hosting | privatnost/redakcija i shared hosting stvaraju praznine |
| Certificate/TLS/HTTP fingerprint | grupisanje ponovljenih deploymenta | uobičajeni software i imitacija stvaraju false positive rezultate |
| Flow timing i oblik bajtova | povezivanje relay faza i ponavljajućih beacon-a | CDN/NAT i ograničena vidljivost umanjuju sigurnost |
| Endpoint proces/identitet | objašnjavanje razloga uspostavljanja konekcije | nije prisutno na edge/IoT uređajima; attacker može koristiti native tools |
| Cloud/CDN/API audit | identifikovanje tenant-a i kontrole nad infrastrukturom | retencija i pristup provajdera/pristup po osnovu zakona variraju |
| Plaćanje/nalog/uređaj | povezivanje nabavke sa osobom/entitetom | moraju se uzeti u obzir nominee, kompromitacija i deljeni uređaji |
| Zaplenjeni implant/konfiguracija | otkrivanje ključeva, peer-ova, kontrolera i build veza | integritet prikupljanja i vreme zaplene su važni |
| Ljudski/fizički dokazi | povezivanje digitalnog događaja sa mestom/operatorom | intruzivno, zavisi od jurisdikcije i zahteva strogo rukovanje |

Nijedan pojedinačni red ne bi trebalo da bude osnova za atribuciju države sa visokom pouzdanošću. Koristite konkurentne hipoteze i navedite koje bi opažanje falsifikovalo svaku od njih.

## Minimalna telemetrija

1. **DNS:** klijent, upit, tip, odgovori, TTL, response code, resolver i timestamp.
2. **Network flow:** source/destination/port, početak/kraj, paketi/bajtovi, TCP flags i lokacija senzora.
3. **TLS/HTTP:** SNI kada je vidljiv, certificate, negotiated protocol, client/server fingerprint, method, kategorija authority/path, status i broj bajtova. Zaštitite osetljive pune URL-ove.
4. **Identitet:** rezultat autentikacije, faktor/certificate/device, source, aplikacija, ID sesije i risk odluka.
5. **Endpoint:** proces koji inicira konekciju, parent, user, binary signature/hash i destination.
6. **Edge/network device:** configuration diff, admin login, integritet procesa/fajla/firmware-a, interface i flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token i rezultat.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, dodeljeni VLAN/IP i posture.

Sinhronizujte satove, čuvajte originalne vremenske zone, dokumentujte NAT/proxy granice i zadržite dovoljno istorije da nadživi 31-dnevni ORB node.

## Izgradnja attribution grafa

Predstavite opažanja kao nodes i edges sa definisanim tipovima:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Korisni čvorovi obuhvataju IP, prefiks, ASN, domen, DNS nalog, sertifikat/ključ, fingerprint sličan JA3/JA4, HTTP gramatiku, hash datoteke/konfiguracije, cloud tenant, API token, email, personu, sredstvo plaćanja i fizički uređaj. Svaka veza mora da sadrži `first_seen`, `last_seen`, senzor/izvor, nivo poverenja i informaciju da li je opažena ili izvedena.

Sama gustina grafa može da zavara: CDN ili sertifikaciono telo povezuje mnoge nepovezane aktere. Veze kojima upravlja isti operator, a koje su retke — isti API nalog, SSH ključ, origin allowlist, jedinstveno telo odgovora ili kontrolni protokol — treba ponderisati značajnije od uobičajenog hostinga.

## Lov na ORB i kompromitovane rutere

### Na osnovu uočenog izlaza

1. Utvrdite da li adresa pripada hostingu, rezidencijalnoj, mobilnoj, obrazovnoj ili poslovnoj mreži; ne odbacujte rezidencijalne izvore.
2. Preuzmite istorijske DNS podatke, servise/sertifikate, otvorene portove i uočeno ponašanje pri skeniranju/eksploataciji za ograničeni period.
3. Pretražite peers koji dele retke service fingerprint-e, destinacije kontrolera, materijal sertifikata ili vreme rotacije.
4. Klasifikujte verovatne uloge: pristup, traversal, izlaz/staging ili administracija.
5. Proverite da li je više nepovezanih intrusion cluster-a koristilo isti pool; multi-tenancy slabi direktnu atribuciju aktera, ali jača ORB hipotezu.
6. Pratite nove čvorove koji odgovaraju profilu uloge nakon što stari IP-ovi nestanu.

### Kod vlasnika mreže

- Upozoravajte na novo upravljanje izloženo Internetu i podrazumevanu/zastarelu autentifikaciju.
- Promene konfiguracije rutera/firewall-a i administratorsku autentifikaciju šaljite van uređaja.
- Uspostavite baseline odlaznih konekcija sa infrastrukturom koja obično pokreće mali broj sesija.
- Detektujte nove proxy/listener procese, tunele, scheduled tasks, promene firmware-a i neočekivani DNS.
- Zamenite uređaje kojima je istekao životni vek; reboot koji uklanja volatile malware ne rešava izloženost.
- Ograničite upravljanje na autentifikovani administration plane i poznate izvore.

Mandiant preporučuje praćenje ORB infrastrukture kao entiteta koji se razvija, jer kratkotrajno blokiranje IP-ova ne obuhvata topologiju i životni ciklus.<sup>[[1]](#references)</sup>

## Fast-flux i dynamic-DNS analitika

Agregirajte prema registrovanom domenu i kliznom vremenskom prozoru. Praktičan skor može da kombinuje:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Istražujte domene na osnovu više nezavisnih karakteristika, a ne jednog praga. Uporedite ih sa allow-modelom CDN/anti-DDoS sistema i proverite rotaciju autoritativnih name-servera kako biste razlikovali single flux od double flux. Kod DGA-ova dodajte NXDOMAIN burstove po klijentu, distribuciju dužine i znakova, sinhronizovane upite sa više hostova i proces koji ih generiše. MITRE-ove aktuelne smernice takođe naglašavaju promene visoke učestalosti, nizak TTL i korelaciju procesa i mreže.<sup>[[2]](#references)</sup>

## Detekcija domain-frontinga

Kada enterprise endpoint ili ovlašćena tačka za inspekciju imaju oba identiteta, uporedite:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Povećajte nivo pouzdanosti kada SNI i authority pripadaju nepovezanim tenant-ima, proces nije odobreni client, sesija je periodična/dugotrajna, a unutrašnji origin je redak. Prazan SNI je karakteristika koju treba evidentirati, a ne automatski smatrati zlonamernom. ECH može sakriti SNI na mreži, pa endpoint, DNS i provider/CDN logovi postaju važniji. MITRE dokumentuje i varijante sa nepodudarnim i praznim SNI-jem.<sup>[[3]](#references)</sup>

## Detekcija sekvence Dead-drop resolver-a

Ponašanje sa visokim signalom predstavlja sekvencu, a ne blokirani domen:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Pretražite celu flotu u potrazi za identičnim putanjama objekata, hash vrednostima odgovora, API identifikatorima i odredištima narednog koraka. Sačuvajte preuzeti sadržaj jer akter može da ga izmeni ili obriše. Ograničite nepotrebne service API-je i zahtevajte da odobrene aplikacije koriste enterprise proxy-je, ali uzmite u obzir developerske alate i automatizaciju. MITRE u stvarnim procedurama navodi GitHub, forume, dokumente i social/web services.<sup>[[4]](#references)</sup>

## Grupisanje redirector-a i ponovljivih deployment-a

Čak i kada se domeni i adrese menjaju, operateri često ponovo deploy-uju istu automatizaciju. Grupisanje zasnivajte na kombinacijama sledećih karakteristika:

- polja sertifikata/ponovna upotreba ključa i vreme izdavanja;
- TLS verzija/cipher/redoslеd ekstenzija i ponašanje servera;
- identični HTTP status, redosled zaglavlja, ponašanje keša, ikonica/telo i error page;
- neuobičajeni parovi portova i redirect lanci;
- obrazac DNS provajdera/name server-a i raspored TTL-a;
- vreme deployment-a, uptime i period održavanja;
- izloženost back-end origin-a ili identične allowliste.

Jedna generička Nginx stranica predstavlja slabe dokaze. Više retkih, nezavisnih podudaranja uz vremenski kontinuitet može opravdati hipotezu o infrastrukturnom klasteru.

## Detekcija residential proxy-ja i nemogućih sesija

Održavajte identitet sesije iznad IP sloja. Označite kombinacije kao što su:

- jedan session/device fingerprint menja zemlje/ASN-ove brže nego što je putovanje moguće;
- consumer IP se menja pri svakom zahtevu, dok cookies i TLS/browser identitet ostaju nepromenjeni;
- navodni lokalni uređaj ima latency/time-zone/language koji nisu u skladu sa izlazom;
- adresa naizmenično koristi nepovezane populacije naloga ili pokazuje ponašanje backconnect proxy-ja;
- privilegovana sesija se pojavljuje preko residential access-a bez sertifikata uređaja organizacije.

Carrier NAT, accessibility tools, corporate VPN-ovi i putovanja stvaraju benigne anomalije. Zahtevajte step-up authentication ili istragu umesto nepovratnog blokiranja samo na osnovu oznaka „residential proxy“.

## Detekcija wireless-a i prikrivenih uređaja

Povežite RADIUS/NAC sa AP-om i fizičkim kontekstom:

1. pronađite prvi put viđene kombinacije nalog–uređaj–AP;
2. identifikujte credentials korišćene bez managed EAP sertifikata/posture-a;
3. uporedite istovremene sesije i prisustvo na osnovu badge/building podataka;
4. proverite neuobičajeno slab/granični signal i kretanje između AP-ova;
5. pretražite obližnje managed endpoint-e u potrazi za wireless scanning-om, novouključenim interface bridge/NAT-om, virtual adapter-ima ili tunnel-ima;
6. popišite novu switchport, DHCP, USB network i PoE aktivnost;
7. sprovedite autorizovano RF/fizičko pretraživanje kada dokazi to opravdavaju.

Ovo otkriva i APT28-style nearest-neighbor putanju i drop iz vežbe. MAC randomization ne sme se tretirati kao identitet ili dokaz krivice.

## Detekcija finansijske atribucije

- Sačuvajte tačan chain, token, adresu, transakciju i block identifikatore.
- Pratite vrednost kroz change, peel chains, fan-out/in, mixers, bridges i service deposits, uz označavanje heuristika.
- Korelišite vreme, iznos umanjen za naknade, contract event, likvidnost i withdrawal na odredišnom chain-u.
- Pribavite ili sačuvajte zakonite exchange, bridge, merchant, account, device i delivery records.
- Proverite aktuelne sankcionisane entitete/adrese i derivate u okviru primenljivog programa; ne oslanjajte se na staru statičku listu.
- Korišćenje privacy-protocol-a tretirajte kao ulazni podatak za kontekst rizika, a ne kao dokaz protivpravnog postupanja.

FATF-ovi red flags su izričito kontekstualni: neuobičajen obrazac, iznos/učestalost, geografija, izvor sredstava i anonymity-enhancing services postaju značajni zajedno.<sup>[[5]](#references)</sup>

## Deception i canaries

Defenders mogu kreirati signale visoke pouzdanosti bez pokušaja deanonymization-a običnih korisnika:

- jedinstveni credentials ili dokumenti koji nikada ne bi smeli da napuste jedan sistem;
- lažni administrative endpoint-i i decoy share-ovi;
- instrumentovani DNS nazivi ugrađeni samo u kontrolisane artefakte;
- canary cloud ključevi bez legitimne upotrebe;
- decoy Wi-Fi identitet koji nijedan managed uređaj ne poseduje.

Pažljivo ograničite i upravljajte deception-om. Canary treba da identifikuje zloupotrebu sopstvenog sredstva defender-a, a ne da prikuplja nepovezan saobraćaj trećih strana.

## Prioriteti countermeasure-a

1. Uklonite nepodržane Internet-facing router-e, VPN-ove i appliance-e.
2. Zahtevajte phishing-resistant MFA i device-bound sertifikate, uključujući internal/wireless access.
3. Centralizujte dovoljno nepromenljive identity, endpoint, DNS, flow, proxy, cloud i network-device logove.
4. Ograničite management i egress; popišite svaki eksterno dostupan service.
5. Nadgledajte DNS, certificate transparency i cloud konfiguraciju radi neovlašćenih asset-a.
6. Obezbedite process-to-network i object-level SaaS vidljivost.
7. Uvežbavajte istrage kroz više slojeva i koordinaciju sa susednim provider-ima.
8. Pratite infrastrukturne klastere i ponašanja, a ne samo IP blocklist-e.

## Analitička disciplina

Koristite jezik pouzdanosti:

- **Observed:** zapis senzora/provajdera direktno pokazuje odnos.
- **Strongly supported:** više nezavisnih opažanja daje prednost toj hipotezi u odnosu na alternative.
- **Assessed:** zaključak zasnovan na navedenim pretpostavkama i dokazima.
- **Unknown:** nedostatak vidljivosti sprečava zaključak.

Uvek zadržite najmanje dve hipoteze: infrastruktura kojom upravlja akter nasuprot kompromitovanom/deljenom posredniku; jedan akter nasuprot multi-tenant service-u; namerno izbegavanje detekcije nasuprot legitimnom privacy/CDN ponašanju. Sposobnost objašnjavanja neizvesnosti deo je ispravne detekcije.

## References

- [1] [Google Cloud/Mandiant — Špijunski akteri povezani sa Kinom koriste ORB mreže](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Indikatori upozorenja za virtuelnu imovinu](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Akteri iz NR Kine kompromituju i održavaju trajni pristup](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Smernice za poboljšanu vidljivost i hardening komunikacione infrastrukture](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
