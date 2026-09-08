# Pripisivanje, detekcija i protivmere

{{#include ../banners/hacktricks-training.md}}

Infrastruktura za izbegavanje pripisivanja osmišljena je tako da pojedinačni indikatori mogu lako da se zamene. Defenders should preserve raw evidence, model relationships, and hunt for behavior that survives a change of IP, domain or persona.

## Hijerarhija dokaza

| Dokaz | Koristan za | Glavna ograničenja |
|---|---|---|
| Izvorna IP adresa/ASN/geolokacija | lociranje vidljivog izlaza i provajdera | izlaz može biti relay, NAT ili žrtva; geolokacija je približna |
| Pasivni DNS/registracija | istoriju infrastrukture i co-hosting | privatnost/redakcija podataka i shared hosting stvaraju praznine |
| Certificate/TLS/HTTP fingerprint | grupisanje ponovljenih deploymenta | uobičajeni software i mimicry stvaraju false positive rezultate |
| Vremenski tok i oblik paketa | povezivanje relay faza i ponavljajućih beacon-a | CDN/NAT i ograničena vidljivost smanjuju izvesnost |
| Endpoint proces/identitet | objašnjavanje razloga za uspostavljanje veze | nisu prisutni na edge/IoT uređajima; attacker može koristiti native tools |
| Cloud/CDN/API audit | identifikovanje tenant-a i kontrole nad infrastrukturom | retencija i pristup provajdera/pravnih organa se razlikuju |
| Payment/account/device | povezivanje nabavke sa osobom/entitetom | moraju se uzeti u obzir nominee, kompromitacija i deljeni uređaji |
| Zaplenjeni implant/configuration | otkrivanje ključeva, peer-ova, kontrolera i build veza | integritet prikupljanja i vreme zaplene su važni |
| Ljudski/fizički dokazi | povezivanje digitalnog događaja sa mestom/operatorom | invazivno, zavisi od jurisdikcije i zahteva strogo rukovanje |

Nijedan pojedinačni red ne bi trebalo da bude dovoljan za pripisivanje državnom akteru sa visokim nivoom pouzdanosti. Koristite konkurentne hipoteze i navedite koje bi zapažanje opovrglo svaku od njih.

## Minimalna telemetrija

1. **DNS:** klijent, pitanje, tip, odgovori, TTL, response code, resolver i vremenska oznaka.
2. **Network flow:** izvor/destinacija/port, početak/kraj, paketi/bytes, TCP flags i lokacija senzora.
3. **TLS/HTTP:** SNI kada je vidljiv, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status i broj bytes. Zaštitite osetljive pune URL-ove.
4. **Identity:** rezultat autentifikacije, factor/certificate/device, izvor, aplikacija, session ID i risk decision.
5. **Endpoint:** proces koji pokreće radnju, parent, user, binary signature/hash i destinacija.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface i flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token i result.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP i posture.

Sinhronizujte satove, čuvajte originalne vremenske zone, dokumentujte NAT/proxy granice i zadržite dovoljno istorije da nadživi ORB node star 31 dan.

## Izgradnja attribution graph-a

Predstavite zapažanja kao tipizirane nodes i edges:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Korisni čvorovi obuhvataju IP, prefiks, ASN, domen, DNS nalog, sertifikat/ključ, fingerprint sličan JA3/JA4, HTTP gramatiku, hash fajla/konfiguracije, cloud tenant, API token, e-mail, personu, instrument plaćanja i fizički uređaj. Svaka veza mora da sadrži `first_seen`, `last_seen`, senzor/izvor, nivo pouzdanosti i podatak o tome da li je opažena ili izvedena.

Sama gustina grafa može da zavara: CDN ili sertifikaciono telo povezuje mnoge nepovezane aktere. Retke odnose pod kontrolom operatora—isti API nalog, SSH ključ, origin allowlist, jedinstveno telo odgovora ili kontrolni protokol—treba vrednovati više nego uobičajeni hosting.

## Lov na ORB i kompromitovane rutere

### Na osnovu uočene izlazne tačke

1. Utvrdite da li adresa pripada hosting, residential, mobilnoj, obrazovnoj ili poslovnoj mreži; nemojte odbaciti residential izvore.
2. Preuzmite istorijski DNS, servise/sertifikate, otvorene portove i uočeno ponašanje pri skeniranju/eksploataciji za ograničeni period.
3. Pretražite peer-ove koji dele retke service fingerprint-e, odredišta kontrolera, materijal sertifikata ili vreme rotacije.
4. Klasifikujte verovatne uloge: pristup, traversal, izlaz/staging ili administracija.
5. Proverite da li je više nepovezanih intrusion klastera koristilo isti pool; multi-tenancy slabi direktnu atribuciju aktera, ali jača ORB hipotezu.
6. Pratite nove čvorove koji odgovaraju profilu uloge nakon što stari IP-ovi nestanu.

### Kod vlasnika mreže

- Upozoravajte na novo upravljanje izloženo Internetu i podrazumevanu/legacy autentikaciju.
- Promene konfiguracije rutera/firewall-a i administratorsku autentikaciju šaljite van uređaja.
- Napravite baseline izlaznih konekcija iz infrastrukture koja obično pokreće mali broj sesija.
- Detektujte nove proxy/listener procese, tunele, scheduled tasks, promene firmware-a i neočekivani DNS.
- Zamenite uređaje kojima je istekao životni vek; reboot kojim se uklanja volatile malware ne rešava izloženost.
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
Istražite domene pomoću više nezavisnih karakteristika, a ne na osnovu jednog praga. Uporedite ih sa allow-modelom za CDN/anti-DDoS i proverite rotaciju autoritativnih name-servera kako biste razlikovali single od double flux-a. Za DGA-ove dodajte NXDOMAIN burst-ove po klijentu, distribuciju dužine/broja karaktera, sinhronizovane upite između hostova i proces koji ih generiše. MITRE-ove aktuelne smernice takođe naglašavaju promene visoke učestalosti, nizak TTL i korelaciju procesa i mreže.<sup>[[2]](#references)</sup>

## Detekcija Domain-fronting-a

Tamo gde enterprise endpoint ili ovlašćena inspection tačka imaju oba identiteta, uporedite:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Povećajte nivo pouzdanosti kada SNI i authority pripadaju nepovezanim tenantima, proces nije odobreni client, sesija je periodična/dugotrajna, a unutrašnji origin je redak. Prazan SNI je karakteristika koju treba zabeležiti, a ne automatski smatrati zlonamernom. ECH može sakriti SNI na mreži, pa endpoint, DNS i provider/CDN logovi postaju važniji. MITRE dokumentuje i varijante sa nepodudarnim i praznim SNI-jem.<sup>[[3]](#references)</sup>

## Detekcija sekvence dead-drop resolvera

Ponašanje sa visokim nivoom signala predstavlja sekvencu, a ne blokirani domen:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Pretražite čitavu flotu u potrazi za identičnim putanjama objekata, hash vrednostima odgovora, API identifikatorima i odredištima za nastavak aktivnosti. Sačuvajte preuzeti sadržaj jer akter može da ga izmeni ili obriše. Ograničite nepotrebne service API-je i zahtevajte da odobrene aplikacije koriste enterprise proxy-je, ali uzmite u obzir developerske alate i automatizaciju. MITRE u stvarnim procedurama navodi GitHub, forume, dokumente i social/web servise.<sup>[[4]](#references)</sup>

## Grupisanje Redirector-a i ponovljivih deployment-a

Čak i kada se domeni i adrese promene, operatori često ponovo deploy-uju istu automatizaciju. Grupisanje zasnivajte na kombinacijama sledećih karakteristika:

- polja sertifikata/ponovna upotreba ključa i vreme izdavanja;
- TLS verzija/cipher/redoslеd ekstenzija i ponašanje servera;
- identičan HTTP status, redosled header-a, ponašanje cache-a, favicon/body i error stranica;
- neuobičajeni parovi portova i redirect lanci;
- obrazac DNS provider-a/name server-a i raspored TTL vrednosti;
- vreme deployment-a, uptime i period održavanja;
- izloženost back-end origin-a ili identične allowliste.

Jedna generička Nginx stranica predstavlja slabe dokaze. Više retkih, nezavisnih podudaranja uz vremenski kontinuitet može opravdati hipotezu o infrastructure cluster-u.

## Detekcija Residential proxy-ja i nemogućih sesija

Održavajte identitet sesije iznad IP sloja. Označite kombinacije kao što su:

- fingerprint jedne sesije/uređaja menja zemlje/ASN-ove brže nego što putovanje dozvoljava;
- consumer IP se menja pri svakom request-u, dok cookies i TLS/browser identitet ostaju nepromenjeni;
- navedeni lokalni uređaj ima latency/time-zone/language koji nisu u skladu sa izlaznom adresom;
- adresa naizmenično koristi nepovezane populacije naloga ili pokazuje backconnect proxy ponašanje;
- privilegovana sesija se pojavljuje sa residential pristupa bez device sertifikata organizacije.

Carrier NAT, accessibility alati, corporate VPN-ovi i putovanja stvaraju benigne anomalije. Zahtevajte step-up authentication ili istragu umesto nepovratnog blokiranja zasnovanog isključivo na oznakama „residential proxy“.

## Detekcija Wireless i prikrivenih uređaja

Povežite RADIUS/NAC sa AP-om i fizičkim kontekstom:

1. pronađite prvi put viđene kombinacije nalog–uređaj–AP;
2. identifikujte credentials korišćene bez upravljanog EAP sertifikata/posture-a;
3. uporedite istovremene sesije i prisustvo u zgradi prema badge podacima;
4. proverite neuobičajeno slab/granični signal i kretanje između AP-ova;
5. potražite na obližnjim upravljanim endpoint-ima wireless scanning, novouključen interface bridge/NAT, virtual adapters ili tunnels;
6. evidentirajte novu switchport, DHCP, USB network i PoE aktivnost;
7. obavite odobren RF/fizički pregled kada dokazi to podržavaju.

Ovo otkriva i APT28-style nearest-neighbor putanju i exercise drop. MAC randomizacija ne sme se tretirati kao identitet ili dokaz krivice.

## Detekcija Financial-attribution

- Sačuvajte tačan chain, token, address, transaction i block identifikatore.
- Pratite vrednost kroz change, peel chain-ove, fan-out/in, mixers, bridges i service deposits, uz označavanje heuristika.
- Korelišite vreme, iznos umanjen za fees, contract event, liquidity i withdrawal na odredišnom chain-u.
- Pribavite ili sačuvajte zakonite exchange, bridge, merchant, account, device i delivery zapise.
- Proverite aktuelne sankcionisane entitete/adrese i derivate prema važećem programu; ne oslanjajte se na staru statičku listu.
- Upotrebu privacy-protocol-a tretirajte kao ulazni podatak za procenu rizika, a ne kao dokaz protivpravnog postupanja.

Red flags organizacije FATF izričito zavise od konteksta: neuobičajeni obrazac, iznos/frekvencija, geografija, izvor sredstava i anonymity-enhancing services postaju značajni tek zajedno.<sup>[[5]](#references)</sup>

## Obmana i canary mehanizmi

Defenders mogu kreirati signale visoke pouzdanosti bez pokušaja deanonymization-a običnih korisnika:

- jedinstveni credentials ili dokumenti koji nikada ne bi smeli napustiti jedan sistem;
- lažni administrativni endpoint-i i decoy share-ovi;
- instrumentovani DNS nazivi ugrađeni samo u kontrolisane artefakte;
- canary cloud ključevi bez legitimne upotrebe;
- decoy Wi-Fi identitet koji nijedan upravljani uređaj ne poseduje.

Pažljivo ograničite i upravljajte deception mehanizmima. Canary treba da identifikuje zloupotrebu sopstvenog asset-a defender-a, a ne da prikuplja nepovezan saobraćaj trećih strana.

## Prioriteti countermeasure-a

1. Uklonite router-e, VPN-ove i appliance-e izložene Internetu koji nisu podržani.
2. Zahtevajte phishing-resistant MFA i device-bound sertifikate, uključujući interni/wireless pristup.
3. Centralizujte dovoljno immutable identity, endpoint, DNS, flow, proxy, cloud i network-device logove.
4. Ograničite management i egress; evidentirajte svaki externally reachable service.
5. Nadgledajte DNS, certificate transparency i cloud konfiguraciju radi neovlašćenih asset-a.
6. Obezbedite SaaS vidljivost na nivou procesa–mreže i objekta.
7. Vežbajte cross-layer istrage i koordinaciju sa susednim provider-ima.
8. Pratite infrastructure cluster-e i ponašanja, a ne samo IP blocklist-e.

## Analitička disciplina

Koristite jezik nivoa pouzdanosti:

- **Observed:** zapis senzora/provider-a direktno pokazuje odnos.
- **Strongly supported:** više nezavisnih zapažanja daje prednost toj opciji u odnosu na alternative.
- **Assessed:** zaključak zasnovan na navedenim pretpostavkama i dokazima.
- **Unknown:** nedostatak vidljivosti onemogućava zaključak.

Uvek zadržite najmanje dve hipoteze: infrastructure kojom upravlja akter nasuprot kompromitovanom/deljenom posredniku; jedan akter nasuprot multi-tenant servisu; namerna evazija nasuprot legitimnom privacy/CDN ponašanju. Sposobnost objašnjavanja neizvesnosti deo je ispravne detekcije.

## References

- [1] [Google Cloud/Mandiant — Špijunski akteri povezani sa Kinom koriste ORB mreže](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Indikatori upozorenja za Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Akteri iz NR Kine kompromituju i održavaju perzistentan pristup](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Smernice za unapređenu vidljivost i hardening communications infrastructure](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
