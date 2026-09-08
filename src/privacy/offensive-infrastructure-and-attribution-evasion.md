# Ofanzivna infrastruktura i izbegavanje atribucije

Operater retko dobija značajnu anonimnost korišćenjem samo jednog proxy-ja. Stvarne kampanje grade **graf razdvajanja**: operater dolazi do pristupnog čvora, tranzitni čvorovi skrivaju taj čvor od izlaza, redirectors štite stvarni C2, a jednokratna imena upućuju na javnu ivicu.

Koristite [Katalog tehnika anonimnog pristupa Internetu](anonymous-internet-access-techniques.md) za standardizovani pregled prednosti/mana, implementacije i detekcije svake putanje. Ova stranica detaljnije obrađuje kompoziciju adversarijalne infrastrukture.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Poslednja adresa koju meta vidi stoga predstavlja dokaz o putanji, a ne dokaz o tome ko je upravljao tastaturom. MITRE glavne komponente mapira na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klase infrastrukture

| Klasa | Zašto je akter koristi | Trajna izloženost | Najbolja tačka za pivot za branioca |
|---|---|---|---|
| Iznajmljeni VPS/cloud | Brzi, predvidljivi, rutabilni i laki za ponovnu izgradnju | zakupac, naplata, konzola, prijave sa izvora i istorija image-a | događaji naloga/control-plane-a i ponavljajući server fingerprint |
| Commercial VPN/Tor | Veliki skup zajedničkih izlaza; nije potrebno administriranje servera | vidljivost provajdera/guard-a i end-to-end vremenska korelacija | ponašanje odredišta, dokazi sa endpointa i korelacija protoka |
| Residential/mobile proxy | Potrošački ASN i geografska uverljivost | evidencije brokera/korisnika; proxyware ili ponašanje zaraženog hosta | nemoguće putovanje, proxy protokoli i promena adresa po sesiji |
| Compromised server/router/IoT | Pozajmljuje reputaciju žrtve i njenu jurisdikciju | implant, tok upravljanja i ponavljajući upstream kontroler | telemetrija uređaja i ORB topologija, a ne jedna izlazna IP adresa |
| CDN/redirector | Razdvaja javni edge od back-end C2 | TLS/HTTP gramatika, sertifikat, rutiranje i artefakti cloud naloga | korelacija edge-a sa originom i klasterovanje oblika zahteva |
| Legitimni web servis | Uklapa se u dozvoljeni GitHub/cloud/social saobraćaj | API token, identifikatori tenant-a/objekta i neuobičajena procesna genealogija | proces na endpointu zajedno sa semantikom servisa/API-ja |
| Fizička/cellular/satelitska putanja | Menja prividno fizičko poreklo | RF, carrier, pretplatnički, uređajski i lokacijski zapisi | kombinovani radio/fizički i mrežni dokazi |

## Mreže operativnih relay box-eva

**ORB network** je upravljani proxy fleet koji se koristi kao posredni servis. Mandiant ih deli na provisioned networks sa iznajmljenim serverima, non-provisioned networks sa kompromitovanim ruterima/IoT uređajima i hibride. Zrela topologija ima četiri logičke uloge:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** održava inventar, kredencijale, stanje i politiku rutiranja.
2. **Access/relay node:** autentifikuje klijente ili operatore; predstavlja stabilnu ulaznu tačku u promenljivu mesh mrežu.
3. **Traversal nodes:** jedan ili više iznajmljenih ili kompromitovanih sistema prosleđuju opaque connections.
4. **Exit/staging node:** predstavlja konačnu izvornu adresu sistemima koji vrše izviđanje, exploitation ili C2 ciljevima.

Mesh može birati exit čvorove prema zemlji, ASN-u, latenciji ili dostupnosti i rotirati neispravne čvorove. Više threat grupa može iznajmljivati istu mrežu. Mandiant je uočio da je IPv4 adresa ostajala povezana sa nekim ORB-ovima najmanje 31 dan; zato preporučuje da se **mreža posmatra kao evoluirajući entitet nalik akteru**, umesto da se blokira zastarela lista IP adresa.<sup>[[2]](#references)</sup>

### Šta ovo omogućava — i šta otkriva

- Meta vidi exit koji može biti geografski blizu i naizgled residential.
- Exit vidi metu i prethodni hop, ali ne nužno i operatora.
- Access servis vidi klijenta i zahtev za rutiranje. Nezavisno upravljani mesh može držati klijenta odvojenim od exit čvorova, ali stvara moćan zapis o drugoj strani.
- Ponavljajući portovi, redosled handshake-a, server banneri, sertifikati, periodi dostupnosti i odnosi sa kontrolerima mogu otkriti fleet čak i dok se IP adrese rotiraju.
- Kompromitovanom ruteru često nedostaje endpoint telemetrija, ali njegov ISP i dalje poseduje pretplatničke podatke i podatke o protoku; zaplena otkriva artefakte implanta/konfiguracije.

{% hint style="info" %}
Za autorizovanu vežbu reprodukujte topologiju pomoću VM-ova ili rutera u vlasništvu organizacije i sačuvajte attribution map kontrolera. Nemojte angažovati open proxy-je ili uređaje trećih strana. [Lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) kreira istu hop strukturu vidljivu braniocu, bez viktimizacije posrednika.
{% endhint %}

## Residential i mobile proxy mreže

Residential proxy servisi dodeljuju sesije adresama potrošačkog broadband-a; mobile proxy-ji izlaze kroz carrier NAT skupove. Izvori mogu biti namenski prijavljeni uređaji, SDK/proxyware ugrađen u potrošačke aplikacije, reseller-i ili malware. Ova porekla nisu ekvivalentna: nedostatak informisanog pristanka pretvara privacy servis u kompromitovanu infrastrukturu.

Načini rotacije utiču na detekciju:

- **per-request rotation** proizvodi brze diskontinuitete IP adrese i ASN-a/geografije, dok identitet na višem sloju ostaje stabilan;
- **sticky sessions** zadržavaju exit od nekoliko minuta do nekoliko sati, nalik uobičajenom pretplatniku;
- **backconnect gateways** klijentu izlažu jednu broker endpoint adresu, dok interno biraju exit čvorove;
- **mobile pools** postavljaju veliki broj stvarnih pretplatnika iza malog skupa carrier NAT adresa, zbog čega je IP blokiranje skupo.

Branioci treba da korelišu IP sa autentifikovanom sesijom, TLS/client fingerprint-om, HTTP redosledom, device cookie-jem i ponašanjem. Navodno lokalna residential prijava, praćena drugom zemljom dok sve karakteristike višeg sloja ostaju identične, predstavlja jači signal od same reputacije. Nasuprot tome, deljenje adresa i mobile handoff stvaraju legitimnu promenljivost, zato residential/proxy klasifikaciju nikada ne treba tretirati kao konačnu presudu.

## Multi-hop proxy lanci

MITRE razlikuje external proxies od **multi-hop proxies (T1090.003)**. Važna osobina nije broj hop-ova, već razdvajanje znanja i administracije.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Ako jedna strana upravlja sistemima A i B, deljeni logovi ili vremensko usklađivanje protoka mogu rekonstruisati circuit. Dodavanje uzastopnih komercijalnih VPN-ova sa iste endpoint/adrese ili naloga može povećati latenciju, a da pritom ostavi zajednički identitet, podatke o plaćanju i vremenske dokaze. Tor smanjuje ovaj problem nezavisno odabranim relay-ima i deljenim dizajnom klijenta, ali interaktivna mreža sa malom latencijom ne može obećati otpornost na posmatrača koji meri oba kraja.

Uobičajeni propusti su DNS ili IPv6 bypass, aplikacije koje same otvaraju sockets, management saobraćaj koji direktno dolazi do relay-a, sinhronizovana aktivnost, ponovna upotreba SSH ključeva i prijavljivanje na naloge koji otkrivaju identitet. Ispravna verifikacija je failure test: zaustavite svaki relay redom i pokažite da workload ne može da pređe na clear path.

## Redirector slojevi i oblikovanje saobraćaja

Javni **redirector** prihvata saobraćaj koji odgovara gramatici specifičnoj za operaciju i prosleđuje ga zaštićenom team serveru. Sve ostalo može biti odbijeno ili mu se može poslužiti bezopasan sadržaj.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Više nivoa ograničava izloženost: ukidanje javnog domena ne mora da otkrije team server. CDN-ovi dodaju anycast kapacitet i ugledan spoljašnji domen, ali CDN nalog i edge logovi postaju tačke atribucije. TLS fingerprints, istorije sertifikata, karakteristične putanje/redosled zaglavlja, veličine odgovora, ponašanje preusmeravanja i origin allowlists mogu grupisati navodno nepovezane frontove.

Za detekciju, zabeležite polja reverse-proxy-ja pre normalizacije, uporedite SNI/Host/authority, pregledajte retke kombinacije zaglavlja, grupišite tela odgovora i TLS fingerprints i pretražite cloud/CDN audit logove zbog preklapanja konfiguracije. Za ovlašćene red team operacije izbegavajte kopiranje stvarnog brenda ili postavljanje prikupljanja akreditiva iza nepovezane treće strane.

## Domain fronting i domainless fronting

Kod klasičnog **domain fronting (T1090.004)**, TLS veza oglašava dozvoljeni front domen u SNI-ju, dok šifrovani HTTP `Host` ili HTTP/2 `:authority` zahtevaju drugi back-end domen. Saradnički CDN rutira na osnovu unutrašnje vrednosti. Mrežni posmatrač bez TLS dešifrovanja vidi front; CDN vidi obe vrednosti i origin. Kod domainless varijanti, SNI može biti prazan, dok drugo polje za rutiranje bira odredište.<sup>[[4]](#references)</sup>

Ovo nije magično lažno predstavljanje: funkcioniše samo kada posrednik namerno ili slučajno dozvoljava nepodudaranje i zna kako da rutira unutrašnje ime. Veliki provajderi su ograničili fronting između naloga. Encrypted ClientHello (ECH) menja ono što posmatrač na putanji može da vidi, ali ne uklanja CDN, endpoint ili application zapise.

Tačke za detekciju obuhvataju:

- ancestry procesa endpointa i odredište koje nije očekivano za tu aplikaciju;
- nepodudaranje SNI-ja i HTTP authority-ja tamo gde je TLS inspekcija zakonita i dostupna;
- CDN logove koji pokazuju da jedan tenant/front rutira ka drugom authority/origin-u;
- neuobičajene dugotrajne ili periodične sesije ka servisu koji je obično interaktivan;
- stabilne veličine i učestalost šifrovanih tokova kroz promenljive front domene.

Bezbedna laboratorija simulira nepodudaranje rutiranja na reverse proxy-ju u vlasništvu organizacije; ne zloupotrebljava javni CDN.

## Dynamic resolution: DDNS, DGA i fast flux

Dynamic resolution odvaja logički servis od fiksne infrastrukture:

- **DDNS:** autentifikovani klijent ažurira stabilno ime nakon promene svoje adrese.
- **DGA:** endpoint i kontroler izvode kandidate za imena domena iz vremenskog/ključnog seed-a; operator registruje mali podskup.
- **Fast flux:** ime vraća brzo promenljiv skup kompromitovanih/proxy adresa, često sa niskim TTL-ovima.
- **Double flux:** rotiraju se i servisne adrese i adrese authoritative name servera, čime se skriva i control layer.

Fast flux je obrazac distribucije opterećenja koji se koristi adversarialno, a ne samo „mnogo DNS odgovora“. Jači dokazi kombinuju nizak TTL, veliki broj jedinstvenih adresa, široku ASN/geografsku disperziju, kratak životni vek čvorova, ponovljeno application ponašanje i sumnjivu istoriju registracije. CDN-ovi legitimno dele nekoliko tih osobina. MITRE preporučuje korelisanje DNS ponašanja sa procesom i narednim vezama.<sup>[[5]](#references)</sup>

DGA se može detektovati pomoću leksičke entropije, obrazaca suglasnika/cifara, NXDOMAIN naleta, sinhronizovanih first-seen domena i konteksta procesa. Wordlist DGA i generativni modeli zaobilaze jednostavna pravila entropije, zbog čega klasterovanje kroz vreme na nivou cele flote i lineage endpointa postaju važniji.

## Kompromitovani domeni i domain shadowing

Akter može oteti registrar/DNS nalog, preuzeti napušteni poddomen ili dodati zapise ispod inače uglednog domena. **Domain shadowing** zadržava legitimni apex, dok veliki broj poddomena pod kontrolom napadača pokazuje ka promenljivim delivery ili C2 hostovima. Pozajmljuje starost i reputaciju i može zaobići blokiranje na nivou celog domena.<sup>[[6]](#references)</sup>

Defenderima su potrebni audit logovi registrara i authoritative DNS-a, MFA, registry/registrar locks, upozorenja za nove delegacije/API tokene/name servere, praćenje certificate transparency-ja i inventar cloud resursa na koje DNS upućuje. Nezavisno od reputacije apex-a istražite rezoluciju i istoriju sertifikata poddomena.

## Web services i dead-drop resolvers

**Dead-drop resolver (T1102.001)** čuva kodirani pokazivač na aktuelni C2 unutar legitimne objave, profila, dokumenta, repozitorijuma, cloud objekta ili blockchain polja. Malware preuzima javni objekat, dekodira domen/IP i kontaktira sledeću fazu. Bidirectional varijante razmenjuju komande ili fajlove kroz service API-je.<sup>[[7]](#references)</sup>

Ovo pruža otpornost i skriva back-end C2 od statičke analize binarnog fajla. Takođe stvara stabilne identifikatore objekta, tenanta, repozitorijuma, API-ja i obrazaca pristupa. Defenderi treba da povežu:

1. proces koji je kontaktirao servis;
2. tačnu API putanju/objekat i hash odgovora;
3. aktivnost dekodiranja ili obrade stringova;
4. novu outbound vezu ubrzo nakon toga; i
5. identično ponašanje na drugim sistemima u floti.

Blokiranje celog GitHub-a, cloud storage-a ili društvenih mreža retko je izvodljivo. Service-aware egress policy i korelacija na nivou procesa uspešniji su od blokiranja samo na osnovu domena.

## Personae, nalozi i nabavni compartmenti

Anonymity infrastrukture pada kada persona, recovery email, telefon, plaćanje, browser ili admin IP poveže compartmente. Operacije povezane sa državama razvijale su social profile, email identitete i cloud naloge mnogo pre njihove upotrebe; ATT&CK ovo beleži kao Establish Accounts (T1585), uključujući social, email i cloud sub-techniques.<sup>[[8]](#references)</sup>

Defender ili istražitelj gradi graf iz:

- vremena kreiranja i prve prijave, lokalizacije, vremenske zone i rasporeda rada;
- recovery polja, MFA uređaja, identifikacionih dokumenata i sredstava plaćanja;
- browser/TLS fingerprints i istorije izvorne mreže;
- ponovne upotrebe avatara, porekla slika, stila pisanja i rasta društvenog grafa;
- zajedničkog domen registranta, name servera, sertifikata, analytics ID-ja ili commit-a repozitorijuma;
- radnji na management plane-u koje zaobilaze javnu relay arhitekturu.

Za ovlašćeni red team, sintetičke persone treba dokumentovati kontroloru vežbe, koristiti recovery/payment kanale u vlasništvu organizacije, izbegavati predstavljanje kao stvarne nepovezane osobe i imati planirano povlačenje. SOC može ostati slep; operacija ne sme postati bez odgovornosti.

## Emerging compound patterns za threat-model

Sledeće su **defender-driven compositions**, a ne tvrdnje da je neki imenovani akter primenio svaki tačan dizajn. Kombinuju već uočene primitive i korisne su kao purple-team hipoteze.

### Asymmetric one-way tasking

Komande pristižu kroz javni, broadcast ili append-only izvor, dok rezultati izlaze kroz nepovezan kanal sa odlaganjem. Primeri primitive obuhvataju web-service one-way communication i dead drop-ove. Razdvajanje sprečava da jedan tok izgleda bidirekciono i otežava jednostavnu korelaciju zahteva i odgovora.<sup>[[9]](#references)</sup>

**Detekcija:** sačuvajte čitanja na nivou objekta, zatim korelišite promene stanja procesa i kasnije outbound transfere kroz širi vremenski prozor. Tražite redak proces koji čita isti javni objekat čak i kada neposredan odgovor ne usledi.

### Multi-stage channel promotion

Tiha prva faza obavlja inventarizaciju i samo odabrane sisteme promoviše na nepovezan kanal druge faze. Drugi endpoint, protokol i proces možda ne dele nikakvu infrastrukturu sa prvim. Ovo ograničava izloženost sposobne infrastrukture i eksplicitno je modelovano kao ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detekcija:** povežite `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; ne zatvarajte incident nakon blokiranja prvog domena.

### Cross-protocol relay translation

Različiti hopovi prevode HTTPS, QUIC, WebSocket, DNS, SSH ili message-queue API, umesto da transparentno prosleđuju pakete. Prevođenje uklanja jedan end-to-end fingerprint protokola, ali stvara gateway-e sa karakterističnim vremenom, baferovanjem i semantičkom konverzijom. Protocol tunneling (T1572) može se kombinovati sa proxy-jima i service impersonation-om.<sup>[[11]](#references)</sup>

**Detekcija:** tražite gateway hostove koji primaju jedan protokol i pokreću drugi uz čvrsto povezano ponašanje u bajtovima/vremenu; uporedite nameru endpointa sa protokolom koji se stvarno prenosi.

### Passive activation on edge devices

Umesto beaconing-a, implant prati saobraćaj koji već stiže do router/VPN-a i aktivira se samo na magic value, obrazac source-port-a ili autentifikovani token. Normalan saobraćaj nastavlja ka stvarnom servisu. ATT&CK ovo naziva Traffic Signaling (T1205), sa dokumentovanim primerima network-device i APT upotrebe.<sup>[[12]](#references)</sup>

**Detekcija:** integritet firmware-a/fajlova, raw packet capture tokom ovlašćenog hunt-a, neočekivani socket filteri i diferencijalno ponašanje servisa. Odsustvo periodičnog beacon-a ne dokazuje da je edge uređaj čist.

### Serverless i ephemeral origin rotation

Front zadržava stabilan logički identitet, dok kratkotrajne funkcije/kontejneri obrađuju pojedinačne faze u više regiona/naloga. Ovo smanjuje životni vek na disku i broj fiksnih origin IP adresa, ali control-plane kreiranje, image/layer, role, secret, request ID i billing telemetry postaju trajni graf.

**Detekcija:** zadržite cloud audit i invocation logove izvan workload-a; grupišite deployment templates, role, environment keys i veze front-to-origin.

### Privacy-layer diversity

Operacija može namerno izbegavati jedan homogeni lanac: na primer, jedan kanal koristi iznajmljeni relay, tasking koristi javni objekat, izlaz dolazi sa cellular link-a u vlasništvu organizacije, a administracija koristi zasebnu mrežu organizacije. Ovo smanjuje vrednost kompromitovanja jednog provajdera, ali povećava rizik od korelacije vremena između slojeva i operativnih grešaka.

**Detekcija:** izgradite timeline kampanje kroz identity, DNS, SaaS, network i cloud senzore. Tražite sinhronizovane promene stanja, a ne identične indikatore.

### Decentralized ili transparency-log dead drops

Akter može postaviti mali šifrovani pokazivač u bilo koji trajni javni append-only sistem, content-addressed store ili transparency-like feed. Javni objekat je otporan, ali njegov tačan indeks/content hash i ponašanje klijenta pri polling-u postaju stabilni identifikatori.

**Detekcija:** beležite pune API/object identifikatore i hash-eve odgovora; upozoravajte na nestandardne procese koji obavljaju polling immutable objekata, nakon čega slede dekodiranje ili nove veze.

### Delayed store-and-forward operations

Interaktivni C2 stvara snažnu vremensku korelaciju. Store-and-forward dizajn grupiše šifrovane zadatke i vraća rezultate nekoliko minuta ili sati kasnije kroz drugi queue ili fizički prenos. Odriče se odziva radi slabijeg end-to-end vremenskog signala.

**Detekcija:** produžite prozore korelacije, modelujte periodični pristup queue-u i ispitajte endpoint staging. Grupisanje pomera signal sa vremenskog obrasca paketa na zakazano ponašanje procesa/fajla; ne uklanja ga.

## Design review: razmišljajte u terminima posmatrača

Za svaki put popunite ovu tabelu pre deployment-a i nakon prikupljanja:

| Sloj | Vidi source? | Vidi destination? | Vidi content? | Stabilni identifikatori | Vlasnik retention-a/prava |
|---|---:|---:|---:|---|---|
| lokalna mreža/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(i) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Ako jedan uobičajeni provajder može popuniti svaku kolonu, arhitektura pruža prikrivanje od targeta, ali ne i robusno razdvajanje. Ako nijedan interni kontrolor ne može povezati aktivnost sa angažmanom, arhitektura nije pogodna za profesionalni red teaming.

## References

- [1] [MITRE ATT&CK — Nabavka infrastrukture (T1583), kompromitovanje infrastrukture (T1584) i Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus špijunski akteri koriste ORB mreže](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Kompromitovanje infrastrukture: domeni (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
