# Ofanzivna infrastruktura i izbegavanje atribucije

{{#include ../banners/hacktricks-training.md}}

Operater retko dobija značajnu anonimnost korišćenjem samo jednog proxy-ja. Stvarne kampanje grade **graf razdvajanja**: operater pristupa access node-u, traversal nodes skrivaju taj node od izlaza, redirectors štite stvarni C2, a jednokratna imena upućuju na javnu ivicu.

Koristite [Katalog tehnika anonimnog pristupa Internetu](anonymous-internet-access-techniques.md) za standardizovani pregled prednosti/mana, implementacije i detekcije svakog puta. Ova stranica detaljnije obrađuje kompoziciju adversarijalne infrastrukture.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Poslednja adresa koju meta vidi stoga predstavlja dokaz o putanji, a ne dokaz o tome ko je upravljao tastaturom. MITRE glavne komponente mapira na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klase infrastrukture

| Klasa | Zašto je actor koristi | Trajna izloženost | Najbolji pivot za defendera |
|---|---|---|---|
| Iznajmljeni VPS/cloud | Brz, predvidiv, rutabilan i lak za ponovnu izgradnju | tenant, billing, console, source-login i istorija image-a | account/control-plane događaji i ponovljeni server fingerprint |
| Commercial VPN/Tor | Veliki deljeni izlazni skup; nema administracije servera | vidljivost provider-a/guard-a i end-to-end timing | ponašanje odredišta, endpoint dokazi i korelacija flow-a |
| Residential/mobile proxy | Consumer ASN i geografska uverljivost | evidencije brokera/korisnika; proxyware ili ponašanje zaraženog hosta | impossible travel, proxy protokoli i promena adrese po sesiji |
| Compromised server/router/IoT | Pozajmljuje reputaciju žrtve i jurisdikciju | implant, management flow i ponovljeni upstream controller | telemetry uređaja i ORB topologija, a ne jedna exit IP adresa |
| CDN/redirector | Razdvaja javni edge od back-end C2 | TLS/HTTP gramatika, certificate, routing i cloud-account artifacts | korelacija edge-to-origin i klasterizacija request-shape-a |
| Legitimate web service | Uklapa se u dozvoljeni GitHub/cloud/social saobraćaj | API token, tenant/object identifiers i neuobičajena process lineage | endpoint proces plus service/API semantika |
| Physical/cellular/satellite path | Menja prividno fizičko poreklo | RF, carrier, subscriber, device i location zapisi | kombinovani radio/fizički i network dokazi |

## Mreže operativnih relay box-eva

**ORB network** je upravljana proxy flota koja se koristi kao posredna usluga. Mandiant ih deli na provisioned networks iznajmljenih servera, non-provisioned networks kompromitovanih router-a/IoT uređaja i hibride. Zrela topologija ima četiri logičke uloge:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** održava inventar, credentials, health i routing policy.
2. **Access/relay node:** autentifikuje korisnike ili operatore; predstavlja stabilnu ulaznu tačku u promenljivu mesh mrežu.
3. **Traversal nodes:** jedan ili više iznajmljenih ili kompromitovanih sistema prosleđuju opaque connections.
4. **Exit/staging node:** predstavlja konačnu source adresu izviđanju, exploitation-u ili C2 metama.

Mesh može birati exit-e prema zemlji, ASN-u, latenciji ili dostupnosti i menjati nezdrave node-ove. Više threat grupa može iznajmljivati istu mrežu. Mandiant je uočio da IPv4 adresa ostane povezana sa nekim ORB-ovima svega 31 dan; zato preporučuje da se **mreža tretira kao entitet koji se razvija nalik actor-u**, umesto da se blokira zastarela lista IP adresa.<sup>[[2]](#references)</sup>

### Šta ovo omogućava — i šta odaje

- Meta vidi exit koji može biti geografski blizu i naizgled residential.
- Exit vidi metu i prethodni hop, ali ne nužno operatora.
- Access service vidi customer-a i zahtev za rutom. Nezavisno upravljani mesh može držati customer-a odvojeno od exit-a, ali time stvara moćan zapis o counterpart-yju.
- Ponovljeni portovi, redosled handshake-a, server banner-i, certificate-i, uptime window-i i controller odnosi mogu otkriti flotu čak i kada se IP adrese rotiraju.
- Kompromitovanom router-u često nedostaje endpoint telemetry, ali njegov ISP i dalje poseduje subscriber i flow podatke; zaplena otkriva implant/configuration artifacts.

{% hint style="info" %}
Za autorizovanu vežbu reprodukujte topologiju pomoću VM-ova ili router-a u vlasništvu organizacije i sačuvajte attribution map controller-a. Nemojte angažovati open proxy-je ili uređaje trećih strana. [Lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) kreira istu hop strukturu vidljivu defenderu bez viktimizacije posrednika.
{% endhint %}

## Residential i mobile proxy mreže

Residential proxy servisi dodeljuju sesije adresama consumer broadband-a; mobile proxy-ji izlaze kroz carrier NAT pool-ove. Supply može poticati od izričito uključenih appliance-a, SDK/proxyware-a ugrađenog u consumer aplikacije, reseller-a ili malware-a. Ova porekla nisu ekvivalentna: nedostatak informisanog pristanka pretvara privacy service u compromised infrastructure.

Načini rotacije utiču na detection:

- **per-request rotation** proizvodi brze diskontinuitete IP adrese i ASN-a/geografije, dok identitet na višem sloju ostaje stabilan;
- **sticky sessions** zadržavaju exit nekoliko minuta ili sati, nalik uobičajenom subscriber-u;
- **backconnect gateways** customer-u izlažu jednu broker endpoint adresu, a exit-e biraju interno;
- **mobile pools** postavljaju veliki broj stvarnih subscriber-a iza malog broja carrier NAT adresa, zbog čega je IP block skup.

Defenderi treba da korelišu IP adresu sa authenticated session-om, TLS/client fingerprint-om, HTTP ordering-om, device cookie-jem i ponašanjem. Navodno lokalni residential login praćen drugom zemljom, dok sve karakteristike višeg sloja ostaju identične, predstavlja jači signal od same reputacije. Nasuprot tome, deljenje adresa i mobile handoff stvaraju legitimnu churn pojavu, zato residential/proxy klasifikaciju nikada ne treba tretirati kao konačnu odluku.

### Proxyware control planes i preklapanje reseller-a

Residential pool ne treba modelovati kao ravnu listu exit-a. Analiza IPIDEA ecosystem-a otkrila je ponovljivi **two-tier control plane**: ugrađeni SDK najpre šalje device/enrollment metadata Tier One domenu i dobija scheduling, kao i Tier Two `connect`/`proxy` IP:port parove. Node periodično proverava Tier Two connect port radi encoded task-a, otvara drugu konekciju ka uparenom proxy port-u i prosleđuje dostavljene bajtove ka traženom odredištu. Nominalno različiti SDK-ovi i proxy brendovi imali su zasebne discovery domene, ali su se spajali na deljenu Tier Two infrastrukturu i preklapajuće exit pool-ove kroz zajedničko vlasništvo i reseller odnose.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Ovo proizvodi trajnije pivot tačke za hunting od residential IP bloka:<sup>[[13]](#references)</sup>

- neočekivani utility, VPN, game ili embedded-device proces šalje stabilni ID uređaja/customer key i prima promenljivu listu servera;
- endpoint ispituje direktan IP na neuobičajenom portu, a zatim se odmah povezuje na drugi port na istoj adresi, pre otvaranja socket-a ka novoj destinaciji;
- nekoliko prividnih brendova deli Tier Two adrese, gramatiku protokola, SDK kod ili preklapanje exit node-ova;
- različite aplikacije koje kontaktiraju različite Tier One domene primaju adrese iz istog Tier Two pool-a.

Ovo preklapanje takođe ograničava atribuciju: to što se IP adresa vidi u reklamiranom pool-u jednog vendora ne dokazuje koji reseller, customer ili threat actor ju je koristio u relevantnom trenutku. Sačuvajte vremenske oznake protoka, lineage procesa, tela Tier One odgovora i identifikatore Tier Two task-ova.<sup>[[13]](#references)</sup> U autorizovanoj vežbi ovu hijerarhiju emulirajte samo pomoću endpoint-a u vlasništvu organizacije; nikada ne uključujte consumer uređaje ili third-party proxyware.

## Lanci multi-hop proxyja

MITRE razlikuje external proxies od **multi-hop proxies (T1090.003)**. Važno svojstvo nije broj hopova, već razdvajanje znanja i administracije.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Ako jedna strana upravlja sistemima A i B, zajednički logovi ili vremensko usklađivanje saobraćaja mogu rekonstruisati circuit. Dodavanje uzastopnih komercijalnih VPN-ova sa iste endpoint/account tačke može povećati latenciju, a da pritom ostanu zajednički identitet, podaci o plaćanju i vremenski obrasci. Tor smanjuje ovaj problem nezavisno odabranim relay-ima i deljenim dizajnom client-a, ali interaktivna mreža sa niskom latencijom ne može garantovati otpornost na posmatrača koji meri oba kraja.

Česti propusti su DNS ili IPv6 bypass, aplikacije koje otvaraju sopstvene socket-e, management saobraćaj koji direktno dolazi do relay-a, sinhronizovana aktivnost, ponovo korišćeni SSH ključevi i prijavljivanje na identifikujuće account-e. Ispravna verifikacija je failure test: zaustavite svaki relay redom i pokažite da workload ne može da pređe na clear putanju.

### Kolaps tunela i curenje prema upstream-u

Relay arhitektura je često najlakše atribuirati kada zakaže. Unit 42 je dokumentovao multi-tier espionage putanju koja je koristila VPS-ove okrenute ka victim-u, relay VPS-ove, residential proxy-je, Tor i druge proxy servise; kada je tunnel izostavljen ili kolabirao, skrivena upstream infrastruktura direktno se povezivala sa relay i sistemima okrenutim ka victim-u. Ista istraga je takođe koristila X.509 certificate nakratko izložen na upstream infrastrukturi kao pivot između tier-ova.<sup>[[14]](#references)</sup>

Držite **data plane** (`victim <-> exit`) odvojenim od **control plane-a** (`operator/upstream -> relay administration`). Zadržite ingress i authentication logove na svakom tier-u kojim upravljate, istoriju certificate-a i kratke neuspešne konekcije — ne samo uspešne C2 sesije. Source koji se pojavljuje samo tokom ispada relay-a ili direktno administrira više sistema okrenutih ka victim-u jači je kandidat za upstream nego običan exit, ali njegov ASN/geolokacija i dalje predstavljaju hipotezu, a ne dokaz identiteta operatora.

Authorized lab treba da natera workload da fail closed. Za workload izolovan u Linux network namespace-u, prva ruta mora koristiti tunnel; nakon njegovog uklanjanja, i request i route lookup moraju da zakažu, umesto da izaberu fizički uplink:
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
Ponovite test za DNS i IPv6, kao i na svakoj granici relay-a. Ako bilo koja proba uspe, zabeležite stvarnu adresu interfejsa/izvornu adresu pre popravljanja policy routing-a ili firewall-a; to opažanje predstavlja attribution leak koji bi istražitelj video.

## Slojevi redirector-a i oblikovanje saobraćaja

Javni **redirector** prihvata saobraćaj koji odgovara gramatici specifičnoj za operaciju i prosleđuje ga zaštićenom team server-u. Sve ostalo može biti odbijeno ili mu se može poslužiti bezazlen sadržaj.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Više nivoa ograničava izloženost: gašenje javnog domena ne mora otkriti team server. CDN-ovi dodaju anycast kapacitet i ugledan spoljašnji domen, ali CDN nalog i edge logovi postaju tačke atribucije. TLS fingerprints, istorije sertifikata, karakteristične putanje/redosled headera, veličine odgovora, ponašanje pri redirekciji i origin allowlists mogu grupisati navodno nepovezane frontove.

Radi detekcije, zabeležite polja reverse-proxy-ja pre normalizacije, uporedite SNI/Host/authority, pregledajte retke kombinacije headera, grupišite tela odgovora i TLS fingerprints, i pretražite cloud/CDN audit logove radi preklapanja konfiguracije. Za autorizovane red team operacije izbegavajte kopiranje stvarnog brenda ili postavljanje prikupljanja kredencijala iza nepovezane treće strane.

## Domain fronting i domainless fronting

Kod klasičnog **domain fronting (T1090.004)**, TLS veza oglašava dozvoljeni front domen u SNI-ju, dok šifrovani HTTP `Host` ili HTTP/2 `:authority` zahtevaju drugi back-end domen. Saradnički CDN usmerava saobraćaj na osnovu unutrašnje vrednosti. Mrežni posmatrač bez TLS dešifrovanja vidi front; CDN vidi obe vrednosti i origin. Kod domainless varijanti, SNI može biti prazan, dok drugo polje za rutiranje bira odredište.<sup>[[4]](#references)</sup>

Ovo nije magično oponašanje: funkcioniše samo kada posrednik namerno ili slučajno dozvoljava nepodudaranje i zna kako da usmeri unutrašnje ime. Veliki provajderi su ograničili fronting između naloga. Encrypted ClientHello (ECH) menja ono što on-path posmatrač može da vidi, ali ne uklanja CDN, endpoint ili application zapise.

Tačke detekcije obuhvataju:

- ancestry endpoint procesa i odredište koje se ne očekuje za tu aplikaciju;
- nepodudaranje SNI-ja i HTTP authority-ja tamo gde je TLS inspection zakonit i dostupan;
- CDN logove koji pokazuju da jedan tenant/front usmerava saobraćaj ka drugom authority/origin-u;
- neuobičajene dugotrajne ili periodične sesije ka servisu koji je obično interaktivan;
- stabilne veličine i ritam šifrovanog toka kroz promenljive front domene.

Bezbedna laboratorija simulira nepodudaranje rutiranja na reverse proxy-ju u vlasništvu organizacije; ne zloupotrebljava javni CDN.

## Dynamic resolution: DDNS, DGA i fast flux

Dynamic resolution odvaja logički servis od fiksne infrastrukture:

- **DDNS:** autentifikovani klijent ažurira stabilno ime nakon promene svoje adrese.
- **DGA:** endpoint i kontroler izvode kandidate za imena domena na osnovu vremenskog/ključnog seed-a; operator registruje mali podskup.
- **Fast flux:** ime vraća skup brzo promenljivih adresa kompromitovanih/proxy sistema, često sa niskim TTL vrednostima.
- **Double flux:** rotiraju se i adrese servisa i adrese authoritative name servera, čime se skriva i kontrolni sloj.

Fast flux je obrazac distribucije opterećenja koji se koristi adversarno, a ne samo „mnogo DNS odgovora“. Jači dokazi kombinuju nizak TTL, veliki broj jedinstvenih adresa, široku ASN/geografsku disperziju, kratak životni vek čvorova, ponovljeno application ponašanje i sumnjivu istoriju registracije. CDN-ovi legitimno dele nekoliko tih svojstava. MITRE preporučuje korelisanje DNS ponašanja sa procesom i naknadnim konekcijama.<sup>[[5]](#references)</sup>

DGA se može detektovati pomoću leksičke entropije, obrazaca suglasnika/cifara, naleta NXDOMAIN odgovora, sinhronizovanih domena prvi put viđenih i konteksta procesa. Wordlist DGA i generativni modeli zaobilaze jednostavna pravila entropije, zbog čega su vremensko grupisanje na nivou flote i lineage endpointa važniji.

## Kompromitovani domeni i domain shadowing

Akter može oteti registrar/DNS nalog, preuzeti dangling subdomain ili dodati zapise ispod inače uglednog domena. **Domain shadowing** čuva legitimni apex, dok veliki broj subdomena pod kontrolom napadača usmerava saobraćaj ka promenljivim delivery ili C2 hostovima. Time se pozajmljuju starost i reputacija i može se izbeći blokiranje celog domena.<sup>[[6]](#references)</sup>

Braniocima su potrebni audit logovi registrar-a i authoritative DNS-a, MFA, registry/registrar locks, upozorenja za nove delegacije/API tokene/name servere, monitoring certificate transparency-ja i inventar cloud resursa na koje DNS upućuje. Rezoluciju i istoriju sertifikata subdomena istražite nezavisno od reputacije apex-a.

## Web servisi i dead-drop resolveri

**dead-drop resolver (T1102.001)** čuva kodirani pokazivač ka trenutnom C2-u unutar legitimne objave, profila, dokumenta, repository-ja, cloud objekta ili blockchain polja. Malware preuzima javni objekat, dekodira domen/IP i kontaktira sledeću fazu. Bidirectional varijante razmenjuju komande ili fajlove kroz service API-je.<sup>[[7]](#references)</sup>

Ovo obezbeđuje otpornost i skriva back-end C2 od statičke analize binarnog fajla. Takođe stvara stabilne identifikatore objekta, tenant-a, repository-ja, API-ja i obrazaca pristupa. Branioci treba da povežu:

1. proces koji je kontaktirao servis;
2. tačnu API putanju/objekat i hash odgovora;
3. aktivnost dekodiranja ili obrade stringova;
4. novu outbound konekciju ubrzo nakon toga; i
5. identično ponašanje na drugim sistemima u floti.

Blokiranje celog GitHub-a, cloud storage-a ili društvenih mreža retko je izvodljivo. Egress policy koja razume servise i korelacija na nivou procesa efikasniji su od blokiranja zasnovanog samo na domenima.

## Personae, nalozi i compartment-i nabavke

Anonymity infrastrukture pada kada persona, recovery email, telefon, plaćanje, browser ili admin IP poveže compartment-e. Operacije povezane sa državama negovale su društvene profile, email identitete i cloud naloge dugo pre njihove upotrebe; ATT&CK to beleži kao Establish Accounts (T1585), uključujući social, email i cloud sub-techniques.<sup>[[8]](#references)</sup>

Branilac ili istražitelj gradi graf na osnovu:

- vremena kreiranja i prve prijave, locale-a, vremenske zone i radnog rasporeda;
- recovery polja, MFA uređaja, identitetskih dokumenata i instrumenata plaćanja;
- browser/TLS fingerprints i istorije izvornih mreža;
- ponovne upotrebe avatara, porekla slika, stila pisanja i rasta društvenog grafa;
- zajedničkog domain registranta, name servera, sertifikata, analytics ID-ja ili repository commit-a;
- radnji u management plane-u koje zaobilaze javnu relay arhitekturu.

Za autorizovani red team, sintetičke persone treba dokumentovati kod kontrolora vežbe, koristiti recovery/payment kanale u vlasništvu organizacije, izbegavati oponašanje stvarnih nepovezanih osoba i imati planirano povlačenje. SOC može ostati slep; operacija ne sme postati bez odgovornosti.

## Novi složeni obrasci za threat-model

Sledeće su **defender-driven compositions**, a ne tvrdnje da je imenovani akter primenio svaki tačno navedeni dizajn. Oni kombinuju već uočene primitive i korisne su purple-team hipoteze.

### Asimetrično jednosmerno tasking

Komande pristižu kroz javni, broadcast ili append-only izvor, dok rezultati napuštaju sistem kroz nepovezani kanal sa zakašnjenjem. Primeri primitive obuhvataju web-service one-way communication i dead drop-ove. Razdvajanje sprečava da jedan tok izgleda dvosmerno i otežava jednostavnu korelaciju zahteva i odgovora.<sup>[[9]](#references)</sup>

**Detekcija:** sačuvajte čitanja na nivou objekta, a zatim korelišite promene stanja procesa i kasnije outbound prenose kroz širi vremenski prozor. Tražite redak proces koji čita isti javni objekat čak i kada ne sledi neposredan odgovor.

### Promocija kanala kroz više faza

Tiha prva faza vrši inventarizaciju i samo odabrane sisteme promoviše na nepovezani kanal druge faze. Drugi endpoint, protokol i proces možda nemaju zajedničku infrastrukturu sa prvim. Time se ograničava izloženost sposobne infrastrukture i eksplicitno se modeluje kao ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detekcija:** povežite `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; ne zatvarajte incident nakon blokiranja prvog domena.

### Relay translation između protokola

Različiti hop-ovi prevode HTTPS, QUIC, WebSocket, DNS, SSH ili message-queue API umesto da transparentno prosleđuju pakete. Prevođenje uklanja jedinstveni end-to-end fingerprint protokola, ali stvara gateway-e sa karakterističnim vremenom, baferovanjem i semantičkom konverzijom. Protocol tunneling (T1572) može se kombinovati sa proxy-jima i service impersonation-om.<sup>[[11]](#references)</sup>

**Detekcija:** tražite gateway hostove koji primaju jedan protokol i pokreću drugi uz tesno povezano ponašanje u bajtovima i vremenu; uporedite nameru endpointa sa protokolom koji se stvarno prenosi.

### Pasivna aktivacija na edge uređajima

Umesto beaconing-a, implant prati saobraćaj koji već stiže do router/VPN-a i aktivira se samo na magic value, obrazac izvornog porta ili autentifikovani token. Uobičajeni saobraćaj nastavlja ka stvarnom servisu. ATT&CK ovo naziva Traffic Signaling (T1205), uz dokumentovane primere mrežnih uređaja i APT operacija.<sup>[[12]](#references)</sup>

**Detekcija:** integritet firmware-a/fajlova, raw packet capture tokom autorizovanog hanta, neočekivani socket filteri i diferencijalno ponašanje servisa. Odsustvo periodičnog beacon-a ne dokazuje da je edge uređaj čist.

### Serverless i rotacija ephemeral origina

Front zadržava stabilan logički identitet, dok kratkotrajne funkcije/kontejneri obrađuju pojedinačne faze u više regiona/naloga. Ovo smanjuje životni vek na disku i broj fiksnih origin IP adresa, ali kreiranje u control plane-u, image/layer, role, secret, request ID i billing telemetrija postaju trajni graf.

**Detekcija:** zadržite cloud audit i invocation logove izvan workload-a; grupišite deployment template-e, role, environment ključeve i odnose front-to-origin.

### Raznovrsnost privacy sloja

Operacija može namerno izbegavati jedan homogeni lanac: na primer, jedan kanal koristi iznajmljeni relay, tasking koristi javni objekat, exit dolazi sa cellular link-a u vlasništvu laboratorije, a administracija koristi zasebnu mrežu organizacije. Ovo smanjuje vrednost kompromitovanja jednog provajdera, ali povećava rizik od korelacije vremena između slojeva i operativnih grešaka.

**Detekcija:** izgradite vremenske linije kampanje kroz identity, DNS, SaaS, network i cloud senzore. Tražite sinhronizovane promene stanja umesto identičnih indikatora.

### Decentralizovani dead drop-ovi ili dead drop-ovi u transparency logovima

Akter može postaviti mali šifrovani pokazivač u bilo koji trajni javni append-only sistem, content-addressed store ili transparency-like feed. Javni objekat je otporan, ali njegov tačni indeks/content hash i ponašanje klijenta pri polling-u postaju stabilni identifikatori.

**Detekcija:** beležite pune API/objekt identifikatore i hash-eve odgovora; upozoravajte na nestandardne procese koji polling-uju immutable objekte, nakon čega slede dekodiranje ili nove konekcije.

### Odložene store-and-forward operacije

Interaktivni C2 stvara jaku vremensku korelaciju. Store-and-forward dizajn grupiše šifrovane poslove i vraća rezultate minutima ili satima kasnije kroz drugi queue ili fizički prenos. Time se žrtvuje odzivnost radi slabije end-to-end vremenske korelacije.

**Detekcija:** produžite vremenske prozore korelacije, modelujte periodični pristup queue-u i pregledajte staging na endpointu. Grupisanje premešta signal sa vremenskog ponašanja paketa na zakazano ponašanje procesa/fajla; ne uklanja ga.

## Pregled dizajna: razmišljajte u terminima posmatrača

Za svaku putanju popunite ovu tabelu pre deployment-a i nakon prikupljanja:

| Sloj | Vidi izvor? | Vidi odredište? | Vidi sadržaj? | Stabilni identifikatori | Vlasnik zadržavanja/legalni vlasnik |
|---|---:|---:|---:|---|---|
| lokalna mreža/carrier | | | | | |
| entry/access servis | | | | | |
| traversal operator(i) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provajder | | | | | |

Ako jedan uobičajeni provajder može da popuni svaku kolonu, arhitektura obezbeđuje prikrivanje od targeta, ali ne i robusno razdvajanje. Ako nijedan interni kontrolor ne može da poveže aktivnost sa angažmanom, arhitektura nije pogodna za profesionalni red teaming.

## References

- [1] [MITRE ATT&CK — Nabavka infrastrukture (T1583), kompromitovanje infrastrukture (T1584) i proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
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
- [13] [Google Threat Intelligence Group — Ometanje najveće svetske residential proxy mreže](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Shadow Campaigns: Otkrivanje globalne špijunaže](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
