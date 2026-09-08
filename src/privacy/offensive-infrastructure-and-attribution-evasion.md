# Ofanzivna infrastruktura i izbegavanje atribucije

{{#include ../banners/hacktricks-training.md}}

Operater retko dobija smislenu anonimnost korišćenjem samo jednog proxy-ja. Stvarne kampanje grade **graf razdvajanja**: operater pristupa pristupnom čvoru, tranzitni čvorovi skrivaju taj čvor od izlaza, redirector-i štite pravi C2, a jednokratni nazivi upućuju na javnu krajnju tačku.

Koristite [Katalog tehnika anonimnog pristupa Internetu](anonymous-internet-access-techniques.md) za standardizovani prikaz prednosti/mana, primene i detekcije svake putanje. Ova stranica detaljnije obrađuje kompoziciju adversarijske infrastrukture.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Poslednja adresa koju cilj vidi stoga predstavlja dokaz o putanji, a ne dokaz o tome ko je upravljao tastaturom. MITRE glavne komponente mapira na Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) i Web Service (T1102).<sup>[[1]](#references)</sup>

## Klase infrastrukture

| Klasa | Zašto je actor koristi | Trajna izloženost | Najbolji pivot za defendera |
|---|---|---|---|
| Iznajmljeni VPS/cloud | Brzi, predvidljivi, rutabilni i laki za ponovnu izgradnju | tenant, billing, konzola, source-login i istorija image-a | događaji na account/control-plane nivou i ponavljajući server fingerprint |
| Commercial VPN/Tor | Veliki deljeni skup za izlaz; bez administracije servera | vidljivost provider-a/guard-a i end-to-end timing | ponašanje odredišta, endpoint dokazi i korelacija protoka |
| Residential/mobile proxy | Consumer ASN i geografska uverljivost | broker/customer zapisi; proxyware ili ponašanje zaraženog hosta | impossible travel, proxy protokoli i promena adrese po sesiji |
| Compromised server/router/IoT | Pozajmljuje reputaciju i jurisdikciju žrtve | implant, management flow i ponavljajući upstream controller | device telemetrija i ORB topologija, a ne jedna izlazna IP adresa |
| CDN/redirector | Razdvaja javni edge od back-end C2 | TLS/HTTP gramatika, certificate, routing i artefakti cloud account-a | korelacija edge-a sa origin-om i grupisanje po obliku zahteva |
| Legitimni web service | Uklapa se u dozvoljeni GitHub/cloud/social saobraćaj | API token, tenant/object identifikatori i neuobičajena process lineage | endpoint proces uz service/API semantiku |
| Fizička/cellular/satellite putanja | Menja prividno fizičko poreklo | RF, carrier, subscriber, device i location zapisi | objedinjeni radio/fizički i mrežni dokazi |

## Mreže operativnih relay box-ova

**ORB network** je upravljani proxy fleet koji se koristi kao posredni service. Mandiant ih deli na provisioned networks iznajmljenih servera, non-provisioned networks kompromitovanih router-a/IoT uređaja i hibride. Zrela topologija ima četiri logičke uloge:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** održava inventar, credentials, health i routing policy.
2. **Access/relay node:** autentifikuje customers ili operators; predstavlja stabilnu ulaznu tačku u mesh koji se menja.
3. **Traversal nodes:** jedan ili više iznajmljenih ili kompromitovanih sistema prosleđuju opaque veze.
4. **Exit/staging node:** predstavlja konačnu izvornu adresu reconnaissance, exploitation ili C2 ciljevima.

Mesh može da bira exit-e prema državi, ASN-u, latency-ju ili dostupnosti i da rotira node-ove koji nisu zdravi. Više threat grupa može iznajmljivati istu mrežu. Mandiant je uočio da je IPv4 adresa ostajala povezana sa nekim ORB-ovima samo 31 dan; zato preporučuje da se **mreža posmatra kao entitet nalik actor-u koji se razvija**, umesto da se blokira zastarela lista IP adresa.<sup>[[2]](#references)</sup>

### Šta ovo omogućava — i šta leak-uje

- Cilj vidi exit koji može biti geografski blizu i naizgled residential.
- Exit vidi cilj i prethodni hop, ali ne nužno operatora.
- Access service vidi customer-a i zahtev za rutom. Nezavisno upravljani mesh može držati customer-a odvojenim od exit-a, ali stvara moćan zapis o drugoj strani.
- Ponavljajući portovi, redosled handshake-a, server banner-i, certificates, uptime prozori i odnosi sa controller-ima mogu otkriti fleet čak i kada se IP adrese rotiraju.
- Kompromitovani router često nema endpoint telemetriju, ali njegov ISP i dalje poseduje subscriber i flow podatke; zaplena otkriva artefakte implant-a/configuration-a.

{% hint style="info" %}
Za autorizovanu vežbu, reprodukujte topologiju pomoću VM-ova ili router-a u vlasništvu organizacije i sačuvajte attribution map controller-a. Ne angažujte open proxy-je ili uređaje trećih strana. [Lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) pravi istu hop strukturu vidljivu defenderu, bez viktimizacije posrednika.
{% endhint %}

## Residential i mobile proxy mreže

Residential proxy services dodeljuju sesije consumer broadband adresama; mobile proxy-jevi izlaze kroz carrier NAT pool-ove. Supply može poticati od izričito uključenih appliance-a, SDK/proxyware-a ugrađenog u consumer applications, reseller-a ili malware-a. Ova porekla nisu ekvivalentna: nedostatak informisanog pristanka pretvara privacy service u compromised infrastructure.

Režimi rotacije utiču na detekciju:

- **per-request rotation** proizvodi brze diskontinuitete IP adrese i ASN-a/geografije, dok identitet na višem sloju ostaje stabilan;
- **sticky sessions** zadržavaju exit minutima ili satima, nalik uobičajenom subscriber-u;
- **backconnect gateways** customer-u izlažu jednu broker endpoint tačku i interno biraju exit-e;
- **mobile pools** postavljaju veliki broj stvarnih subscriber-a iza malog skupa carrier NAT adresa, zbog čega je blokiranje IP adresa skupo.

Defenderi treba da korelišu IP sa authenticated session-om, TLS/client fingerprint-om, HTTP redosledom, device cookie-jem i ponašanjem. Navodno lokalni residential login praćen drugom zemljom, dok sve karakteristike višeg sloja ostaju identične, jači je indikator od same reputacije. Nasuprot tome, deljenje adresa i mobile handoff stvaraju legitimnu promenljivost, zato residential/proxy klasifikaciju nikada ne treba tretirati kao konačnu odluku.

## Multi-hop proxy chains

MITRE razlikuje external proxies od **multi-hop proxies (T1090.003)**. Važno svojstvo nije broj hop-ova, već razdvajanje znanja i administracije.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Ako jedna strana upravlja sistemima A i B, deljeni logovi ili vremensko usklađivanje toka mogu rekonstruisati circuit. Dodavanje uzastopnih komercijalnih VPN-ova sa iste krajnje tačke/naloga može povećati latenciju, ali pritom ostaviti zajedničke dokaze o identitetu, plaćanju i vremenu. Tor smanjuje ovaj problem nezavisno izabranim relejima i zajedničkim dizajnom klijenta, ali interaktivna mreža sa malom latencijom ne može obećati otpornost na posmatrača koji meri oba kraja.

Uobičajeni kvarovi su DNS ili IPv6 bypass, aplikacije koje same otvaraju socket-e, management saobraćaj koji direktno stiže do releja, sinhronizovana aktivnost, ponovo korišćeni SSH ključevi i prijavljivanje na naloge koji otkrivaju identitet. Ispravna verifikacija je test kvara: zaustavite svaki relej redom i pokažite da workload ne može da pređe na direktnu putanju.

## Slojevi redirector-a i oblikovanje saobraćaja

Javni **redirector** prihvata saobraćaj koji odgovara gramatici specifičnoj za operaciju i prosleđuje ga zaštićenom team server-u. Sve ostalo može biti odbijeno ili mu se može poslužiti bezazlen sadržaj.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Više nivoa ograničava izloženost: gašenje javnog domena ne mora otkriti team server. CDN-ovi dodaju anycast kapacitet i ugledni spoljašnji domen, ali CDN nalog i edge logovi postaju tačke atribucije. TLS fingerprints, istorije sertifikata, karakteristične putanje/redosled zaglavlja, veličine odgovora, ponašanje preusmeravanja i origin allowlists mogu grupisati navodno nepovezane frontove.

Za detekciju, zabeležite polja reverse-proxy-ja pre normalizacije, uporedite SNI/Host/authority, pregledajte retke kombinacije zaglavlja, grupišite tela odgovora i TLS fingerprints i pretražite cloud/CDN audit logove radi preklapanja konfiguracija. Za autorizovane red team operacije, izbegavajte kopiranje stvarnog brenda ili postavljanje prikupljanja kredencijala iza nepovezane treće strane.

## Domain fronting i domainless fronting

Kod klasičnog **domain fronting (T1090.004)**, TLS veza oglašava dozvoljeni front domen u SNI-ju, dok šifrovani HTTP `Host` ili HTTP/2 `:authority` zahtevaju drugi back-end domen. Saradnički CDN rutira na osnovu unutrašnje vrednosti. Mrežni posmatrač bez TLS dešifrovanja vidi front; CDN vidi obe vrednosti i origin. Kod domainless varijanti, SNI može biti prazan, dok drugo polje za rutiranje bira odredište.<sup>[[4]](#references)</sup>

Ovo nije magično imitiranje: funkcioniše samo kada posrednik namerno ili slučajno dozvoli nepodudaranje i zna kako da rutira unutrašnje ime. Veliki provajderi su ograničili cross-account fronting. Encrypted ClientHello (ECH) menja ono što on-path posmatrač može da vidi, ali ne uklanja CDN, endpoint ili application zapise.

Tačke za detekciju obuhvataju:

- ancestry procesa endpointa i odredište koje nije očekivano za tu aplikaciju;
- nepodudaranje SNI-ja i HTTP authority-ja tamo gde je TLS inspection zakonit i dostupan;
- CDN logove koji prikazuju da jedan tenant/front rutira ka drugom authority/origin-u;
- neuobičajene dugotrajne ili periodične sesije ka servisu koji je obično interaktivan;
- stabilne veličine i učestalost šifrovanih tokova kroz promenljive front domene.

Bezbedna laboratorija simulira nepodudaranje rutiranja na reverse proxy-ju u vlasništvu organizacije; ne zloupotrebljava javni CDN.

## Dynamic resolution: DDNS, DGA i fast flux

Dynamic resolution odvaja logički servis od fiksne infrastrukture:

- **DDNS:** autentifikovani klijent ažurira stabilno ime nakon promene svoje adrese.
- **DGA:** endpoint i controller izvode kandidate za imena domena iz vremenskog/ključnog seed-a; operator registruje mali podskup.
- **Fast flux:** ime vraća brzo promenljiv skup kompromitovanih/proxy adresa, često sa niskim TTL-ovima.
- **Double flux:** rotiraju se i servisne adrese i adrese authoritative name servera, čime se skriva i control layer.

Fast flux je obrazac distribucije opterećenja koji se koristi protivnički, a ne samo „mnogo DNS odgovora“. Jači dokazi kombinuju nizak TTL, veliki broj jedinstvenih adresa, široku disperziju ASN-ova/geografije, kratak životni vek čvorova, ponavljano ponašanje aplikacije i sumnjivu istoriju registracije. CDN-ovi legitimno dele nekoliko ovih svojstava. MITRE preporučuje korelaciju DNS ponašanja sa procesom i naknadnim konekcijama.<sup>[[5]](#references)</sup>

DGA se može detektovati pomoću leksičke entropije, obrazaca suglasnika/cifara, NXDOMAIN bursts, sinhronizovanih domena koji su prvi put viđeni i konteksta procesa. Wordlist DGA i generativni modeli zaobilaze jednostavna pravila entropije, zbog čega klasterska analiza kroz ceo fleet po vremenu i lineage endpointa postaju važniji.

## Compromised domains i domain shadowing

Actor može oteti registrar/DNS nalog, preuzeti dangling subdomain ili dodati zapise ispod inače uglednog domena. **Domain shadowing** čuva legitimni apex, dok veliki broj attacker-controlled subdomain-a upućuje na promenljive delivery ili C2 hostove. Ono pozajmljuje starost i reputaciju i može izbeći blokiranje na nivou celog domena.<sup>[[6]](#references)</sup>

Defenderima su potrebni registrar i authoritative-DNS audit logovi, MFA, registry/registrar locks, upozorenja za nove delegacije/API tokene/name servere, monitoring certificate transparency-ja i inventar cloud resursa na koje DNS upućuje. Istražite rezoluciju i istoriju sertifikata subdomena nezavisno od reputacije apex-a.

## Web services i dead-drop resolvers

**Dead-drop resolver (T1102.001)** čuva enkodirani pokazivač na aktuelni C2 unutar legitimne objave, profila, dokumenta, repozitorijuma, cloud objekta ili blockchain polja. Malware preuzima javni objekat, dekodira domen/IP i kontaktira sledeću fazu. Bidirectional varijante razmenjuju komande ili fajlove putem service API-ja.<sup>[[7]](#references)</sup>

Ovo obezbeđuje otpornost i skriva back-end C2 od statičke analize binarnog fajla. Takođe stvara stabilne identifikatore objekta, tenanta, repozitorijuma, API-ja i obrazaca pristupa. Defenderi treba da povežu:

1. proces koji je kontaktirao servis;
2. tačnu API putanju/objekat i hash odgovora;
3. aktivnost dekodiranja ili obrade stringova;
4. novu outbound konekciju ubrzo nakon toga; i
5. identično ponašanje na drugim mestima u fleet-u.

Blokiranje celog GitHub-a, cloud storage-a ili društvenih mreža retko je izvodljivo. Service-aware egress policy i korelacija na nivou procesa efikasnije su od blokiranja zasnovanog samo na domenu.

## Personas, accounts i procurement compartments

Anonymity infrastrukture pada kada persona, recovery email, telefon, plaćanje, browser ili admin IP povežu compartment-e. Operacije povezane sa državama negovale su društvene profile, email identitete i cloud naloge mnogo pre njihove upotrebe; ATT&CK ovo beleži kao Establish Accounts (T1585), uključujući social, email i cloud sub-techniques.<sup>[[8]](#references)</sup>

Defender ili investigator gradi graf iz:

- vremena kreiranja i prvog logovanja, locale-a, vremenske zone i rasporeda rada;
- recovery polja, MFA uređaja, identifikacionih dokumenata i sredstava plaćanja;
- browser/TLS fingerprint-a i istorije izvorne mreže;
- ponovne upotrebe avatara, porekla slika, stila pisanja i rasta društvenog grafa;
- zajedničkog domain registranta, name servera, sertifikata, analytics ID-ja ili commit-a repozitorijuma;
- radnji na management plane-u koje zaobilaze javnu relay arhitekturu.

Za autorizovani red team, sintetičke persone treba dokumentovati kontroloru vežbe, koristiti recovery/payment kanale u vlasništvu organizacije, izbegavati imitiranje stvarnih nepovezanih osoba i imati planirano povlačenje. SOC može ostati slep; operacija ne sme postati bez odgovornosti.

## Emerging compound patterns to threat-model

Sledeće su **defender-driven compositions**, a ne tvrdnje da je neki imenovani actor primenio svaku tačno opisanu konstrukciju. One kombinuju već uočene primitive i korisne su kao purple-team hipoteze.

### Asymmetric one-way tasking

Komande stižu kroz javni, broadcast ili append-only izvor, dok rezultati izlaze kroz nepovezani kanal nakon odlaganja. Primeri primitive obuhvataju web-service one-way communication i dead drops. Razdvajanje sprečava da jedan tok izgleda bidirekciono i otežava jednostavnu korelaciju zahteva i odgovora.<sup>[[9]](#references)</sup>

**Detekcija:** sačuvajte čitanja na nivou objekta, zatim korelišite promene stanja procesa i kasnije outbound transfere kroz širi vremenski prozor. Tražite redak proces koji čita isti javni objekat čak i kada neposredan odgovor ne sledi.

### Multi-stage channel promotion

Tiha prva faza vrši inventory i samo odabrane sisteme promoviše na nepovezani second-stage kanal. Drugi endpoint, protokol i proces možda ne dele nikakvu infrastrukturu sa prvim. Ovo ograničava izloženost sposobne infrastrukture i eksplicitno je modelovano kao ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detekcija:** povežite `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; ne zaključujte incident nakon blokiranja prvog domena.

### Cross-protocol relay translation

Različiti hop-ovi prevode HTTPS, QUIC, WebSocket, DNS, SSH ili message-queue API umesto da transparentno prosleđuju pakete. Prevođenje uklanja jedan end-to-end protocol fingerprint, ali stvara gateway-e sa karakterističnim timingom, baferovanjem i semantičkom konverzijom. Protocol tunneling (T1572) može se kombinovati sa proxy-jima i service impersonation-om.<sup>[[11]](#references)</sup>

**Detekcija:** tražite gateway hostove koji primaju jedan protokol i pokreću drugi, uz tesno povezano ponašanje u bajtovima/vremenu; uporedite namenu endpointa sa protokolom koji se stvarno prenosi.

### Passive activation on edge devices

Umesto beaconing-a, implant prati saobraćaj koji već stiže do rutera/VPN-a i aktivira se samo na magic value, obrazac source-port-a ili autentifikovani token. Normalan saobraćaj nastavlja ka stvarnom servisu. ATT&CK ovo naziva Traffic Signaling (T1205), uz dokumentovane primere za network devices i APT.<sup>[[12]](#references)</sup>

**Detekcija:** proverite integritet firmware-a/fajlova, izvršite raw packet capture tokom autorizovanog hunt-a, tražite neočekivane socket filters i razlike u ponašanju servisa. Odsustvo periodičnog beacon-a ne dokazuje da je edge device čist.

### Serverless and ephemeral origin rotation

Front održava stabilan logički identitet, dok kratkotrajne funkcije/kontejneri obrađuju pojedinačne faze u više regiona/naloga. Ovo smanjuje životni vek na disku i broj fiksnih origin IP-jeva, ali control-plane kreiranje, image/layer, role, secret, request ID i billing telemetrija postaju trajni graf.

**Detekcija:** čuvajte cloud audit i invocation logove izvan workload-a; grupišite deployment template-e, role, environment keys i odnose front-to-origin.

### Privacy-layer diversity

Operacija može namerno izbegavati jedan homogen lanac: na primer, jedan kanal koristi leased relay, tasking koristi javni objekat, exit dolazi sa owned lab cellular link-a, a administracija koristi zasebnu mrežu organizacije. Ovo smanjuje vrednost kompromitovanja jednog provajdera, ali povećava rizik od cross-layer vremenske korelacije i operativnih grešaka.

**Detekcija:** izgradite timeline kampanje kroz identity, DNS, SaaS, network i cloud senzore. Tražite sinhronizovane promene stanja umesto identičnih indikatora.

### Decentralized or transparency-log dead drops

Actor može postaviti mali šifrovani pokazivač u bilo koji trajni javni append-only sistem, content-addressed store ili transparency-like feed. Javni objekat je otporan, ali njegov tačan indeks/content hash i ponašanje klijenta pri polling-u postaju stabilni identifikatori.

**Detekcija:** beležite pune API/object identifikatore i hash-eve odgovora; upozoravajte na nestandardne procese koji polling-uju nepromenljive objekte, nakon čega sledi dekodiranje ili nove konekcije.

### Delayed store-and-forward operations

Interaktivni C2 stvara snažnu vremensku korelaciju. Store-and-forward dizajn grupiše šifrovane poslove i vraća rezultate nekoliko minuta ili sati kasnije kroz drugi queue ili fizički transfer. On žrtvuje odzivnost radi slabije end-to-end vremenske korelacije.

**Detekcija:** produžite vremenske prozore korelacije, modelujte periodični pristup queue-u i ispitajte endpoint staging. Grupisanje premešta signal sa timing-a paketa na zakazano ponašanje procesa/fajla; ne uklanja ga.

## Design review: think in observers

Za svaki path popunite ovu tabelu pre deployment-a i nakon prikupljanja:

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Ako jedan uobičajeni provajder može popuniti svaku kolonu, arhitektura obezbeđuje prikrivanje od target-a, ali ne i robusno razdvajanje. Ako nijedan interni kontrolor ne može povezati aktivnost sa angažmanom, arhitektura nije pogodna za profesionalni red teaming.

## References

- [1] [MITRE ATT&CK — Nabavljanje infrastrukture (T1583), Kompromitovanje infrastrukture (T1584) i Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Espionage akteri povezani sa Kinom koriste ORB mreže](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
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
{{#include ../banners/hacktricks-training.md}}
