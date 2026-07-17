# AI rizici

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 ranjivosti mašinskog učenja

Owasp je identifikovao 10 najvažnijih ranjivosti mašinskog učenja koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do različitih bezbednosnih problema, uključujući trovanje podataka, inverziju modela i adversarial napade. Razumevanje ovih ranjivosti ključno je za izgradnju bezbednih AI sistema.

Za ažuriranu i detaljnu listu 10 najvažnijih ranjivosti mašinskog učenja pogledajte projekat [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Napadač dodaje sitne, često nevidljive izmene **ulaznim podacima**, zbog čega model donosi pogrešnu odluku.\
*Primer*: Nekoliko tačkica boje na znaku STOP navode samovozeći automobil da "vidi" znak za ograničenje brzine.

- **Data Poisoning Attack**: **Skup podataka za obuku** namerno se zagađuje lošim uzorcima, čime se model uči štetnim pravilima.\
*Primer*: Binarni fajlovi malware-a označavaju se kao "bezopasni" u korpusu za obuku antivirusnog programa, pa sličan malware kasnije prolazi neotkriven.

- **Model Inversion Attack**: Ispitivanjem izlaza, napadač gradi **inverzni model** koji rekonstruiše osetljive karakteristike originalnih ulaza.\
*Primer*: Rekonstrukcija MRI snimka pacijenta na osnovu predviđanja modela za otkrivanje raka.

- **Membership Inference Attack**: Napadač ispituje da li je **određeni zapis** korišćen tokom obuke, uočavanjem razlika u nivou pouzdanosti.\
*Primer*: Potvrđivanje da se bankarska transakcija neke osobe nalazi u podacima za obuku modela za otkrivanje prevara.

- **Model Theft**: Ponovljeno slanje upita omogućava napadaču da nauči granice odlučivanja i **klonira ponašanje modela** (kao i IP).\
*Primer*: Prikupljanje dovoljnog broja parova pitanja i odgovora sa ML-as-a-Service API-ja radi izgradnje gotovo ekvivalentnog lokalnog modela.

- **AI Supply-Chain Attack**: Kompromitovanje bilo koje komponente (podataka, biblioteka, pre-trained težina, CI/CD-a) u **ML pipeline-u** radi korumpiranja narednih modela.\
*Primer*: Zavisnost zatrovana na model-hub-u instalira model za analizu sentimenta sa backdoor-om u veliki broj aplikacija.

- **Transfer Learning Attack**: Zlonamerna logika postavlja se u **pre-trained model** i opstaje nakon fine-tuning-a za zadatak žrtve.\
*Primer*: Vision backbone sa skrivenim okidačem i dalje menja oznake nakon prilagođavanja za medicinsko snimanje.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **pomeraju izlaze modela** u korist ciljeva napadača.\
*Primer*: Ubacivanje "čistih" spam poruka označenih kao ham, tako da spam filter propušta slične buduće poruke.

- **Output Integrity Attack**: Napadač **menja predviđanja modela tokom prenosa**, a ne sam model, čime obmanjuje naredne sisteme.\
*Primer*: Menjanje rezultata klasifikatora malware-a iz "zlonamerno" u "bezopasno" pre nego što ga faza karantina fajla obradi.

- **Model Poisoning** --- Direktne, ciljane izmene samih **parametara modela**, često nakon dobijanja pristupa za pisanje, radi promene ponašanja.\
*Primer*: Podešavanje težina modela za otkrivanje prevara u produkciji tako da se transakcije sa određenih kartica uvek odobravaju.


## Google SAIF rizici

Google-ov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje različite rizike povezane sa AI sistemima:

- **Data Poisoning**: Zlonamerni akteri menjaju ili ubacuju podatke za obuku/tuning kako bi smanjili preciznost, ugradili backdoor-e ili iskrivili rezultate, čime ugrožavaju integritet modela tokom čitavog životnog ciklusa podataka.

- **Unauthorized Training Data**: Unošenje autorski zaštićenih, osetljivih ili neodobrenih skupova podataka stvara pravne, etičke i performansne rizike, jer model uči iz podataka koje nikada nije smeo da koristi.

- **Model Source Tampering**: Manipulacija kôdom modela, zavisnostima ili težinama u lancu snabdevanja ili od strane insajdera, pre ili tokom obuke, može ugraditi skrivenu logiku koja opstaje čak i nakon ponovne obuke.

- **Excessive Data Handling**: Slabe kontrole zadržavanja podataka i upravljanja podacima dovode do toga da sistemi čuvaju ili obrađuju više ličnih podataka nego što je potrebno, povećavajući izloženost i compliance rizik.

- **Model Exfiltration**: Napadači kradu fajlove/težine modela, što dovodi do gubitka intelektualne svojine i omogućava kopirane servise ili naknadne napade.

- **Model Deployment Tampering**: Napadači menjaju artefakte modela ili serving infrastrukturu, tako da se pokrenuti model razlikuje od proverenе verzije, što potencijalno menja njegovo ponašanje.

- **Denial of ML Service**: Preplavljivanje API-ja ili slanje “sponge” ulaza može iscrpeti računarske resurse/energiju i oboriti model, po uzoru na klasične DoS napade.

- **Model Reverse Engineering**: Prikupljanjem velikog broja parova ulaz-izlaz, napadači mogu klonirati ili distilovati model, podstičući imitacione proizvode i prilagođene adversarial napade.

- **Insecure Integrated Component**: Ranjivi plugin-ovi, agenti ili upstream servisi omogućavaju napadačima da ubace kôd ili eskaliraju privilegije unutar AI pipeline-a.

- **Prompt Injection**: Formulisanje promptova (direktno ili indirektno) radi ubacivanja instrukcija koje nadjačavaju nameru sistema, zbog čega model izvršava neželjene komande.

- **Model Evasion**: Pažljivo dizajnirani ulazi navode model da pogrešno klasifikuje, halucinira ili generiše nedozvoljeni sadržaj, čime se narušavaju bezbednost i poverenje.

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz svojih podataka za obuku ili korisničkog konteksta, čime se krše privatnost i propisi.

- **Inferred Sensitive Data**: Model zaključuje lične karakteristike koje nikada nisu bile navedene, stvarajući novu štetu po privatnost putem zaključivanja.

- **Insecure Model Output**: Nesanitizovani odgovori prosleđuju štetan kôd, dezinformacije ili neprikladan sadržaj korisnicima ili narednim sistemima.

- **Rogue Actions**: Autonomno integrisani agenti izvršavaju neželjene operacije u stvarnom svetu (upisivanje fajlova, API pozive, kupovine itd.) bez odgovarajućeg nadzora korisnika.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan okvir za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Kategorizuje različite attack tehnike i taktike koje napadači mogu koristiti protiv AI modela, kao i načine korišćenja AI sistema za izvođenje različitih napada.


## LLMJacking (krađa tokena i preprodaja pristupa LLM-ovima hostovanim u cloud-u)

Napadači kradu aktivne session tokene ili cloud API akreditive i bez autorizacije pozivaju plaćene LLM-ove hostovane u cloud-u. Pristup se često preprodaje putem reverse proxy-ja koji prosleđuju zahteve preko naloga žrtve, npr. deployment-i "oai-reverse-proxy". Posledice uključuju finansijski gubitak, zloupotrebu modela izvan pravila i pripisivanje aktivnosti tenant-u žrtve.

TTPs:
- Prikupljanje tokena sa zaraženih developerskih mašina ili browser-a; krađa CI/CD tajni; kupovina procurelih kolačića.
- Postavljanje reverse proxy-ja koji prosleđuje zahteve stvarnom provider-u, skriva upstream ključ i omogućava multipleksiranje velikog broja korisnika.
- Zloupotreba direktnih base-model endpoint-a radi zaobilaženja enterprise guardrails-a i rate limit-a.

Mitigacije:
- Vezati tokene za fingerprint uređaja, IP opsege i client attestation; primenjivati kratka vreme isteka i osvežavanje uz MFA.
- Ograničiti ključeve na minimum (bez pristupa alatima, read-only gde je primenljivo); rotirati ih pri anomalijama.
- Sav saobraćaj terminirati na serveru iza policy gateway-a koji primenjuje safety filtere, kvote po ruti i izolaciju tenant-a.
- Pratiti neuobičajene obrasce korišćenja (iznenadne skokove troškova, neuobičajene regione, UA string-ove) i automatski opozvati sumnjive sesije.
- Prednost dati mTLS-u ili potpisanim JWT-ovima koje izdaje vaš IdP, umesto dugotrajnih statičkih API ključeva.

## Ojačavanje self-hosted LLM inference-a

Pokretanje lokalnog LLM servera za poverljive podatke stvara drugačiju attack površinu od cloud-hosted API-ja: inference/debug endpoint-i mogu da procure promptove, serving stack obično izlaže reverse proxy, a GPU device node-ovi omogućavaju pristup velikim `ioctl()` površinama. Ako procenjujete ili postavljate on-prem inference servis, pregledajte najmanje sledeće tačke.

### Curenje promptova putem debug i monitoring endpoint-a

Tretirajte inference API kao **osetljiv servis za više korisnika**. Debug ili monitoring rute mogu izložiti sadržaj promptova, stanje slotova, metapodatke modela ili informacije o internom redu čekanja. U `llama.cpp`, endpoint `/slots` je naročito osetljiv jer izlaže stanje po slotovima i namenjen je samo za inspekciju/upravljanje slotovima.

- Postavite reverse proxy ispred inference servera i **podrazumevano sve zabranite**.
- Dozvolite samo tačne kombinacije HTTP metoda + putanja koje su potrebne klijentu/UI-ju.
- Onemogućite introspection endpoint-e u samom backend-u kad god je moguće, na primer `llama-server --no-slots`.
- Vežite reverse proxy za `127.0.0.1` i izložite ga putem autentifikovanog transporta, kao što je SSH local port forwarding, umesto objavljivanja na LAN-u.

Primer allowlist-e sa nginx-om:
```nginx
map "$request_method:$uri" $llm_whitelist {
default 0;

"GET:/health"              1;
"GET:/v1/models"           1;
"POST:/v1/completions"     1;
"POST:/v1/chat/completions" 1;
}

server {
listen 127.0.0.1:80;

location / {
if ($llm_whitelist = 0) { return 403; }
proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
}
}
```
### Rootless kontejneri bez mreže i UNIX sockets

Ako inference daemon podržava osluškivanje na UNIX socketu, dajte prednost tome u odnosu na TCP i pokrenite kontejner sa **bez mrežnog steka**:
```bash
podman run --rm -d \
--network none \
--user 1000:1000 \
--userns=keep-id \
--umask=007 \
--volume /var/lib/models:/models:ro \
--volume /srv/llm/socks:/run/llama-cpp \
ghcr.io/ggml-org/llama.cpp:server-cuda13 \
--host /run/llama-cpp/llama-cpp.sock \
--model /models/model.gguf \
--parallel 4 \
--no-slots
```
Prednosti:
- `--network none` uklanja izloženost dolaznom/odlaznom TCP/IP saobraćaju i izbegava pomoćne procese u korisničkom režimu koji bi rootless kontejnerima inače bili potrebni.
- UNIX socket omogućava korišćenje POSIX dozvola/ACL-ova na putanji socket-a kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman smanjuju uticaj izlaska iz kontejnera, jer root unutar kontejnera nije root na hostu.
- Montiranja modela samo za čitanje smanjuju mogućnost menjanja modela iz kontejnera.

### Minimizacija GPU device-node-ova

Za inference uz GPU, `/dev/nvidia*` fajlovi predstavljaju vredne lokalne attack surface-e jer izlažu velike drajverske `ioctl()` handlere i potencijalno deljene putanje za upravljanje GPU memorijom.

- Nemojte ostaviti `/dev/nvidia*` sa dozvolom upisa za sve korisnike.
- Ograničite `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev pravila i ACL-ova tako da samo mapirani UID kontejnera može da ih otvori.
- Blokirajte nepotrebne module kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem` na headless inference hostovima.
- Učitajte pri pokretanju samo potrebne module, umesto da runtime po potrebi pokreće `modprobe` tokom pokretanja inference-a.

Primer:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jedna važna stavka za proveru je **`/dev/nvidia-uvm`**. Čak i ako workload eksplicitno ne koristi `cudaMallocManaged()`, noviji CUDA runtime-i i dalje mogu zahtevati `nvidia-uvm`. Pošto je ovaj uređaj deljen i upravlja GPU virtuelnom memorijom, tretirajte ga kao površinu za izlaganje podataka između tenant-a. Ako ga inference backend podržava, Vulkan backend može biti zanimljiv kompromis, jer može u potpunosti izbeći izlaganje `nvidia-uvm` container-u.

### LSM ograničavanje inference worker-a

AppArmor/SELinux/seccomp treba koristiti kao dodatni sloj zaštite oko inference procesa:

- Dozvolite samo shared libraries, putanje do modela, direktorijum sa socket-om i GPU device nodes koji su zaista potrebni.
- Izričito zabranite visokorizične capabilities kao što su `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Direktorijum sa modelom držite samo za čitanje, a writable putanje ograničite isključivo na runtime socket/cache direktorijume.
- Nadgledajte denial logs, jer pružaju korisnu telemetriju za detekciju kada model server ili post-exploitation payload pokuša da napusti očekivano ponašanje.

Primer AppArmor pravila za GPU-backed worker:
```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```
## Phantom Squatting: Domeni koje je halucinirao LLM kao vektor AI supply-chain napada

Phantom squatting je **ekvivalent slopsquatting-a na nivou domena/URL-a**. Umesto da halucinira nepostojeći naziv paketa, LLM halucinira uverljiv **portal, API, webhook, billing, SSO, download ili support domen** stvarnog brenda, a napadač registruje taj namespace pre nego što ga čovek ili agent upotrebi.

Ovo je važno zato što se u mnogim AI-potpomognutim radnim tokovima izlaz modela tretira kao **pouzdana zavisnost**:
- Developeri kopiraju predloženi endpoint u kod ili CI/CD integracije.
- AI agenti automatski preuzimaju dokumentaciju, šeme, APK-ove, ZIP datoteke ili webhook ciljeve.
- Generisani runbook-ovi ili dokumentacija mogu sadržati lažni URL kao da je zvaničan.

### Offensive workflow

1. **Ispitajte površinu halucinacija**: postavljajte pitanja specifična za brend o realističnim workflow-ovima kao što su `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ili portali za `mobile app`.
2. **Normalizujte kandidate**: razrešite generisane URL-ove, svedite NXDOMAIN odgovore na roditeljski domen koji je moguće registrovati i uklonite duplikate prompt familija. Korpus promptova treba da ostane raznovrstan, na primer odbacivanjem skoro identičnih promptova pomoću **Jaccard similarity**.
3. **Dajte prioritet predvidljivim halucinacijama**:
- **Thermal Hallucination Persistence (THP)**: isti lažni domen pojavljuje se pri različitim temperaturama, uključujući nisku temperaturu kao što je `T=0.1`.
- **Konsenzus između modela**: više LLM familija generiše isti lažni domen.
4. **Registrujte i naoružajte** roditeljski domen, a zatim hostujte phishing, lažne APK/ZIP download-e, credential harvesters, zlonamerne dokumente ili API endpoint-e koji prikupljaju secrets/webhook payloads. **Čiste domen-level halucinacije** najlakše je monetizovati jer napadač kontroliše čitav namespace; halucinacije subdomena/path-a i dalje se mogu zloupotrebiti kada je normalizovani roditeljski domen neregistrovan.
5. **Iskoristite period bez reputacije**: novoregistrovani domeni često nemaju istoriju na blocklistama, URL reputation i zrelu telemetriju, pa mogu zaobići kontrole dok detekcije ne sustignu situaciju. Napadači mogu produžiti ovaj period pomoću benignih odgovora namenjenih samo crawler-ima, redirect cloaking-a, CAPTCHA gate-ova ili odloženog staging-a payload-a.

### Zašto je opasno za agente

Za ljudsku žrtvu lažni domen obično i dalje zahteva klik i još neku radnju. Kod **agentic workflow-a**, LLM može biti i **mamac** i **izvršilac**: agent primi halucinirani URL, preuzme ga, parsira odgovor, a zatim može da leak-uje tokene, izvrši instrukcije, download-uje dependency ili ubaci poisoned data u CI/CD bez ikakvog pregleda čoveka.

### Praktični napadački promptovi

High-yield promptovi obično izgledaju kao normalni enterprise zadaci, a ne kao eksplicitni phishing mamci:
- „Koji je payment sandbox URL za `<brand>` integracije?“
- „Koji webhook endpoint treba da koristim za `<brand>` build notifikacije?“
- „Gde se nalazi employee benefits / billing / SSO portal za `<brand>`?“
- „Daj mi direktan Android APK ili desktop client download za `<brand>`.“

### Defensive inversion

Tretirajte ovo kao problem proaktivnog domain monitoringa, a ne samo kao problem prompt injection-a:
- Napravite **korpus promptova za brendove** i periodično ispitujte LLM-ove na koje se vaši korisnici/agenti oslanjaju.
- Čuvajte halucinirane URL-ove i pratite koji su stabilni kroz različite temperature/modele.
- Pratite **Adversarial Exploitation Window (AEW)**: vreme između prve halucinacije i registracije od strane napadača. Pozitivan AEW znači da defenderi mogu unapred registrovati domen, postaviti sinkhole ili ga blokirati pre weaponization-a.
- Pratite prelaze **NXDOMAIN → registered** za roditeljske domene.
- Nakon registracije proverite registrar, datum kreiranja, nameservers, privacy shielding, sadržaj stranice, screenshots, status parked-page-a i sličnost brand asset-a.
- Dodajte policy gate-ove tako da agenti/developeri **po podrazumevanim podešavanjima ne veruju domenima koje je generisao LLM**: zahtevajte allowlists, validaciju vlasništva, CT/RDAP provere ili odobrenje čoveka pre prve upotrebe.

Ovo istovremeno pripada u nekoliko AI risk kategorija: **AI supply-chain attack**, **insecure model output** i **rogue actions** kada agenti autonomno koriste halucinirani URL.

## Reference
- [Unit 42 – Rizici LLM-ova za pomoć pri programiranju: štetan sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Pregled LLMJacking šeme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (preprodaja ukradenog LLM pristupa)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Detaljna analiza deployment-a on-premise LLM servera sa niskim privilegijama](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specifikacija](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: Domeni koje je halucinirao AI kao vektor Software Supply Chain napada](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: Kako AI halucinacije podstiču novu klasu Supply Chain napada](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
