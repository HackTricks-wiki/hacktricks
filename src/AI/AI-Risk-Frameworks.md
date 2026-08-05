# Rizici AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 ranjivosti Machine Learning-a

Owasp je identifikovao 10 najvažnijih ranjivosti Machine Learning-a koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do različitih bezbednosnih problema, uključujući trovanje podataka, inverziju modela i adversarial napade. Razumevanje ovih ranjivosti ključno je za izgradnju bezbednih AI sistema.

Za ažuriranu i detaljnu listu 10 najvažnijih ranjivosti Machine Learning-a pogledajte projekat [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: Napadač dodaje sitne, često nevidljive izmene **ulaznim podacima**, zbog čega model donosi pogrešnu odluku.\
*Primer*: Nekoliko tačkica boje na znaku STOP navodi samovozeći automobil da "vidi" znak za ograničenje brzine.

- **Data Poisoning Attack**: **Training set** se namerno zagađuje lošim uzorcima, čime se model uči štetnim pravilima.\
*Primer*: Binarni fajlovi malware-a označavaju se kao "benign" u training korpusu antivirusnog softvera, pa sličan malware kasnije prolazi neopaženo.

- **Model Inversion Attack**: Ispitivanjem izlaza, napadač pravi **reverse model** koji rekonstruiše osetljive karakteristike originalnih ulaza.\
*Primer*: Ponovno kreiranje MRI snimka pacijenta na osnovu predikcija modela za otkrivanje raka.

- **Membership Inference Attack**: Napadač proverava da li je **određeni zapis** korišćen tokom training-a, uočavanjem razlika u nivou pouzdanosti.\
*Primer*: Potvrđivanje da se bankarska transakcija određene osobe nalazi u training podacima modela za otkrivanje prevara.

- **Model Theft**: Ponovljeno slanje upita omogućava napadaču da nauči granice odlučivanja i **klonira ponašanje modela** (i IP).\
*Primer*: Prikupljanje dovoljnog broja parova pitanja i odgovora sa ML-as-a-Service API-ja radi izgradnje gotovo ekvivalentnog lokalnog modela.

- **AI Supply-Chain Attack**: Kompromitovanje bilo koje komponente (podataka, biblioteka, pre-trained weights, CI/CD-a) u **ML pipeline-u** radi korumpiranja nizvodnih modela.\
*Primer*: Zatrovana dependency na model-hub-u instalira model za analizu sentimenta sa backdoor-om u veliki broj aplikacija.

- **Transfer Learning Attack**: Zlonamerna logika postavlja se u **pre-trained model** i opstaje tokom fine-tuning-a za zadatak žrtve.\
*Primer*: Vision backbone sa skrivenim trigger-om i dalje menja oznake nakon prilagođavanja za medicinsko snimanje.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **pomeraju izlaze modela** u korist napadačeve agende.\
*Primer*: Ubacivanje "čistih" spam poruka označenih kao ham, tako da spam filter propušta slične buduće poruke.

- **Output Integrity Attack**: Napadač **menja predikcije modela tokom prenosa**, a ne sam model, čime obmanjuje nizvodne sisteme.\
*Primer*: Menjanje rezultata klasifikatora malware-a iz "malicious" u "benign" pre nego što ga faza karantina fajla obradi.

- **Model Poisoning** --- Direktne, ciljane izmene samih **parametara modela**, često nakon sticanja write pristupa, radi promene ponašanja.\
*Primer*: Podešavanje weight-ova produkcionog modela za otkrivanje prevara tako da transakcije sa određenih kartica uvek budu odobrene.


## Google SAIF rizici

Google-ov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje različite rizike povezane sa AI sistemima:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Zlonamerni akteri menjaju ili ubacuju training/tuning podatke kako bi smanjili tačnost, postavili backdoor-e ili iskrivili rezultate, čime ugrožavaju integritet modela tokom celog životnog ciklusa podataka.

- **Unauthorized Training Data**: Unošenje zaštićenih autorskim pravima, osetljivih ili neodobrenih skupova podataka stvara pravne, etičke i performansne rizike, jer model uči iz podataka koje nije smeo da koristi.

- **Model Source Tampering**: Supply-chain ili insider manipulacija kodom modela, dependencies-ima ili weight-ovima pre ili tokom training-a može ubaciti skrivenu logiku koja opstaje čak i nakon ponovnog training-a.

- **Excessive Data Handling**: Slabe kontrole zadržavanja podataka i upravljanja podacima dovode do toga da sistemi čuvaju ili obrađuju više ličnih podataka nego što je potrebno, povećavajući rizik od izlaganja i neusklađenosti sa propisima.

- **Model Exfiltration**: Napadači kradu fajlove/weight-ove modela, što dovodi do gubitka intelektualne svojine i omogućava copy-cat servise ili naknadne napade.

- **Model Deployment Tampering**: Napadači menjaju artefakte modela ili serving infrastrukturu, tako da se pokrenuti model razlikuje od proverenog modela, što potencijalno menja njegovo ponašanje.

- **Denial of ML Service**: Preplavljivanje API-ja ili slanje “sponge” inputa može iscrpeti compute/energiju i oboriti model, po uzoru na klasične DoS napade.

- **Model Reverse Engineering**: Prikupljanjem velikog broja parova ulaz-izlaz, napadači mogu klonirati ili destilovati model, podstičući proizvode za imitaciju i prilagođene adversarial napade.

- **Insecure Integrated Component**: Ranjivi plugin-ovi, agenti ili upstream servisi omogućavaju napadačima da ubace kod ili eskaliraju privilegije unutar AI pipeline-a.

- **Prompt Injection**: Kreiranje prompt-ova (direktno ili indirektno) radi ubacivanja instrukcija koje nadjačavaju nameru sistema, čime se model navodi da izvršava neželjene komande.

- **Model Evasion**: Pažljivo dizajnirani inputi navode model da pogrešno klasifikuje, halucinira ili generiše nedozvoljeni sadržaj, čime se narušavaju bezbednost i poverenje.

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz svojih training podataka ili konteksta korisnika, kršeći privatnost i propise.

- **Inferred Sensitive Data**: Model zaključuje lične karakteristike koje nikada nisu bile navedene, stvarajući novu štetu po privatnost putem inference-a.

- **Insecure Model Output**: Nesanitizovani odgovori prosleđuju štetan kod, dezinformacije ili neprikladan sadržaj korisnicima ili nizvodnim sistemima.

- **Rogue Actions**: Autonomno integrisani agenti izvršavaju neželjene operacije u stvarnom svetu (upisivanje fajlova, API pozive, kupovine itd.) bez adekvatnog nadzora korisnika.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan framework za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Kategorizuje različite attack tehnike i taktike koje napadači mogu koristiti protiv AI modela, kao i načine korišćenja AI sistema za izvođenje različitih napada.<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Napadači kradu aktivne session token-e ili cloud API credentials i bez autorizacije pozivaju cloud-hosted LLM-ove koji se naplaćuju. Pristup se često preprodaje putem reverse proxy-ja koji prosleđuju zahteve preko naloga žrtve, npr. deployment-i "oai-reverse-proxy". Posledice uključuju finansijski gubitak, zloupotrebu modela izvan policy-ja i pripisivanje aktivnosti tenant-u žrtve.<sup>[[2]](#references)[[3]](#references)</sup>

TTPs:
- Prikupljanje token-a sa zaraženih developerskih mašina ili browser-a; krađa CI/CD secrets-a; kupovina procurilih cookies-a.
- Postavljanje reverse proxy-ja koji prosleđuje zahteve pravom provider-u, skriva upstream key i multipleksira veliki broj korisnika.
- Zloupotreba direktnih base-model endpoint-a radi zaobilaženja enterprise guardrails-a i rate limit-a.

Mitigations:
- Povezati token-e sa fingerprint-om uređaja, IP opsezima i client attestation-om; primeniti kratka važenja i osvežavanje uz MFA.
- Ograničiti key-jeve na minimum (bez tool pristupa, read-only gde je primenljivo); rotirati ih pri anomalijama.
- Sav saobraćaj terminirati server-side iza policy gateway-a koji primenjuje safety filter-e, kvote po ruti i izolaciju tenant-a.
- Pratiti neuobičajene obrasce korišćenja (iznenadne skokove potrošnje, neuobičajene regione, UA string-ove) i automatski opozvati sumnjive session-e.
- Prednost dati mTLS-u ili potpisanim JWT-ovima koje izdaje vaš IdP, umesto dugotrajnih statičkih API key-jeva.

## Ojačavanje self-hosted LLM inference-a

Pokretanje lokalnog LLM servera za poverljive podatke stvara drugačiju attack surface od cloud-hosted API-ja: inference/debug endpoint-i mogu otkriti prompt-ove, serving stack obično izlaže reverse proxy, a GPU device node-ovi omogućavaju pristup velikim `ioctl()` površinama. Ako procenjujete ili postavljate on-prem inference servis, pregledajte najmanje sledeće tačke.<sup>[[4]](#references)</sup>

### Curenje prompt-ova putem debug i monitoring endpoint-a

Tretirajte inference API kao **multi-user osetljivi servis**. Debug ili monitoring rute mogu otkriti sadržaj prompt-ova, stanje slot-ova, metadata modela ili informacije o internom redu čekanja. U `llama.cpp`, endpoint `/slots` je posebno osetljiv jer izlaže stanje po slotu i namenjen je samo za pregled/upravljanje slotovima.<sup>[[4]](#references)[[5]](#references)</sup>

- Postavite reverse proxy ispred inference servera i **podrazumevano zabranite pristup**.
- Dozvolite samo tačne kombinacije HTTP method + path koje su potrebne klijentu/UI-ju.
- Isključite introspection endpoint-e u samom backend-u kad god je moguće, na primer `llama-server --no-slots`.
- Povežite reverse proxy sa `127.0.0.1` i izložite ga putem autentifikovanog transporta, kao što je SSH local port forwarding, umesto objavljivanja na LAN-u.

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
### Rootless kontejneri bez mreže i UNIX socketi

Ako inference daemon podržava osluškivanje na UNIX socketu, preferirajte to umesto TCP-a i pokrenite kontejner sa **bez mrežnog steka**:
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
- `--network none` uklanja dolaznu/odlaznu TCP/IP izloženost i izbegava user-mode helpers koje bi rootless containers inače zahtevali.
- UNIX socket omogućava korišćenje POSIX permissions/ACL-ova na putanji socket-a kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman smanjuju uticaj container breakout-a zato što container root nije host root.
- Read-only model mounts smanjuju verovatnoću izmene modela iz samog container-a.

### Minimizacija GPU device-node-ova

Kod inference-a podržanog GPU-om, `/dev/nvidia*` fajlovi predstavljaju lokalne attack surface-e visoke vrednosti zato što izlažu velike driver `ioctl()` handlere i potencijalno deljene putanje za upravljanje GPU memorijom.<sup>[[4]](#references)</sup>

- Ne ostavljajte `/dev/nvidia*` globalno upisivim.
- Ograničite `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev pravila i ACL-ova tako da ih može otvoriti samo mapirani container UID.
- Blacklist-ujte nepotrebne module kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem` na headless inference hostovima.
- Preload-ujte samo potrebne module pri boot-u umesto da runtime oportunistički pokreće `modprobe` tokom pokretanja inference-a.

Primer:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jedna važna stavka za proveru je **`/dev/nvidia-uvm`**. Čak i ako workload ne koristi eksplicitno `cudaMallocManaged()`, noviji CUDA runtime-i i dalje mogu zahtevati `nvidia-uvm`. Pošto je ovaj uređaj deljen i upravlja GPU virtuelnom memorijom, tretirajte ga kao površinu za izlaganje podataka između tenant-a. Ako inference backend to podržava, Vulkan backend može biti zanimljiv kompromis, jer možda uopšte neće biti potrebno izlagati `nvidia-uvm` container-u.

### LSM ograničavanje inference worker procesa

AppArmor/SELinux/seccomp treba koristiti kao odbranu po dubini oko inference procesa:<sup>[[4]](#references)</sup>

- Dozvolite samo shared libraries, putanje modela, direktorijum socket-a i GPU device nodes koji su zaista potrebni.
- Eksplicitno zabranite visokorizične capabilities kao što su `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Direktorijum modela zadržite samo za čitanje, a writable putanje ograničite isključivo na runtime socket/cache direktorijume.
- Pratite denial logove, jer pružaju korisnu telemetriju za detekciju kada model server ili post-exploitation payload pokuša da napusti očekivano ponašanje.

Primer AppArmor pravila za worker proces koji koristi GPU:
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
## Phantom Squatting: Domeni koje je halucinirao LLM kao vektor napada na AI lanac snabdevanja

Phantom squatting je **ekvivalent slopsquatting-a na nivou domena/URL-a**. Umesto da halucinira nepostojeće ime paketa, LLM halucinira uverljiv **portal, API, webhook, billing, SSO, download ili support domen** stvarnog brenda, a napadač registruje taj namespace pre nego što ga upotrebi čovek ili agent.<sup>[[8]](#references)[[9]](#references)</sup>

Ovo je važno zato što se u mnogim workflow-ima potpomognutim AI-jem izlaz modela tretira kao **pouzdana zavisnost**:
- Developeri kopiraju predloženi endpoint u code ili CI/CD integracije.
- AI agenti automatski preuzimaju dokumentaciju, šeme, APK-ove, ZIP-ove ili webhook odredišta.
- Generisani runbook-ovi ili dokumentacija mogu ugraditi lažni URL kao da je zvaničan.

### Ofanzivni workflow

1. **Ispitajte površinu halucinacija**: postavljajte pitanja specifična za brend o realističnim workflow-ima, kao što su `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ili portali za `mobile app`.
2. **Normalizujte kandidate**: razrešite generisane URL-ove, svedite NXDOMAIN odgovore na nadređeni domen koji se može registrovati i deduplirajte prompt familije. Korpus promptova treba da ostane raznovrstan, na primer izbacivanjem gotovo identičnih promptova pomoću **Jaccard similarity**.
3. **Dajte prioritet predvidljivim halucinacijama**:
- **Thermal Hallucination Persistence (THP)**: isti lažni domen pojavljuje se pri različitim temperaturama, uključujući nisku temperaturu kao što je `T=0.1`.
- **Konsenzus između modela**: više LLM familija generiše isti lažni domen.
4. **Registrujte i weaponize-ujte** nadređeni domen, a zatim postavite phishing, lažne APK/ZIP download-e, credential harvesters, malicious docs ili API endpoint-e koji prikupljaju secrets/webhook payloads. **Čiste halucinacije na nivou domena** najlakše se monetizuju jer napadač kontroliše ceo namespace; halucinacije poddomena/putanja i dalje se mogu zloupotrebiti kada normalizovani nadređeni domen nije registrovan.
5. **Iskoristite period bez reputacije**: novoregistrovani domeni često nemaju istoriju na blocklistama, URL reputaciju ni zrelu telemetriju, pa mogu zaobići kontrole dok detekcije ne sustignu situaciju. Napadači mogu produžiti ovaj period benignim odgovorima dostupnim samo crawler-ima, redirect cloaking-om, CAPTCHA kapijama ili odloženim staging-om payload-a.

### Zašto je opasno za agente

Kod ljudske žrtve, lažni domen obično i dalje zahteva klik i dodatnu radnju. Kod **agentic workflow-a**, LLM može biti i **mamac** i **izvršilac**: agent primi halucinirani URL, preuzme ga, parsira odgovor, a zatim može da leak-uje tokene, izvrši instrukcije, preuzme dependency ili ubaci poisoned data u CI/CD bez ikakve ljudske provere.<sup>[[8]](#references)</sup>

### Praktični napadački promptovi

Promptovi sa visokim učinkom obično izgledaju kao uobičajeni enterprise zadaci, a ne kao eksplicitni phishing mamci:
- “Koji je payment sandbox URL za `<brand>` integracije?”
- “Koji webhook endpoint treba da koristim za build notifications kompanije `<brand>`?”
- “Gde se nalazi employee benefits / billing / SSO portal za `<brand>`?”
- “Daj mi direktan Android APK ili desktop client download za `<brand>`.”

### Defanzivna inverzija

Tretirajte ovo kao proaktivan problem monitoringa domena, a ne samo kao problem prompt injection-a:
- Napravite **korpus promptova za brendove** i periodično ispitujte LLM-ove na koje se vaši korisnici/agenti oslanjaju.
- Čuvajte halucinirane URL-ove i pratite koji su stabilni kroz različite temperature/modele.
- Pratite **Adversarial Exploitation Window (AEW)**: vreme između prve halucinacije i registracije od strane napadača. Pozitivan AEW znači da defenderi mogu unapred registrovati, sinkhole-ovati ili blokirati domen pre weaponization-a.
- Pratite prelaze **NXDOMAIN → registrovan** za nadređene domene.
- Nakon registracije proverite registrar, datum kreiranja, nameservers, privacy shielding, sadržaj stranice, screenshots, status parkirane stranice i sličnost sa brand asset-ima.
- Dodajte policy gates tako da agenti/developeri **podrazumevano ne veruju domenima koje generiše LLM**: zahtevajte allowlists, validaciju vlasništva, CT/RDAP provere ili ljudsko odobrenje pre prve upotrebe.

Ovo se istovremeno uklapa u nekoliko AI risk kategorija: **AI supply-chain attack**, **insecure model output** i **rogue actions** kada agenti autonomno koriste halucinirani URL.

## Reference
- [1] [Unit 42 – Rizici LLM-ova za code asistente: štetan sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [Pregled LLMJacking šeme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (preprodaja ukradenog LLM pristupa)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - Detaljna analiza deployment-a on-premise LLM servera sa niskim privilegijama](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [CNCF Container Device Interface (CDI) specifikacija](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: Domeni koje je halucinirao AI kao vektor napada na software supply chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: Kako AI halucinacije podstiču novu klasu supply-chain napada](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 ranjivosti Machine Learning-a](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) rizici](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS matrica](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
