# AI Rizici

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp je identifikovao 10 najvažnijih machine learning ranjivosti koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do različitih bezbednosnih problema, uključujući data poisoning, model inversion i adversarial attacks. Razumevanje ovih ranjivosti ključno je za izgradnju bezbednih AI sistema.

Za ažuriranu i detaljnu listu 10 najvažnijih machine learning ranjivosti pogledajte projekat [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Napadač dodaje sitne, često nevidljive izmene **ulaznim podacima**, zbog čega model donosi pogrešnu odluku.\
*Primer*: Nekoliko tačkica boje na znaku STOP navodi self-driving automobil da "vidi" znak za ograničenje brzine.

- **Data Poisoning Attack**: **Training set** se namerno zagađuje neispravnim uzorcima, čime se model uči štetnim pravilima.\
*Primer*: Malware binarni fajlovi označavaju se kao "benign" u training korpusu antivirusnog programa, pa sličan malware kasnije prolazi neprimećeno.

- **Model Inversion Attack**: Ispitivanjem izlaza, napadač pravi **reverse model** koji rekonstruiše osetljive karakteristike originalnih ulaza.\
*Primer*: Rekonstrukcija MRI snimka pacijenta na osnovu predviđanja modela za otkrivanje raka.

- **Membership Inference Attack**: Napadač proverava da li je **određeni zapis** korišćen tokom training procesa, posmatrajući razlike u nivou pouzdanosti.\
*Primer*: Potvrđivanje da se bankarska transakcija neke osobe nalazi u training podacima modela za otkrivanje prevara.

- **Model Theft**: Ponovljenim slanjem upita napadač može da nauči granice odlučivanja i **klonira ponašanje modela** (kao i IP).\
*Primer*: Prikupljanje dovoljnog broja parova pitanja i odgovora sa ML-as-a-Service API-ja radi izgradnje gotovo ekvivalentnog lokalnog modela.

- **AI Supply-Chain Attack**: Kompromitovanje bilo koje komponente (podataka, biblioteka, pre-trained težina, CI/CD-a) u **ML pipeline-u** radi izmene downstream modela.\
*Primer*: Zagađena dependency na model-hub-u instalira backdoored model za analizu sentimenta u brojne aplikacije.

- **Transfer Learning Attack**: Zlonamerna logika postavlja se u **pre-trained model** i opstaje nakon fine-tuning-a za zadatak žrtve.\
*Primer*: Vision backbone sa skrivenim triggerom i dalje menja oznake nakon prilagođavanja za medical imaging.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **menjaju izlaze modela** u korist napadačeve agende.\
*Primer*: Ubacivanje "čistih" spam poruka označenih kao ham, kako bi spam filter propuštao slične buduće poruke.

- **Output Integrity Attack**: Napadač **menja predviđanja modela tokom prenosa**, a ne sam model, čime obmanjuje downstream sisteme.\
*Primer*: Promena rezultata malware classifier-a sa "malicious" na "benign" pre nego što ga sistem za karantin fajlova obradi.

- **Model Poisoning** --- Direktne, ciljane izmene samih **parametara modela**, često nakon dobijanja write pristupa, radi izmene ponašanja.\
*Primer*: Podešavanje težina modela za otkrivanje prevara u produkciji tako da se transakcije sa određenih kartica uvek odobravaju.


## Google SAIF Rizici

Google-ov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje različite rizike povezane sa AI sistemima:

- **Data Poisoning**: Zlonamerni akteri menjaju ili ubacuju training/tuning podatke kako bi smanjili preciznost, ugradili backdoor-e ili iskrivili rezultate, čime ugrožavaju integritet modela kroz čitav data-lifecycle.

- **Unauthorized Training Data**: Korišćenje copyrighted, osetljivih ili nedozvoljenih datasetova stvara pravne, etičke i performansne rizike, jer model uči iz podataka koje nikada nije smeo da koristi.

- **Model Source Tampering**: Supply-chain ili insider manipulisanje kodom modela, dependencies-ima ili težinama pre ili tokom training-a može ugraditi skrivenu logiku koja opstaje čak i nakon retraining-a.

- **Excessive Data Handling**: Slabe kontrole zadržavanja podataka i governance-a navode sisteme da čuvaju ili obrađuju više ličnih podataka nego što je potrebno, povećavajući izloženost i compliance rizik.

- **Model Exfiltration**: Napadači kradu fajlove/težine modela, što dovodi do gubitka intelektualne svojine i omogućava copy-cat servise ili naknadne napade.

- **Model Deployment Tampering**: Napadači menjaju artefakte modela ili serving infrastrukturu tako da se pokrenuti model razlikuje od proverene verzije, što potencijalno menja njegovo ponašanje.

- **Denial of ML Service**: Preplavljivanje API-ja ili slanje “sponge” ulaza može iscrpeti compute/energiju i oboriti model, slično klasičnim DoS napadima.

- **Model Reverse Engineering**: Prikupljanjem velikog broja parova ulaz-izlaz, napadači mogu klonirati ili distilovati model, podstičući imitacione proizvode i prilagođene adversarial attacks.

- **Insecure Integrated Component**: Ranjivi plugins, agents ili upstream servisi omogućavaju napadačima da ubace kod ili eskaliraju privilegije unutar AI pipeline-a.

- **Prompt Injection**: Formulisanje promptova (direktno ili indirektno) radi ubacivanja instrukcija koje nadjačavaju nameru sistema, navodeći model da izvrši neželjene komande.

- **Model Evasion**: Pažljivo dizajnirani ulazi navode model da pogrešno klasifikuje, halucinira ili generiše nedozvoljen sadržaj, čime se narušavaju bezbednost i poverenje.

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz svojih training podataka ili korisničkog konteksta, čime se krše privatnost i propisi.

- **Inferred Sensitive Data**: Model zaključuje lične atribute koji nikada nisu direktno navedeni, stvarajući nove povrede privatnosti putem inference-a.

- **Insecure Model Output**: Nesanitizovani odgovori prosleđuju štetan kod, dezinformacije ili neprimeren sadržaj korisnicima ili downstream sistemima.

- **Rogue Actions**: Autonomno-integrisani agents izvršavaju neželjene operacije u stvarnom svetu (upisivanje fajlova, API pozive, kupovine itd.) bez odgovarajućeg nadzora korisnika.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan framework za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Kategorizuje različite attack techniques i tactics koje adversaries mogu koristiti protiv AI modela, kao i načine korišćenja AI sistema za izvođenje različitih napada.

## LLMJacking (Krađa tokena i preprodaja pristupa LLM-ovima hostovanim u cloud-u)

Napadači kradu aktivne session tokene ili cloud API credentials i bez ovlašćenja pozivaju plaćene LLM-ove hostovane u cloud-u. Pristup se često preprodaje putem reverse proxies koji prosleđuju zahteve preko naloga žrtve, npr. deployment-i "oai-reverse-proxy". Posledice uključuju finansijski gubitak, zloupotrebu modela izvan policy-ja i pripisivanje aktivnosti tenant-u žrtve.

TTPs:
- Prikupljaju tokene sa zaraženih developer računara ili browser-a; kradu CI/CD secrets; kupuju leaked cookies.
- Postavljaju reverse proxy koji prosleđuje zahteve pravom provider-u, skrivajući upstream key i multipleksirajući više korisnika.
- Zloupotrebljavaju direct base-model endpoints kako bi zaobišli enterprise guardrails i rate limits.

Mitigations:
- Vezuju tokene za device fingerprint, IP opsege i client attestation; primenjuju kratka vremena isteka i refresh uz MFA.
- Ograničavaju ključeve na minimum (bez tool pristupa, read-only gde je primenljivo); rotiraju ih pri pojavi anomalija.
- Sav saobraćaj završavaju server-side iza policy gateway-a koji primenjuje safety filters, kvote po route-u i izolaciju tenant-a.
- Prate neuobičajene obrasce korišćenja (nagla povećanja troškova, neuobičajene regione, UA strings) i automatski opozivaju sumnjive sesije.
- Prednost daju mTLS-u ili signed JWT-ovima koje izdaje vaš IdP, umesto dugotrajnih statičkih API ključeva.

## Ojačavanje self-hosted LLM inference-a

Pokretanje lokalnog LLM servera za poverljive podatke stvara drugačiju attack surface od cloud-hosted API-ja: inference/debug endpoints mogu leak-ovati promptove, serving stack obično izlaže reverse proxy, a GPU device nodes omogućavaju pristup velikim `ioctl()` površinama. Ako procenjujete ili deploy-ujete on-prem inference servis, pregledajte najmanje sledeće tačke.

### Curenje promptova kroz debug i monitoring endpoints

Tretirajte inference API kao **multi-user sensitive service**. Debug ili monitoring routes mogu otkriti sadržaj promptova, stanje slotova, metadata modela ili informacije o internom redu čekanja. U `llama.cpp`, endpoint `/slots` je naročito osetljiv jer izlaže stanje po slotovima i namenjen je samo za pregled/upravljanje slotovima.

- Postavite reverse proxy ispred inference servera i **podrazumevano sve zabranite**.
- Dozvolite samo precizno definisane kombinacije HTTP metoda + path-ova koje su potrebne klijentu/UI-ju.
- Onemogućite introspection endpoints u samom backend-u kad god je moguće, na primer `llama-server --no-slots`.
- Vežite reverse proxy za `127.0.0.1` i izložite ga putem authenticated transport-a, kao što je SSH local port forwarding, umesto objavljivanja na LAN-u.

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

Ako inference daemon podržava osluškivanje na UNIX socketu, dajte prednost tome u odnosu na TCP i pokrenite kontejner **bez mrežnog steka**:
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
- `--network none` uklanja ulaznu/izlaznu TCP/IP izloženost i izbegava user-mode helper-e koji bi rootless containers inače zahtevali.
- UNIX socket omogućava korišćenje POSIX dozvola/ACL-ova na putanji socket-a kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman smanjuju posledice container breakout-a jer container root nije host root.
- Montiranje modela samo za čitanje smanjuje mogućnost izmene modela iz samog container-a.

### Minimizacija GPU device-node-ova

Za inference zasnovan na GPU-u, `/dev/nvidia*` fajlovi predstavljaju lokalne attack surface-e visoke vrednosti jer izlažu velike driver `ioctl()` handler-e i potencijalno deljene putanje za upravljanje GPU memorijom.

- Ne ostavljajte `/dev/nvidia*` world writable.
- Ograničite `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev pravila i ACL-ova tako da ih može otvoriti samo mapirani container UID.
- Blacklist-ujte nepotrebne module kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem` na headless inference hostovima.
- Preload-ujte samo potrebne module pri boot-u, umesto da runtime oportunistički pokreće `modprobe` tokom pokretanja inference-a.

Primer:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jedna važna tačka za proveru je **`/dev/nvidia-uvm`**. Čak i ako workload eksplicitno ne koristi `cudaMallocManaged()`, noviji CUDA runtime-ovi i dalje mogu zahtevati `nvidia-uvm`. Pošto je ovaj uređaj deljen i upravlja virtuelnom memorijom GPU-a, tretirajte ga kao površinu za izlaganje podataka između tenant-a. Ako ga inference backend podržava, Vulkan backend može biti zanimljiv kompromis jer može potpuno izbeći izlaganje `nvidia-uvm` kontejneru.

### LSM ograničavanje inference worker-a

AppArmor/SELinux/seccomp treba koristiti kao dodatni sloj zaštite oko inference procesa:

- Dozvolite samo shared libraries, putanje do modela, direktorijum socket-a i GPU device nodes koji su zaista potrebni.
- Eksplicitno zabranite visokorizične capabilities kao što su `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Direktorijum modela držite samo za čitanje, a writable putanje ograničite isključivo na runtime socket/cache direktorijume.
- Pratite denial logove jer pružaju korisnu telemetry za detekciju kada model server ili post-exploitation payload pokuša da napusti očekivano ponašanje.

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
## Phantom Squatting: LLM-hallucinated domains kao vektor AI supply-chain napada

Phantom squatting je **domain/URL ekvivalent slopsquatting-a**. Umesto da izhalucinira nepostojeći naziv paketa, LLM izhalucinira uverljiv **portal, API, webhook, billing, SSO, download ili support domen** stvarnog brenda, a napadač registruje taj namespace pre nego što ga upotrebi čovek ili agent.

Ovo je važno zato što se u mnogim AI-assisted workflow-ovima izlaz modela tretira kao **trusted dependency**:
- Developeri kopiraju predloženi endpoint u kod ili CI/CD integracije.
- AI agenti automatski preuzimaju dokumentaciju, schema-e, APK-ove, ZIP-ove ili webhook ciljeve.
- Generisani runbook-ovi ili dokumentacija mogu ugraditi lažni URL kao da je authoritative.

### Ofanzivni tok rada

1. **Ispitaj površinu halucinacija**: postavljaj pitanja specifična za brend o realističnim workflow-ovima kao što su `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ili portali za `mobile app`.
2. **Normalizuj kandidate**: razreši generisane URL-ove, svedi NXDOMAIN odgovore na parent registerable domain i ukloni duplikate prompt porodica. Prompt corpus treba da ostane raznovrstan, na primer izbacivanjem gotovo identičnih promptova pomoću **Jaccard similarity**.
3. **Prioritizuj predvidljive halucinacije**:
- **Thermal Hallucination Persistence (THP)**: isti lažni domen pojavljuje se pri različitim temperaturama, uključujući nisku temperaturu kao što je `T=0.1`.
- **Cross-model consensus**: više LLM familija generiše isti lažni domen.
4. **Registruj i weaponize-uj** parent domen, a zatim hostuj phishing, lažne APK/ZIP download-e, credential harvester-e, malicioznu dokumentaciju ili API endpoint-e koji prikupljaju secrets/webhook payload-e. **Pure domain-level hallucinations** najlakše se monetizuju zato što napadač kontroliše ceo namespace; subdomain/path halucinacije se i dalje mogu zloupotrebiti kada je normalizovani parent neregistrovan.
5. **Iskoristi zero-reputation window**: novoregistrovani domeni često nemaju blocklist istoriju, URL reputation ni zrele telemetry podatke, pa mogu zaobići kontrole dok detekcije ne sustignu situaciju. Napadači mogu produžiti ovaj period pomoću benignih odgovora dostupnih samo crawler-ima, redirect cloaking-a, CAPTCHA gate-ova ili odloženog payload staging-a.

### Zašto je opasno za agente

Za ljudsku žrtvu, lažni domen obično i dalje zahteva klik i dodatnu radnju. U **agentic workflow-u**, LLM može biti i **mamac** i **izvršilac**: agent dobije izhalucinirani URL, preuzme ga, parsira odgovor i zatim može da leak-uje tokene, izvrši instrukcije, preuzme dependency ili ubaci poisoned data u CI/CD bez ikakvog human review-a.

### Praktični attacker promptovi

High-yield promptovi obično izgledaju kao uobičajeni enterprise zadaci, a ne kao eksplicitni phishing mamci:
- „Koji je payment sandbox URL za `<brand>` integracije?“
- „Koji webhook endpoint treba da koristim za `<brand>` build notifikacije?“
- „Gde se nalazi employee benefits / billing / SSO portal za `<brand>`?“
- „Daj mi direktan Android APK ili desktop client download za `<brand>`.“

### Defensive inversion

Tretiraj ovo kao proaktivan problem domain monitoring-a, a ne samo kao problem prompt injection-a:
- Napravi **brand prompt corpus** i periodično ispituj LLM-ove na koje se tvoji korisnici/agenti oslanjaju.
- Čuvaj izhalucinirane URL-ove i prati koji od njih su stabilni pri različitim temperaturama/modelima.
- Prati **Adversarial Exploitation Window (AEW)**: vreme između prve halucinacije i registracije od strane napadača. Pozitivan AEW znači da defenders mogu da pre-registruju, sinkhole-uju ili pre-blokiraju domen pre weaponization-a.
- Prati prelaze **NXDOMAIN → registered** za parent domene.
- Nakon registracije analiziraj registrar, creation date, nameserver-e, privacy shielding, sadržaj stranice, screenshots, status parked page-a i sličnost brand asset-a.
- Dodaj policy gate-ove tako da agenti/developeri po default-u **ne veruju LLM-generated domain-ima**: zahtevaj allowlist-e, ownership validation, CT/RDAP provere ili human approval pre prve upotrebe.

Ovo se istovremeno uklapa u nekoliko AI risk kategorija: **AI supply-chain attack**, **insecure model output** i **rogue actions** kada agenti autonomno koriste izhalucinirani URL.

## Reference
- [Unit 42 – Rizici Code Assistant LLM-ova: štetan sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Pregled LLMJacking scheme-a – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (preprodaja ukradenog LLM access-a)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Detaljna analiza deployment-a on-premise low-privileged LLM server-a](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-hallucinated domains kao vektor software supply-chain napada](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: Kako AI halucinacije podstiču novu klasu supply-chain napada](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
