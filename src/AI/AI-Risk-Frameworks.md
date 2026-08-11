# AI rizici

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 ranjivosti Machine Learning-a

Owasp je identifikovao 10 najvažnijih ranjivosti Machine Learning-a koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do različitih bezbednosnih problema, uključujući trovanje podataka, inverziju modela i adversarial napade. Razumevanje ovih ranjivosti ključno je za izgradnju bezbednih AI sistema.

Za ažuriranu i detaljnu listu 10 najvažnijih ranjivosti Machine Learning-a pogledajte projekat [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Napadač dodaje sitne, često nevidljive izmene **dolaznim podacima**, zbog čega model donosi pogrešnu odluku.\
*Primer*: Nekoliko tačkica boje na znaku stop navodi samovozeći automobil da „vidi“ znak za ograničenje brzine.

- **Data Poisoning Attack**: **Training set** se namerno zagađuje lošim uzorcima, čime se model uči štetnim pravilima.\
*Primer*: Malware binarni fajlovi označavaju se kao „benigni“ u korpusu podataka za trening antivirusnog softvera, omogućavajući sličnom malware-u da kasnije prođe neprimećeno.

- **Model Inversion Attack**: Ispitivanjem izlaza, napadač gradi **reverse model** koji rekonstruiše osetljive karakteristike originalnih ulaza.\
*Primer*: Rekonstrukcija MRI snimka pacijenta na osnovu predviđanja modela za detekciju raka.

- **Membership Inference Attack**: Adversary proverava da li je **određeni zapis** korišćen tokom treninga, uočavanjem razlika u nivou pouzdanosti.\
*Primer*: Potvrđivanje da se bankarska transakcija neke osobe nalazi u training data modela za detekciju prevara.

- **Model Theft**: Ponovljeno slanje upita omogućava napadaču da nauči granice odlučivanja i **klonira ponašanje modela** (kao i IP).\
*Primer*: Prikupljanje dovoljnog broja parova pitanja i odgovora sa ML-as-a-Service API-ja radi izgradnje gotovo ekvivalentnog lokalnog modela.

- **AI Supply-Chain Attack**: Kompromitovanje bilo koje komponente (podataka, biblioteka, pre-trained težina, CI/CD-a) u **ML pipeline-u** radi korumpiranja modela koji od njega zavise.\
*Primer*: Zatrovana dependency komponenta na model-hub-u instalira model za analizu sentimenta sa backdoor-om u veliki broj aplikacija.

- **Transfer Learning Attack**: Zlonamerna logika ubacuje se u **pre-trained model** i preživljava fine-tuning nad zadatkom žrtve.\
*Primer*: Vision backbone sa skrivenim trigger-om i dalje menja oznake nakon prilagođavanja za medicinsko snimanje.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **menjaju izlaze modela** u korist ciljeva napadača.\
*Primer*: Ubacivanje „čistih“ spam emailova označenih kao ham, tako da spam filter propušta slične buduće emailove.

- **Output Integrity Attack**: Napadač **menja predviđanja modela tokom prenosa**, a ne sam model, čime obmanjuje downstream sisteme.\
*Primer*: Menjanje presude klasifikatora malware-a sa „malicious“ na „benign“ pre nego što je faza karantina fajla obradi.

- **Model Poisoning** --- Direktne, ciljane izmene samih **parametara modela**, često nakon dobijanja write access-a, radi promene ponašanja.\
*Primer*: Podešavanje težina modela za detekciju prevara u produkciji tako da se transakcije sa određenih kartica uvek odobre.


## Google SAIF Risks

Google-ov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje različite rizike povezane sa AI sistemima:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Zlonamerni akteri menjaju ili ubacuju training/tuning podatke kako bi smanjili tačnost, ugradili backdoor-e ili iskrivili rezultate, narušavajući integritet modela kroz čitav životni ciklus podataka.

- **Unauthorized Training Data**: Unošenje dataset-ova koji su zaštićeni autorskim pravima, osetljivi ili za čije korišćenje ne postoji dozvola stvara pravne, etičke i performansne rizike, jer se model uči iz podataka koje nikada nije smeo da koristi.

- **Model Source Tampering**: Manipulacija kôdom modela, dependency komponentama ili težinama u okviru supply chain-a ili od strane insajdera, pre ili tokom treninga, može ugraditi skrivenu logiku koja opstaje čak i nakon ponovnog treninga.

- **Excessive Data Handling**: Slabe kontrole zadržavanja podataka i upravljanja podacima navode sisteme da čuvaju ili obrađuju više ličnih podataka nego što je potrebno, povećavajući rizik od izlaganja i neusklađenosti sa propisima.

- **Model Exfiltration**: Napadači kradu fajlove/težine modela, što dovodi do gubitka intelektualne svojine i omogućava copy-cat servise ili naknadne napade.

- **Model Deployment Tampering**: Adversaries menjaju artefakte modela ili serving infrastrukturu tako da se pokrenuti model razlikuje od proverene verzije, što potencijalno menja njegovo ponašanje.

- **Denial of ML Service**: Preplavljivanje API-ja ili slanje „sponge“ ulaza može iscrpeti računarske resurse/energiju i oboriti model, po uzoru na klasične DoS napade.

- **Model Reverse Engineering**: Prikupljanjem velikog broja parova ulaz-izlaz, napadači mogu klonirati ili distilovati model, podstičući proizvode za imitaciju i prilagođene adversarial napade.

- **Insecure Integrated Component**: Ranjivi plugin-ovi, agenti ili upstream servisi omogućavaju napadačima da ubace kôd ili eskaliraju privilegije unutar AI pipeline-a.

- **Prompt Injection**: Formulisanje prompt-ova (direktno ili indirektno) radi ubacivanja instrukcija koje nadjačavaju nameru sistema, navodeći model da izvrši neželjene komande.

- **Model Evasion**: Pažljivo dizajnirani ulazi navode model da pogrešno klasifikuje, halucinira ili generiše nedozvoljeni sadržaj, čime se narušavaju bezbednost i poverenje.

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz svojih training data ili korisničkog konteksta, kršeći privatnost i propise.

- **Inferred Sensitive Data**: Model zaključuje lične karakteristike koje nikada nisu bile prosleđene, stvarajući novu štetu po privatnost putem zaključivanja.

- **Insecure Model Output**: Neprovereni odgovori prosleđuju štetan kôd, dezinformacije ili neprikladan sadržaj korisnicima ili downstream sistemima.

- **Rogue Actions**: Autonomno integrisani agenti izvršavaju neželjene operacije u stvarnom svetu (upisivanje fajlova, API pozive, kupovine itd.) bez odgovarajućeg nadzora korisnika.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan framework za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Kategorizuje različite attack tehnike i taktike koje adversaries mogu koristiti protiv AI modela, kao i načine korišćenja AI sistema za izvođenje različitih napada.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Napadači kradu aktivne session tokene ili cloud API credentials i bez autorizacije pozivaju plaćene, cloud-hosted LLM-ove. Access se često preprodaje putem reverse proxy-ja koji prosleđuju zahteve preko naloga žrtve, npr. deployment-i „oai-reverse-proxy“. Posledice uključuju finansijski gubitak, zloupotrebu modela suprotno pravilima i pripisivanje aktivnosti tenant-u žrtve.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Prikupljati tokene sa zaraženih developerskih mašina ili browser-a; krasti CI/CD secrets; kupovati leaked cookies.<sup>[[5]](#references)</sup>
- Podignuti reverse proxy koji prosleđuje zahteve stvarnom provider-u, skriva upstream key i multipleksira veliki broj korisnika.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Zloupotrebiti direktne base-model endpoint-e radi zaobilaženja enterprise guardrails-a i rate limit-a.<sup>[[4]](#references)</sup>

Mitigations:
- Povezati tokene sa fingerprint-om uređaja, IP opsezima i client attestation-om; nametnuti kratka važenja i osvežavati ih uz MFA.
- Ograničiti keys na najmanji potreban opseg (bez tool access-a, read-only gde je primenljivo); rotirati ih kada se uoči anomalija.
- Svu komunikaciju terminirati server-side iza policy gateway-a koji sprovodi safety filtere, kvote po ruti i izolaciju tenant-a.
- Pratiti neuobičajene obrasce korišćenja (iznenadne skokove potrošnje, atipične regione, UA strings) i automatski opozvati sumnjive sesije.
- Prednost dati mTLS-u ili potpisanim JWT-ovima koje izdaje vaš IdP, umesto dugotrajnih statičkih API keys.

## Self-hosted LLM inference hardening

Pokretanje lokalnog LLM servera za poverljive podatke stvara drugačiju attack surface od cloud-hosted API-ja: inference/debug endpoint-i mogu da izazovu leak prompt-ova, serving stack obično izlaže reverse proxy, a GPU device nodes omogućavaju pristup velikim `ioctl()` površinama. Ako procenjujete ili postavljate on-prem inference servis, pregledajte najmanje sledeće tačke.<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

Tretirajte inference API kao **multi-user sensitive service**. Debug ili monitoring rute mogu otkriti sadržaj prompt-ova, stanje slotova, metadata modela ili informacije o internom redu čekanja. U `llama.cpp`, endpoint `/slots` je naročito osetljiv jer izlaže stanje po slotovima i namenjen je isključivo za inspekciju/upravljanje slotovima.<sup>[[8]](#references)</sup>

- Postavite reverse proxy ispred inference servera i **podrazumevano sve zabranite**.
- Dozvolite samo tačne kombinacije HTTP method + path koje su potrebne client/UI-ju.
- Onemogućite introspection endpoint-e u samom backend-u kad god je moguće, na primer `llama-server --no-slots`.<sup>[[9]](#references)</sup>
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
### Rootless kontejneri bez mreže i UNIX socketi

Ako inference daemon podržava osluškivanje na UNIX socketu, preferirajte to u odnosu na TCP i pokrenite kontejner bez network stacka:<sup>[[8]](#references)</sup>
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
- `--network none` uklanja ulaznu/izlaznu TCP/IP izloženost i izbegava user-mode helpers koji bi rootless containers inače zahtevali.
- UNIX socket omogućava korišćenje POSIX permissions/ACLs na putanji socket-a kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman umanjuju uticaj container breakout-a jer container root nije host root.
- Read-only model mounts umanjuju mogućnost izmene modela iz samog container-a.

Za persistent deployments, ista ograničenja mogu se izraziti kao Podman Quadlet units. Ako se GPU pristup delegira kroz Container Device Interface, specifikaciju CDI uređaja treba ograničiti koliko god je moguće, umesto izlaganja svakog accelerator node-a.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimizacija GPU device-node-ova

Kod inference-a koji koristi GPU, `/dev/nvidia*` fajlovi predstavljaju high-value lokalne attack surfaces jer izlažu velike driver `ioctl()` handlers i potencijalno deljene GPU memory-management paths.<sup>[[8]](#references)</sup>

- Ne ostavljajte `/dev/nvidia*` world writable.
- Ograničite `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev rules i ACLs tako da ih može otvoriti samo mapirani container UID.
- Blacklist-ujte nepotrebne module, kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem`, na headless inference hostovima.
- Učitajte unapred samo neophodne module pri boot-u, umesto da runtime oportunistički pokreće `modprobe` tokom pokretanja inference-a.

Primer:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jedna važna stavka za proveru je **`/dev/nvidia-uvm`**. Čak i ako workload eksplicitno ne koristi `cudaMallocManaged()`, noviji CUDA runtime-i i dalje mogu zahtevati `nvidia-uvm`. Pošto se ovaj device deli i upravlja GPU virtuelnom memorijom, tretirajte ga kao površinu za izlaganje podataka između tenant-a. Ako inference backend to podržava, Vulkan backend može biti zanimljiv kompromis jer može u potpunosti izbeći izlaganje `nvidia-uvm` container-u.<sup>[[8]](#references)</sup>

### LSM ograničavanje inference worker-a

AppArmor/SELinux/seccomp treba koristiti kao defense in depth oko inference procesa:<sup>[[8]](#references)</sup>

- Dozvolite samo shared libraries, putanje modela, socket direktorijum i GPU device nodes koji su zaista potrebni.
- Eksplicitno zabranite high-risk capabilities kao što su `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Direktorijum modela držite samo za čitanje, a writable putanje ograničite isključivo na runtime socket/cache direktorijume.
- Nadgledajte denial logove jer pružaju korisnu telemetry za detekciju kada model server ili post-exploitation payload pokušaju da izađu iz očekivanog ponašanja.

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
## Phantom Squatting: domeni koje halucinira LLM kao vektor AI supply-chain napada

Phantom squatting je **ekvivalent domena/URL-ova za slopsquatting**. Umesto da halucinira nepostojeće ime paketa, LLM halucinira uverljiv **portal, API, webhook, billing, SSO, download ili support domen** za stvarni brend, a napadač registruje taj namespace pre nego što ga upotrebi čovek ili agent.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ovo je važno zato što se u mnogim AI-assisted workflow-ovima izlaz modela tretira kao **trusted dependency**:
- Developeri unose predloženi endpoint u kod ili CI/CD integracije.
- AI agenti automatski preuzimaju dokumentaciju, šeme, APK-ove, ZIP-ove ili webhook ciljeve.
- Generisani runbook-ovi ili dokumenti mogu ugraditi lažni URL kao da je autoritativan.

### Offensive workflow

1. **Ispitajte površinu halucinacija**: postavljajte pitanja specifična za brend o realističnim workflow-ovima kao što su `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ili portali za `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizujte kandidate**: razrešite generisane URL-ove, svedite NXDOMAIN odgovore na nadređeni domen koji je moguće registrovati i uklonite duplikate prompt porodica. Prompt korpusi treba da ostanu raznovrsni, na primer izbacivanjem skoro identičnih promptova pomoću **Jaccard similarity**.
3. **Prioritizujte predvidljive halucinacije**:
- **Thermal Hallucination Persistence (THP)**: isti lažni domen pojavljuje se pri različitim temperaturama, uključujući nisku temperaturu kao što je `T=0.1`.
- **Cross-model consensus**: više LLM porodica generiše isti lažni domen.
4. **Registrujte i weaponize-ujte** nadređeni domen, a zatim hostujte phishing, lažne APK/ZIP download-ove, credential harvestere, malicious dokumente ili API endpoint-e koji prikupljaju secrets/webhook payloads. **Pure domain-level hallucinations** najlakše je monetizovati zato što napadač kontroliše ceo namespace; halucinacije poddomena/putanja i dalje mogu biti zloupotrebljene kada normalizovani nadređeni domen nije registrovan.
5. **Iskoristite zero-reputation window**: novoregistrovani domeni često nemaju blocklist istoriju, URL reputation ni zrelu telemetriju, pa mogu zaobići kontrole dok ih detekcije ne sustignu. Napadači mogu produžiti ovaj period pomoću benignih odgovora dostupnih samo crawler-ima, redirect cloaking-a, CAPTCHA kapija ili odloženog staging-a payload-a.

### Zašto je opasno za agente

Za ljudsku žrtvu, lažni domen obično i dalje zahteva klik i još jednu radnju. U **agentic workflow-u**, LLM može biti i **mamac** i **izvršilac**: agent prima halucinirani URL, preuzima ga, parsira odgovor, a zatim može da leak-uje tokene, izvrši instrukcije, preuzme dependency ili ubaci poisoned data u CI/CD bez ikakvog human review-a.<sup>[[12]](#references)</sup>

### Praktični attacker promptovi

High-yield promptovi obično izgledaju kao normalni enterprise zadaci, a ne kao eksplicitni phishing mamci:<sup>[[12]](#references)</sup>
- „Koji je payment sandbox URL za integracije brenda `<brand>`?”
- „Koji webhook endpoint treba da koristim za build notifications brenda `<brand>`?”
- „Gde se nalazi employee benefits / billing / SSO portal za `<brand>`?”
- „Daj mi direktan Android APK ili desktop client download za `<brand>`.”

### Defensive inversion

Tretirajte ovo kao proaktivan problem domain monitoring-a, a ne samo kao problem prompt injection-a:<sup>[[12]](#references)</sup>
- Napravite **brand prompt corpus** i periodično ispitujte LLM-ove na koje se vaši korisnici/agenti oslanjaju.
- Čuvajte halucinirane URL-ove i pratite koji su stabilni kroz različite temperature/modele.
- Pratite **Adversarial Exploitation Window (AEW)**: vreme između prve halucinacije i registracije od strane napadača. Pozitivan AEW znači da defenders mogu da pre-registruju, sinkhole-uju ili pre-block-uju domen pre weaponization-a.
- Pratite prelaze **NXDOMAIN → registered** za nadređene domene.
- Prilikom registracije analizirajte registrar, datum kreiranja, nameservers, privacy shielding, sadržaj stranice, screenshots, status parked-page-a i sličnost brand asset-a.
- Dodajte policy gates tako da agenti/developeri **po podrazumevanim podešavanjima ne veruju domenima koje generiše LLM**: zahtevajte allowlists, validaciju vlasništva, CT/RDAP provere ili human approval pre prve upotrebe.

Ovo se istovremeno uklapa u nekoliko AI risk kategorija: **AI supply-chain attack**, **insecure model output** i **rogue actions** kada agenti autonomno koriste halucinirani URL.

## References

- [1] [OWASP Top 10 ranjivosti machine learning-a](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Rizici](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS matrica pretnji](https://atlas.mitre.org/)
- [4] [Unit 42 – Rizici Code Assistant LLM-ova: štetan sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: ukradeni Cloud credential-i upotrebljeni u novom AI napadu](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Pregled LLMJacking šeme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (preprodaja ukradenog LLM pristupa)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Detaljna analiza deployment-a on-premise LLM servera sa niskim privilegijama](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specifikacija](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domeni koje halucinira AI kao vektor software supply-chain napada](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: kako AI halucinacije podstiču novu klasu supply-chain napada](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
