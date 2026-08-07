# AI rizici

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp je identifikovao 10 najvažnijih ranjivosti machine learning sistema koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do različitih bezbednosnih problema, uključujući poisoning podataka, inverziju modela i adversarial napade. Razumevanje ovih ranjivosti ključno je za izgradnju bezbednih AI sistema.

Za ažuriranu i detaljnu listu 10 najvažnijih ranjivosti machine learning sistema pogledajte projekat [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Napadač dodaje male, često nevidljive izmene **ulaznim podacima**, kako bi model doneo pogrešnu odluku.\
*Primer*: Nekoliko tačkica boje na znaku stop može navesti self-driving automobil da "vidi" znak ograničenja brzine.

- **Data Poisoning Attack**: **Training set** se namerno zagađuje lošim uzorcima, čime se model uči štetnim pravilima.\
*Primer*: Malware binarni fajlovi se u antivirusnom training korpusu označavaju kao "benign", omogućavajući sličnom malware-u da kasnije prođe neprimećeno.

- **Model Inversion Attack**: Ispitivanjem izlaza, napadač pravi **reverse model** koji rekonstruiše osetljive karakteristike originalnih ulaza.\
*Primer*: Ponovno kreiranje MRI snimka pacijenta na osnovu predviđanja modela za otkrivanje raka.

- **Membership Inference Attack**: Napadač proverava da li je **određeni zapis** korišćen tokom training-a, posmatrajući razlike u nivou pouzdanosti.\
*Primer*: Potvrđivanje da se bankarska transakcija određene osobe pojavljuje u training podacima modela za otkrivanje prevara.

- **Model Theft**: Ponovljeno slanje upita omogućava napadaču da nauči granice odlučivanja i **klonira ponašanje modela** (kao i IP).\
*Primer*: Prikupljanje dovoljnog broja Q&A parova iz ML-as-a-Service API-ja radi izgradnje gotovo ekvivalentnog lokalnog modela.

- **AI Supply-Chain Attack**: Kompromitovanje bilo koje komponente (podataka, biblioteka, pre-trained weights, CI/CD) u **ML pipeline-u** radi izmene nizvodnih modela.\
*Primer*: Zavisnost sa model-hub-a koja sadrži poisoning instalira model za analizu sentimenta sa backdoor-om u velikom broju aplikacija.

- **Transfer Learning Attack**: Zlonamerna logika se postavlja u **pre-trained model** i opstaje tokom fine-tuning-a za zadatak žrtve.\
*Primer*: Vision backbone sa skrivenim trigger-om i dalje menja oznake nakon prilagođavanja za medicinsko snimanje.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **pomeraju izlaze modela** u korist napadačeve agende.\
*Primer*: Ubacivanje "čistih" spam emailova označenih kao ham, kako bi spam filter propuštao slične buduće emailove.

- **Output Integrity Attack**: Napadač **menja predviđanja modela tokom prenosa**, a ne sam model, čime obmanjuje nizvodne sisteme.\
*Primer*: Promena presude malware classifier-a sa "malicious" na "benign" pre nego što je vidi faza karantina fajla.

- **Model Poisoning** --- Direktne, ciljane izmene **parametara modela**, često nakon dobijanja write access-a, radi promene ponašanja.\
*Primer*: Menjanje weights-a produkcionog modela za otkrivanje prevara tako da se transakcije sa određenih kartica uvek odobre.


## Google SAIF rizici

Google-ov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/) opisuje različite rizike povezane sa AI sistemima:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Zlonamerni akteri menjaju ili ubacuju training/tuning podatke kako bi smanjili preciznost, ugradili backdoor-e ili iskrivili rezultate, čime ugrožavaju integritet modela tokom čitavog data-lifecycle-a.

- **Unauthorized Training Data**: Unošenje autorski zaštićenih, osetljivih ili neodobrenih dataset-ova stvara pravne, etičke i performansne rizike, jer model uči iz podataka za čije korišćenje nikada nije dobio dozvolu.

- **Model Source Tampering**: Supply-chain ili insiderska manipulacija kodom modela, dependencies-ima ili weights-ima pre ili tokom training-a može ugraditi skrivenu logiku koja opstaje čak i nakon ponovnog training-a.

- **Excessive Data Handling**: Slabe kontrole zadržavanja podataka i governance-a dovode do toga da sistemi čuvaju ili obrađuju više ličnih podataka nego što je potrebno, povećavajući rizik od izlaganja i neusklađenosti sa propisima.

- **Model Exfiltration**: Napadači kradu fajlove/weights modela, što dovodi do gubitka intelektualne svojine i omogućava copy-cat servise ili naknadne napade.

- **Model Deployment Tampering**: Napadači menjaju artefakte modela ili serving infrastrukturu tako da se pokrenuti model razlikuje od proverene verzije, što potencijalno menja njegovo ponašanje.

- **Denial of ML Service**: Preplavljivanje API-ja ili slanje “sponge” ulaza može iscrpeti compute/energy resurse i oboriti model, poput klasičnih DoS napada.

- **Model Reverse Engineering**: Prikupljanjem velikog broja input-output parova, napadači mogu klonirati ili distilovati model, podstičući proizvode za imitaciju i prilagođene adversarial napade.

- **Insecure Integrated Component**: Ranjivi plugin-ovi, agenti ili upstream servisi omogućavaju napadačima da ubace kod ili eskaliraju privilegije unutar AI pipeline-a.

- **Prompt Injection**: Kreiranje prompt-ova (direktno ili indirektno) radi ubacivanja instrukcija koje nadjačavaju nameru sistema, navodeći model da izvrši neželjene komande.

- **Model Evasion**: Pažljivo dizajnirani ulazi navode model da pogrešno klasifikuje, halucinira ili generiše nedozvoljen sadržaj, čime se umanjuju bezbednost i poverenje.

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz svojih training podataka ili korisničkog konteksta, kršeći privatnost i propise.

- **Inferred Sensitive Data**: Model zaključuje lične karakteristike koje nikada nisu bile prosleđene, stvarajući novu štetu po privatnost putem inference-a.

- **Insecure Model Output**: Nesanirani odgovori prosleđuju štetan kod, dezinformacije ili neprikladan sadržaj korisnicima ili nizvodnim sistemima.

- **Rogue Actions**: Autonomno integrisani agenti izvršavaju neželjene operacije u stvarnom svetu (upisivanje fajlova, API pozive, kupovine itd.) bez odgovarajućeg nadzora korisnika.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan framework za razumevanje i ublažavanje rizika povezanih sa AI sistemima. On kategorizuje različite attack tehnike i taktike koje adversaries mogu koristiti protiv AI modela, kao i načine korišćenja AI sistema za izvođenje različitih napada.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Napadači kradu aktivne session tokene ili cloud API credentials i bez ovlašćenja pozivaju plaćene, cloud-hosted LLM-ove. Pristup se često preprodaje putem reverse proxy-ja koji prosleđuju zahteve preko naloga žrtve, npr. deployment-i "oai-reverse-proxy". Posledice uključuju finansijski gubitak, korišćenje modela mimo politike i pripisivanje aktivnosti tenant-u žrtve.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Prikupljati tokene sa zaraženih developer računara ili browser-a; krasti CI/CD secrets; kupovati leaked cookies.<sup>[[5]](#references)</sup>
- Postaviti reverse proxy koji prosleđuje zahteve stvarnom provider-u, skriva upstream key i multipleksira veliki broj korisnika.<sup>[[5]](#references)[[7]](#references)</sup>
- Zloupotrebiti direktne base-model endpoint-e radi zaobilaženja enterprise guardrails-a i rate limit-a.<sup>[[4]](#references)</sup>

Mitigations:
- Vezati tokene za device fingerprint, IP opsege i client attestation; primenjivati kratka važenja i refresh uz MFA.
- Ograničiti ključeve na najmanji potreban opseg (bez tool access-a, read-only gde je primenljivo); rotirati ih pri anomalijama.
- Prekinuti sav saobraćaj server-side, iza policy gateway-a koji primenjuje safety filter-e, kvote po ruti i izolaciju tenant-a.
- Pratiti neuobičajene obrasce korišćenja (nagla povećanja troškova, netipični regioni, UA strings) i automatski opozvati sumnjive sesije.
- Prednost dati mTLS-u ili potpisanim JWT-ovima koje izdaje vaš IdP, umesto dugotrajnih statičkih API ključeva.

## Ojačavanje self-hosted LLM inference-a

Pokretanje lokalnog LLM servera za poverljive podatke stvara drugačiju attack surface od cloud-hosted API-ja: inference/debug endpoint-i mogu leak-ovati prompt-ove, serving stack obično izlaže reverse proxy, a GPU device node-ovi omogućavaju pristup velikim `ioctl()` površinama. Ako procenjujete ili postavljate on-prem inference servis, proverite najmanje sledeće tačke.<sup>[[8]](#references)</sup>

### Curenje prompt-ova putem debug i monitoring endpoint-a

Tretirajte inference API kao **osetljiv servis sa više korisnika**. Debug ili monitoring rute mogu otkriti sadržaj prompt-ova, stanje slotova, metadata modela ili informacije o internom redu čekanja. U `llama.cpp`, endpoint `/slots` je naročito osetljiv jer otkriva stanje po slotovima i namenjen je isključivo za pregled/upravljanje slotovima.<sup>[[8]](#references)</sup>

- Postavite reverse proxy ispred inference servera i **podrazumevano sve zabranite**.
- Dozvolite samo tačne kombinacije HTTP metoda + putanja koje su potrebne client/UI-ju.
- Isključite introspection endpoint-e u samom backend-u kad god je moguće, na primer `llama-server --no-slots`.<sup>[[9]](#references)</sup>
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
### Rootless kontejneri bez mreže i UNIX socket-a

Ako inference daemon podržava osluškivanje na UNIX socket-u, koristite njega umesto TCP-a i pokrenite kontejner sa **isključenim mrežnim stekom**:<sup>[[8]](#references)</sup>
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
- `--network none` uklanja TCP/IP izloženost ka ulaznom i izlaznom saobraćaju i izbegava user-mode helpers koji bi rootless containers inače zahtevali.
- UNIX socket omogućava korišćenje POSIX dozvola/ACL-ova na putanji socket-a kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman smanjuju uticaj container breakout-a jer container root nije host root.
- Read-only model mounts smanjuju verovatnoću tamperovanja modela iz container-a.

### Minimalizacija GPU device-node-ova

Za inference uz GPU, `/dev/nvidia*` fajlovi predstavljaju lokalne attack surface-e visoke vrednosti jer izlažu velike driver `ioctl()` handlere i potencijalno deljene GPU memory-management putanje.<sup>[[8]](#references)</sup>

- Ne ostavljajte `/dev/nvidia*` sa world-writable dozvolama.
- Ograničite `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev pravila i ACL-ova tako da ih može otvoriti samo mapirani container UID.
- Blacklist-ujte nepotrebne module kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem` na headless inference hostovima.
- Učitajte unapred samo neophodne module tokom boot-a umesto da runtime oportunistički pokreće `modprobe` tokom pokretanja inference-a.

Primer:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jedna važna stavka za proveru je **`/dev/nvidia-uvm`**. Čak i ako workload ne koristi eksplicitno `cudaMallocManaged()`, noviji CUDA runtime-i i dalje mogu zahtevati `nvidia-uvm`. Pošto je ovaj uređaj deljen i upravlja GPU virtuelnom memorijom, tretirajte ga kao površinu za izlaganje podataka između tenant-a. Ako ga inference backend podržava, Vulkan backend može biti zanimljiv kompromis jer može u potpunosti izbeći izlaganje `nvidia-uvm` uređaja container-u.<sup>[[8]](#references)</sup>

### LSM ograničavanje inference worker-a

AppArmor/SELinux/seccomp treba koristiti kao defense in depth oko inference procesa:<sup>[[8]](#references)</sup>

- Dozvolite samo shared libraries, putanje do modela, direktorijum socket-a i GPU device nodes koji su zaista potrebni.
- Eksplicitno zabranite visokorizične capabilities, kao što su `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Direktorijum modela zadržite u read-only režimu, a writable putanje ograničite samo na runtime socket/cache direktorijume.
- Pratite denial log-ove jer pružaju korisnu telemetry za detekciju kada model server ili post-exploitation payload pokušaju da napuste očekivano ponašanje.

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
## Phantom Squatting: domeni koje je halucinirao LLM kao vektor AI lanca snabdevanja

Phantom squatting je **ekvivalent slopsquatting-a za domene/URL-ove**. Umesto da halucinira nepostojeći naziv paketa, LLM halucinira verodostojan **portal, API, webhook, billing, SSO, download ili support domen** za stvarni brend, a napadač registruje taj namespace pre nego što ga čovek ili agent upotrebi.<sup>[[12]](#references)[[13]](#references)</sup>

Ovo je važno zato što se u mnogim AI-potpomognutim tokovima rada izlaz modela tretira kao **trusted dependency**:
- Developeri kopiraju predloženi endpoint u code ili CI/CD integracije.
- AI agents automatski preuzimaju dokumentaciju, sheme, APK-ove, ZIP-ove ili webhook odredišta.
- Generisani runbook-ovi ili dokumentacija mogu da ugrade lažni URL kao da je autoritativan.

### Offensive workflow

1. **Ispitajte površinu halucinacija**: postavljajte pitanja specifična za brend o realističnim tokovima rada kao što su `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ili portali za `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizujte kandidate**: razrešite generisane URL-ove, svedite NXDOMAIN odgovore na nadređeni domen koji se može registrovati i uklonite duplikate prompt families. Prompt korpusi treba da ostanu raznovrsni, na primer izbacivanjem gotovo identičnih promptova pomoću **Jaccard similarity**.
3. **Dajte prioritet predvidljivim halucinacijama**:
- **Thermal Hallucination Persistence (THP)**: isti lažni domen pojavljuje se pri različitim temperaturama, uključujući nisku temperaturu kao što je `T=0.1`.
- **Cross-model consensus**: više LLM families generiše isti lažni domen.
4. **Registrujte i weaponize-ujte** nadređeni domen, a zatim hostujte phishing, lažne APK/ZIP download-e, credential harvesters, malicious docs ili API endpoints koji prikupljaju secrets/webhook payloads. **Pure domain-level hallucinations** najlakše se monetizuju zato što napadač kontroliše ceo namespace; subdomain/path hallucinations se i dalje mogu zloupotrebiti kada normalizovani nadređeni domen nije registrovan.
5. **Iskoristite zero-reputation window**: novoregistrovani domeni često nemaju istoriju na blocklistama, URL reputation ni zrelu telemetriju, pa mogu zaobići kontrole dok detekcije ne sustignu situaciju. Napadači mogu produžiti ovaj prozor pomoću benignih odgovora dostupnih samo crawler-ima, redirect cloaking-a, CAPTCHA gates ili odloženog payload staging-a.

### Zašto je opasno za agente

Za ljudsku žrtvu, lažni domen obično i dalje zahteva klik i još jednu radnju. Kod **agentic workflow-a**, LLM može biti i **mamac** i **izvršilac**: agent prima halucinirani URL, preuzima ga, parsira odgovor, a zatim može da leak-uje tokene, izvrši instructions, preuzme dependency ili pošalje poisoned data u CI/CD bez ikakvog human review-a.<sup>[[12]](#references)</sup>

### Praktični attacker promptovi

High-yield promptovi obično izgledaju kao uobičajeni enterprise zadaci, a ne kao eksplicitni phishing lures:<sup>[[12]](#references)</sup>
- „Koji je payment sandbox URL za `<brand>` integrations?”
- „Koji webhook endpoint treba da koristim za `<brand>` build notifications?”
- „Gde se nalazi employee benefits / billing / SSO portal za `<brand>`?”
- „Daj mi direktan Android APK ili desktop client download za `<brand>`.”

### Defensive inversion

Tretirajte ovo kao proaktivan problem domain monitoring-a, a ne samo kao problem prompt injection-a:<sup>[[12]](#references)</sup>
- Napravite **brand prompt corpus** i periodično ispitujte LLM-ove na koje se vaši korisnici/agenti oslanjaju.
- Čuvajte halucinirane URL-ove i pratite koji su stabilni pri različitim temperaturama/modelima.
- Pratite **Adversarial Exploitation Window (AEW)**: vreme između prve halucinacije i registracije od strane napadača. Pozitivan AEW znači da defenders mogu unapred da registruju domen, preusmere ga u sinkhole ili ga unapred blokiraju pre weaponization-a.
- Pratite prelaze **NXDOMAIN → registered** za nadređene domene.
- Nakon registracije, analizirajte registrar, datum kreiranja, nameservers, privacy shielding, sadržaj stranice, screenshots, status parked page-a i sličnost brand assets-a.
- Dodajte policy gates tako da agents/developers **po podrazumevanim vrednostima ne veruju domenima koje je generisao LLM**: zahtevajte allowlists, validaciju vlasništva, CT/RDAP checks ili human approval pre prve upotrebe.

Ovo istovremeno spada u nekoliko AI risk kategorija: **AI supply-chain attack**, **insecure model output** i **rogue actions** kada agenti autonomno koriste halucinirani URL.

## Reference

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – Rizici LLM-ova za code assistants: štetan sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: ukradeni cloud credentials korišćeni u novom AI napadu](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Pregled LLMJacking scheme-a – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (preprodaja ukradenog LLM access-a)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Detaljna analiza deployment-a on-premise low-privileged LLM server-a](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: domeni koje je halucinirao AI kao vektor software supply chain-a](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: kako AI halucinacije podstiču novu klasu supply-chain napada](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
