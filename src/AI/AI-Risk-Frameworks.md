# Rizici AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 ranjivosti mašinskog učenja

OWASP je identifikovao top 10 ranjivosti mašinskog učenja koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do različitih bezbednosnih problema, uključujući data poisoning, model inversion i adversarial attacks. Razumevanje ovih ranjivosti je ključno za izgradnju sigurnih AI sistema.

Za ažuriranu i detaljnu listu top 10 ranjivosti mašinskog učenja, pogledajte [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: Napadač dodaje sitne, često nevidljive izmene u **dolazne podatke** kako bi model doneo pogrešnu odluku.\
*Primer*: Nekoliko tačkica farbe na stop‑znaku zbuni self‑driving automobil koji "vidi" saobraćajni znak za ograničenje brzine.

- **Data Poisoning Attack**: **skup za treniranje** je namerno zagađen lošim uzorcima, učeći model štetnim pravilima.\
*Primer*: Maliciozni binarni fajlovi su pogrešno označeni kao "benign" u korpusu za treniranje antivirus softvera, što omogućava sličnom malveru da kasnije prođe nezapaženo.

- **Model Inversion Attack**: Probingom izlaza, napadač pravi **reverse model** koji rekonstruše osetljive karakteristike originalnih inputa.\
*Primer*: Rekreiranje MRI snimka pacijenta iz predikcija modela za detekciju raka.

- **Membership Inference Attack**: Adversar testira da li je **konkretan zapis** korišćen tokom treniranja tako što primećuje razlike u konfidentnosti.\
*Primer*: Potvrđivanje da transakcija jedne osobe postoji u training setu modela za detekciju prevare.

- **Model Theft**: Ponavljanim upitima napadač uči granice odluke i uspeva da **klonira ponašanje modela** (i IP).\
*Primer*: Sakupljanje dovoljnog broja Q&A parova iz ML‑as‑a‑Service API‑ja kako bi se izgradio skoro ekvivalentan lokalni model.

- **AI Supply‑Chain Attack**: Kompromitovanje bilo koje komponente (data, libraries, pre‑trained weights, CI/CD) u **ML pipeline** može pokvariti downstream modele.\
*Primer*: Poisoned dependency na model‑hub‑u instalira backdoored sentiment‑analysis model u mnogo aplikacija.

- **Transfer Learning Attack**: Maliciozna logika je ubačena u **pre‑trained model** i preživi fine‑tuning na zadatku žrtve.\
*Primer*: Vision backbone sa skrivenim trigger‑om i dalje menja labelu nakon što se adaptira za medicinsko snimanje.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **pomere izlaze modela** tako da idu u korist napadaču.\
*Primer*: Ubacivanje "čistih" spam poruka označenih kao ham kako bi spam filter propustio slične buduće poruke.

- **Output Integrity Attack**: Napadač **menja predikcije modela u tranzitu**, a ne sam model, varajući downstream sisteme.\
*Primer*: Menjanje verdicta malver klasifikatora sa "malicious" na "benign" pre nego što faza karantina fajla to vidi.

- **Model Poisoning** --- Direktne, ciljne izmene u **parametrima modela** same po sebi, često nakon dobijanja write pristupa, kako bi se promenilo ponašanje.\
*Primer*: Podešavanje težina na modelu za detekciju prevare u produkciji tako da transakcije sa određenih kartica uvek budu odobrene.


## Google SAIF Risks

Google‑ov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) navodi različite rizike povezane sa AI sistemima:

- **Data Poisoning**: Maliciozni akteri menjaju ili ubacuju training/tuning podatke da bi degradirali tačnost, implantirali backdoor‑e ili iskrivili rezultate, podrivajući integritet modela kroz čitav životni ciklus podataka.

- **Unauthorized Training Data**: Uvođenje autorski zaštićenih, osetljivih ili neodobrenih dataset‑ova stvara pravne, etičke i performansne obaveze zato što model uči iz podataka čije korišćenje nije bilo dozvoljeno.

- **Model Source Tampering**: Manipulacija lanca snabdevanja ili insider kompromitovanje koda modela, zavisnosti ili weights pre ili tokom treniranja može ugradi skrivenu logiku koja opstaje i posle retreninga.

- **Excessive Data Handling**: Slabi kontrolni mehanizmi za čuvanje i upravljanje podacima dovode sisteme do skladištenja ili obrade više ličnih podataka nego što je neophodno, povećavajući izloženost i rizik od neusklađenosti.

- **Model Exfiltration**: Napadači kradu model fajlove/weights, što dovodi do gubitka intelektualne svojine i omogućava copy‑cat servise ili prateće napade.

- **Model Deployment Tampering**: Adversar menja model artefakte ili serving infrastrukturu tako da pokrenuti model razlikuje od verifikovane verzije, što potencijalno menja ponašanje.

- **Denial of ML Service**: Preplavljivanje API‑ja ili slanje "sponge" inputa može iscrpiti compute/energiju i oboriti model, što podseća na klasične DoS napade.

- **Model Reverse Engineering**: Sakupljanjem velikog broja input‑output parova, napadači mogu klonirati ili distilovati model, podstičući imitacione proizvode i prilagođene adversarial napade.

- **Insecure Integrated Component**: Ranljivi plugin‑ovi, agenti ili upstream servisi dozvoljavaju napadačima da ubace kod ili eskaliraju privilegije unutar AI pipeline‑a.

- **Prompt Injection**: Formulisanje promptova (direktno ili indirektno) za smugglovanje instrukcija koje prevazilaze sistemski intent, primoravajući model da izvrši nepredviđene komande.

- **Model Evasion**: Pažljivo dizajnirani inputi pokreću model da pogrešno klasifikuje, hallucinira ili izbacuje zabranjeni sadržaj, narušavajući bezbednost i poverenje.

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz trening podataka ili korisničkog konteksta, kršeći privatnost i regulative.

- **Inferred Sensitive Data**: Model zaključuje lične atribute koji nikada nisu bili dati, stvarajući nove privatnosne štete kroz inferenciju.

- **Insecure Model Output**: Nesanitizovani odgovori prosleđuju štetni kod, dezinformacije ili neprimeren sadržaj korisnicima ili downstream sistemima.

- **Rogue Actions**: Autonomno integrisani agenti izvršavaju nepredviđene real‑world operacije (pisanja fajlova, API pozivi, kupovine itd.) bez adekvatnog korisničkog nadzora.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan okvir za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Kategorizuje različite tehnike napada i taktike koje adversari mogu koristiti protiv AI modela i takođe kako koristiti AI sisteme za izvođenje različitih napada.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Napadači kradu aktivne session tokene ili cloud API credentials i pozivaju plaćene, cloud‑hosted LLM‑ove bez autorizacije. Pristup se često preprodaje preko reverse proxies koji stoje ispred naloga žrtve, npr. "oai-reverse-proxy" deploymenti. Posledice uključuju finansijski gubitak, zloupotrebu modela van politike i atribuciju žrtvi tenant‑a.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Podizanje reverse proxy‑ja koji prosleđuje zahteve pravom provajderu, sakrivajući upstream key i multiplexujući mnoge korisnike.
- Abuse direct base‑model endpoints da se zaobiđu enterprise guardrails i rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read‑only where applicable); rotate on anomaly.
- Terminate all traffic server‑side behind a policy gateway that enforces safety filters, per‑route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto‑revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long‑lived static API keys.

## Self-hosted LLM inference hardening

Pokretanje lokalnog LLM servera za poverljive podatke stvara drugačiji attack surface u odnosu na cloud‑hosted API‑je: inference/debug endpoints mogu otkriti prompt sadržaje, serving stack obično izlaže reverse proxy, a GPU device nodes daju pristup velikim `ioctl()` surfaces. Ako procenjujete ili deploy‑ujete on‑prem inference servis, pregledajte bar sledeće tačke.

### Prompt leakage via debug and monitoring endpoints

Treat the inference API as a **multi-user sensitive service**. Debug or monitoring routes can expose prompt contents, slot state, model metadata, or internal queue information. In `llama.cpp`, the `/slots` endpoint is especially sensitive because it exposes per-slot state and is only meant for slot inspection/management.

- Put a reverse proxy in front of the inference server and **deny by default**.
- Only allowlist the exact HTTP method + path combinations that are needed by the client/UI.
- Disable introspection endpoints in the backend itself whenever possible, for example `llama-server --no-slots`.
- Bind the reverse proxy to `127.0.0.1` and expose it through an authenticated transport such as SSH local port forwarding instead of publishing it on the LAN.

Example allowlist with nginx:
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
### Rootless containers bez mreže i sa UNIX soketima

Ako inference daemon podržava slušanje na UNIX soketu, preferirajte to umesto TCP i pokrenite container bez **mrežnog steka**:
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
- `--network none` uklanja izloženost TCP/IP saobraćaju (ulaznom/izlaznom) i izbegava user-mode helpere koje bi rootless containers inače zahtevali.
- UNIX socket vam omogućava korišćenje POSIX permissions/ACLs na putanji socketa kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman smanjuju uticaj container breakout-a jer container root nije host root.
- Read-only model mounts smanjuju verovatnoću manipulacije modelom iznutra containera.

### Minimizacija GPU device-node

Za GPU-backed inference, `/dev/nvidia*` fajlovi predstavljaju visokovredne lokalne površine za napad jer otkrivaju velike driver `ioctl()` handlere i potencijalno deljene puteve za upravljanje GPU memorijom.

- Ne ostavljajte `/dev/nvidia*` world writable.
- Ograničite `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev pravila i ACLs tako da samo mapirani container UID može da ih otvori.
- Stavite na blacklist nepotrebne module kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem` na headless inference hosts.
- Preload-ujte samo neophodne module pri boot-u umesto da runtime oportunistički pokreće `modprobe` tokom startovanja inference-a.

Primer:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jedna važna stavka za pregled je **`/dev/nvidia-uvm`**. Čak i ako radno opterećenje eksplicitno ne koristi `cudaMallocManaged()`, noviji CUDA runtime-i i dalje mogu zahtevati `nvidia-uvm`. Pošto je ovaj uređaj deljen i upravlja virtuelnom memorijom GPU-a, tretirajte ga kao površinu izlaganja podataka između zakupaca. Ako inference backend to podržava, Vulkan backend može biti interesantan kompromis jer može u potpunosti izbeći izlaganje `nvidia-uvm` kontejneru.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp treba koristiti kao odbranu u dubini oko procesa inference-a:

- Dozvolite samo deljene biblioteke, putanje modela, direktorijum soketa i GPU device node-ove koji su zaista potrebni.
- Izričito zabranite visokorizične capabilities kao što su `sys_admin`, `sys_module`, `sys_rawio` i `sys_ptrace`.
- Održavajte direktorijum modela samo za čitanje i ograničite zapisive putanje samo na runtime socket/cache direktorijume.
- Pratite denial logove jer pružaju korisnu telemetriju detekcije kada model server ili post-exploitation payload pokušaju da zaobiđu očekivano ponašanje.

Primer AppArmor pravila za radnika sa podrškom za GPU:
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
## Izvori
- [Unit 42 – Rizici Code Assistant LLMs: Štetni sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Pregled LLMJacking šeme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (prodaja ukradenog pristupa LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Dubinska analiza implementacije on-premise LLM servera sa niskim privilegijama](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
