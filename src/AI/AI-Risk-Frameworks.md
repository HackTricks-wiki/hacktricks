# AI rizici

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 ranjivosti mašinskog učenja

OWASP je identifikovao top 10 ranjivosti mašinskog učenja koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do različitih sigurnosnih problema, uključujući data poisoning, model inversion i adversarial attacks. Razumevanje ovih ranjivosti je ključno za izgradnju sigurnih AI sistema.

Za ažuriranu i detaljnu listu top 10 ranjivosti mašinskog učenja, pogledajte [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Napadač dodaje sitne, često nevidljive izmene u **ulazne podatke** kako bi model doneo pogrešnu odluku.\
*Example*: Nekoliko tačkica boje na stop‑znaku navede autonomni automobil da „vidi“ znak ograničenja brzine.

- **Data Poisoning Attack**: **skup za treniranje** se namerno zagađuje lošim uzorcima, učeći model štetnim pravilima.\
*Example*: Malware binari su pogrešno označeni kao „benign“ u korpusu za treniranje antivirusa, omogućavajući sličnom malveru da kasnije prođe neopaženo.

- **Model Inversion Attack**: Probingom output‑a, napadač gradi **reverse model** koji rekonstruše osetljive karakteristike originalnih ulaza.\
*Example*: Rekonstruisanje MRI snimka pacijenta iz predikcija modela za detekciju karcinoma.

- **Membership Inference Attack**: Napadač testira da li je **konkretan zapis** korišćen tokom treniranja tako što uočava razlike u confidence‑u.\
*Example*: Potvrđivanje da li se transakcija određene osobe pojavljuje u podacima koji su korišćeni za treniranje modela za detekciju prevara.

- **Model Theft**: Ponavljanim upitima napadač uči granice odluka i može **klonirati ponašanje modela** (i intelektualnu svojinu).\
*Example*: Prikupljanje dovoljno Q&A parova sa ML‑as‑a‑Service API‑ja da se izgradi skoro‑ekvivalentan lokalni model.

- **AI Supply‑Chain Attack**: Kompromitovanje bilo koje komponente (podataka, biblioteka, pre‑trained weights, CI/CD) u **ML pipeline** da bi se pokvarili downstream modeli.\
*Example*: Zatrovani dependency na model‑hub instalira backdoored sentiment‑analysis model u mnoge aplikacije.

- **Transfer Learning Attack**: Maliciozna logika je ubačena u **pre‑trained model** i preživi fino‑tuning na zadatku žrtve.\
*Example*: Vision backbone sa skrivenim trigger‑om i dalje menja labelu nakon adaptacije za medicinski imaging.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **pomere izlaze modela** da favorizuju napadačevu agendu.\
*Example*: Ubacivanje „čistih“ spam mejlova označenih kao ham tako da spam filter propusti slične buduće mejlove.

- **Output Integrity Attack**: Napadač **menja predikcije modela u tranzitu**, a ne sam model, zavaravajući downstream sisteme.\
*Example*: Mijenjanje odluke malware classifier‑a iz „malicious“ u „benign“ pre nego što faza karantinovanja fajla to vidi.

- **Model Poisoning** --- Direktne, ciljane izmene u **parametrima modela** samih, često nakon sticanja write pristupa, da bi se promenilo ponašanje.\
*Example*: Podešavanje weight‑ova na modelu za detekciju prevara u produkciji tako da transakcije sa određenih kartica budu uvek odobrene.


## Google SAIF rizici

Google‑ov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje razne rizike povezane sa AI sistemima:

- **Data Poisoning**: Maliciozni akteri menjaju ili ubacuju training/tuning podatke da degradiraju tačnost, implantiraju backdoors ili iskrivljuju rezultate, podrivajući integritet modela kroz ceo lifecycle podataka.

- **Unauthorized Training Data**: Uvođenje autorski zaštićenih, osetljivih ili neovlašćenih dataset‑ova stvara pravne, etičke i performansne probleme jer model uči iz podataka koje nije smeo koristiti.

- **Model Source Tampering**: Supply‑chain ili insider manipulacija koda modela, dependencija ili weights pre ili tokom treniranja može ugraditi skrivenu logiku koja opstaje i nakon retraining‑a.

- **Excessive Data Handling**: Slabe kontrole za čuvanje i upravljanje podacima dovode do toga da sistemi skladište ili procesuiraju više ličnih podataka nego što je potrebno, povećavajući izloženost i rizik usklađenosti.

- **Model Exfiltration**: Napadači kradu fajlove/weights modela, što dovodi do gubitka intelektualne svojine i omogućava copy‑cat servise ili naredne napade.

- **Model Deployment Tampering**: Napadači menjaju model artifacts ili serving infrastrukturu tako da pokretani model odstupa od verifikovane verzije, potencijalno menjajući ponašanje.

- **Denial of ML Service**: Preplavljivanje API‑ja ili slanje „sponge“ inputa može iscrpeti compute/energiju i izbaciti model offline, slično klasičnim DoS napadima.

- **Model Reverse Engineering**: Prikupljanjem velikog broja input‑output parova, napadači mogu klonirati ili distilovati model, podstičući imitacijske proizvode i prilagođene adversarial napade.

- **Insecure Integrated Component**: Ranljivi plugin‑ovi, agenti ili upstream servisi dozvoljavaju napadačima da ubace kod ili eskaliraju privilegije unutar AI pipeline‑a.

- **Prompt Injection**: Kreiranje promptova (direktno ili indirektno) koji unose instrukcije koje nadjačavaju sistemsku nameru, nateravši model da izvrši neželjene komande.

- **Model Evasion**: Pažljivo dizajnirani inputi navode model da pogrešno klasifikuje, halucinira ili daje zabranjen sadržaj, narušavajući sigurnost i poverenje.

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz svog training skupa ili korisničkog konteksta, kršeći privatnost i regulative.

- **Inferred Sensitive Data**: Model zaključuje lične atribute koji nikada nisu bili eksplicitno dati, stvarajući nove povrede privatnosti putem inferencije.

- **Insecure Model Output**: Ništendirani odgovori prosleđuju štetan kod, dezinformacije ili neprikladan sadržaj korisnicima ili downstream sistemima.

- **Rogue Actions**: Autonomno integrisani agenti izvršavaju neželjene real‑world operacije (pisanje fajlova, API pozivi, kupovine itd.) bez adekvatnog nadzora korisnika.

## MITRE AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan okvir za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Kategorizuje različite tehnike napada i taktike koje protivnici mogu koristiti protiv AI modela, kao i kako koristiti AI sisteme za izvođenje različitih napada.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Napadači kradu aktivne session token‑e ili cloud API kredencijale i pozivaju plaćene, cloud‑hosted LLM‑ove bez autorizacije. Pristup se često preprodaje preko reverse proxies koji frontuju račun žrtve, npr. "oai-reverse-proxy" deployment‑a. Posledice uključuju finansijski gubitak, zloupotrebu modela van politike i pripisivanje aktivnosti victim tenant‑u.

TTPs:
- Harvest tokens sa inficiranih developer mašina ili browser‑a; steal CI/CD secrets; buy leaked cookies.
- Podizanje reverse proxy‑ja koji prosleđuje zahteve pravom provider‑u, sakrivajući upstream key i multiplex‑ujući mnogo korisnika.
- Abuse direct base‑model endpoints da bi se zaobišli enterprise guardrails i rate limits.

Mitigations:
- Bind tokens na device fingerprint, IP ranges, i client attestation; enforce short expirations i refresh sa MFA.
- Scope keys minimalno (no tool access, read‑only gde je primenljivo); rotate pri anomalijama.
- Terminate sav trafić server‑side iza policy gateway‑a koji enforce‑uje safety filtere, per‑route kvote i tenant isolation.
- Monitor za neuobičajene pattern‑e korišćenja (nagli spike‑ovi troškova, netipične regije, UA strings) i auto‑revoke sumnjive session‑e.
- Prefer mTLS ili signed JWTs izdatih od vašeg IdP nad long‑lived static API key‑evima.

## Self-hosted LLM inference hardening

Pokretanje lokalnog LLM servera za poverljive podatke stvara drugačiju attack površinu u odnosu na cloud‑hosted API‑je: inference/debug endpoints mogu leak promptove, serving stack obično izlaže reverse proxy, a GPU device node‑ovi daju pristup velikim ioctl() površinama. Ako procenjujete ili deploy‑ujete on‑prem inference servis, pregledajte bar sledeće tačke.

### Curenje prompta preko debug i monitoring endpointa

Tretirajte inference API kao **multi‑user sensitive service**. Debug ili monitoring rute mogu eksponirati sadržaj promptova, slot state, model metadata ili internu queue informaciju. U llama.cpp, `/slots` endpoint je posebno osetljiv jer eksponira per‑slot stanje i namenjen je samo za inspekciju/menadžment slotova.

- Stavite reverse proxy ispred inference servera i **deny by default**.
- Dozvolite samo tačne kombinacije HTTP method + path koje su potrebne klijentu/UI‑ju.
- Onemogućite introspection endpoint‑e u backend‑u kad god je moguće, na primer `llama-server --no-slots`.
- Bind‑ujte reverse proxy na `127.0.0.1` i izlažite ga kroz autentifikovani transport kao što je SSH local port forwarding umesto da ga objavljujete na LAN‑u.

Primer allowliste sa nginx:
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
### Rootless containers bez mreže i sa UNIX sockets

Ako inference daemon podržava osluškivanje na UNIX socket, preferirajte to umesto TCP i pokrenite container sa **no network stack**:
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
- `--network none` uklanja ulaznu/izlaznu TCP/IP izloženost i izbegava user-mode helpere koje bi rootless containers inače zahtevali.
- UNIX socket vam omogućava korišćenje POSIX permissions/ACLs na putanji socketa kao prvog sloja kontrole pristupa.
- `--userns=keep-id` i rootless Podman smanjuju uticaj container breakout-a jer container root nije host root.
- Montiranja modela u režimu samo-za-čitanje smanjuju šansu za neovlašćenu izmenu modela iznutra containera.

### Minimizacija GPU device-node-ova

Za GPU-backed inference, `/dev/nvidia*` fajlovi su visoko-vredne lokalne površine napada jer izlažu velike drajver `ioctl()` handlere i potencijalno deljene puteve za upravljanje GPU memorijom.

- Ne ostavljajte `/dev/nvidia*` world-writable.
- Ograničite `nvidia`, `nvidiactl` i `nvidia-uvm` pomoću `NVreg_DeviceFileUID/GID/Mode`, udev pravila i ACL-a tako da samo mapirani container UID može da ih otvori.
- Stavite na blacklist nepotrebne module kao što su `nvidia_drm`, `nvidia_modeset` i `nvidia_peermem` na headless inference hostovima.
- Preload-ujte samo potrebne module pri boot-u umesto da runtime oportunistički poziva `modprobe` tokom pokretanja inference.

Primer:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jedna važna tačka za reviziju je **`/dev/nvidia-uvm`**. Čak i ako workload ne koristi eksplicitno `cudaMallocManaged()`, recentni CUDA runtimes možda i dalje zahtevaju `nvidia-uvm`. Pošto je ovaj device shared i rukovodi GPU virtualnom memorijom, tretirajte ga kao cross-tenant data-exposure surface. Ako inference backend podržava, Vulkan backend može biti zanimljiv kompromis jer može izbeći izlaganje `nvidia-uvm` containeru uopšte.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp treba koristiti kao defense in depth oko inference procesa:

- Allow only the shared libraries, model paths, socket directory, and GPU device nodes that are actually required.
- Izričito odbiti high-risk capabilities kao što su `sys_admin`, `sys_module`, `sys_rawio`, i `sys_ptrace`.
- Držite model directory read-only i ograničite writable paths samo na runtime socket/cache directories.
- Monitor denial logs jer oni pružaju korisnu detection telemetry kada model server ili post-exploitation payload pokuša da iskorači iz očekivanog ponašanja.

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
## Reference
- [Unit 42 – Rizici Code Assistant LLMs: štetan sadržaj, zloupotreba i obmana](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Pregled šeme LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (preprodaja ukradenog pristupa LLM-ovima)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Dubinska analiza postavljanja on-premise low-privileged LLM servera](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specifikacija](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
