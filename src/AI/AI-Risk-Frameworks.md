# AI-risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp het die top 10 machine learning vulnerabilities geïdentifiseer wat AI-stelsels kan beïnvloed. Hierdie vulnerabilities kan tot verskeie sekuriteitskwessies lei, insluitend data poisoning, model inversion en adversarial attacks. Dit is noodsaaklik om hierdie vulnerabilities te verstaan om veilige AI-stelsels te bou.

Vir 'n bygewerkte en gedetailleerde lys van die top 10 machine learning vulnerabilities, verwys na die [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels onsigbare veranderinge aan **inkomende data** toe sodat die model die verkeerde besluit neem.\
*Voorbeeld*: 'n Paar verfspikkels op 'n stopteken mislei 'n selfbesturende motor om 'n spoedbeperkingsteken te "sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus met slegte samples besoedel, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware binaries word verkeerdelik as "benign" gemerk in 'n antivirus-training corpus, waardeur soortgelyke malware later ongemerk deurglip.

- **Model Inversion Attack**: Deur outputs te ondersoek, bou 'n aanvaller 'n **reverse model** wat sensitiewe eienskappe van die oorspronklike inputs rekonstrueer.\
*Voorbeeld*: Die herskepping van 'n pasiënt se MRI-beeld uit 'n cancer-detection model se predictions.

- **Membership Inference Attack**: Die adversary toets of 'n **spesifieke rekord** tydens training gebruik is deur verskille in confidence raak te sien.\
*Voorbeeld*: Bevestiging dat 'n persoon se banktransaksie in 'n fraud-detection model se training data voorkom.

- **Model Theft**: Herhaalde querying stel 'n aanvaller in staat om decision boundaries te leer en die **model se gedrag te kloon** (sowel as die IP).\
*Voorbeeld*: Die insameling van genoeg Q&A-pare vanaf 'n ML-as-a-Service API om 'n byna-ekwivalente plaaslike model te bou.

- **AI Supply-Chain Attack**: Kompromitteer enige komponent (data, libraries, pre-trained weights, CI/CD) in die **ML pipeline** om downstream models te korrupteer.\
*Voorbeeld*: 'n Besoedelde dependency op 'n model-hub installeer 'n backdoored sentiment-analysis model oor baie apps.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **pre-trained model** geplant en oorleef fine-tuning op die slagoffer se taak.\
*Voorbeeld*: 'n Vision backbone met 'n versteekte trigger verander steeds labels nadat dit vir medical imaging aangepas is.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd gemerkte data **verskuif die model se outputs** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: Die inspuiting van "clean" spam-e-posse wat as ham gemerk is, sodat 'n spam filter soortgelyke toekomstige e-posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander model predictions tydens transmissie**, nie die model self nie, en mislei downstream systems.\
*Voorbeeld*: Die omkeer van 'n malware classifier se "malicious"-uitspraak na "benign" voordat die file-quarantine stage dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **model parameters** self, dikwels nadat write access verkry is, om gedrag te verander.\
*Voorbeeld*: Die aanpassing van weights op 'n fraud-detection model in production sodat transaksies van sekere cards altyd goedgekeur word.


## Google SAIF-risiko's

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beskryf verskeie risiko's wat met AI-stelsels verband hou:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Kwaadwillige akteurs verander of spuit training/tuning data in om akkuraatheid te verlaag, backdoors te installeer of resultate te skeeftrek, wat model integrity oor die hele data-lifecycle ondermyn.

- **Unauthorized Training Data**: Die inname van copyrighted, sensitiewe of ongemagtigde datasets skep legal, ethical en performance liabilities omdat die model leer uit data wat dit nooit toegelaat is om te gebruik nie.

- **Model Source Tampering**: Supply-chain- of insider-manipulasie van model code, dependencies of weights voor of tydens training kan hidden logic insluit wat selfs ná retraining voortduur.

- **Excessive Data Handling**: Swak data-retention- en governance-controls lei daartoe dat stelsels meer personal data as nodig stoor of verwerk, wat exposure- en compliance-risk verhoog.

- **Model Exfiltration**: Aanvallers steel model files/weights, wat lei tot verlies van intellectual property en copy-cat services of follow-on attacks moontlik maak.

- **Model Deployment Tampering**: Adversaries verander model artifacts of serving infrastructure sodat die running model van die goedgekeurde weergawe verskil, wat behaviour moontlik verander.

- **Denial of ML Service**: APIs word oorstroom of “sponge”-inputs word gestuur om compute/energy uit te put en die model offline te dwing, soortgelyk aan klassieke DoS attacks.

- **Model Reverse Engineering**: Deur groot hoeveelhede input-output-pare in te samel, kan attackers die model kloon of distil, wat imitation products en aangepaste adversarial attacks aanwakker.

- **Insecure Integrated Component**: Kwesbare plugins, agents of upstream services stel aanvallers in staat om code in te spuit of privileges binne die AI pipeline te eskaleer.

- **Prompt Injection**: Deur prompts (direk of indirek) te konstrueer om instructions in te smokkel wat system intent override, kan die model onbedoelde commands uitvoer.

- **Model Evasion**: Noukeurig ontwerpte inputs veroorsaak dat die model verkeerd klassifiseer, hallusineer of disallowed content output, wat safety en trust ondermyn.

- **Sensitive Data Disclosure**: Die model openbaar private of confidential information uit sy training data of user context, wat privacy en regulations oortree.

- **Inferred Sensitive Data**: Die model lei personal attributes af wat nooit verskaf is nie, wat nuwe privacy harms deur inference skep.

- **Insecure Model Output**: Unsanitized responses gee harmful code, misinformation of inappropriate content aan users of downstream systems deur.

- **Rogue Actions**: Autonomously-integrated agents voer onbedoelde real-world operations (file writes, API calls, purchases, ens.) uit sonder voldoende user oversight.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) verskaf 'n omvattende framework om risiko's wat met AI-stelsels verband hou te verstaan en te versag. Dit kategoriseer verskeie attack techniques en tactics wat adversaries teen AI models kan gebruik, asook hoe om AI-stelsels te gebruik om verskillende attacks uit te voer.<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Aanvallers steel aktiewe session tokens of cloud API credentials en roep betaalde, cloud-hosted LLMs sonder authorization aan. Access word dikwels herverkoop deur reverse proxies wat die victim se account front, byvoorbeeld "oai-reverse-proxy"-deployments. Gevolge sluit financial loss, model misuse buite policy en attribution aan die victim tenant in.<sup>[[2]](#references)[[3]](#references)</sup>

TTPs:
- Harvest tokens vanaf infected developer machines of browsers; steel CI/CD secrets; koop leaked cookies.
- Stel 'n reverse proxy op wat requests na die genuine provider forward, die upstream key versteek en baie customers multiplex.
- Abuse direct base-model endpoints om enterprise guardrails en rate limits te omseil.

Versagtings:
- Bind tokens aan device fingerprint, IP ranges en client attestation; dwing short expirations af en refresh met MFA.
- Scope keys minimaal (geen tool access nie, read-only waar van toepassing); rotate by anomaly.
- Terminate alle traffic server-side agter 'n policy gateway wat safety filters, per-route quotas en tenant isolation afdwing.
- Monitor vir unusual usage patterns (sudden spend spikes, atypical regions, UA strings) en auto-revoke suspicious sessions.
- Verkies mTLS of signed JWTs wat deur jou IdP uitgereik is bo long-lived static API keys.

## Self-hosted LLM inference hardening

Die gebruik van 'n local LLM server vir confidential data skep 'n ander attack surface as cloud-hosted APIs: inference/debug endpoints kan prompts leak, die serving stack stel gewoonlik 'n reverse proxy bloot, en GPU device nodes gee toegang tot groot `ioctl()`-surfaces. As jy 'n on-prem inference service assesseer of deploy, hersien minstens die volgende punte.<sup>[[4]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

Behandel die inference API as 'n **multi-user sensitive service**. Debug- of monitoring routes kan prompt contents, slot state, model metadata of internal queue information blootstel. In `llama.cpp` is die `/slots` endpoint besonder sensitief omdat dit per-slot state blootstel en slegs vir slot inspection/management bedoel is.<sup>[[4]](#references)[[5]](#references)</sup>

- Plaas 'n reverse proxy voor die inference server en **deny by default**.
- Allowlist slegs die presiese HTTP method + path combinations wat die client/UI benodig.
- Disable introspection endpoints in die backend self waar moontlik, byvoorbeeld `llama-server --no-slots`.
- Bind die reverse proxy aan `127.0.0.1` en stel dit bloot deur 'n authenticated transport soos SSH local port forwarding, eerder as om dit op die LAN te publish.

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
### Rootless-containers sonder netwerk en UNIX-sockets

As die inference daemon luister op ’n UNIX-socket ondersteun, verkies dit bo TCP en voer die container met **geen netwerkstack** uit:
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
Voordele:
- `--network none` verwyder inkomende/uitgaande TCP/IP-blootstelling en vermy gebruikersmodushelpers wat rootless containers andersins sou benodig.
- ’n UNIX-sok laat jou toe om POSIX-permissies/ACL’s op die sokpad as die eerste toegangsbeheerlaag te gebruik.
- `--userns=keep-id` en rootless Podman verminder die impak van ’n container-ontsnapping omdat container-root nie host-root is nie.
- Leesalleen-modelmonterings verminder die kans op modelmanipulasie vanuit die container.

### Minimalisering van GPU-device nodes

Vir GPU-gesteunde inferensie is `/dev/nvidia*`-lêers waardevolle plaaslike aanvalsvlakke omdat hulle groot driver-`ioctl()`-hanteerders en potensieel gedeelde GPU-geheuebestuurspaaie blootstel.<sup>[[4]](#references)</sup>

- Moenie `/dev/nvidia*` wêreldskryfbaar laat nie.
- Beperk `nvidia`, `nvidiactl` en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev-reëls en ACL’s sodat slegs die gemapte container-UID dit kan oopmaak.
- Swartlys onnodige modules soos `nvidia_drm`, `nvidia_modeset` en `nvidia_peermem` op headless inferensiehosts.
- Laai slegs vereiste modules vooraf tydens selflaai, in plaas daarvan om die runtime toe te laat om dit opportunisties te `modprobe` tydens die opstart van inferensie.

Voorbeeld:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs al gebruik die workload nie uitdruklik `cudaMallocManaged()` nie, kan onlangse CUDA-runtimes steeds `nvidia-uvm` vereis. Omdat hierdie toestel gedeel word en GPU-virtuelegeheuebestuur hanteer, moet dit as ’n oppervlak vir datablootstelling tussen tenants hanteer word. Indien die inference-backend dit ondersteun, kan ’n Vulkan-backend ’n interessante kompromis wees omdat dit moontlik kan voorkom dat `nvidia-uvm` hoegenaamd aan die container blootgestel word.

### LSM-beperking vir inference-werkers

AppArmor/SELinux/seccomp behoort as defense in depth rondom die inference-proses gebruik te word:<sup>[[4]](#references)</sup>

- Laat slegs die shared libraries, model paths, socket directory en GPU device nodes toe wat werklik benodig word.
- Weier uitdruklik hoërisiko-capabilities soos `sys_admin`, `sys_module`, `sys_rawio` en `sys_ptrace`.
- Hou die model directory read-only en beperk writable paths tot slegs die runtime socket/cache directories.
- Monitor denial logs omdat hulle nuttige detection telemetry verskaf wanneer die model server of ’n post-exploitation-payload probeer om sy verwagte gedrag te ontduik.

Voorbeeld van AppArmor-reëls vir ’n GPU-gesteunde worker:
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
## Phantom Squatting: LLM-gegenereerde domeine as 'n AI supply-chain-vektor

Phantom squatting is die **domein/URL-ekwivalent van slopsquatting**. In plaas daarvan om 'n nie-bestaande pakketnaam te hallusineer, hallusineer die LLM 'n geloofwaardige **portaal-, API-, webhook-, fakturering-, SSO-, aflaai- of ondersteuningsdomein** vir 'n werklike handelsmerk, waarna 'n aanvaller daardie namespace registreer voordat 'n mens of agent dit gebruik.<sup>[[8]](#references)[[9]](#references)</sup>

Dit is belangrik omdat modeluitsette in baie AI-gesteunde workflows as 'n **trusted dependency** behandel word:
- Ontwikkelaars plak die voorgestelde endpoint in kode of CI/CD-integrasies.
- AI-agente haal dokumentasie, skemas, APK's, ZIP's of webhook-teikens outomaties op.
- Gegenereerde runbooks of dokumentasie kan die vals URL insluit asof dit gesaghebbend is.

### Offensive workflow

1. **Toets die hallusinasie-oppervlak**: vra handelsmerk-spesifieke vrae oor realistiese workflows soos `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` of `mobile app`-portale.
2. **Normaliseer kandidate**: resolveer gegenereerde URL's, vou NXDOMAIN-antwoorde saam tot die ouer registreerbare domein, en verwyder duplikate uit prompt-families. Prompt-korpora moet divers bly, byvoorbeeld deur byna-duplikate met **Jaccard similarity** te verwyder.
3. **Prioritiseer voorspelbare hallusinasies**:
- **Thermal Hallucination Persistence (THP)**: dieselfde vals domein verskyn oor verskillende temperature, insluitend lae temperature soos `T=0.1`.
- **Cross-model consensus**: verskeie LLM-families genereer dieselfde vals domein.
4. **Registreer en weaponize** die ouerdomein, en host dan phishing, vals APK/ZIP-aflaaie, credential harvesters, kwaadwillige dokumente of API-endpoints wat secrets/webhook-payloads versamel. **Pure domain-level hallucinations** is die maklikste om te monetiseer omdat die aanvaller die hele namespace beheer; subdomain/path-hallucinations kan steeds misbruik word wanneer die genormaliseerde ouer ongeregistreer is.
5. **Benut die zero-reputation window**: nuut geregistreerde domeine het dikwels geen blocklist-geskiedenis, URL reputation of volwasse telemetry nie, en kan dus controls omseil totdat detections op datum kom. Aanvallers kan hierdie venster verleng met crawler-only benign responses, redirect cloaking, CAPTCHA-gates of vertraagde payload staging.

### Why it is dangerous for agents

Vir 'n menslike slagoffer benodig die vals domein gewoonlik steeds 'n klik en nog 'n handeling. In 'n **agentic workflow** kan die LLM sowel die **lure** as die **executor** wees: die agent ontvang die hallusineerde URL, haal dit op, parse die response, en kan dan tokens leak, instruksies uitvoer, 'n dependency aflaai of poisoned data na CI/CD stoot sonder enige menslike review.<sup>[[8]](#references)</sup>

### Practical attacker prompts

High-yield prompts lyk gewoonlik soos normale enterprise-take eerder as eksplisiete phishing-lures:
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Behandel dit as 'n proaktiewe domain-monitoring-probleem, nie slegs as 'n prompt-injection-probleem nie:
- Bou 'n **brand prompt corpus** en toets die LLM's waarop jou users/agente staatmaak periodiek.
- Stoor gehallusineerde URL's en volg watter URL's stabiel bly oor temperature/models.
- Volg die **Adversarial Exploitation Window (AEW)**: die tyd tussen die eerste hallusinasie en attacker registration. Positiewe AEW beteken defenders kan registreer, sinkhole of pre-block voordat weaponization plaasvind.
- Monitor **NXDOMAIN → registered**-oorgange vir die ouerdomeine.
- Wanneer registrasie plaasvind, triage registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status en brand-asset similarity.
- Voeg policy gates by sodat agente/ontwikkelaars nie **LLM-generated domains by default trust** nie: vereis allowlists, ownership validation, CT/RDAP-checks of human approval voor die eerste gebruik.

Dit pas gelyktydig by verskeie AI-risk-buckets: **AI supply-chain attack**, **insecure model output** en **rogue actions** wanneer agente die gehallusineerde URL outonoom consumeer.

## References
- [1] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risks](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
