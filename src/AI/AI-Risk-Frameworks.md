# KI-risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp het die top 10 machine learning-vulnerabilities geïdentifiseer wat AI-stelsels kan beïnvloed. Hierdie vulnerabilities kan tot verskeie sekuriteitskwessies lei, insluitend data poisoning, model inversion en adversarial attacks. Dit is noodsaaklik om hierdie vulnerabilities te verstaan vir die bou van veilige AI-stelsels.

Vir 'n opgedateerde en gedetailleerde lys van die top 10 machine learning-vulnerabilities, verwys na die [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projek.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels onsigbare veranderinge aan **inkomende data** toe sodat die model die verkeerde besluit neem.\
*Voorbeeld*: 'n Paar verfspatsels op 'n stopteken mislei 'n selfbesturende motor om 'n spoedbeperkingsteken te "sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus met slegte samples besoedel, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware binaries word as "benign" gemerk in 'n antivirus-training corpus, waardeur soortgelyke malware later ongemerk kan deurglip.

- **Model Inversion Attack**: Deur outputs te ondersoek, bou 'n aanvaller 'n **reverse model** wat sensitiewe kenmerke van die oorspronklike inputs rekonstrueer.\
*Voorbeeld*: Die herskepping van 'n pasiënt se MRI-beeld uit 'n cancer-detection-model se predictions.

- **Membership Inference Attack**: Die adversary toets of 'n **spesifieke record** tydens training gebruik is deur verskille in confidence raak te sien.\
*Voorbeeld*: Bevestiging dat 'n persoon se banktransaksie in 'n fraud-detection-model se training data voorkom.

- **Model Theft**: Herhaalde querying laat 'n aanvaller decision boundaries leer en die **model se gedrag** (en IP) **clone**.\
*Voorbeeld*: Die harvesting van genoeg Q&A-pare uit 'n ML-as-a-Service API om 'n byna ekwivalente plaaslike model te bou.

- **AI Supply-Chain Attack**: Kompromitteer enige komponent (data, libraries, pre-trained weights, CI/CD) in die **ML pipeline** om downstream models te korrupteer.\
*Voorbeeld*: 'n Besoedelde dependency op 'n model-hub installeer 'n backdoored sentiment-analysis-model oor baie apps heen.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **pre-trained model** geplant en oorleef fine-tuning op die slagoffer se taak.\
*Voorbeeld*: 'n Vision backbone met 'n versteekte trigger verander steeds labels nadat dit vir medical imaging aangepas is.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd gemerkte data **verskuif die model se outputs** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: Die inspuiting van "clean" spam-e-posse wat as ham gemerk is, sodat 'n spam filter soortgelyke toekomstige e-posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander model predictions tydens transmissie**, nie die model self nie, en mislei downstream systems.\
*Voorbeeld*: Die verandering van 'n malware classifier se "malicious"-uitspraak na "benign" voordat die file-quarantine stage dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **model parameters** self, dikwels nadat write access verkry is, om gedrag te verander.\
*Voorbeeld*: Die aanpassing van weights op 'n fraud-detection-model in production sodat transaksies van sekere kaarte altyd goedgekeur word.


## Google SAIF-risiko's

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beskryf verskeie risiko's wat met AI-stelsels verband hou:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Kwaadwillige akteurs verander of spuit training/tuning data in om akkuraatheid te verlaag, backdoors te plant of resultate te skeeftrek, wat modelintegriteit oor die hele data-lifecycle ondermyn.

- **Unauthorized Training Data**: Die inname van copyrighted, sensitiewe of ongemagtigde datasets skep wetlike, etiese en performance-verpligtinge omdat die model leer uit data wat dit nooit toegelaat is om te gebruik nie.

- **Model Source Tampering**: Supply-chain- of insider-manipulasie van model code, dependencies of weights voor of tydens training kan versteekte logika insluit wat selfs ná retraining voortduur.

- **Excessive Data Handling**: Swak data-retention- en governance-kontroles lei daartoe dat systems meer personal data as nodig stoor of verwerk, wat exposure- en compliance-risiko verhoog.

- **Model Exfiltration**: Attackers steel model files/weights, wat 'n verlies aan intellectual property veroorsaak en copy-cat services of follow-on attacks moontlik maak.

- **Model Deployment Tampering**: Adversaries verander model artifacts of serving infrastructure sodat die lopende model van die goedgekeurde weergawe verskil, wat gedrag moontlik verander.

- **Denial of ML Service**: Deur APIs te oorstroom of “sponge”-inputs te stuur, kan compute/energy uitgeput word en die model offline gedwing word, soortgelyk aan klassieke DoS attacks.

- **Model Reverse Engineering**: Deur groot hoeveelhede input-output-pare te harvest, kan attackers die model clone of distil, wat imitation products en aangepaste adversarial attacks aanvuur.

- **Insecure Integrated Component**: Kwesbare plugins, agents of upstream services laat attackers toe om code in te spuit of privileges binne die AI pipeline te eskaleer.

- **Prompt Injection**: Deur prompts direk of indirek te konstrueer om instruksies in te smokkel wat system intent oorheers, kan die model onbedoelde commands uitvoer.

- **Model Evasion**: Noukeurig ontwerpte inputs veroorsaak dat die model verkeerd klassifiseer, hallucinate of disallowed content uitset, wat safety en trust erodeer.

- **Sensitive Data Disclosure**: Die model openbaar private of confidential information uit sy training data of user context, wat privacy en regulations oortree.

- **Inferred Sensitive Data**: Die model lei personal attributes af wat nooit verskaf is nie, wat nuwe privacy harms deur inference skep.

- **Insecure Model Output**: Unsanitized responses stuur harmful code, misinformation of inappropriate content aan users of downstream systems.

- **Rogue Actions**: Autonomously-integrated agents voer onbedoelde real-world operations uit (file writes, API calls, purchases, ens.) sonder voldoende user oversight.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende framework vir die begrip en vermindering van risiko's wat met AI-stelsels verband hou. Dit kategoriseer verskeie attack techniques en tactics wat adversaries teen AI-modelle kan gebruik, asook hoe om AI-stelsels te gebruik om verskillende attacks uit te voer.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers steel aktiewe session tokens of cloud API credentials en roep betaalde, cloud-hosted LLMs sonder authorization aan. Access word dikwels deur reverse proxies herverkoop wat die victim se account front, byvoorbeeld "oai-reverse-proxy"-deployments. Gevolge sluit financial loss, model misuse buite policy en attribution aan die victim tenant in.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Harvest tokens van infected developer machines of browsers; steel CI/CD secrets; koop leaked cookies.<sup>[[5]](#references)</sup>
- Stel 'n reverse proxy op wat requests na die genuine provider aanstuur, die upstream key verberg en baie customers multiplex.<sup>[[5]](#references)[[7]](#references)</sup>
- Abuse direct base-model endpoints om enterprise guardrails en rate limits te omseil.<sup>[[4]](#references)</sup>

Mitigations:
- Bind tokens aan device fingerprint, IP-ranges en client attestation; pas short expirations toe en refresh met MFA.
- Scope keys minimaal (geen tool access nie, read-only waar toepaslik); rotate met 'n anomaly.
- Terminate alle traffic server-side agter 'n policy gateway wat safety filters, per-route quotas en tenant isolation afdwing.
- Monitor vir unusual usage patterns (skielike spend spikes, atypical regions, UA strings) en auto-revoke verdagte sessions.
- Verkies mTLS of signed JWTs wat deur jou IdP uitgereik word bo long-lived static API keys.

## Self-hosted LLM inference hardening

Die uitvoer van 'n plaaslike LLM-server vir confidential data skep 'n ander attack surface as cloud-hosted APIs: inference/debug endpoints kan prompts leakan, die serving stack stel gewoonlik 'n reverse proxy bloot, en GPU device nodes gee toegang tot groot `ioctl()`-surfaces. Indien jy 'n on-prem inference service assess of deploy, hersien ten minste die volgende punte.<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

Behandel die inference API as 'n **multi-user sensitive service**. Debug- of monitoring routes kan prompt contents, slot state, model metadata of internal queue information blootstel. In `llama.cpp` is die `/slots`-endpoint besonder sensitief omdat dit per-slot state blootstel en slegs vir slot inspection/management bedoel is.<sup>[[8]](#references)</sup>

- Plaas 'n reverse proxy voor die inference server en **deny by default**.
- Allowlist slegs die presiese HTTP method + path combinations wat deur die client/UI benodig word.
- Disable introspection endpoints in die backend self waar moontlik, byvoorbeeld `llama-server --no-slots`.<sup>[[9]](#references)</sup>
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
### Rootless containers sonder netwerk en UNIX sockets

As die inference daemon luister op ’n UNIX socket ondersteun, verkies dit bo TCP en voer die container met **geen netwerk stack** uit:<sup>[[8]](#references)</sup>
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
- `--network none` verwyder inkomende/uitgaande TCP/IP-blootstelling en vermy user-mode helpers wat rootless containers andersins sou benodig.
- ’n UNIX-socket laat jou toe om POSIX-permissies/ACLs op die socket-pad as die eerste toegangsbeheerlaag te gebruik.
- `--userns=keep-id` en rootless Podman verminder die impak van ’n container breakout omdat container root nie host root is nie.
- Read-only model-monterings verminder die kans op model-tampering vanuit die container.

### Minimalisering van GPU device-nodes

Vir GPU-gesteunde inference is `/dev/nvidia*`-lêers hoëwaarde plaaslike attack surfaces omdat hulle groot driver-`ioctl()`-handlers en potensieel gedeelde GPU-geheuebestuurspaaie blootstel.<sup>[[8]](#references)</sup>

- Moenie `/dev/nvidia*` world writable laat nie.
- Beperk `nvidia`, `nvidiactl` en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev-reëls en ACLs sodat slegs die gemapte container-UID hulle kan oopmaak.
- Blacklist onnodige modules soos `nvidia_drm`, `nvidia_modeset` en `nvidia_peermem` op headless inference-hosts.
- Preload slegs vereiste modules tydens boot, in plaas daarvan om die runtime toe te laat om hulle opportunisties te `modprobe` tydens inference-opstart.

Voorbeeld:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs al gebruik die workload nie eksplisiet `cudaMallocManaged()` nie, kan onlangse CUDA runtimes steeds `nvidia-uvm` vereis. Omdat hierdie toestel gedeel word en GPU-virtuelegeheuebestuur hanteer, moet dit as ’n oppervlak vir cross-tenant-data-blootstelling hanteer word. As die inference-backend dit ondersteun, kan ’n Vulkan-backend ’n interessante afweging wees, omdat dit moontlik die blootstelling van `nvidia-uvm` aan die container heeltemal vermy.<sup>[[8]](#references)</sup>

### LSM-inperking vir inference-workers

AppArmor/SELinux/seccomp moet as defense in depth rondom die inference-proses gebruik word:<sup>[[8]](#references)</sup>

- Laat slegs die shared libraries, modelpaaie, soketgids en GPU-toestelnodes toe wat werklik benodig word.
- Weier uitdruklik hoërisiko-capabilities soos `sys_admin`, `sys_module`, `sys_rawio` en `sys_ptrace`.
- Hou die modelgids read-only en beperk skryfbare paaie tot slegs die runtime-soket-/cache-gidse.
- Monitor denial logs, omdat hulle nuttige detection-telemetrie verskaf wanneer die modelserver of ’n post-exploitation-payload probeer om uit sy verwagte gedrag te ontsnap.

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
## Phantom Squatting: Deur LLM-gehalleusineerde domeine as 'n AI Supply-Chain-vektor

Phantom squatting is die **domein/URL-ekwivalent van slopsquatting**. In plaas daarvan om 'n nie-bestaande pakketnaam te hallusineer, hallusineer die LLM 'n geloofwaardige **portaal-, API-, webhook-, fakturering-, SSO-, aflaai- of ondersteuningsdomein** vir 'n werklike handelsmerk, en 'n aanvaller registreer daardie namespace voordat 'n mens of agent dit gebruik.<sup>[[12]](#references)[[13]](#references)</sup>

Dit is belangrik omdat modeluitset in baie AI-gesteunde workflows as 'n **vertroude dependency** behandel word:
- Developers plak die voorgestelde endpoint in code- of CI/CD-integrations.
- AI-agents haal documentation, schemas, APKs, ZIPs of webhook-teikens outomaties op.
- Gegenereerde runbooks of docs kan die fake URL insluit asof dit authoritative is.

### Offensive workflow

1. **Probe the hallucination surface**: vra handelsmerkspesifieke vrae oor realistiese workflows soos `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` of `mobile app`-portale.<sup>[[12]](#references)</sup>
2. **Normalize candidates**: resolve gegenereerde URLs, vou NXDOMAIN-antwoorde saam tot die parent registerable domain, en verwyder duplikate uit prompt families. Prompt corpora moet divers bly, byvoorbeeld deur byna-duplikate met **Jaccard similarity** te verwyder.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: dieselfde fake domain verskyn oor verskillende temperature, insluitend lae temperature soos `T=0.1`.
- **Cross-model consensus**: verskeie LLM-families genereer dieselfde fake domain.
4. **Register and weaponize** die parent domain, en host dan phishing, fake APK/ZIP-downloads, credential harvesters, malicious docs of API-endpoints wat secrets/webhook-payloads versamel. **Pure domain-level hallucinations** is die maklikste om te monetiseer omdat die aanvaller die hele namespace beheer; subdomain/path-hallucinations kan steeds misbruik word wanneer die genormaliseerde parent ongeregistreerd is.
5. **Exploit the zero-reputation window**: nuut geregistreerde domeine het dikwels geen blocklist-geskiedenis, URL-reputasie of volwasse telemetry nie, en kan dus controls omseil totdat detections op datum kom. Aanvallers kan hierdie window verleng met crawler-only benign responses, redirect cloaking, CAPTCHA-gates of vertraagde payload staging.

### Why it is dangerous for agents

Vir 'n menslike slagoffer benodig die fake domain gewoonlik steeds 'n click en 'n verdere aksie. In 'n **agentic workflow** kan die LLM beide die **lure** en die **executor** wees: die agent ontvang die gehallusineerde URL, haal dit op, parse die response, en kan dan tokens leak, instructions uitvoer, 'n dependency aflaai of poisoned data in CI/CD push sonder enige human review.<sup>[[12]](#references)</sup>

### Practical attacker prompts

High-yield prompts lyk gewoonlik soos normale enterprise-take eerder as eksplisiete phishing-lures:<sup>[[12]](#references)</sup>
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Behandel dit as 'n proaktiewe domain-monitoring-probleem, nie net as 'n prompt-injection-probleem nie:<sup>[[12]](#references)</sup>
- Bou 'n **brand prompt corpus** en probeer periodiek die LLMs waarop jou users/agents staatmaak.
- Stoor gehallusineerde URLs en track watter daarvan stabiel bly oor temperature/models.
- Track die **Adversarial Exploitation Window (AEW)**: tyd tussen die eerste hallusinasie en attacker registration. 'n Positiewe AEW beteken defenders kan pre-register, sinkhole of pre-block voordat weaponization plaasvind.
- Monitor **NXDOMAIN → registered**-transitions vir die parent domains.
- By registration, triage registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status en brand-asset similarity.
- Voeg policy gates by sodat agents/developers nie **LLM-generated domains by default trust nie**: vereis allowlists, ownership validation, CT/RDAP-checks of human approval voordat dit die eerste keer gebruik word.

Dit pas tegelykertyd by verskeie AI-risk buckets: **AI supply-chain attack**, **insecure model output** en **rogue actions** wanneer agents die gehallusineerde URL outonoom consumeer.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Stolen Cloud Credentials Used in New AI Attack](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
