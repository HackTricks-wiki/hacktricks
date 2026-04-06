# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp het die Top 10 masjienleer-kwesbaarhede geïdentifiseer wat AI-stelsels kan raak. Hierdie kwesbaarhede kan lei tot verskeie veiligheidsprobleme, insluitend data poisoning, model inversion en adversarial attacks. Om hierdie kwesbaarhede te verstaan is noodsaaklik vir die bou van veilige AI-stelsels.

Vir 'n bygewerkte en gedetailleerde lys van die top 10 masjienleer-kwesbaarhede, verwys na die [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: 'n Aanhanger voeg klein, dikwels onsigbare veranderinge aan **incoming data** toe sodat die model die verkeerde besluit neem.\
*Example*: 'n Paar spatjies verf op 'n stop‑sign fool 'n self‑driving car om 'n speed‑limit sign te "sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus met slegte voorbeelde besoedel, wat die model skadelike reëls leer.\
*Example*: Malware binaries word verkeerdelik as "benign" gemerk in 'n antivirus training corpus, wat soortgelyke malware later deurlaat.

- **Model Inversion Attack**: Deur inoutputs te probeer, bou 'n aanvaller 'n **reverse model** wat sensitiewe kenmerke van die oorspronklike inputs rekonstrueer.\
*Example*: Herstel van 'n pasiënt se MRI‑beeld uit 'n cancer‑detection model se voorspellings.

- **Membership Inference Attack**: Die teenstander toets of 'n **specific record** tydens training gebruik is deur vertrouensverskille te identifiseer.\
*Example*: Bevestig dat iemand se banktransaksie in 'n fraud‑detection model se training data voorkom.

- **Model Theft**: Herhaalde querying laat 'n aanvaller toe om decision boundaries te leer en **clone the model's behavior** (en IP).\
*Example*: Insamel genoeg Q&A‑pare van 'n ML‑as‑a‑Service API om 'n na‑ekwivalente lokale model te bou.

- **AI Supply‑Chain Attack**: Kompromiseer enige komponent (data, libraries, pre‑trained weights, CI/CD) in die **ML pipeline** om downstream models te korrupteer.\
*Example*: 'n Poisoned dependency op 'n model‑hub installeer 'n backdoored sentiment‑analysis model oor baie apps.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **pre‑trained model** geplant en oorleef fine‑tuning op die slagoffer se taak.\
*Example*: 'n Vision backbone met 'n hidden trigger verander steeds labels nadat dit aangepas is vir medical imaging.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd gemerkte data **shifts the model's outputs** om die aanvaller se agenda te bevoordeel.\
*Example*: Injekseer "clean" spam‑e‑posse gemerk as ham sodat 'n spam filter soortgelyke toekomstige e‑posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **alters model predictions in transit**, nie die model self nie, en bedrieg downstream stelsels.\
*Example*: Verwissel 'n malware classifier se "malicious" verdict na "benign" voordat die file‑quarantine fase dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **model parameters** self, dikwels nadat skryf‑toegang verkry is, om gedrag te verander.\
*Example*: Fynstel weights op 'n fraud‑detection model in produksie sodat transaksies van sekere kaarte altyd goedgekeur word.


## Google SAIF Risks

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) omskryf verskeie risiko's verbonde aan AI‑stelsels:

- **Data Poisoning**: Kwaadwilliges verander of injekteer training/tuning data om akkuraatheid te degradeer, backdoors te implanteer, of resultate te skeef trek, wat modelintegriteit oor die hele data‑lewe‑siklus ondermyn.

- **Unauthorized Training Data**: Insluiting van copyrighted, sensitiewe, of ongereguleerde datasets skep regsaaklike, etiese en prestasie‑verantwoordelikhede omdat die model leer van data wat dit nooit moes gebruik het nie.

- **Model Source Tampering**: Supply‑chain of insider manipulasie van model code, dependencies, of weights voor of tydens training kan hidden logic inkorporeer wat selfs ná retraining bly voortbestaan.

- **Excessive Data Handling**: Swak data‑retention en governance behelswaardes laat stelsels meer persoonlike data stoor of verwerk as nodig, wat blootstelling en compliance risiko verhoog.

- **Model Exfiltration**: Aanhangers steel model files/weights, wat verlies van intellektuele eiendom veroorsaak en copy‑cat dienste of opvolg‑aanvalle moontlik maak.

- **Model Deployment Tampering**: Teenstanders wysig model artifacts of serving infrastruktuur sodat die lopende model verskil van die geverifieerde weergawe, moontlik die gedrag verander.

- **Denial of ML Service**: Oorlaai van APIs of stuur van “sponge” inputs kan compute/energie uitput en die model afneem, soortgelyk aan klassieke DoS‑aanvalle.

- **Model Reverse Engineering**: Deur groot hoeveelhede input‑output pare te oes, kan aanvallers die model kloon of distilleer, wat na‑bootsingsprodukte en aangepaste adversarial attacks moontlik maak.

- **Insecure Integrated Component**: Kwesbare plugins, agents, of upstream dienste laat aanvallers toe om code in te injecteer of privilegies op te skaal binne die AI‑pipeline.

- **Prompt Injection**: Formuleer prompts (direk of indirek) om instruksies te smokkelaars wat system intent oorskryf, en die model laat onbedoelde commands uitvoer.

- **Model Evasion**: Sorgvuldig ontwerpte inputs laat die model verkeerd klasifiseer, hallucinate, of verbode inhoud uitset, wat veiligheid en vertroue erodeer.

- **Sensitive Data Disclosure**: Die model openbaar private of vertroulike inligting uit sy training data of gebruikerskonteks, wat privaatheid en regulasies oortree.

- **Inferred Sensitive Data**: Die model aflei persoonlike eienskappe wat nooit verskaf is nie, en so nuwe privaatheidskade deur inferensie skep.

- **Insecure Model Output**: Onsiginste antwoorde lewer skadelike code, misinformation, of ongepaste inhoud aan gebruikers of downstream stelsels.

- **Rogue Actions**: Outonoom geïntegreerde agents voer onbedoelde werklike wêreld operasies uit (file writes, API calls, purchases, ens.) sonder voldoende gebruikers‑toesig.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende raamwerk om risiko's verbonde aan AI‑stelsels te verstaan en te versag. Dit kategoriseer verskeie aanvalstegnieke en taktieke wat teenstanders teen AI‑modelle kan gebruik en ook hoe om AI‑stelsels te gebruik om verskillende aanvalle uit te voer.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Aanhangers steel aktiewe session tokens of cloud API credentials en roep betaalde, cloud-hosted LLMs sonder magtiging aan. Access word dikwels herverkoop via reverse proxies wat die slagoffer se rekening voorstaan, bv. "oai-reverse-proxy" deployments. Gevolge sluit in finansiële verlies, model misbruik buite beleid, en toeskrywing aan die slagoffer tenant.

TTPs:
- Harvest tokens van geïnfecteerde developer machines of browsers; steel CI/CD secrets; koop leaked cookies.
- Stand up 'n reverse proxy wat requests na die egte provider forward, die upstream key verberg en baie customers multiplex.
- Abuse direct base‑model endpoints om enterprise guardrails en rate limits te omseil.

Mitigations:
- Bind tokens aan device fingerprint, IP ranges, en client attestation; enforce short expirations en refresh met MFA.
- Scope keys minimaal (no tool access, read‑only waar toepaslik); rotate on anomaly.
- Terminate alle verkeer server‑side agter 'n policy gateway wat safety filters afdwing, per‑route quotas, en tenant isolation.
- Monitor vir ongebruiklike gebruikspatrone (sudden spend spikes, atypiese regions, UA strings) en auto‑revoke suspicious sessions.
- Prefer mTLS of signed JWTs uitgereik deur jou IdP bo long‑lived static API keys.

## Self-hosted LLM inference hardening

Running 'n lokale LLM server vir vertroulike data skep 'n ander aanvalsvlak as cloud-hosted APIs: inference/debug endpoints mag prompts leak, die serving stack openbaar gewoonlik 'n reverse proxy, en GPU device nodes gee toegang tot groot ioctl() surfaces. As jy 'n on‑prem inference service assesseer of implementeer, hersien ten minste die volgende punte.

### Prompt leak via debug and monitoring endpoints

Behandel die inference API as 'n **multi-user sensitive service**. Debug of monitoring routes kan prompt contents, slot state, model metadata, of internal queue information blootstel. In `llama.cpp`, die `/slots` endpoint is veral sensitief omdat dit per‑slot state blootstel en slegs bedoel is vir slot inspection/management.

- Put 'n reverse proxy in front of the inference server en **deny by default**.
- Only allowlist die presiese HTTP method + path kombinasies wat deur die client/UI benodig word.
- Disable introspection endpoints in die backend self waar moontlik, byvoorbeeld `llama-server --no-slots`.
- Bind die reverse proxy aan `127.0.0.1` en expose dit deur 'n authenticated transport soos SSH local port forwarding in plaas van dit op die LAN te publish.

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
### Rootless houers sonder netwerk en UNIX-sokette

As die inference daemon ondersteuning bied om op 'n UNIX-sok te luister, verkies dit bo TCP en laat die houer hardloop met **geen netwerkstapel**:
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
- `--network none` verwyder inkomende/uitgaande TCP/IP-blootstelling en vermy user-mode helpers wat rootless containers andersins benodig.
- 'n UNIX-sok laat jou toe om POSIX permissions/ACLs op die sokpad te gebruik as die eerste toegangskontrolelaag.
- `--userns=keep-id` en rootless Podman verminder die impak van 'n container-uitbraak omdat container root nie host root is nie.
- Lees-alleen model mounts verminder die kans op modelmanipulasie van binne die container.

### GPU-toestelknoop-minimalisering

Vir GPU-gedrewe inferensie is `/dev/nvidia*`-lêers hoëwaarde plaaslike aanvalsvlakke omdat hulle groot drywer `ioctl()` handlers en moontlik gedeelde GPU-geheuebestuursbane openbaar.

- Moenie `/dev/nvidia*` wêreldskryfbaar laat nie.
- Beperk `nvidia`, `nvidiactl`, en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev-reëls, en ACLs sodat slegs die toegewezen container-UID hulle kan open.
- Swartlys onnodige modules soos `nvidia_drm`, `nvidia_modeset`, en `nvidia_peermem` op headless inferensie-gashere.
- Prelaai slegs vereiste modules tydens boot in plaas daarvan om die runtime opportunisties toe te laat om hulle tydens inferensie-opstart met `modprobe` te laai.

Voorbeeld:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs as die workload nie eksplisiet `cudaMallocManaged()` gebruik nie, kan onlangse CUDA-runtimes steeds `nvidia-uvm` vereis. Aangesien hierdie toestel gedeel word en GPU virtuele geheuebestuur hanteer, behandel dit as 'n kruis-huurder data-blootstellingsoppervlak. As die inference backend dit ondersteun, kan 'n Vulkan backend 'n interessante kompromie wees omdat dit mag voorkom dat `nvidia-uvm` aan die container blootgestel word.

### LSM-beperking vir inferensie-werkers

AppArmor/SELinux/seccomp moet as verdediging-in-diepte rondom die inferensie-proses gebruik word:

- Laat slegs die gedeelde biblioteke, model-paaie, socket-direktorie, en GPU-toestelnodes toe wat werklik benodig word.
- Weier uitdruklik hoë-risiko capabilities soos `sys_admin`, `sys_module`, `sys_rawio`, en `sys_ptrace`.
- Hou die modeldirektorie net-leesbaar en beperk skryfbare paaie tot slegs die runtime socket-/cache-direktore.
- Monitor denial logs omdat hulle nuttige opsporingstelemetrie voorsien wanneer die model server of 'n post-exploitation payload probeer om aan sy verwagte gedrag te ontsnap.

Voorbeeld AppArmor-reëls vir 'n GPU-ondersteunde werker:
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
## Verwysings
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
