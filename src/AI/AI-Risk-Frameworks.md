# AI Risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP het die top 10 masjienleer-kwesbaarhede geïdentifiseer wat AI-stelsels kan raak. Hierdie kwesbaarhede kan tot verskeie sekuriteitsprobleme lei, insluitend data poisoning, model inversion, and adversarial attacks. Om hierdie kwesbaarhede te verstaan is noodsaaklik vir die bou van veilige AI-stelsels.

Vir 'n opgedateerde en gedetailleerde lys van die top 10 masjienleer-kwesbaarhede, verwys na die [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels ongesiene veranderinge by **inkomende data** sodat die model die verkeerde besluit neem.\
*Voorbeeld*: 'n Paar spikkels verf op 'n stop‑sign mislei 'n self‑driving car om 'n speed‑limit sign "te sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus besoedel met slegte voorbeelde, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware‑binaries word verkeerdelik as "benign" geëtiketteer in 'n antivirus‑trainingcorpus, wat soortgelyke malware later deurlaat.

- **Model Inversion Attack**: Deur outputs te probeer bou 'n aanvaller 'n **reverse model** wat sensitiewe kenmerke van die oorspronklike insette rekonstrueer.\
*Voorbeeld*: 'n Pasiënt se MRI‑beeld herbou uit 'n cancer‑detection model se voorspellinge.

- **Membership Inference Attack**: Die teenstander toets of 'n **specific record** tydens training gebruik is deur vertrouensverskille te herken.\
*Voorbeeld*: Bevestig dat 'n persoon se banktransaksie in 'n fraud‑detection model se trainingdata voorkom.

- **Model Theft**: Herhaalde bevraging laat 'n aanvaller toe om beslissinggrense te leer en **clone the model's behavior** (en IP).\
*Voorbeeld*: Genoeg Q&A‑pare van 'n ML‑as‑a‑Service API oes om 'n naby‑ekwivalente plaaslike model te bou.

- **AI Supply‑Chain Attack**: Kompromitteer enige komponent (data, libraries, pre‑trained weights, CI/CD) in die **ML pipeline** om downstream models te korrupteer.\
*Voorbeeld*: 'n Giftige dependency op 'n model‑hub installeer 'n backdoored sentiment‑analysis model oor baie apps.

- **Transfer Learning Attack**: Kwaadaardige logika word in 'n **pre‑trained model** geplant en oorleef fine‑tuning op die slagoffer se taak.\
*Voorbeeld*: 'n vision backbone met 'n versteekte trigger draai steeds labels om nadat dit aangepas is vir medical imaging.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd geëtiketteerde data **shifts the model's outputs** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: "Clean" spam‑e‑posse inject wat as ham geëtiketteer is sodat 'n spamfilter soortgelyke toekomstige e‑posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **alters model predictions in transit**, nie die model self nie, en mislei downstream systems.\
*Voorbeeld*: 'n Malware‑classifier se "malicious" vonnis na "benign" flip voor die file‑quarantine‑stadium dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderings aan die **model parameters** self, dikwels nadat skryf‑toegang verkry is, om gedrag te verander.\
*Voorbeeld*: Gewigte op 'n fraud‑detection model in produksie verstel sodat transaksies van sekere kaarte altyd goedgekeur word.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) skets verskeie risiko's geassosieer met AI‑stelsels:

- **Data Poisoning**: Kwaadaardige akteurs verander of injekteer training/tuning‑data om akkuraatheid te degradeer, backdoors in te plant, of resultate te skeef trek, wat modelintegriteit deur die hele data‑levensiklus ondermyn.

- **Unauthorized Training Data**: Insluk van copyrighted, sensitiewe, of nie‑toegelate datastelle skep regs-, etiese en prestasie‑aanspreeklikhede omdat die model leer uit data wat dit nooit moes gebruik nie.

- **Model Source Tampering**: Supply‑chain of insider‑manipulasie van modelkode, dependencies, of weights voor of tydens training kan versteekte logika inbou wat selfs na retraining voortduur.

- **Excessive Data Handling**: Swak data‑retensie en governance‑kontroles laat stelsels toe om meer persoonlike data te stoor of te verwerk as nodig, wat blootstelling en nakoming‑risiko verhoog.

- **Model Exfiltration**: Aanvallers steel model‑lêers/weights, wat verlies van intellektuele eiendom veroorsaak en copy‑cat dienste of opvolg‑aanvalle moontlik maak.

- **Model Deployment Tampering**: Teenstanders wysig model‑artefakte of serving‑infrastruktuur sodat die draaiende model van die geverifieerde weergawe verskil, moontlik gedrag verander.

- **Denial of ML Service**: API's oorlaai of “sponge” insette stuur kan compute/energie uitput en die model afneem, wat klassieke DoS‑aanvalle naboots.

- **Model Reverse Engineering**: Deur groot hoeveelhede inset‑uitsetpare te oes kan aanvallers die model kloon of distilleer, wat imitasiestukke en aangepaste adversarial aanvalle aanhits.

- **Insecure Integrated Component**: Kwesbare plugins, agents, of upstream‑dienste laat aanvallers toe om kode in te spuit of privilegieë te eskaleer binne die AI‑pyplyn.

- **Prompt Injection**: Prompts (direk of indirek) skep om instruksies in te smokkel wat stelselbedoeling oorskryf en die model onbedoelde opdragte laat uitvoer.

- **Model Evasion**: Noukeurig ontwerpte insette veroorsaak dat die model mis‑klassifiseer, halusineer, of verbode inhoud uitset, wat veiligheid en vertroue ondermyn.

- **Sensitive Data Disclosure**: Die model openbaar private of vertroulike inligting uit sy trainingdata of gebruikerskonteks, wat privaatheid en regulasies skend.

- **Inferred Sensitive Data**: Die model lei persoonlike eienskappe af wat nooit voorsien is nie, wat nuwe privaatheidsskade deur inferensie skep.

- **Insecure Model Output**: Ongesanitiseerde antwoorde dra skadelike kode, verkeerde inligting, of onvanpaste inhoud oor aan gebruikers of downstream systems.

- **Rogue Actions**: Autonoom geïntegreerde agents voer onbedoelde werklike wêreld‑operasies uit (lêer‑skryf, API‑oproepe, aankope, ens.) sonder voldoende gebruiker‑toesig.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende raamwerk om risiko's geassosieer met AI‑stelsels te verstaan en te versag. Dit kategoriseer verskeie aanvalstegnieke en taktieke wat teenstanders teen AI‑modelle kan gebruik en ook hoe AI‑stelsels gebruik kan word om verskillende aanvalle uit te voer.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Aanvallers steel aktiewe sessie‑tokens of cloud API credentials en roep betaalde, cloud-hosted LLMs aan sonder magtiging. Toegang word dikwels weerverkoop via reverse proxies wat die slagoffer se rekening voorhou, bv. "oai-reverse-proxy" deployments. Gevolge sluit in finansiële verlies, modelmisbruik buite beleidsgrense, en toeskrywing aan die slagoffer‑tenant.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base-model endpoints to bypass enterprise guardrails and rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read-only where applicable); rotate on anomaly.
- Terminate all traffic server-side behind a policy gateway that enforces safety filters, per-route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto-revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long-lived static API keys.

## Verharding van self-gehoste LLM-inferensie

Die bedryf van 'n plaaslike LLM‑bediener vir vertroulike data skep 'n ander aanvalsoorvlak as cloud-hosted APIs: inference/debug endpoints may leak prompts, die serving stack meestal 'n reverse proxy blootstel, en GPU‑toestelnodes gee toegang tot groot `ioctl()` oppervlaktes. As jy 'n on‑prem inference‑diens evalueer of uitrol, hersien ten minste die volgende punte.

### Prompt leakage via debug and monitoring endpoints

Behandel die inference API as 'n **multi-user sensitive service**. Debug of monitoring routes kan prompt contents, slot state, model metadata, of internal queue information blootstel. In `llama.cpp`, die `/slots` endpoint is besonders sensitief omdat dit per-slot state blootstel en slegs bedoel is vir slot inspection/management.

- Put a reverse proxy in front of the inference server and **weier per verstek**.
- Only allowlist the exact HTTP method + path combinations that are needed by the client/UI.
- Skakel introspeksie‑endpoints in die backend self uit waar moontlik, byvoorbeeld `llama-server --no-slots`.
- Bind die reverse proxy aan `127.0.0.1` en stel dit bloot deur 'n geauthentiseerde vervoer soos SSH local port forwarding in, in plaas daarvan om dit op die LAN te publiseer.

Voorbeeld allowlist met nginx:
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

As die inference daemon dit ondersteun om op 'n UNIX socket te luister, verkies dit bo TCP en voer die container uit met **no network stack**:
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
- `UNIX` socket laat jou POSIX permissions/ACLs op die socket path gebruik as die eerste access-control layer.
- `--userns=keep-id` en rootless Podman verminder die impak van 'n container breakout omdat container root nie host root is nie.
- Read-only model mounts verminder die kans op model tampering van binne die container.

### GPU device-node minimalisering

Vir GPU-backed inference is `/dev/nvidia*` lêers hoë-waarde plaaslike aanvalsvlakke omdat hulle groot driver `ioctl()` handlers en moontlik gedeelde GPU memory-management paaie blootlê.

- Moet nie `/dev/nvidia*` vir almal skryfbaar laat nie.
- Beperk `nvidia`, `nvidiactl`, en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev reëls, en ACLs sodat slegs die gemapte container UID dit kan oopmaak.
- Swartlys onnodige modules soos `nvidia_drm`, `nvidia_modeset`, en `nvidia_peermem` op headless inference hosts.
- Laai slegs die vereiste modules vooraf by boot in, in plaas daarvan om die runtime kansvattersgewys toe te laat om dit tydens inference startup met `modprobe` te laai.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs as die workload nie eksplisiet `cudaMallocManaged()` gebruik nie, mag onlangse CUDA runtimes steeds `nvidia-uvm` benodig. Omdat hierdie toestel gedeel word en GPU virtuele geheuebestuur hanteer, beskou dit as 'n oppervlak vir data-blootstelling tussen huurders. As die inference backend dit ondersteun, kan 'n Vulkan backend 'n interessante afruil wees omdat dit dalk voorkom dat `nvidia-uvm` oorhoofs aan die container blootgestel word.

### LSM-beperking vir inference-werkers

AppArmor/SELinux/seccomp moet as verdediging-in-diepte rondom die inference-proses gebruik word:

- Laat slegs die gedeelde biblioteke, modelpaaie, socket-gids en GPU device nodes toe wat werklik benodig word.
- Weier uitdruklik hoërisiko capabilities soos `sys_admin`, `sys_module`, `sys_rawio`, en `sys_ptrace`.
- Maak die modelgids slegs-lees en beperk skryfbare paaie slegs tot die runtime socket/cache directories.
- Monitor weierlogboeke omdat hulle nuttige deteksie-telemetrie verskaf wanneer die modelserver of 'n post-exploitation payload probeer om uit sy verwagte gedrag te ontsnap.

Example AppArmor rules for a GPU-backed worker:
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
- [Unit 42 – Die risiko's van Code Assistant LLMs: Skadelike inhoud, misbruik en misleiding](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Oorsig van die LLMJacking-skema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (herverkoop van gesteelde LLM-toegang)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Diepduik in die ontplooiing van 'n on-premise lae-privilegieerde LLM-bediener](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) spesifikasie](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
