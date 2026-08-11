# KI-risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp het die top 10 machine learning-kwesbaarhede geïdentifiseer wat KI-stelsels kan beïnvloed. Hierdie kwesbaarhede kan tot verskeie sekuriteitskwessies lei, insluitend data poisoning, model inversion en adversarial attacks. Dit is noodsaaklik om hierdie kwesbaarhede te verstaan om veilige KI-stelsels te bou.

Vir 'n bygewerkte en gedetailleerde lys van die top 10 machine learning-kwesbaarhede, verwys na die [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projek.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels onsigbare veranderinge aan **inkomende data** toe sodat die model die verkeerde besluit neem.\
*Voorbeeld*: 'n Paar verfvlekke op 'n stopteken mislei 'n selfbesturende motor om 'n spoedbeperkingsteken te "sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus met slegte voorbeelde besoedel, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware-binaries word in 'n antivirus-training corpus verkeerdelik as "benign" gemerk, sodat soortgelyke malware later ongemerk deurgaan.

- **Model Inversion Attack**: Deur uitsette te ondersoek, bou 'n aanvaller 'n **reverse model** wat sensitiewe kenmerke van die oorspronklike insette rekonstrueer.\
*Voorbeeld*: Om 'n pasiënt se MRI-beeld te herskep uit 'n kankeropsporingsmodel se voorspellings.

- **Membership Inference Attack**: Die teenstander toets of 'n **spesifieke rekord** tydens training gebruik is deur verskille in vertroue raak te sien.\
*Voorbeeld*: Om te bevestig dat 'n persoon se banktransaksie in 'n bedroghostingsmodel se training data voorkom.

- **Model Theft**: Herhaalde navrae stel 'n aanvaller in staat om besluitnemingsgrense te leer en die **model se gedrag** (en IP) te **clone**.\
*Voorbeeld*: Om genoeg V&A-pare van 'n ML-as-'n-Service-API te versamel om 'n byna ekwivalente plaaslike model te bou.

- **AI Supply-Chain Attack**: Kompromitteer enige komponent (data, libraries, pre-trained weights, CI/CD) in die **ML pipeline** om daaropvolgende modelle te korrupteer.\
*Voorbeeld*: 'n Besoedelde dependency op 'n model-hub installeer 'n model vir sentiment-analise met 'n backdoor in baie apps.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **pre-trained model** geplant en oorleef fine-tuning op die slagoffer se taak.\
*Voorbeeld*: 'n Vision backbone met 'n versteekte trigger verander steeds labels nadat dit vir mediese imaging aangepas is.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd gemerkte data **skuif die model se uitsette** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: Om "skoon" spam-e-posse in te voeg wat as ham gemerk is, sodat 'n spamfilter soortgelyke toekomstige e-posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander modelvoorspellings tydens oordrag**, nie die model self nie, en mislei sodoende downstream-stelsels.\
*Voorbeeld*: Om 'n malware-classifier se "malicious"-uitspraak na "benign" te verander voordat die lêer-karantynfase dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **modelparameters** self, dikwels nadat skryftoegang verkry is, om gedrag te verander.\
*Voorbeeld*: Om gewigte op 'n bedroghostingsmodel in production aan te pas sodat transaksies van sekere kaarte altyd goedgekeur word.


## Google SAIF Risks

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beskryf verskeie risiko's wat met KI-stelsels verband hou:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Kwaadwillige akteurs verander of voeg training-/tuning-data in om akkuraatheid te verlaag, backdoors te plant of resultate te verdraai, wat modelintegriteit oor die hele data-lifecycle ondermyn.

- **Unauthorized Training Data**: Die inname van kopieregbeskermde, sensitiewe of ongemagtigde datasets skep wetlike, etiese en prestasie-aanspreeklikhede omdat die model leer uit data wat dit nooit toegelaat is om te gebruik nie.

- **Model Source Tampering**: Supply-chain- of insider-manipulasie van modelkode, dependencies of weights voor of tydens training kan versteekte logika insluit wat selfs ná retraining voortduur.

- **Excessive Data Handling**: Swak data-retention- en governance-kontroles lei daartoe dat stelsels meer persoonlike data as nodig stoor of verwerk, wat blootstelling- en compliance-risiko verhoog.

- **Model Exfiltration**: Aanvallers steel modellêers/weights, wat verlies aan intellektuele eiendom veroorsaak en copy-cat-dienste of daaropvolgende attacks moontlik maak.

- **Model Deployment Tampering**: Teenstanders verander model artifacts of serving-infrastruktuur sodat die model wat loop van die goedgekeurde weergawe verskil, wat moontlik gedrag verander.

- **Denial of ML Service**: Deur API's te oorstroom of "sponge"-insette te stuur, kan compute/energie uitgeput word en die model vanlyn gehaal word, soortgelyk aan klassieke DoS-attacks.

- **Model Reverse Engineering**: Deur groot getalle inset-uitset-pare te versamel, kan aanvallers die model clone of distil, wat imitatieprodukte en aangepaste adversarial attacks aanhelp.

- **Insecure Integrated Component**: Kwesbare plugins, agents of upstream-dienste stel aanvallers in staat om kode in die KI-pipeline in te spuit of privileges te verhoog.

- **Prompt Injection**: Deur prompts (direk of indirek) te ontwerp om instruksies in te smokkel wat die stelsel se bedoeling oorheers, kan die model onbedoelde commands uitvoer.

- **Model Evasion**: Noukeurig ontwerpte insette veroorsaak dat die model verkeerd klassifiseer, hallucineer of verbode inhoud uitvoer, wat veiligheid en vertroue afbreek.

- **Sensitive Data Disclosure**: Die model openbaar private of vertroulike inligting uit sy training data of gebruiker-konteks, wat privaatheid en regulasies oortree.

- **Inferred Sensitive Data**: Die model lei persoonlike eienskappe af wat nooit verskaf is nie, wat nuwe privaatheidskade deur inferensie veroorsaak.

- **Insecure Model Output**: Ongesuiwerde antwoorde stuur skadelike kode, misinligting of onvanpaste inhoud aan gebruikers of downstream-stelsels.

- **Rogue Actions**: Outonoom geïntegreerde agents voer onbedoelde werklike bedrywighede uit (lêerskrywings, API-oproepe, aankope, ens.) sonder voldoende gebruikertoesig.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende framework om risiko's wat met KI-stelsels verband hou, te verstaan en te versag. Dit kategoriseer verskeie attack-tegnieke en -taktieke wat teenstanders teen KI-modelle kan gebruik, asook hoe om KI-stelsels te gebruik om verskillende attacks uit te voer.<sup>[[3]](#references)</sup>

## LLMJacking (Diefstal en Herverkoop van Toegang tot Cloud-hosted LLM's)

Aanvallers steel aktiewe sessietokens of cloud API-credentials en roep betaalde, cloud-hosted LLM's sonder toestemming aan. Toegang word dikwels deur reverse proxies herverkoop wat die slagoffer se rekening as front gebruik, byvoorbeeld "oai-reverse-proxy"-deployments. Gevolge sluit finansiële verlies, modelmisbruik buite beleid en toeskrywing aan die slagoffer-tenant in.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Versamel tokens van besmette developer-masjiene of browsers; steel CI/CD-secrets; koop gelekte cookies.<sup>[[5]](#references)</sup>
- Stel 'n reverse proxy op wat versoeke na die egte provider aanstuur, die upstream key verberg en baie customers multiplex.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Misbruik direkte base-model-endpoints om enterprise guardrails en rate limits te omseil.<sup>[[4]](#references)</sup>

Mitigations:
- Bind tokens aan device fingerprint, IP-ranges en client attestation; dwing kort vervaldatums af en refresh met MFA.
- Beperk keys tot die minimum (geen tool access nie, read-only waar toepaslik); rotate by anomalieë.
- Terminate alle traffic server-side agter 'n policy gateway wat safety filters, per-route quotas en tenant isolation afdwing.
- Monitor vir ongewone gebruikspatrone (skielike spend spikes, atipiese streke, UA strings) en revoke verdagte sessies outomaties.
- Verkies mTLS of signed JWTs wat deur jou IdP uitgereik word bo langlewende statiese API keys.

## Verharding van self-hosted LLM inference

Die gebruik van 'n plaaslike LLM-server vir vertroulike data skep 'n ander attack surface as cloud-hosted API's: inference/debug-endpoints kan prompts lek, die serving stack stel gewoonlik 'n reverse proxy bloot, en GPU-device nodes bied toegang tot groot `ioctl()`-surfaces. As jy 'n on-prem inference-diens assesseer of deploy, hersien ten minste die volgende punte.<sup>[[8]](#references)</sup>

### Prompt leakage via debug- en monitoring-endpoints

Behandel die inference API as 'n **multi-user sensitive service**. Debug- of monitoring-routes kan prompt-inhoud, slot state, modelmetadata of interne queue-inligting blootstel. In `llama.cpp` is die `/slots`-endpoint besonder sensitief omdat dit per-slot state blootstel en slegs vir slot-inspeksie/-bestuur bedoel is.<sup>[[8]](#references)</sup>

- Plaas 'n reverse proxy voor die inference-server en **deny by default**.
- Allowlist slegs die presiese HTTP method + path-kombinasies wat deur die client/UI benodig word.
- Deaktiveer introspection-endpoints in die backend self waar moontlik, byvoorbeeld `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Bind die reverse proxy aan `127.0.0.1` en stel dit deur 'n geauthentiseerde transport soos SSH local port forwarding bloot, eerder as om dit op die LAN te publiseer.

Voorbeeld van 'n allowlist met nginx:
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
### Rootless containers sonder netwerk en UNIX-sockets

As die inference-daemon listening op ’n UNIX-socket ondersteun, verkies dit bo TCP en voer die container met **geen netwerkstack** uit:<sup>[[8]](#references)</sup>
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
- ’n UNIX-socket laat jou toe om POSIX-permissies/ACL’s op die socket-pad as die eerste toegangsbeheerlaag te gebruik.
- `--userns=keep-id` en rootless Podman verminder die impak van ’n container breakout omdat container root nie host root is nie.
- Leesalleen-modelmonterings verminder die kans op modelmanipulasie vanuit die container.

Vir persistente deployments kan dieselfde beperkings as Podman Quadlet-eenhede uitgedruk word. As GPU-toegang deur die Container Device Interface gedelegeer word, hou die CDI-device-spesifikasie so beperk as moontlik eerder as om elke accelerator-node bloot te stel.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node-minimering

Vir GPU-gesteunde inference is `/dev/nvidia*`-lêers hoëwaarde-plaaslike aanvalsvlakke omdat hulle groot driver `ioctl()`-handlers en potensieel gedeelde GPU-geheuebestuurspaaie blootstel.<sup>[[8]](#references)</sup>

- Moenie `/dev/nvidia*` wêreldskryfbaar laat nie.
- Beperk `nvidia`, `nvidiactl` en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev-reëls en ACL’s sodat slegs die gemapte container UID hulle kan oopmaak.
- Blacklist onnodige modules soos `nvidia_drm`, `nvidia_modeset` en `nvidia_peermem` op headless inference-gashere.
- Preload slegs vereiste modules tydens boot in plaas daarvan om die runtime toe te laat om hulle opportunisties te `modprobe` tydens inference-opstart.

Voorbeeld:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs al gebruik die workload nie uitdruklik `cudaMallocManaged()` nie, mag onlangse CUDA runtimes steeds `nvidia-uvm` vereis. Omdat hierdie toestel gedeel word en GPU-virtuelegeheuebestuur hanteer, moet dit as ’n cross-tenant-data-blootstellingsoppervlak behandel word. Indien die inference backend dit ondersteun, kan ’n Vulkan backend ’n interessante kompromie wees, omdat dit moontlik die blootstelling van `nvidia-uvm` aan die container heeltemal vermy.<sup>[[8]](#references)</sup>

### LSM-beperking vir inference workers

AppArmor/SELinux/seccomp behoort as defense in depth rondom die inference-proses gebruik te word:<sup>[[8]](#references)</sup>

- Laat slegs die shared libraries, model paths, socket directory en GPU device nodes toe wat werklik benodig word.
- Weier hoërisiko-capabilities soos `sys_admin`, `sys_module`, `sys_rawio` en `sys_ptrace` uitdruklik.
- Hou die model directory read-only en beperk writable paths tot slegs die runtime socket/cache directories.
- Monitor denial logs, omdat hulle nuttige detection telemetry verskaf wanneer die model server of ’n post-exploitation payload probeer om sy verwagte gedrag te ontduik.

Voorbeeld van AppArmor-reëls vir ’n GPU-backed worker:
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
## Phantom Squatting: LLM-gehallusineerde domeine as 'n AI Supply-Chain Vector

Phantom squatting is die **domain/URL-ekwivalent van slopsquatting**. In plaas daarvan om 'n nie-bestaande pakketnaam te hallusineer, hallusineer die LLM 'n geloofwaardige **portal-, API-, webhook-, billing-, SSO-, download- of support-domain** vir 'n werklike brand, en 'n aanvaller registreer daardie namespace voordat 'n mens of agent dit gebruik.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Dit is belangrik omdat modeluitsette in baie AI-assisted workflows as 'n **trusted dependency** behandel word:
- Developers plak die voorgestelde endpoint in code of CI/CD-integrations.
- AI agents haal documentation, schemas, APKs, ZIPs of webhook targets outomaties op.
- Gegenereerde runbooks of docs kan die fake URL insluit asof dit authoritative is.

### Offensive workflow

1. **Probe the hallucination surface**: vra brand-spesifieke vrae oor realistiese workflows soos `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` of `mobile app`-portals.<sup>[[12]](#references)</sup>
2. **Normalize candidates**: resolve gegenereerde URLs, collapse NXDOMAIN-responses na die parent registerable domain, en deduplicate prompt families. Prompt corpora moet divers bly, byvoorbeeld deur near-duplicates met **Jaccard similarity** te verwyder.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: dieselfde fake domain verskyn oor temperature heen, insluitend lae temperature soos `T=0.1`.
- **Cross-model consensus**: verskeie LLM-families genereer dieselfde fake domain.
4. **Register and weaponize** die parent domain, en host dan phishing, fake APK/ZIP-downloads, credential harvesters, malicious docs of API-endpoints wat secrets/webhook-payloads versamel. **Pure domain-level hallucinations** is die maklikste om te monetize omdat die aanvaller die hele namespace beheer; subdomain/path-hallucinations kan steeds misbruik word wanneer die genormaliseerde parent ongeregistreer is.
5. **Exploit the zero-reputation window**: nuutgeregistreerde domains het dikwels geen blocklist-history, URL-reputation of mature telemetry nie, en kan dus controls omseil totdat detections op datum kom. Aanvallers kan hierdie window verleng met crawler-only benign responses, redirect cloaking, CAPTCHA-gates of delayed payload staging.

### Why it is dangerous for agents

Vir 'n human victim het die fake domain gewoonlik steeds 'n click en 'n verdere aksie nodig. In 'n **agentic workflow** kan die LLM beide die **lure** en die **executor** wees: die agent ontvang die hallucinated URL, fetch dit, parse die response, en kan dan tokens leak, instructions execute, 'n dependency download of poisoned data in CI/CD push sonder enige human review.<sup>[[12]](#references)</sup>

### Practical attacker prompts

High-yield prompts lyk gewoonlik soos normale enterprise-tasks eerder as eksplisiete phishing-lures:<sup>[[12]](#references)</sup>
- “Wat is die payment sandbox URL vir `<brand>`-integrations?”
- “Watter webhook endpoint moet ek gebruik vir `<brand>` build notifications?”
- “Waar is die employee benefits / billing / SSO-portal vir `<brand>`?”
- “Gee my die direkte Android APK- of desktop-client-download vir `<brand>`.”

### Defensive inversion

Behandel dit as 'n proactive domain-monitoring-probleem, nie net as 'n prompt-injection-probleem nie:<sup>[[12]](#references)</sup>
- Bou 'n **brand prompt corpus** en probe periodiek die LLMs waarop jou users/agents staatmaak.
- Stoor hallucinated URLs en track watter daarvan stabiel is oor temperatures/models heen.
- Track die **Adversarial Exploitation Window (AEW)**: tyd tussen die eerste hallucination en attacker registration. Positiewe AEW beteken dat defenders vooraf kan registreer, sinkhole of pre-block voordat weaponization plaasvind.
- Monitor **NXDOMAIN → registered**-transitions vir die parent domains.
- Wanneer registrasie plaasvind, triage registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status en brand-asset similarity.
- Voeg policy gates by sodat agents/developers **nie by verstek LLM-generated domains vertrou nie**: vereis allowlists, ownership validation, CT/RDAP-checks of human approval voor eerste gebruik.

Dit pas terselfdertyd by verskeie AI risk buckets: **AI supply-chain attack**, **insecure model output** en **rogue actions** wanneer agents die hallucinated URL outomaties consume.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Die risks van Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Gesteelde Cloud Credentials wat in 'n Nuwe AI Attack Gebruik Word](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking-skema-oorsig – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (herverkoop van gesteelde LLM-toegang)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - In-diepte ondersoek na die deployment van 'n on-premise low-privileged LLM-server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI)-spesifikasie](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-gehallusineerde domeine as 'n Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Hoe AI-hallucinations 'n Nuwe Klas Supply Chain Attacks Aandryf](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
