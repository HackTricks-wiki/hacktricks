# KI-risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp het die top 10 machine learning-kwesbaarhede geïdentifiseer wat KI-stelsels kan beïnvloed. Hierdie kwesbaarhede kan tot verskeie sekuriteitskwessies lei, insluitend data poisoning, model inversion en adversarial attacks. Dit is noodsaaklik om hierdie kwesbaarhede te verstaan om veilige KI-stelsels te bou.

Vir 'n opgedateerde en gedetailleerde lys van die top 10 machine learning-kwesbaarhede, verwys na die projek [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels onsigbare veranderinge aan **inkomende data** toe sodat die model die verkeerde besluit neem.\
*Voorbeeld*: 'n Paar verfspikkels op 'n stopteken mislei 'n selfbesturende motor om 'n spoedbeperkingsteken te "sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus met slegte voorbeelde besoedel, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware-binaries word in 'n antivirus-training corpus verkeerdelik as "benign" gemerk, waardeur soortgelyke malware later deurglip.

- **Model Inversion Attack**: Deur uitsette te ondersoek, bou 'n aanvaller 'n **reverse model** wat sensitiewe kenmerke van die oorspronklike insette rekonstrueer.\
*Voorbeeld*: Die herskepping van 'n pasiënt se MRI-beeld uit 'n kankeropsporingsmodel se voorspellings.

- **Membership Inference Attack**: Die teenstander toets of 'n **spesifieke rekord** tydens training gebruik is deur verskille in vertroue raak te sien.\
*Voorbeeld*: Bevestiging dat 'n persoon se banktransaksie in 'n fraud detection-model se training data voorkom.

- **Model Theft**: Herhaalde navrae stel 'n aanvaller in staat om besluitnemingsgrense te leer en die model se **gedrag te kloon** (en sy IP).\
*Voorbeeld*: Die insameling van genoeg Q&A-pare uit 'n ML-as-a-Service-API om 'n byna ekwivalente plaaslike model te bou.

- **AI Supply-Chain Attack**: Enige komponent (data, libraries, pre-trained weights, CI/CD) in die **ML-pipeline** word gekompromitteer om daaropvolgende modelle te korrupteer.\
*Voorbeeld*: 'n Besoedelde dependency op 'n model-hub installeer 'n model vir sentiment analysis met 'n backdoor in talle apps.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **pre-trained model** geplant en oorleef fine-tuning op die slagoffer se taak.\
*Voorbeeld*: 'n Vision backbone met 'n versteekte trigger keer steeds labels om nadat dit vir medical imaging aangepas is.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd gemerkte data **verskuif die model se uitsette** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: Die inspuiting van "clean" spam-e-posse wat as ham gemerk is, sodat 'n spamfilter soortgelyke toekomstige e-posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander modelvoorspellings tydens oordrag**, nie die model self nie, en mislei sodoende downstream-stelsels.\
*Voorbeeld*: Die omskakeling van 'n malware classifier se "malicious"-uitspraak na "benign" voordat die file-quarantine-stadium dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **modelparameters** self, dikwels nadat skryftoegang verkry is, om gedrag te verander.\
*Voorbeeld*: Die aanpassing van gewigte op 'n fraud detection-model in production sodat transaksies van sekere kaarte altyd goedgekeur word.


## Google SAIF-risiko's

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beskryf verskeie risiko's wat met KI-stelsels verband hou:

- **Data Poisoning**: Kwaadwillige rolspelers verander of voeg training/tuning-data by om akkuraatheid te verlaag, backdoors te plant of resultate te verdraai, wat modelintegriteit deur die hele data-lifecycle ondermyn.

- **Unauthorized Training Data**: Die inname van kopieregbeskermde, sensitiewe of ongemagtigde datasets skep regs-, etiese en prestasie-aanspreeklikhede omdat die model uit data leer wat dit nooit toegelaat is om te gebruik nie.

- **Model Source Tampering**: Supply-chain- of insider-manipulasie van modelkode, dependencies of gewigte voor of tydens training kan versteekte logika inbed wat selfs ná retraining voortduur.

- **Excessive Data Handling**: Swak data-retention- en governance-kontroles lei daartoe dat stelsels meer persoonlike data as nodig stoor of verwerk, wat blootstelling- en compliance-risiko verhoog.

- **Model Exfiltration**: Aanvallers steel modelfile/gewigte, wat verlies aan intellektuele eiendom veroorsaak en copy-cat-dienste of opvolgaanvalle moontlik maak.

- **Model Deployment Tampering**: Teenstanders verander modelartefakte of serving-infrastructure sodat die model wat loop van die goedgekeurde weergawe verskil, wat gedrag moontlik kan verander.

- **Denial of ML Service**: Die oorstroming van APIs of die stuur van “sponge”-insette kan rekenkrag/energie uitput en die model vanlyn neem, soortgelyk aan klassieke DoS attacks.

- **Model Reverse Engineering**: Deur groot getalle input-output-pare in te samel, kan aanvallers die model kloon of distilleer, wat nabootsingsprodukte en aangepaste adversarial attacks voed.

- **Insecure Integrated Component**: Kwesbare plugins, agents of upstream-dienste stel aanvallers in staat om kode in die AI-pipeline in te spuit of privileges te eskaleer.

- **Prompt Injection**: Die samestelling van prompts (direk of indirek) om instruksies te smokkel wat die stelsel se bedoeling oorheers, sodat die model onbedoelde commands uitvoer.

- **Model Evasion**: Noukeurig ontwerpte insette veroorsaak dat die model verkeerd klassifiseer, hallusineer of disallowed content uitvoer, wat veiligheid en vertroue erodeer.

- **Sensitive Data Disclosure**: Die model openbaar private of vertroulike inligting uit sy training data of user context, wat privaatheid en regulasies oortree.

- **Inferred Sensitive Data**: Die model lei persoonlike eienskappe af wat nooit verskaf is nie, wat nuwe privaatheidskade deur inferensie skep.

- **Insecure Model Output**: Ongesuiwerde response stuur skadelike kode, misinformation of onvanpaste content aan users of downstream-stelsels deur.

- **Rogue Actions**: Outomaties geïntegreerde agents voer onbedoelde werklike operasies uit (file writes, API calls, aankope, ens.) sonder voldoende user-oversight.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende raamwerk om risiko's wat met KI-stelsels verband hou, te verstaan en te versag. Dit kategoriseer verskeie attack techniques en tactics wat teenstanders teen KI-modelle kan gebruik, asook hoe om KI-stelsels te gebruik om verskillende attacks uit te voer.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Aanvallers steel aktiewe session tokens of cloud API credentials en roep betaalde, cloud-hosted LLMs sonder toestemming aan. Toegang word dikwels deur reverse proxies herverkoop wat die slagoffer se account front, byvoorbeeld "oai-reverse-proxy"-deployments. Gevolge sluit finansiële verlies, modelmisbruik buite beleid en toeskrywing aan die slagoffer-tenant in.

TTPs:
- Versamel tokens vanaf besmette developer machines of browsers; steel CI/CD-secrets; koop leaked cookies.
- Stel 'n reverse proxy op wat requests na die egte provider aanstuur, die upstream key verberg en baie customers multiplex.
- Misbruik direkte base-model endpoints om enterprise guardrails en rate limits te omseil.

Mitigations:
- Bind tokens aan device fingerprint, IP-ranges en client attestation; dwing kort vervaldatums af en refresh met MFA.
- Beperk keys minimaal (geen tool access nie, read-only waar toepaslik); roteer tydens anomaly.
- Terminate alle traffic server-side agter 'n policy gateway wat safety filters, per-route quotas en tenant isolation afdwing.
- Monitor vir ongewone gebruikspatrone (skielike spend spikes, atipiese regions, UA strings) en revoke verdagte sessions outomaties.
- Verkies mTLS of signed JWTs wat deur jou IdP uitgereik word bo statiese API keys met 'n lang leeftyd.

## Self-hosted LLM inference hardening

Die gebruik van 'n plaaslike LLM-server vir confidential data skep 'n ander attack surface as cloud-hosted APIs: inference/debug-endpoints kan prompts leak, die serving stack stel gewoonlik 'n reverse proxy bloot, en GPU device nodes bied toegang tot groot `ioctl()`-surfaces. Indien jy 'n on-prem inference service assesseer of deploy, hersien ten minste die volgende punte.

### Prompt leakage via debug and monitoring endpoints

Behandel die inference API as 'n **multi-user sensitive service**. Debug- of monitoring-routes kan prompt-inhoud, slot state, modelmetadata of interne queue-inligting blootstel. In `llama.cpp` is die `/slots`-endpoint besonder sensitief omdat dit per-slot state blootstel en slegs vir slot inspection/management bedoel is.

- Plaas 'n reverse proxy voor die inference server en **deny by default**.
- Allowlist slegs die presiese kombinasies van HTTP method + path wat deur die client/UI benodig word.
- Disable introspection-endpoints in die backend self waar moontlik, byvoorbeeld `llama-server --no-slots`.
- Bind die reverse proxy aan `127.0.0.1` en stel dit bloot deur 'n geauthentiseerde transport soos SSH local port forwarding, eerder as om dit op die LAN te publiseer.

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
### Rootless containers sonder netwerk en UNIX-sockets

As die inference daemon luister op ’n UNIX-socket ondersteun, verkies dit bo TCP en voer die container met **geen netwerkstack nie**:
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
- ’n UNIX-socket laat jou toe om POSIX-permissions/ACLs op die socket path as die eerste access-control-laag te gebruik.
- `--userns=keep-id` en rootless Podman verminder die impak van ’n container breakout omdat container root nie host root is nie.
- Read-only model mounts verminder die kans op model-tampering vanuit die container.

### Minimalisering van GPU device-nodes

Vir GPU-backed inference is `/dev/nvidia*`-lêers waardevolle plaaslike attack surfaces omdat hulle groot driver-`ioctl()`-handlers en potensieel gedeelde GPU memory-management-paaie blootstel.

- Moenie `/dev/nvidia*` world writable laat nie.
- Beperk `nvidia`, `nvidiactl` en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev-reëls en ACLs sodat slegs die mapped container UID dit kan oopmaak.
- Blacklist onnodige modules soos `nvidia_drm`, `nvidia_modeset` en `nvidia_peermem` op headless inference-hosts.
- Preload slegs vereiste modules tydens boot in plaas daarvan om die runtime toe te laat om hulle opportunisties te `modprobe` tydens inference-startup.

Voorbeeld:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs al gebruik die workload nie uitdruklik `cudaMallocManaged()` nie, mag onlangse CUDA runtimes steeds `nvidia-uvm` vereis. Omdat hierdie device gedeel word en GPU-virtuelegeheuebestuur hanteer, moet dit as ’n cross-tenant data-exposure-oppervlak behandel word. As die inference backend dit ondersteun, kan ’n Vulkan backend ’n interessante afweging wees omdat dit moontlik glad nie nodig is om `nvidia-uvm` aan die container bloot te stel nie.

### LSM-beperking vir inference workers

AppArmor/SELinux/seccomp behoort as gelaagde verdediging rondom die inference-proses gebruik te word:

- Laat slegs die shared libraries, model paths, socket directory en GPU device nodes toe wat werklik benodig word.
- Weier uitdruklik hoërisiko-capabilities soos `sys_admin`, `sys_module`, `sys_rawio` en `sys_ptrace`.
- Hou die model directory read-only en beperk writable paths tot slegs die runtime socket/cache directories.
- Monitor denial logs omdat hulle nuttige detection telemetry verskaf wanneer die model server of ’n post-exploitation payload probeer om uit sy verwagte gedrag te ontsnap.

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
## Phantom Squatting: LLM-gehallusineerde domeine as 'n AI Supply-Chain-vektor

Phantom squatting is die **domein/URL-ekwivalent van slopsquatting**. In plaas daarvan om 'n nie-bestaande pakketnaam te hallusineer, hallusineer die LLM 'n geloofwaardige **portaal-, API-, webhook-, fakturering-, SSO-, aflaai- of ondersteuningsdomein** vir 'n werklike handelsmerk, en 'n aanvaller registreer daardie namespace voordat 'n mens of agent dit gebruik.

Dit is belangrik omdat modeluitset in baie AI-gesteunde werkvloeie as 'n **vertroude afhanklikheid** behandel word:
- Ontwikkelaars plak die voorgestelde endpoint in kode of CI/CD-integrasies.
- AI-agente haal dokumentasie, skemas, APK's, ZIP's of webhook-teikens outomaties op.
- Gegenereerde runbooks of dokumentasie kan die vals URL insluit asof dit gesaghebbend is.

### Offensiewe werkvloei

1. **Ondersoek die hallusinasie-oppervlak**: vra handelsmerkspesifieke vrae oor realistiese werkvloeie soos `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` of `mobile app`-portale.
2. **Normaliseer kandidate**: resolve gegenereerde URL's, vou NXDOMAIN-antwoorde saam na die ouer registreerbare domein, en verwyder duplikate uit prompt-families. Prompt-korpusse moet divers bly, byvoorbeeld deur byna-duplikate met **Jaccard similarity** te verwyder.
3. **Prioritiseer voorspelbare hallusinasies**:
- **Thermal Hallucination Persistence (THP)**: dieselfde vals domein verskyn oor temperature heen, insluitend lae temperature soos `T=0.1`.
- **Cross-model consensus**: verskeie LLM-families genereer dieselfde vals domein.
4. **Registreer en weaponize** die ouerdomein, en host dan phishing, vals APK/ZIP-aflaaie, credential harvesters, kwaadwillige dokumente of API-endpoints wat secrets/webhook-payloads insamel. **Suiwer domeinvlak-hallusinasies** is die maklikste om te monetiseer omdat die aanvaller die hele namespace beheer; subdomein-/pad-hallusinasies kan steeds misbruik word wanneer die genormaliseerde ouer ongeregistreer is.
5. **Benut die zero-reputation window**: nuut geregistreerde domeine het dikwels geen blocklist-geskiedenis, URL-reputasie of volwasse telemetrie nie, en kan dus kontroles omseil totdat opsporingsmeganismes op datum kom. Aanvallers kan hierdie venster verleng met crawler-only benign responses, redirect cloaking, CAPTCHA-gates of vertraagde payload-staging.

### Waarom dit gevaarlik is vir agente

Vir 'n menslike slagoffer benodig die vals domein gewoonlik steeds 'n klik en nog 'n aksie. In 'n **agentic workflow** kan die LLM beide die **lokaas** en die **uitvoerder** wees: die agent ontvang die gehallusineerde URL, haal dit op, ontleed die antwoord, en kan dan tokens lek, instruksies uitvoer, 'n dependency aflaai of vergiftigde data na CI/CD stoot sonder enige menslike hersiening.

### Praktiese aanvaller-prompts

Hoë-opbrengs-prompts lyk gewoonlik soos normale ondernemingstake eerder as eksplisiete phishing-lokasies:
- “Wat is die payment sandbox URL vir `<brand>`-integrasies?”
- “Watter webhook endpoint moet ek gebruik vir `<brand>` build-notifications?”
- “Waar is die employee benefits / billing / SSO-portaal vir `<brand>`?”
- “Gee my die direkte Android APK- of desktop client-aflaai vir `<brand>`.”

### Defensiewe inversie

Behandel dit as 'n proaktiewe domeinmoniteringsprobleem, nie slegs as 'n prompt-injection-probleem nie:
- Bou 'n **brand prompt corpus** en ondersoek die LLM's waarop jou gebruikers/agente staatmaak periodiek.
- Stoor gehallusineerde URL's en volg watter URL's stabiel bly oor temperature/modelle heen.
- Volg die **Adversarial Exploitation Window (AEW)**: tyd tussen die eerste hallusinasie en aanvallerregistrasie. 'n Positiewe AEW beteken verdedigers kan vooraf registreer, sinkhole of vooraf blokkeer voordat weaponization plaasvind.
- Monitor **NXDOMAIN → registered**-oorgange vir die ouerdomeine.
- Triage by registrasie die registrar, skeppingsdatum, nameservers, privaatheidsafskerming, bladsy-inhoud, skermkiekies, parked-page-status en ooreenkoms met handelsmerkbates.
- Voeg beleidshekke by sodat agente/ontwikkelaars **nie LLM-gegenereerde domeine by verstek vertrou nie**: vereis allowlists, eienaarskapvalidering, CT/RDAP-kontroles of menslike goedkeuring voor eerste gebruik.

Dit pas gelyktydig by verskeie AI-risikokategorieë: **AI supply-chain attack**, **insecure model output** en **rogue actions** wanneer agente die gehallusineerde URL outonoom verbruik.

## Verwysings
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
