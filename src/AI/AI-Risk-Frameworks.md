# KI-risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp het die top 10 machine learning-kwesbaarhede geïdentifiseer wat KI-stelsels kan beïnvloed. Hierdie kwesbaarhede kan tot verskeie sekuriteitsprobleme lei, insluitend data poisoning, model inversion en adversarial attacks. Om hierdie kwesbaarhede te verstaan, is noodsaaklik vir die bou van veilige KI-stelsels.

Vir 'n opgedateerde en gedetailleerde lys van die top 10 machine learning-kwesbaarhede, verwys na die [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)-projek.

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels onsigbare veranderinge aan **inkomende data** toe sodat die model die verkeerde besluit neem.\
*Voorbeeld*: 'n Paar verfspatsels op 'n stopteken mislei 'n selfbesturende motor om 'n spoedbeperkingsteken te "sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus met slegte voorbeelde besoedel, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware-binaries word in 'n antivirus-training corpus verkeerdelik as "benign" gemerk, sodat soortgelyke malware later ongemerk deurglip.

- **Model Inversion Attack**: Deur uitsette te ondersoek, bou 'n aanvaller 'n **reverse model** wat sensitiewe eienskappe van die oorspronklike insette rekonstrueer.\
*Voorbeeld*: Om 'n pasiënt se MRI-beeld te herskep uit die voorspellings van 'n kankeropsporingsmodel.

- **Membership Inference Attack**: Die adversary toets of 'n **spesifieke rekord** tydens training gebruik is deur verskille in vertroue raak te sien.\
*Voorbeeld*: Om te bevestig dat 'n persoon se banktransaksie in 'n fraud-opsporingsmodel se training data voorkom.

- **Model Theft**: Herhaalde navrae stel 'n aanvaller in staat om besluitgrense te leer en die **model se gedrag te kloon** (en die IP daarvan te kopieer).\
*Voorbeeld*: Om genoeg Q&A-pare van 'n ML-as-a-Service-API te versamel om 'n byna ekwivalente plaaslike model te bou.

- **AI Supply-Chain Attack**: Kompromitteer enige komponent (data, libraries, vooraf-opgeleide gewigte, CI/CD) in die **ML-pipeline** om stroomaf-modelle te beskadig.\
*Voorbeeld*: 'n Besoedelde dependency op 'n model-hub installeer 'n sentiment-analise-model met 'n backdoor in talle apps.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **pre-trained model** geplaas en oorleef fine-tuning op die slagoffer se taak.\
*Voorbeeld*: 'n Vision backbone met 'n versteekte trigger verander steeds labels nadat dit vir mediese beeldvorming aangepas is.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd gemerkte data **verskuif die model se uitsette** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: Om "skoon" spam-e-posse wat as ham gemerk is, in te voeg sodat 'n spamfilter soortgelyke toekomstige e-posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander modelvoorspellings tydens oordrag**, nie die model self nie, en mislei sodoende stroomaf-stelsels.\
*Voorbeeld*: Om 'n malware classifier se "malicious"-uitspraak na "benign" te verander voordat die file-quarantine-fase dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **modelparameters** self, dikwels nadat skryftoegang verkry is, om gedrag te verander.\
*Voorbeeld*: Om gewigte op 'n fraud-opsporingsmodel in produksie aan te pas sodat transaksies van sekere kaarte altyd goedgekeur word.


## Google SAIF-risiko's

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beskryf verskeie risiko's wat met KI-stelsels verband hou:

- **Data Poisoning**: Kwaadwillige akteurs verander of voeg training/tuning-data in om akkuraatheid te verlaag, backdoors te plaas of resultate te verdraai, wat modelintegriteit regdeur die hele data-lewensiklus ondermyn.

- **Unauthorized Training Data**: Die inname van materiaal met kopiereg, sensitiewe of ongemagtigde datasets skep wetlike, etiese en prestasieaanspreeklikhede omdat die model leer uit data wat dit nooit toegelaat is om te gebruik nie.

- **Model Source Tampering**: Supply-chain- of insider-manipulasie van modelkode, dependencies of gewigte voor of tydens training kan versteekte logika insluit wat selfs ná retraining voortduur.

- **Excessive Data Handling**: Swak dataretensie- en governance-kontroles lei daartoe dat stelsels meer persoonlike data as nodig stoor of verwerk, wat blootstelling- en compliance-risiko verhoog.

- **Model Exfiltration**: Aanvallers steel modelfiles/gewigte, wat tot verlies van intellektuele eiendom lei en copycat-dienste of opvolgaanvalle moontlik maak.

- **Model Deployment Tampering**: Adversaries verander modelartefakte of die serving-infrastruktuur sodat die model wat loop van die goedgekeurde weergawe verskil, wat gedrag moontlik verander.

- **Denial of ML Service**: Deur API's te oorstroom of "sponge"-insette te stuur, kan compute/energie uitgeput word en die model vanlyn gehaal word, soortgelyk aan klassieke DoS-attacks.

- **Model Reverse Engineering**: Deur groot getalle input-output-pare te versamel, kan aanvallers die model kloon of distil, wat nabootsingsprodukte en pasgemaakte adversarial attacks moontlik maak.

- **Insecure Integrated Component**: Kwesbare plugins, agents of upstream-dienste stel aanvallers in staat om kode in te spuit of privileges binne die KI-pipeline te verhoog.

- **Prompt Injection**: Deur prompts direk of indirek te ontwerp om instruksies in te smokkel wat die stelsel se bedoeling oorheers, kan die model onbedoelde commands uitvoer.

- **Model Evasion**: Versigtig ontwerpte insette laat die model verkeerd klassifiseer, hallusineer of verbode inhoud uitvoer, wat veiligheid en vertroue ondermyn.

- **Sensitive Data Disclosure**: Die model openbaar private of vertroulike inligting uit sy training data of gebruikerskonteks, wat privaatheid en regulasies skend.

- **Inferred Sensitive Data**: Die model lei persoonlike eienskappe af wat nooit verskaf is nie, wat nuwe privaatheidskade deur inferensie skep.

- **Insecure Model Output**: Ongesuiwerde response stuur skadelike kode, misinformasie of onvanpaste inhoud aan gebruikers of stroomaf-stelsels.

- **Rogue Actions**: Outonoom-geïntegreerde agents voer onbedoelde werklike bedrywighede uit (file writes, API calls, aankope, ens.) sonder voldoende gebruikerstoestig.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende raamwerk om risiko's wat met KI-stelsels verband hou, te verstaan en te versag. Dit kategoriseer verskeie aanvalstegnieke en taktieke wat adversaries teen KI-modelle kan gebruik, asook maniere waarop KI-stelsels vir verskillende attacks gebruik kan word.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Aanvallers steel aktiewe sessietokens of cloud API-credentials en roep betaalde, cloud-hosted LLM's sonder toestemming aan. Toegang word dikwels deur reverse proxies herverkoop wat die slagoffer se rekening aan die voorkant gebruik, byvoorbeeld "oai-reverse-proxy"-deployments. Gevolge sluit finansiële verlies, misbruik van die model buite beleid en toeskrywing aan die slagoffer-tenant in.

TTPs:
- Versamel tokens vanaf besmette developer-masjiene of browsers; steel CI/CD-secrets; koop gelekte cookies.
- Stel 'n reverse proxy op wat requests na die egte provider aanstuur, die upstream key verberg en baie kliënte multiplex.
- Misbruik direkte base-model endpoints om enterprise guardrails en rate limits te omseil.

Mitigations:
- Bind tokens aan device fingerprint, IP-ranges en client attestation; dwing kort vervaldatums af en refresh met MFA.
- Beperk keys minimaal (geen tool access nie, read-only waar toepaslik); roteer dit wanneer anomalieë voorkom.
- Terminate alle verkeer server-side agter 'n policy gateway wat safety filters, per-route quotas en tenant-isolasie afdwing.
- Monitor vir ongewone gebruikspatrone (skielike spend-spikes, atipiese streke, UA-strings) en revoke verdagte sessies outomaties.
- Verkies mTLS of signed JWTs wat deur jou IdP uitgereik is bo statiese API-keys met lang leeftye.

## Verharding van self-hosted LLM-inferensie

Die bestuur van 'n plaaslike LLM-server vir vertroulike data skep 'n ander attack surface as cloud-hosted API's: inference/debug-endpoints kan prompts lek, die serving stack stel gewoonlik 'n reverse proxy bloot, en GPU-device nodes bied toegang tot groot `ioctl()`-surfaces. As jy 'n on-prem inference-diens assesseer of ontplooi, hersien minstens die volgende punte.

### Prompt leakage via debug- en monitoring-endpoints

Behandel die inference API as 'n **multi-user sensitive service**. Debug- of monitoring-routes kan promptinhoud, slot state, modelmetadata of inligting oor die interne queue blootstel. In `llama.cpp` is die `/slots`-endpoint besonder sensitief omdat dit per-slot state blootstel en slegs vir slot-inspeksie/-bestuur bedoel is.

- Plaas 'n reverse proxy voor die inference-server en **deny by default**.
- Allowlist slegs die presiese kombinasies van HTTP-method + path wat deur die client/UI benodig word.
- Deaktiveer introspection-endpoints in die backend self waar moontlik, byvoorbeeld `llama-server --no-slots`.
- Bind die reverse proxy aan `127.0.0.1` en stel dit bloot deur 'n geauthentiseerde transport soos SSH local port forwarding, eerder as om dit op die LAN te publiseer.

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

Indien die inference daemon luister op ’n UNIX-socket ondersteun, verkies dit bo TCP en laat loop die container met **geen netwerkstack nie**:
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
- Lees-alleen-model-monterings verminder die kans op modelpeutering vanuit die container.

### Minimalisering van GPU-device nodes

Vir GPU-gesteunde inference is `/dev/nvidia*`-lêers hoëwaarde-plaaslike aanvalsoppervlakke omdat hulle groot driver-`ioctl()`-handlers en potensieel gedeelde GPU-geheuebestuurspaaie blootstel.

- Moenie `/dev/nvidia*` wêreldwyd skryfbaar laat nie.
- Beperk `nvidia`, `nvidiactl` en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev-reëls en ACLs sodat slegs die gemapte container UID dit kan oopmaak.
- Blacklist onnodige modules soos `nvidia_drm`, `nvidia_modeset` en `nvidia_peermem` op headless inference-hosts.
- Preload slegs vereiste modules tydens boot in plaas daarvan om die runtime toe te laat om hulle opportunisties met `modprobe` tydens inference-opstart te laai.

Voorbeeld:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs al gebruik die workload nie uitdruklik `cudaMallocManaged()` nie, mag onlangse CUDA runtimes steeds `nvidia-uvm` vereis. Omdat hierdie toestel gedeel word en GPU virtuelegeheuebestuur hanteer, moet dit as ’n kruis-tenant-datablootstellingsoppervlak behandel word. As die inference backend dit ondersteun, kan ’n Vulkan backend ’n interessante kompromie wees omdat dit moontlik die blootstelling van `nvidia-uvm` aan die container heeltemal vermy.

### LSM-beperking vir inference workers

AppArmor/SELinux/seccomp behoort as defense in depth rondom die inference-proses gebruik te word:

- Laat slegs die shared libraries, modelpaths, socket-gids en GPU-toestelnodes toe wat werklik vereis word.
- Weier uitdruklik hoërisiko-vermoëns soos `sys_admin`, `sys_module`, `sys_rawio` en `sys_ptrace`.
- Hou die modelgids read-only en beperk writable paths tot slegs die runtime socket/cache-gidse.
- Monitor denial logs omdat hulle nuttige detection telemetry verskaf wanneer die model server of ’n post-exploitation payload probeer om uit sy verwagte gedrag te ontsnap.

Voorbeeld-AppArmor-reëls vir ’n GPU-backed worker:
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
## Phantom Squatting: Deur LLM-gehallusineerde domeine as 'n AI-voorsieningskettingvektor

Phantom squatting is die **domein/URL-ekwivalent van slopsquatting**. In plaas daarvan om 'n nie-bestaande pakketnaam te hallusineer, hallusineer die LLM 'n geloofwaardige **portaal-, API-, webhook-, fakturering-, SSO-, aflaai- of ondersteuningsdomein** vir 'n werklike handelsmerk, waarna 'n aanvaller daardie naamruimte registreer voordat 'n mens of agent dit gebruik.

Dit is belangrik omdat modeluitset in baie AI-gesteunde werksvloeie as 'n **vertroude afhanklikheid** behandel word:
- Ontwikkelaars plak die voorgestelde endpoint in kode of CI/CD-integrasies.
- AI-agente haal dokumentasie, schemas, APK's, ZIP's of webhook-teikens outomaties op.
- Gegenereerde runbooks of dokumentasie kan die vals URL insluit asof dit gesaghebbend is.

### Aanvalsproses

1. **Ondersoek die hallusinasie-oppervlak**: vra handelsmerkspesifieke vrae oor realistiese werksvloeie, soos `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` of `mobile app`-portale.
2. **Normaliseer kandidate**: resolve gegenereerde URL's, vou NXDOMAIN-antwoorde saam na die ouer registreerbare domein, en verwyder duplikate uit promptfamilies. Promptkorpusse moet divers bly, byvoorbeeld deur byna-duplikate met **Jaccard similarity** te verwyder.
3. **Prioritiseer voorspelbare hallusinasies**:
- **Thermal Hallucination Persistence (THP)**: dieselfde vals domein verskyn oor verskillende temperature, insluitend lae temperature soos `T=0.1`.
- **Cross-model consensus**: verskeie LLM-families genereer dieselfde vals domein.
4. **Registreer en bewapen** die ouerdomein, en huisves phishing, vals APK/ZIP-aflaaie, credential harvesters, kwaadwillige dokumente of API-endpoints wat secrets/webhook-payloads insamel. **Suiwer domeinvlak-hallusinasies** is die maklikste om te monetiseer omdat die aanvaller die hele naamruimte beheer; subdomein-/padhallusinasies kan steeds misbruik word wanneer die genormaliseerde ouer ongeregistreer is.
5. **Benut die nul-reputasievenster**: nuut geregistreerde domeine het dikwels geen blocklist-geskiedenis, URL-reputasie of volwasse telemetrie nie, en kan dus kontroles omseil totdat detections op datum kom. Aanvallers kan hierdie venster verleng met crawler-only benign responses, redirect cloaking, CAPTCHA-poorte of vertraagde payload-staging.

### Waarom dit gevaarlik is vir agente

Vir 'n menslike slagoffer benodig die vals domein gewoonlik steeds 'n klik en 'n verdere handeling. In 'n **agentiese werksvloei** kan die LLM beide die **lokmiddel** en die **uitvoerder** wees: die agent ontvang die gehallusineerde URL, haal dit op, ontleed die respons, en kan dan tokens lek, instruksies uitvoer, 'n dependency aflaai of vergiftigde data na CI/CD stuur sonder enige menslike hersiening.

### Praktiese aanvaller-prompts

Hoë-opbrengs-prompts lyk gewoonlik soos normale ondernemingtake eerder as eksplisiete phishing-lokmiddels:
- “Wat is die payment sandbox URL vir `<brand>`-integrasies?”
- “Watter webhook-endpoint moet ek gebruik vir `<brand>`-buildnotifikasies?”
- “Waar is die employee benefits / billing / SSO-portaal vir `<brand>`?”
- “Gee my die direkte Android APK- of desktop client-aflaai vir `<brand>`.”

### Defensiewe omkering

Behandel dit as 'n proaktiewe domeinmoniteringsprobleem, nie net as 'n prompt-injection-probleem nie:
- Bou 'n **handelsmerk-promptkorpus** en ondersoek gereeld die LLM's waarop jou gebruikers/agente staatmaak.
- Stoor gehallusineerde URL's en volg watter URL's stabiel bly oor temperature/modelle.
- Volg die **Adversarial Exploitation Window (AEW)**: tyd tussen die eerste hallusinasie en aanvallerregistrasie. 'n Positiewe AEW beteken verdedigers kan vooraf registreer, sinkhole of vooraf blokkeer voordat bewapening plaasvind.
- Monitor **NXDOMAIN → registered**-oorgange vir die ouerdomeine.
- By registrasie, ondersoek die registrar, skeppingsdatum, nameservers, privaatheidsafskerming, bladsyinhoud, screenshots, parked-page-status en ooreenkoms met handelsmerkbates.
- Voeg beleidshekke by sodat agente/ontwikkelaars **nie LLM-gegenereerde domeine by verstek vertrou nie**: vereis allowlists, eienaarskapvalidasie, CT/RDAP-kontroles of menslike goedkeuring voor eerste gebruik.

Dit pas gelyktydig by verskeie AI-risikokategorieë: **AI supply-chain attack**, **insecure model output** en **rogue actions** wanneer agente die gehallusineerde URL outonoom gebruik.

## Verwysings
- [Unit 42 – Die risiko's van Code Assistant-LLM's: skadelike inhoud, misbruik en misleiding](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Oorsig van die LLMJacking-skema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (herverkoop van gesteelde LLM-toegang)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv – Diepgaande ondersoek na die ontplooiing van 'n on-premise low-privileged LLM-server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp-server-README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI)-spesifikasie](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-gehallusineerde domeine as 'n sagtewarevoorsieningskettingvektor](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: Hoe AI-hallusinasies 'n nuwe klas voorsieningskettingaanvalle aanvuur](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
