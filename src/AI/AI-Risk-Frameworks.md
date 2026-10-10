# KI-risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10-kwesbaarhede in masjienleer

OWASP het die top 10-kwesbaarhede in masjienleer geïdentifiseer wat KI-stelsels kan raak. Hierdie kwesbaarhede kan tot verskeie sekuriteitsprobleme lei, insluitend data poisoning, model inversion en adversarial attacks. Dit is noodsaaklik om hierdie kwesbaarhede te verstaan om veilige KI-stelsels te bou.

Raadpleeg die projek [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) vir 'n bygewerkte en gedetailleerde lys van die top 10-kwesbaarhede in masjienleer.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels onsigbare veranderinge aan **inkomende data** toe sodat die model die verkeerde besluit neem.\
    *Voorbeeld*: 'n Paar spikkels verf op 'n stopteken flous 'n selfbesturende motor om 'n spoedbeperkingsteken "te sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus met slegte voorbeelde besmet, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware-binêre lêers word in 'n antivirus-training corpus verkeerdelik as "benign" gemerk, sodat soortgelyke malware later ongemerk deurglip.

- **Model Inversion Attack**: Deur die uitsette te toets, bou 'n aanvaller 'n **reverse model** wat sensitiewe kenmerke van die oorspronklike insette rekonstrueer.\
*Voorbeeld*: 'n Pasiënt se MRI-beeld rekonstrueer uit 'n kankerdeteksie-model se voorspellings.

- **Membership Inference Attack**: Die aanvaller toets of 'n **spesifieke rekord** tydens training gebruik is deur verskille in vertroue raak te sien.\
*Voorbeeld*: Bevestig dat 'n persoon se banktransaksie in 'n bedrogopsporingsmodel se training data voorkom.

- **Model Theft**: Deur herhaaldelik navrae te stuur, kan 'n aanvaller besluitgrense leer en die **model se gedrag kloon** (en sy IP).\
*Voorbeeld*: Versamel genoeg V&A-pare van 'n ML-as-a-Service-API om 'n byna ekwivalente plaaslike model te bou.

- **AI Supply‑Chain Attack**: Kompromitteer enige komponent (data, libraries, vooraf-opgeleide weights, CI/CD) in die **ML pipeline** om daaropvolgende modelle te korrupteer.\
*Voorbeeld*: 'n Besmette dependency op 'n model-hub installeer 'n model vir sentimentanalise met 'n backdoor in baie apps.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **vooraf-opgeleide model** geplant en oorleef fine-tuning vir die slagoffer se taak.\
*Voorbeeld*: 'n Vision backbone met 'n versteekte trigger verander steeds etikette nadat dit vir mediese beeldvorming aangepas is.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd gemerkte data **verskuif die model se uitsette** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: Spaminhoud wat "skoon" is, word ingespuit en as ham gemerk sodat 'n spamfilter soortgelyke toekomstige e-posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander modelvoorspellings tydens oordrag**, nie die model self nie, en flous so daaropvolgende stelsels.\
*Voorbeeld*: Verander 'n malwareklassifiseerder se uitspraak "malicious" na "benign" voordat die lêer-kwarantynfase dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **modelparameters** self, dikwels nadat skryftoegang verkry is, om gedrag te verander.\
*Voorbeeld*: Pas die weights van 'n bedrogopsporingsmodel in produksie aan sodat transaksies van sekere kaarte altyd goedgekeur word.


## Google SAIF-risiko's

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beskryf verskeie risiko's wat met KI-stelsels verband hou:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Kwaadwillige akteurs verander of voeg training/tuning-data in om akkuraatheid te verlaag, backdoors in te plant of resultate te verdraai, en ondermyn so modelintegriteit deur die hele data-lewensiklus. 

- **Unauthorized Training Data**: Die inname van kopieregbeskermde, sensitiewe of ongemagtigde datastelle skep regs-, etiese en prestasierisiko's omdat die model leer uit data wat hy nie mag gebruik nie. 

- **Model Source Tampering**: Manipulasie deur die supply chain of 'n insider van modelkode, dependencies of weights voor of tydens training kan versteekte logika insluit wat selfs ná retraining voortduur. 

- **Excessive Data Handling**: Swak beheer oor databewaring en data-bestuur lei daartoe dat stelsels meer persoonlike data stoor of verwerk as wat nodig is, wat blootstelling en nakomingsrisiko verhoog. 

- **Model Exfiltration**: Aanvallers steel modelf lêers/weights, wat lei tot verlies van intellektuele eiendom en die ontwikkeling van nabootsingsdienste of opvolgaanvalle moontlik maak. 

- **Model Deployment Tampering**: Teenstanders verander modelartefakte of die bedieningsinfrastruktuur sodat die model wat loop van die goedgekeurde weergawe verskil, wat gedrag moontlik verander. 

- **Denial of ML Service**: Die oorlaai van API's of die stuur van “sponge”-insette kan rekenaarkrag/energie uitput en die model vanlyn haal, soortgelyk aan klassieke DoS attacks. 

- **Model Reverse Engineering**: Deur groot hoeveelhede inset-uitset-pare te versamel, kan aanvallers die model kloon of distilleer, wat nabootsingsprodukte en pasgemaakte adversarial attacks moontlik maak. 

- **Insecure Integrated Component**: Kwesbare plugins, agents of stroomop-dienste laat aanvallers kode inspuit of voorregte binne die KI-pipeline verhoog. 

- **Prompt Injection**: Die opstel van prompts (direk of indirek) om instruksies in te smokkel wat die stelsel se bedoelings oorheers, sodat die model onbedoelde opdragte uitvoer. 

- **Model Evasion**: Noukeurig ontwerpte insette laat die model verkeerd klassifiseer, hallusineer of inhoud lewer wat nie toegelaat word nie, en ondermyn so veiligheid en vertroue. 

- **Sensitive Data Disclosure**: Die model openbaar private of vertroulike inligting uit sy training data of gebruikerskonteks, in stryd met privaatheidsvereistes en regulasies. 

- **Inferred Sensitive Data**: Die model lei persoonlike kenmerke af wat nooit verskaf is nie, en skep nuwe privaatheidskade deur afleiding. 

- **Insecure Model Output**: Ongefilterde antwoorde stuur skadelike kode, waninligting of onvanpaste inhoud aan gebruikers of daaropvolgende stelsels. 

- **Rogue Actions**: Outonoom geïntegreerde agents voer onbedoelde werklike handelinge uit (lêers skryf, API-oproepe, aankope, ens.) sonder voldoende toesig deur die gebruiker.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende raamwerk om risiko's wat met KI-stelsels verband hou, te verstaan en te versag. Dit kategoriseer verskeie aanvalstegnieke en -taktieke wat teenstanders teen KI-modelle kan gebruik, asook maniere waarop KI-stelsels gebruik kan word om verskillende aanvalle uit te voer.<sup>[[3]](#references)</sup>

## LLMJacking (Diefstal van tokens en herverkoop van toegang tot wolkgehuisveste LLM's)

Aanvallers steel aktiewe sessietokens of cloud API-geloofsbriewe en roep betaalde, wolkgehuisveste LLM's sonder magtiging aan. Toegang word dikwels herverkoop via reverse proxies wat die slagoffer se rekening gebruik, byvoorbeeld "oai-reverse-proxy"-ontplooiings. Gevolge sluit finansiële verlies, modelmisbruik buite beleid en toeskrywing aan die slagoffer se tenant in.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP's:
- Versamel tokens van besmette ontwikkelaarmasjiene of blaaiers; steel CI/CD-geheime; koop uitgelekte cookies.<sup>[[5]](#references)</sup>
- Stel 'n reverse proxy op wat versoeke na die egte verskaffer aanstuur, die upstream key verberg en versoeke van baie kliënte saamvoeg.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Misbruik direkte base-model-endpoints om ondernemingsbeskermingsmaatreëls en tarieflimiete te omseil.<sup>[[4]](#references)</sup>

Versagtingsmaatreëls:
- Koppel tokens aan toestelvingerafdrukke, IP-reekse en kliëntattestasie; dwing kort vervaltye af en vernuwe dit met MFA.
- Beperk keys tot die minimum (geen toegang tot tools nie; waar toepaslik, leesalleen); roteer dit wanneer afwykings voorkom.
- Lei alle verkeer aan die bedienerkant deur 'n policy gateway wat veiligheidsfilters, kwotas per roete en tenant-isolasie afdwing.
- Monitor vir ongewone gebruikspatrone (skielike bestedingspieke, atipiese streke, UA-strings) en herroep verdagte sessies outomaties.
- Verkies mTLS of ondertekende JWT's wat deur jou IdP uitgereik word bo statiese API-keys met lang geldigheid.

## Versterking van selfgehuisveste LLM-inferensie

Die gebruik van 'n plaaslike LLM-bediener vir vertroulike data skep 'n ander aanvaloppervlak as cloud-hosted API's: inference-/debug-endpoints kan prompts lek, die bedieningslaag stel gewoonlik 'n reverse proxy bloot, en GPU-toestelnodes bied toegang tot groot `ioctl()`-oppervlaktes. As jy 'n plaaslike inference-diens beoordeel of ontplooi, hersien ten minste die volgende punte.<sup>[[8]](#references)</sup>

### Prompt-lekkasie via debug- en monitering-endpoints

Behandel die inference API as 'n **sensitiewe diens vir veelvuldige gebruikers**. Debug- of moniteringsroetes kan prompt-inhoud, slotstatus, modelmetadata of interne tou-inligting blootlê. In `llama.cpp` is die `/slots`-endpoint besonder sensitief omdat dit status per slot blootlê en slegs vir slotinspeksie/-bestuur bedoel is.<sup>[[8]](#references)</sup>

- Plaas 'n reverse proxy voor die inference-bediener en **weier by verstek**.
- Laat slegs die presiese kombinasies van HTTP-metode + pad toe wat die kliënt/UI nodig het.
- Deaktiveer introspection-endpoints in die backend self waar moontlik, byvoorbeeld `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Koppel die reverse proxy aan `127.0.0.1` en stel dit bloot via 'n geverifieerde verbinding soos SSH local port forwarding, eerder as om dit op die LAN te publiseer.

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

### Wortellose houers sonder netwerk en UNIX-sokke

As die inferensie-daemon luister op ’n UNIX-sok kan gebruik, verkies dit bo TCP en laat die houer loop met **geen netwerkstapel nie**:<sup>[[8]](#references)</sup>

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
- ’n UNIX-socket laat jou toe om POSIX-permissies/ACLs op die socket path as die eerste toegangsbeheerlaag te gebruik.
- `--userns=keep-id` en rootless Podman verminder die impak van ’n container breakout omdat container root nie host root is nie.
- Read-only model mounts verminder die kans op peuterwerk aan modelle van binne die container.

Vir permanente ontplooiings kan dieselfde beperkings as Podman Quadlet-units uitgedruk word. As GPU-toegang via die Container Device Interface gedelegeer word, hou die CDI-device specification so beperk as moontlik eerder as om elke accelerator node bloot te stel.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimalisering van GPU-device nodes

Vir GPU-gesteunde inferensie is `/dev/nvidia*`-lêers plaaslike aanvalsvlakke van groot waarde omdat hulle groot driver `ioctl()`-handlers en moontlik gedeelde GPU-geheuebestuurspaaie blootstel.<sup>[[8]](#references)</sup>

- Moenie `/dev/nvidia*` wêreldwyd skryfbaar laat nie.
- Beperk `nvidia`, `nvidiactl` en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev-reëls en ACLs sodat slegs die toegewysde container UID hulle kan oopmaak.
- Blacklist onnodige modules soos `nvidia_drm`, `nvidia_modeset` en `nvidia_peermem` op headless inferensiehosts.
- Laai slegs vereiste modules vooraf tydens opstart, eerder as om die runtime toe te laat om hulle tydens inferensie-opstart opportunisties met `modprobe` te laai.

Voorbeeld:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs al gebruik die workload nie uitdruklik `cudaMallocManaged()` nie, kan onlangse CUDA-runtimes steeds `nvidia-uvm` vereis. Omdat hierdie toestel gedeel word en GPU-virtuele geheuebestuur hanteer, moet dit as ’n oppervlak vir datablootstelling tussen huurders beskou word. As die inference-backend dit ondersteun, kan ’n Vulkan-backend ’n interessante afweging wees, omdat dit dalk heeltemal kan verhoed dat `nvidia-uvm` aan die container blootgestel word.<sup>[[8]](#references)</sup>

### LSM-inperking vir inference-werkers

AppArmor/SELinux/seccomp moet as verdediging in diepte rondom die inference-proses gebruik word:<sup>[[8]](#references)</sup>

- Laat slegs die gedeelde biblioteke, modelpaaie, socket-gids en GPU-toestelnodes toe wat werklik nodig is.
- Weier uitdruklik hoërisiko-vermoëns soos `sys_admin`, `sys_module`, `sys_rawio` en `sys_ptrace`.
- Hou die modelgids leesalleen en beperk skryfbare paaie tot slegs die runtime-socket-/kasgidse.
- Monitor weieringslogboeke, aangesien hulle nuttige opsporingstelemetrie verskaf wanneer die modelbediener of ’n post-exploitation-payload probeer ontsnap aan die verwagte gedrag.

Voorbeeld van AppArmor-reëls vir ’n GPU-aangedrewe werker:

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

## Phantom Squatting: LLM-geïnhallusineerde domeine as ’n AI-voorsieningskettingvektor

Phantom squatting is die **domein/URL-ekwivalent van slopsquatting**. In plaas daarvan om ’n pakketnaam wat nie bestaan nie te hallusineer, hallusineer die LLM ’n geloofwaardige **portaal-, API-, webhook-, fakturerings-, SSO-, aflaai- of ondersteuningsdomein** vir ’n werklike handelsmerk, en ’n aanvaller registreer daardie naamruimte voordat ’n mens of agent dit gebruik.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Dit maak saak omdat die model se uitvoer in baie KI-ondersteunde werkvloeie as ’n **vertroude afhanklikheid** behandel word:
- Ontwikkelaars plak die voorgestelde eindpunt in kode of CI/CD-integrasies.
- KI-agente haal dokumentasie, skemas, APK's, ZIP-lêers of webhook-teikens outomaties op.
- Gegenereerde runbooks of dokumentasie kan die vals URL insluit asof dit gesaghebbend is.

### Aanvalswerkvloei

1. **Toets die hallusinasie-oppervlak**: vra handelsmerkspesifieke vrae oor realistiese werkvloeie, soos `admin`-, `billing`-, `sandbox`-, `benefits`-, `api`-, `download`-, `support`-, `webhook`- of `mobile app`-portale.<sup>[[12]](#references)</sup>
2. **Normaliseer kandidate**: los gegenereerde URL's op, herlei NXDOMAIN-antwoorde na die ouer registreerbare domein, en verwyder duplikate uit promptfamilies. Promptkorpusse behoort uiteenlopend te bly, byvoorbeeld deur byna-duplikate met **Jaccard-ooreenkoms** te verwyder.
3. **Prioritiseer voorspelbare hallusinasies**:
   - **Thermal Hallucination Persistence (THP)**: dieselfde vals domein verskyn oor verskillende temperature, insluitend ’n lae temperatuur soos `T=0.1`.
   - **Konsensus tussen modelle**: verskeie LLM-families genereer dieselfde vals domein.
4. **Registreer en bewapen** die ouerdomein, en bied dan phishing, vals APK-/ZIP-aflaaie, geloofsbriewestelers, kwaadwillige dokumente of API-eindpunte aan wat geheime/webhook-vragte versamel. **Suiwer domeinvlak-hallusinasies** is die maklikste om geld mee te maak omdat die aanvaller die hele naamruimte beheer; subdomein-/pad-hallusinasies kan steeds misbruik word wanneer die genormaliseerde ouerdomein ongeregistreer is.
5. **Benut die venster met geen reputasie nie**: nuut geregistreerde domeine het dikwels geen bloklys-geskiedenis, URL-reputasie of volwasse telemetrie nie, en kan dus beheermaatreëls omseil totdat opsporing op datum is. Aanvallers kan hierdie venster verleng met onskadelike antwoorde wat net aan webkruipers gewys word, omleidingsverberging, CAPTCHA-poorte of vertraagde loonvrag-ontplooiing.

### Waarom dit gevaarlik is vir agente

Vir ’n menslike slagoffer vereis die vals domein gewoonlik steeds ’n klik en nog ’n handeling. In ’n **agentiese werkvloei** kan die LLM sowel die **lokmiddel** as die **uitvoerder** wees: die agent ontvang die geïnhallusineerde URL, haal dit op, ontleed die antwoord en kan dan tokens uitlek, instruksies uitvoer, ’n afhanklikheid aflaai of vergiftigde data in CI/CD stoot sonder enige menslike hersiening.<sup>[[12]](#references)</sup>

### Praktiese aanvallerprompts

Prompts met ’n hoë opbrengs lyk gewoonlik soos normale ondernemingstake, eerder as eksplisiete phishing-lokmiddels:<sup>[[12]](#references)</sup>
- “Wat is die betaling-sandbox-URL vir `<brand>`-integrasies?”
- “Watter webhook-eindpunt moet ek gebruik vir `<brand>`-boukennisgewings?”
- “Waar is die werknemer-voordele-/fakturering-/SSO-portaal vir `<brand>`?”
- “Gee my die direkte Android APK- of desktop client-aflaai vir `<brand>`.”

### Verdedigende omkering

Behandel dit as ’n proaktiewe domeinmoniteringsprobleem, nie net as ’n prompt-injection-probleem nie:<sup>[[12]](#references)</sup>
- Bou ’n **handelsmerkpromptkorpus** en toets gereeld die LLM's waarop jou gebruikers/agente staatmaak.
- Stoor geïnhallusineerde URL's en hou dop watter daarvan stabiel bly oor temperature/modelle heen.
- Hou die **Adversarial Exploitation Window (AEW)** dop: die tyd tussen die eerste hallusinasie en die aanvaller se registrasie. ’n Positiewe AEW beteken verdedigers kan vooraf registreer, sinkhole of blokkeer voordat die domein bewapen word.
- Monitor **NXDOMAIN → geregistreer**-oorgange vir die ouerdomeine.
- Ondersoek by registrasie die registrateur, skeppingsdatum, naambedieners, privaatheidsbeskerming, bladsyinhoud, skermkiekies, geparkeerde-bladsystatus en ooreenkoms met handelsmerkbates.
- Voeg beleidshekke by sodat agente/ontwikkelaars **nie LLM-gegenereerde domeine by verstek vertrou nie**: vereis toelaatlyste, eienaarskapvalidering, CT/RDAP-kontroles of menslike goedkeuring voor eerste gebruik.

Dit val gelyktydig in verskeie AI-risikokategorieë: **AI-voorsieningskettingaanval**, **onveilige modeluitvoer** en **rogue actions** wanneer agente die geïnhallusineerde URL outonoom gebruik.

## References

- [1] [OWASP Top 10-kwesbaarhede in masjienleer](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risiko's](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS-bedreigingsmatriks](https://atlas.mitre.org/)
- [4] [Unit 42 – Die risiko's van LLM-kodeassistente: skadelike inhoud, misbruik en misleiding](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Gesteelde wolkgeloofsbriewe gebruik in ’n nuwe KI-aanval](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Oorsig van die LLMJacking-skema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (herverkoop van gesteelde LLM-toegang)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Diepgaande ondersoek na die ontplooiing van ’n LLM-bediener op die perseel met lae voorregte](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp-bediener-README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI)-spesifikasie](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: KI-geïnhallusineerde domeine as ’n sagteware-voorsieningskettingvektor](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Hoe KI-hallusinasies ’n nuwe klas voorsieningskettingaanvalle aanwakker](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
