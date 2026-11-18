# KI-risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP het die top 10 kwesbaarhede in machine learning geïdentifiseer wat KI-stelsels kan raak. Hierdie kwesbaarhede kan tot verskeie sekuriteitskwessies lei, insluitend data poisoning, model inversion en adversarial attacks. Dit is noodsaaklik om hierdie kwesbaarhede te verstaan wanneer veilige KI-stelsels gebou word.

Vir 'n bygewerkte en gedetailleerde lys van die top 10 kwesbaarhede in machine learning, raadpleeg die projek [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels onsigbare veranderinge aan **inkomende data** toe sodat die model die verkeerde besluit neem.\
    *Voorbeeld*: 'n Paar verfsproete op 'n stopteken mislei 'n selfbesturende motor om 'n spoedbeperkingsteken te "sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus met slegte voorbeelde besoedel, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware-binêre lêers word in 'n antivirus-training corpus verkeerdelik as "benign" gemerk, sodat soortgelyke malware later ongemerk deurglip.

- **Model Inversion Attack**: Deur uitsette te toets, bou 'n aanvaller 'n **reverse model** wat sensitiewe kenmerke van die oorspronklike insette rekonstrueer.\
*Voorbeeld*: Die herskepping van 'n pasiënt se MRI-beeld uit die voorspellings van 'n kankerdeteksiemodel.

- **Membership Inference Attack**: Die aanvaller toets of 'n **spesifieke rekord** tydens training gebruik is deur verskille in sekerheid raak te sien.\
*Voorbeeld*: Bevestig dat 'n persoon se banktransaksie in die training data van 'n bedrogopsporingsmodel voorkom.

- **Model Theft**: Deur herhaaldelik navrae te doen, kan 'n aanvaller die besluitgrense leer en die **model se gedrag kloon** (en sy IP).\
*Voorbeeld*: Versamel genoeg vraag-en-antwoord-pare van 'n ML-as-a-Service-API om 'n byna ekwivalente plaaslike model te bou.

- **AI Supply‑Chain Attack**: Kompromitteer enige komponent (data, biblioteke, voorafopgeleide gewigte, CI/CD) in die **ML-pyplyn** om daaropvolgende modelle te korrupteer.\
*Voorbeeld*: 'n Besoedelde afhanklikheid op 'n model-hub installeer 'n agterdeur-sentimentanalise-model in talle programme.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **pre-trained model** geplant en oorleef fine-tuning vir die slagoffer se taak.\
*Voorbeeld*: 'n Vision backbone met 'n versteekte sneller verander steeds etikette nadat dit vir mediese beeldvorming aangepas is.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd gemerkte data **verskuif die model se uitsette** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: Voeg "skoon" spam-e-posse in wat as ham gemerk is, sodat 'n spamfilter soortgelyke toekomstige e-posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander modelvoorspellings tydens oordrag**, nie die model self nie, en mislei sodoende daaropvolgende stelsels.\
*Voorbeeld*: Verander 'n malware-klassifiseerder se "malicious"-uitspraak na "benign" voordat die lêerkarantynstadium dit sien.

- **Model Poisoning** --- Direkte, doelgerigte veranderinge aan die **model parameters** self, dikwels nadat skryftoegang verkry is, om gedrag te verander.\
*Voorbeeld*: Pas gewigte van 'n bedrogopsporingsmodel in produksie aan sodat transaksies van sekere kaarte altyd goedgekeur word.


## Google SAIF-risiko's

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beskryf verskeie risiko's wat met KI-stelsels verband hou:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Kwaadwillige rolspelers verander of voeg training-/tuning-data in om akkuraatheid te verlaag, agterdeure in te plant of resultate te verdraai, wat die modelintegriteit deur die hele data-lewensiklus ondermyn. 

- **Unauthorized Training Data**: Die inname van materiaalbeskermde, sensitiewe of ongemagtigde datastelle skep regs-, etiese en prestasierisiko's omdat die model leer uit data wat dit nie mag gebruik nie. 

- **Model Source Tampering**: Manipulasie deur die voorsieningsketting of insiders van modelkode, afhanklikhede of gewigte voor of tydens training kan versteekte logika insluit wat selfs ná retraining voortbestaan. 

- **Excessive Data Handling**: Swak beheer oor databewaring en -bestuur lei daartoe dat stelsels meer persoonlike data as nodig stoor of verwerk, wat blootstellings- en nakomingsrisiko verhoog. 

- **Model Exfiltration**: Aanvallers steel modellêers/-gewigte, wat lei tot verlies van intellektuele eiendom en die ontwikkeling van nabootsingsdienste of opvolgaanvalle moontlik maak. 

- **Model Deployment Tampering**: Aanvallers verander modelartefakte of die bedieningsinfrastruktuur sodat die model wat loop, verskil van die goedgekeurde weergawe en moontlik sy gedrag verander. 

- **Denial of ML Service**: Die oorlaai van API's of die stuur van “sponge”-insette kan rekenaarhulpbronne/energie uitput en die model vanlyn haal, soortgelyk aan klassieke DoS-aanvalle. 

- **Model Reverse Engineering**: Deur groot hoeveelhede inset-uitset-pare te versamel, kan aanvallers die model kloon of distilleer, wat nabootsingsprodukte en pasgemaakte adversarial attacks moontlik maak. 

- **Insecure Integrated Component**: Kwesbare plugins, agents of stroomopdienste laat aanvallers kode invoeg of hul voorregte binne die KI-pyplyn verhoog. 

- **Prompt Injection**: Stel prompts (direk of indirek) saam om instruksies in te smokkel wat die stelsel se bedoeling oorheers, sodat die model onbedoelde opdragte uitvoer. 

- **Model Evasion**: Noukeurig ontwerpte insette laat die model verkeerd klassifiseer, hallusineer of verbode inhoud uitset, wat veiligheid en vertroue ondermyn. 

- **Sensitive Data Disclosure**: Die model openbaar private of vertroulike inligting uit sy training data of gebruikerskonteks, en skend sodoende privaatheid en regulasies. 

- **Inferred Sensitive Data**: Die model lei persoonlike eienskappe af wat nooit verskaf is nie, en skep nuwe privaatheidskade deur afleiding. 

- **Insecure Model Output**: Ongesuiwerde antwoorde stuur skadelike kode, waninligting of onvanpaste inhoud aan gebruikers of daaropvolgende stelsels deur. 

- **Rogue Actions**: Outonoom geïntegreerde agents voer onbedoelde werklike handelinge uit (lêers skryf, API-oproepe doen, aankope doen, ens.) sonder voldoende toesig deur gebruikers.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende raamwerk om risiko's wat met KI-stelsels verband hou, te verstaan en te versag. Dit kategoriseer verskeie aanvalstegnieke en -taktieke wat aanvallers teen KI-modelle kan gebruik, asook hoe KI-stelsels gebruik kan word om verskillende aanvalle uit te voer.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Aanvallers steel aktiewe sessietokens of cloud API-geloofsbriewe en roep betaalde, cloud-hosted LLM's sonder toestemming aan. Toegang word dikwels deur reverse proxies herverkoop wat die slagoffer se rekening as tussenganger gebruik, byvoorbeeld ontplooiings van "oai-reverse-proxy". Gevolge sluit finansiële verlies, modelmisbruik buite die beleid en toeskrywing aan die slagoffer se tenant in.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP's:
- Versamel tokens van besmette ontwikkelaarmasjiene of blaaiers; steel CI/CD-geheime; koop gelekte koekies.<sup>[[5]](#references)</sup>
- Stel 'n reverse proxy op wat versoeke na die egte diensverskaffer aanstuur, die stroomop-sleutel versteek en versoeke van verskeie kliënte saamsnoer.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Misbruik direkte base-model-endpoints om ondernemingsbeveiligingsmaatreëls en koerslimiete te omseil.<sup>[[4]](#references)</sup>

**Hergebruik van API-sleutels op die gasheer:** Ná kompromittering van die gasheer kan 'n implant model-API-versoeke direk vanaf die slagoffer se gasheer stuur en die antwoorde oor C2 deurstuur, sonder om 'n cloud API-sleutel uit te voer of 'n plaaslike AI CLI te begin. In die waargenome handler geniet 'n sleutel wat deur C2 verskaf is voorrang; slegs wanneer dit ontbreek, lees die implant `OPENAI_API_KEY` uit sy eie prosesomgewing. Die gebruik van die slagoffer se rekening vereis dus 'n geldige sleutel wat vir daardie proses sigbaar is, asook toegang tot die model-API. Die operateur se prompt gaan na die Chat Completions-API, terwyl die modeluitset en tokengebruik oor C2 teruggestuur word. Dit kan die slagoffer se betaalde modeltoegang verbruik sonder om die ontwikkelaar se KI-nutsgoed te laat loop, anders as [misbruik van plaaslike AI CLI- of MCP-konfigurasie](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Versagtingsmaatreëls:
- Bind tokens aan toestelvingerafdrukke, IP-reekse en kliëntattestasie; dwing kort vervaltye af en hernu met MFA.
- Beperk sleutels tot die minimum nodige omvang (geen toegang tot tools nie; waar toepaslik, slegs leesregte); roteer dit wanneer afwykings voorkom.
- Lei alle verkeer bedienerkant deur 'n beleidsgateway wat veiligheidsfilters, kwotas per roete en tenant-isolasie afdwing.
- Monitor vir ongewone gebruikspatrone (skielike bestedingspieke, atipiese streke, UA-stringe) en herroep verdagte sessies outomaties.
- Verkies mTLS of ondertekende JWT's wat deur jou IdP uitgereik word bo statiese API-sleutels met lang geldigheid.

## Verharding van self-hosted LLM-inference

Die gebruik van 'n plaaslike LLM-bediener vir vertroulike data skep 'n ander aanvalsoppervlak as cloud-hosted API's: inference-/debug-endpoints kan prompts lek, die bedieningslaag stel gewoonlik 'n reverse proxy bloot, en GPU-toestelnodes bied toegang tot groot `ioctl()`-aanvalsoppervlakke. As jy 'n on-prem inference-diens assesseer of ontplooi, hersien minstens die volgende punte.<sup>[[8]](#references)</sup>

### Prompt-lekkasie via debug- en moniteringsendpoints

Behandel die inference-API as 'n **sensitiewe diens vir veelvuldige gebruikers**. Debug- of moniteringsroetes kan prompt-inhoud, slotstatus, modelmetadata of interne tou-inligting blootlê. In `llama.cpp` is die `/slots`-endpoint besonder sensitief omdat dit status per slot blootlê en slegs vir slotinspeksie/-bestuur bedoel is.<sup>[[8]](#references)</sup>

Vir black-box-fingerprinting en toetsing van blootgestelde modelrunners en verwante KI-dienste, raadpleeg [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Plaas 'n reverse proxy voor die inference-bediener en **weier by verstek**.
- Laat slegs die presiese kombinasies van HTTP-metode en pad toe wat die kliënt/UI benodig.
- Deaktiveer introspection-endpoints in die backend self waar moontlik, byvoorbeeld `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Bind die reverse proxy aan `127.0.0.1` en stel dit bloot deur 'n geverifieerde transportmeganisme soos SSH-local-port-forwarding, eerder as om dit op die LAN te publiseer.

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

As die inference daemon kan luister op ’n UNIX-socket, verkies dit bo TCP en laat die container met **geen netwerkstack** loop:<sup>[[8]](#references)</sup>

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
- `--network none` verwyder blootstelling aan inkomende/uitgaande TCP/IP-verkeer en vermy user-mode helpers wat rootless containers andersins sou benodig.
- ’n UNIX-socket laat jou toe om POSIX-toestemmings/ACLs op die socket-pad as die eerste toegangsbeheerlaag te gebruik.
- `--userns=keep-id` en rootless Podman verminder die impak van ’n container breakout omdat container-root nie host-root is nie.
- Leesalleen-modelmonterings verminder die kans op peutering met die model vanuit die container.

Vir volgehoue ontplooiings kan dieselfde beperkings as Podman Quadlet-eenhede uitgedruk word. As GPU-toegang via die Container Device Interface gedelegeer word, hou die CDI-toestelspesifikasie so beperk as moontlik eerder as om elke accelerator-node bloot te stel.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimalisering van GPU-toestelnodes

Vir GPU-gesteunde inferensie is `/dev/nvidia*`-lêers aanvalsvlakke met ’n hoë waarde omdat hulle groot driver-`ioctl()`-hanteerders en moontlik gedeelde GPU-geheuebestuurspaaie blootstel.<sup>[[8]](#references)</sup>

- Moenie `/dev/nvidia*` wêreldskryfbaar laat nie.
- Beperk `nvidia`, `nvidiactl` en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev-reëls en ACLs sodat slegs die toegekende container-UID hulle kan oopmaak.
- Swartlys onnodige modules soos `nvidia_drm`, `nvidia_modeset` en `nvidia_peermem` op headless inferensie-gashere.
- Voorlaai slegs vereiste modules tydens selflaai, eerder as om die runtime toe te laat om hulle opportunisties met `modprobe` tydens inferensie-opstart te laai.

Voorbeeld:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs al gebruik die werklas nie uitdruklik `cudaMallocManaged()` nie, kan onlangse CUDA-runtimes steeds `nvidia-uvm` vereis. Omdat hierdie toestel gedeel word en GPU-virtuele geheuebestuur hanteer, moet dit as ’n oppervlak vir datablootstelling tussen huurders beskou word. As die inferensie-backend dit ondersteun, kan ’n Vulkan-backend ’n interessante afweging wees omdat dit moontlik heeltemal vermy dat `nvidia-uvm` aan die container blootgestel word.<sup>[[8]](#references)</sup>

### LSM-beperking vir inferensie-werkers

AppArmor/SELinux/seccomp behoort as verdediging in diepte rondom die inferensieproses gebruik te word:<sup>[[8]](#references)</sup>

- Laat slegs die gedeelde biblioteke, modelpaaie, sokgids en GPU-toestelknope toe wat werklik benodig word.
- Weier hoërisiko-vermoëns soos `sys_admin`, `sys_module`, `sys_rawio` en `sys_ptrace` uitdruklik.
- Hou die modelgids leesalleen en beperk skryfbare paaie tot slegs die runtime-sok-/kasgidse.
- Monitor weieringslogboeke omdat hulle nuttige opsporingstelemetrie bied wanneer die modelbediener of ’n post-exploitation-payload probeer om buite die verwagte gedrag te tree.

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

## Phantom Squatting: Deur LLM-gehallusineerde domeine as ’n AI-voorsieningskettingvektor

Phantom squatting is die **domein-/URL-ekwivalent van slopsquatting**. In plaas daarvan om ’n nie-bestaande pakketnaam te hallusineer, hallusineer die LLM ’n geloofwaardige **portaal-, API-, webhook-, fakturering-, SSO-, aflaai- of ondersteuningsdomein** vir ’n regte handelsmerk, en ’n aanvaller registreer daardie naamruimte voordat ’n mens of agent dit gebruik.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Dit is belangrik omdat die model se uitvoer in baie KI-gesteunde werkvloeie as ’n **betroubare afhanklikheid** beskou word:
- Ontwikkelaars plak die voorgestelde eindpunt in kode of CI/CD-integrasies.
- KI-agente haal dokumentasie, skemas, APK’s, ZIP-lêers of webhook-teikens outomaties op.
- Gegenereerde loopboeke of dokumentasie kan die vals URL insluit asof dit gesaghebbend is.

### Aanvallende werkvloei

1. **Ondersoek die hallusinasie-oppervlak**: vra handelsmerkspesifieke vrae oor realistiese werkvloeie soos `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` of `mobile app`-portale.<sup>[[12]](#references)</sup>
2. **Normaliseer kandidate**: los gegenereerde URL’s op, herlei NXDOMAIN-antwoorde na die ouerdomein wat geregistreer kan word, en verwyder duplikate uit prompt-families. Promptkorpusse moet uiteenlopend bly; verwyder byvoorbeeld byna-duplikate met **Jaccard-ooreenkoms**.
3. **Prioritiseer voorspelbare hallusinasies**:
   - **Thermal Hallucination Persistence (THP)**: dieselfde vals domein verskyn by verskillende temperature, insluitend lae temperature soos `T=0.1`.
   - **Konsensus tussen modelle**: verskeie LLM-families genereer dieselfde vals domein.
4. **Registreer en wapen** die ouerdomein, en huisves dan phishing, vals APK-/ZIP-aflaaie, insamelingsbladsye vir aanmeldbesonderhede, kwaadwillige dokumente of API-eindpunte wat geheime/webhook-vragte versamel. **Suiwer domeinvlak-hallusinasies** is die maklikste om te monetiseer omdat die aanvaller die hele naamruimte beheer; subdomein-/pad-hallusinasies kan steeds misbruik word wanneer die genormaliseerde ouerdomein nie geregistreer is nie.
5. **Benut die reputasielose tydperk**: nuut geregistreerde domeine het dikwels geen bloklys-geskiedenis, URL-reputasie of volwasse telemetrie nie, en kan dus beheermaatreëls omseil totdat opsporing op datum kom. Aanvallers kan dié tydperk verleng met onskadelike antwoorde net vir webkruipers, herleidingsverberging, CAPTCHA-poorte of vertraagde payload-ontplooiing.

### Waarom dit vir agente gevaarlik is

Vir ’n menslike slagoffer vereis die vals domein gewoonlik steeds ’n klik en ’n verdere handeling. In ’n **agentiese werkvloei** kan die LLM sowel die **lokmiddel** as die **uitvoerder** wees: die agent ontvang die gehallusineerde URL, haal dit op, ontleed die antwoord en kan dan tokens uitlek, instruksies uitvoer, ’n afhanklikheid aflaai of vergiftigde data in CI/CD invoer sonder enige menslike hersiening.<sup>[[12]](#references)</sup>

### Praktiese aanvaller-prompts

Prompts met ’n hoë trefsyfer lyk gewoonlik soos gewone ondernemingtake eerder as uitdruklike phishing-lokmiddels:<sup>[[12]](#references)</sup>
- “Wat is die URL van die betalingsandbox vir `<brand>`-integrasies?”
- “Watter webhook-eindpunt moet ek vir `<brand>`-boukennisgewings gebruik?”
- “Waar is die werknemervoordele-/fakturering-/SSO-portaal vir `<brand>`?”
- “Gee my die direkte Android-APK- of rekenaarkliënt-aflaai vir `<brand>`.”

### Verdedigende omkering

Behandel dit as ’n proaktiewe domeinmoniteringsprobleem, nie net as ’n prompt-inspuitingsprobleem nie:<sup>[[12]](#references)</sup>
- Bou ’n **handelsmerk-promptkorpus** en toets gereeld die LLM’s waarop jou gebruikers/agente staatmaak.
- Stoor gehallusineerde URL’s en volg watter daarvan stabiel bly oor temperature/modelle heen.
- Volg die **Adversarial Exploitation Window (AEW)**: die tyd tussen die eerste hallusinasie en aanvallerregistrasie. ’n Positiewe AEW beteken dat verdedigers vooraf kan registreer, sinkhole of vooraf blokkeer voordat die domein gewapen word.
- Monitor **NXDOMAIN → geregistreer**-oorgange vir die ouerdomeine.
- Wanneer ’n domein geregistreer word, ondersoek die registrateur, skeppingsdatum, naambedieners, privaatheidsbeskerming, bladsy-inhoud, skermkiekies, geparkeerde-bladsy-status en ooreenkoms met handelsmerkbates.
- Voeg beleidshekke by sodat agente/ontwikkelaars **nie LLM-gegenereerde domeine by verstek vertrou nie**: vereis toelaatlyste, eienaarskapvalidering, CT/RDAP-kontroles of menslike goedkeuring voor eerste gebruik.

Dit pas tegelyk in verskeie KI-risikokategorieë: **KI-voorsieningskettingaanval**, **onveilige modeluitvoer** en **skelm optrede** wanneer agente die gehallusineerde URL outonoom gebruik.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP Top 10-kwesbaarhede in masjienleer](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risiko’s](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS-bedreigingsmatriks](https://atlas.mitre.org/)
- [4] [Unit 42 – Die risiko’s van kodeassistent-LLM’s: skadelike inhoud, misbruik en misleiding](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Gesteelde wolkgeloofsbriewe gebruik in ’n nuwe KI-aanval](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Oorsig van die LLMJacking-skema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (herverkoop van gesteelde LLM-toegang)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Diepgaande ondersoek na die ontplooiing van ’n plaaslike LLM-bediener met lae voorregte](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp-bediener-README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI)-spesifikasie](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: KI-gehallusineerde domeine as ’n sagteware-voorsieningskettingvektor](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Hoe KI-hallusinasies ’n nuwe soort voorsieningskettingaanvalle aanwakker](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: Die nuwe KI-geaktiveerde bevel-en-beheerraamwerk](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
