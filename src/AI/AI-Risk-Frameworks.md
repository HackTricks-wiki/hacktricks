# KI-risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP het die top 10 kwesbaarhede in machine learning geïdentifiseer wat AI-stelsels kan raak. Hierdie kwesbaarhede kan tot verskeie sekuriteitskwessies lei, insluitend data poisoning, model inversion en adversarial attacks. Dit is noodsaaklik om hierdie kwesbaarhede te verstaan wanneer veilige AI-stelsels gebou word.

Vir 'n bygewerkte en gedetailleerde lys van die top 10 kwesbaarhede in machine learning, verwys na die projek [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels onsigbare veranderinge aan **inkomende data** toe sodat die model die verkeerde besluit neem.\
    *Voorbeeld*: 'n Paar verfspatsels op 'n stopteken flous 'n selfbesturende motor om 'n spoedbeperkingsteken te "sien".

- **Data Poisoning Attack**: Die **trainingsdatastel** word doelbewus met slegte voorbeelde besoedel, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware-binaries word in 'n antivirus-trainingskorpus verkeerdelik as "benign" gemerk, sodat soortgelyke malware later ongemerk deurkom.

- **Model Inversion Attack**: Deur uitsette te ondersoek, bou 'n aanvaller 'n **omgekeerde model** wat sensitiewe kenmerke van die oorspronklike insette rekonstrueer.\
*Voorbeeld*: 'n Pasiënt se MRI-beeld herskep op grond van 'n kankerdeteksiemodel se voorspellings.

- **Membership Inference Attack**: Die teenstander toets of 'n **spesifieke rekord** tydens training gebruik is deur verskille in sekerheid raak te sien.\
*Voorbeeld*: Bevestig dat 'n persoon se banktransaksie in 'n bedrogopsporingsmodel se trainingsdata voorkom.

- **Model Theft**: Deur herhaaldelik navrae te stuur, kan 'n aanvaller die besluitnemingsgrense leer en die **model se gedrag kloon** (en sy IP).\
*Voorbeeld*: Genoeg vrae-en-antwoorde-pare van 'n ML-as-a-Service-API versamel om 'n byna ekwivalente plaaslike model te bou.

- **AI Supply‑Chain Attack**: Kompromitteer enige komponent (data, biblioteke, voorafopgeleide gewigte, CI/CD) in die **ML-pyplyn** om afgeleide modelle te korrupteer.\
*Voorbeeld*: 'n Vergiftigde afhanklikheid op 'n modelhub installeer 'n model vir sentimentanalise met 'n backdoor in baie apps.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **voorafopgeleide model** geplant en bly behoue wanneer dit vir die slagoffer se taak fyn ingestel word.\
*Voorbeeld*: 'n Visie-backbone met 'n versteekte sneller verander steeds etikette nadat dit vir mediese beeldvorming aangepas is.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerd geëtiketteerde data **verskuif die model se uitsette** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: "Skoon" strooipos-e-posse wat as gewone e-posse gemerk is, word ingevoeg sodat 'n strooiposfilter soortgelyke toekomstige e-posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander modelvoorspellings onderweg**, nie die model self nie, en flous so afgeleide stelsels.\
*Voorbeeld*: 'n Malware-klassifiseerder se uitspraak "malicious" word na "benign" verander voordat die lêerkwarantynstadium dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **modelparameters** self, dikwels nadat skryftoegang verkry is, om gedrag te verander.\
*Voorbeeld*: Gewigte in 'n bedrogopsporingsmodel in produksie word aangepas sodat transaksies vanaf sekere kaarte altyd goedgekeur word.


## Google SAIF-risiko's

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beskryf verskeie risiko's wat met AI-stelsels verband hou:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Kwaadwillige rolspelers verander of voeg trainings-/instellingsdata in om akkuraatheid te verlaag, backdoors in te plant of resultate te skeeftrek, wat die model se integriteit deur die hele datalewensiklus ondermyn.

- **Unauthorized Training Data**: Die inname van kopieregbeskermde, sensitiewe of ongemagtigde datastelle skep regs-, etiese en prestasierisiko's omdat die model leer uit data wat dit nie mag gebruik nie.

- **Model Source Tampering**: Manipulasie deur die voorsieningsketting of 'n insider van modelkode, afhanklikhede of gewigte voor of tydens training kan versteekte logika inbou wat selfs ná hertraining bly voortbestaan.

- **Excessive Data Handling**: Swak beheer oor databehoud en -bestuur lei daartoe dat stelsels meer persoonlike data as nodig stoor of verwerk, wat blootstelling en nakomingsrisiko verhoog.

- **Model Exfiltration**: Aanvallers steel modelläers/gewigte, wat tot verlies van intellektuele eiendom lei en nagemaakte dienste of daaropvolgende aanvalle moontlik maak.

- **Model Deployment Tampering**: Teenstanders verander modelartefakte of die bedieningsinfrastruktuur sodat die model wat loop van die goedgekeurde weergawe verskil, en moontlik anders optree.

- **Denial of ML Service**: API's word oorval of "sponge"-insette word gestuur om rekenaarhulpbronne/energie uit te put en die model vanlyn te haal, soortgelyk aan klassieke DoS-aanvalle.

- **Model Reverse Engineering**: Deur groot hoeveelhede inset-uitset-pare te versamel, kan aanvallers die model kloon of distilleer, wat nabootsingsprodukte en pasgemaakte adversarial attacks moontlik maak.

- **Insecure Integrated Component**: Kwesbare plugins, agents of stroomopdienste laat aanvallers kode invoeg of voorregte binne die AI-pyplyn verhoog.

- **Prompt Injection**: Prompts word (direk of indirek) só geskep dat instruksies ingesmokkel word wat die stelsel se bedoeling ignoreer, sodat die model onbedoelde opdragte uitvoer.

- **Model Evasion**: Noukeurig ontwerpte insette laat die model verkeerd klassifiseer, hallusineer of inhoud lewer wat nie toegelaat word nie, wat veiligheid en vertroue ondermyn.

- **Sensitive Data Disclosure**: Die model openbaar private of vertroulike inligting uit sy trainingsdata of gebruikerskonteks, wat privaatheid en regulasies skend.

- **Inferred Sensitive Data**: Die model lei persoonlike eienskappe af wat nooit verskaf is nie, en veroorsaak nuwe privaatheidskade deur afleiding.

- **Insecure Model Output**: Ongefiltreerde antwoorde stuur skadelike kode, waninligting of onvanpaste inhoud aan gebruikers of afgeleide stelsels.

- **Rogue Actions**: Outonoom geïntegreerde agents voer onbedoelde handelinge in die werklike wêreld uit (lêers skryf, API-oproepe maak, aankope doen, ens.) sonder voldoende toesig deur die gebruiker.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende raamwerk om risiko's wat met AI-stelsels verband hou, te verstaan en te versag. Dit kategoriseer verskeie aanvalstegnieke en -taktieke wat teenstanders teen AI-modelle kan gebruik, asook maniere waarop AI-stelsels gebruik kan word om verskillende aanvalle uit te voer.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Aanvallers steel aktiewe sessietokens of cloud API-bewyse en gebruik betaalde, cloud-gehoste LLM's sonder magtiging. Toegang word dikwels herverkoop deur middel van reverse proxies wat die slagoffer se rekening as tussenganger gebruik, byvoorbeeld "oai-reverse-proxy"-ontplooiings. Gevolge sluit finansiële verlies, modelmisbruik buite die beleid en toeskrywing aan die slagoffer se tenant in.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP's:
- Versamel tokens van besmette ontwikkelaarmasjiene of blaaiers; steel CI/CD-geheime; koop gelekte koekies.<sup>[[5]](#references)</sup>
- Stel 'n reverse proxy op wat versoeke na die egte verskaffer aanstuur, die stroomop-sleutel verberg en baie kliënte bedien.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Misbruik direkte base-model-eindpunte om ondernemingsbeveiligingsmaatreëls en koerslimiete te omseil.<sup>[[4]](#references)</sup>

Versagtingsmaatreëls:
- Bind tokens aan toestelvingerafdrukke, IP-reekse en kliënt-attestering; dwing kort vervaltye af en verfris met MFA.
- Beperk sleutels tot die minimum nodige omvang (geen toegang tot tools nie; leesalleen waar toepaslik); roteer dit wanneer afwykings voorkom.
- Lei alle verkeer aan die bedienerkant deur 'n beleidsgateway wat veiligheidsfilters, kwotas per roete en tenant-isolasie afdwing.
- Monitor ongewone gebruikspatrone (skielike bestedingspieke, atipiese streke, UA-teksstringe) en herroep verdagte sessies outomaties.
- Verkies mTLS of ondertekende JWT's wat deur jou IdP uitgereik word bo statiese API-sleutels met lang geldigheid.

## Verharding van self-gehoste LLM-inferensie

Om 'n plaaslike LLM-bediener vir vertroulike data te laat loop, skep 'n ander aanvaloppervlak as cloud-gehoste API's: inferensie-/debug-eindpunte kan prompts uitlek, die bedieningslaag stel gewoonlik 'n reverse proxy bloot, en GPU-toestelnodes bied toegang tot groot `ioctl()`-aanvalsoppervlaktes. As jy 'n plaaslike inferensiediens evalueer of ontplooi, hersien ten minste die volgende punte.<sup>[[8]](#references)</sup>

### Prompt-lekkasie via debug- en moniteringseindpunte

Hanteer die inferensie-API as 'n **sensitiewe diens vir veelvuldige gebruikers**. Debug- of moniteringsroetes kan prompt-inhoud, slottoestand, modelmetadata of interne tou-inligting blootlê. In `llama.cpp` is die `/slots`-eindpunt besonder sensitief omdat dit die toestand van elke slot blootlê en slegs bedoel is vir slotinspeksie/-bestuur.<sup>[[8]](#references)</sup>

Vir black-box-vingerafdrukke en toetsing van blootgestelde modelrunners en verwante AI-dienste, kyk na [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Plaas 'n reverse proxy voor die inferensiebediener en **weier by verstek**.
- Laat slegs die presiese kombinasies van HTTP-metode + pad toe wat die kliënt/UI nodig het.
- Deaktiveer introspeksie-eindpunte in die backend self waar moontlik, byvoorbeeld `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Bind die reverse proxy aan `127.0.0.1` en stel dit bloot deur 'n geverifieerde vervoermeganisme, soos SSH-plaaslike poortaanstuur, eerder as om dit op die LAN te publiseer.

Voorbeeld van 'n toelaatlys met nginx:

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

### Rootless-houers sonder netwerk en UNIX-sokke

As die inference-daemon ondersteuning bied vir luister op ’n UNIX-sok, verkies dit bo TCP en laat die houer sonder ’n netwerkstapel loop:<sup>[[8]](#references)</sup>

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
- ’n UNIX-sokkel laat jou toe om POSIX-toestemmings/ACL’s op die sokkelpad as die eerste toegangsbeheerlaag te gebruik.
- `--userns=keep-id` en rootless Podman verminder die impak van ’n container breakout omdat container root nie host root is nie.
- Read-only-modelmonterings verminder die kans op peuterwerk aan die model van binne die container.

Vir aanhoudende ontplooiings kan dieselfde beperkings as Podman Quadlet-eenhede uitgedruk word. As GPU-toegang deur die Container Device Interface gedelegeer word, hou die CDI-toestelspesifikasie so beperk moontlik eerder as om elke versneller-node bloot te stel.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimalisering van GPU-toestelnodes

Vir GPU-ondersteunde inference is `/dev/nvidia*`-lêers waardevolle plaaslike attack surfaces omdat hulle groot driver-`ioctl()`-hanteerders en moontlik gedeelde GPU-geheuebestuurspaaie blootstel.<sup>[[8]](#references)</sup>

- Moenie `/dev/nvidia*` wêreldskryfbaar laat nie.
- Beperk `nvidia`, `nvidiactl` en `nvidia-uvm` met `NVreg_DeviceFileUID/GID/Mode`, udev-reëls en ACL’s sodat net die gemapte container-UID hulle kan oopmaak.
- Swartlys onnodige modules soos `nvidia_drm`, `nvidia_modeset` en `nvidia_peermem` op koplose inference-gashere.
- Laai slegs die nodige modules vooraf tydens selflaai, eerder as om die runtime hulle tydens inference-opstart opportunisties met `modprobe` te laat laai.

Voorbeeld:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Een belangrike hersieningspunt is **`/dev/nvidia-uvm`**. Selfs al gebruik die workload nie uitdruklik `cudaMallocManaged()` nie, kan onlangse CUDA-runtimes steeds `nvidia-uvm` vereis. Omdat hierdie toestel gedeel word en GPU-virtuele geheuebestuur hanteer, moet dit as ’n oppervlak vir datablootstelling tussen tenants behandel word. As die inference-backend dit ondersteun, kan ’n Vulkan-backend ’n interessante kompromie wees omdat dit moontlik blootstelling van `nvidia-uvm` aan die container heeltemal vermy.<sup>[[8]](#references)</sup>

### LSM-inperking vir inference-werkers

AppArmor/SELinux/seccomp moet as verdediging in diepte rondom die inference-proses gebruik word:<sup>[[8]](#references)</sup>

- Laat slegs die gedeelde biblioteke, modelpaaie, socket-gids en GPU-toestelnodusse toe wat werklik nodig is.
- Verbied uitdruklik hoërisiko-vermoëns soos `sys_admin`, `sys_module`, `sys_rawio` en `sys_ptrace`.
- Hou die modelgids leesalleen en beperk skryfbare paaie tot slegs die runtime-socket-/kasgidse.
- Monitor ontkenningslogboeke omdat hulle nuttige opsporingstelemetrie verskaf wanneer die modelbediener of ’n post-exploitation-payload probeer ontsnap aan die verwagte gedrag.

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

## Phantom Squatting: LLM-gehallusineerde domeine as ’n AI-voorsieningskettingvektor

Phantom squatting is die **domein/URL-ekwivalent van slopsquatting**. In plaas daarvan om ’n nie-bestaande pakketnaam te hallusineer, hallusineer die LLM ’n geloofwaardige **portaal-, API-, webhook-, fakturering-, SSO-, aflaai- of ondersteuningsdomein** vir ’n werklike handelsmerk, en ’n aanvaller registreer daardie naamruimte voordat ’n mens of agent dit gebruik.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Dit is belangrik omdat die modeluitset in baie AI-ondersteunde werkvloeie as ’n **vertroude afhanklikheid** behandel word:
- Ontwikkelaars plak die voorgestelde endpoint in kode of CI/CD-integrasies.
- AI-agente haal dokumentasie, skemas, APK’s, ZIP-lêers of webhook-teikens outomaties op.
- Gegenereerde runbooks of dokumente kan die vals URL insluit asof dit gesaghebbend is.

### Aanvalsproses

1. **Ondersoek die hallusinasie-oppervlak**: vra handelsmerkspesifieke vrae oor realistiese werkvloeie soos `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` of `mobile app`-portale.<sup>[[12]](#references)</sup>
2. **Normaliseer kandidate**: los gegenereerde URL’s op, herlei NXDOMAIN-antwoorde na die ouerdomein wat registreerbaar is, en verwyder duplikate uit promptfamilies. Promptkorpusse behoort uiteenlopend te bly, byvoorbeeld deur byna-duplikate met **Jaccard-ooreenkoms** te verwyder.
3. **Prioritiseer voorspelbare hallusinasies**:
   - **Thermal Hallucination Persistence (THP)**: dieselfde vals domein verskyn oor verskillende temperature heen, insluitend ’n lae temperatuur soos `T=0.1`.
   - **Konsensus tussen modelle**: verskeie LLM-families genereer dieselfde vals domein.
4. **Registreer en gebruik die ouerdomein vir aanvalle**, en huisves dan phishing, vals APK/ZIP-aflaaie, aanmeldingsdataversamelaars, kwaadwillige dokumente of API-endpoints wat geheime/webhook-lassies versamel. **Suiwer domeinvlak-hallusinasies** is die maklikste om te monetiseer omdat die aanvaller die hele naamruimte beheer; subdomein-/pad-hallusinasies kan steeds misbruik word wanneer die genormaliseerde ouerdomein nie geregistreer is nie.
5. **Buit die nulreputasie-venster uit**: nuutgeregistreerde domeine het dikwels geen bloklysrekord, URL-reputasie of volwasse telemetrie nie, en kan dus beheermaatreëls omseil totdat opsporing op datum is. Aanvallers kan hierdie venster verleng met onskadelike antwoorde wat slegs vir crawlers sigbaar is, herleidingsverberging, CAPTCHA-hekkies of vertraagde loonvragontplooiing.

### Waarom dit gevaarlik is vir agente

Vir ’n menslike slagoffer vereis die vals domein gewoonlik steeds ’n klik en nog ’n handeling. In ’n **agentiese werkvloei** kan die LLM sowel die **lokmiddel** as die **uitvoerder** wees: die agent ontvang die gehallusineerde URL, haal dit op, ontleed die antwoord en kan dan tokens leak, instruksies uitvoer, ’n afhanklikheid aflaai of vergiftigde data in CI/CD stoot sonder enige menslike hersiening.<sup>[[12]](#references)</sup>

### Praktiese aanvallerprompts

Prompts met ’n hoë opbrengs lyk gewoonlik soos normale ondernemingstake, eerder as eksplisiete phishing-lokmiddels:<sup>[[12]](#references)</sup>
- “Wat is die URL vir die betalingsandbox vir `<brand>`-integrasies?”
- “Watter webhook-endpoint moet ek vir `<brand>`-boukennisgewings gebruik?”
- “Waar is die werknemersvoordele-/fakturering-/SSO-portaal vir `<brand>`?”
- “Gee vir my die direkte Android-APK- of rekenaarkliëntaflaai vir `<brand>`.”

### Verdedigende omkering

Behandel dit as ’n proaktiewe domeinmoniteringsprobleem, nie net as ’n prompt-inspuitingsprobleem nie:<sup>[[12]](#references)</sup>
- Stel ’n **handelsmerkpromptkorpus** saam en toets gereeld die LLM’s waarop jou gebruikers/agente staatmaak.
- Stoor gehallusineerde URL’s en hou dop watter daarvan stabiel bly oor verskillende temperature/modelle heen.
- Volg die **Adversarial Exploitation Window (AEW)**: die tyd tussen die eerste hallusinasie en aanvallerregistrasie. ’n Positiewe AEW beteken verdedigers kan vooraf registreer, sinkhole of blokkeer voordat die domein vir aanvalle gebruik word.
- Monitor **NXDOMAIN → geregistreer**-oorgange vir die ouerdomeine.
- Ondersoek registrateur, skeppingsdatum, naambedieners, privaatheidsbeskerming, bladsyinhoud, skermkiekies, geparkeerde-bladsystatus en ooreenkomste met handelsmerkbates wanneer ’n domein geregistreer word.
- Voeg beleidshekke by sodat agente/ontwikkelaars **nie LLM-gegenereerde domeine by verstek vertrou nie**: vereis toelaatlyste, eienaarskapvalidering, CT/RDAP-kontroles of menslike goedkeuring voor eerste gebruik.

Dit val tegelyk in verskeie AI-risikokategorieë: **AI-voorsieningskettingaanval**, **onveilige modeluitset** en **onbeheerde optrede** wanneer agente die gehallusineerde URL outonoom gebruik.

## References

- [1] [OWASP Top 10-kwesbaarhede in masjienleer](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risiko’s](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS-bedreigingsmatriks](https://atlas.mitre.org/)
- [4] [Unit 42 – Die risiko’s van kodeassistent-LLM’s: skadelike inhoud, misbruik en misleiding](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Gesteelde wolkgeloofsbriewe gebruik in ’n nuwe AI-aanval](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Oorsig van die LLMJacking-skema – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (herverkoop van gesteelde LLM-toegang)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Diepgaande ondersoek na die ontplooiing van ’n LLM-bediener op die perseel met lae voorregte](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp-bediener-README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI)-spesifikasie](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-gehallusineerde webdomeine as ’n sagteware-voorsieningskettingvektor](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Hoe AI-hallusinasies ’n nuwe klas voorsieningskettingaanvalle aanwakker](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
