# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp imetambua udhaifu 10 mkuu wa machine learning unaoweza kuathiri mifumo ya AI. Udhaifu huu unaweza kusababisha masuala mbalimbali ya usalama, yakiwemo data poisoning, model inversion na mashambulizi ya adversarial. Kuelewa udhaifu huu ni muhimu katika kujenga mifumo salama ya AI.

Kwa orodha iliyosasishwa na ya kina ya udhaifu 10 mkuu wa machine learning, rejelea mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Mshambuliaji huongeza mabadiliko madogo, mara nyingi yasiyoonekana, kwenye **data inayoingia** ili model ifanye uamuzi usio sahihi.\
    *Mfano*: Madoa machache ya rangi kwenye alama ya stop hudanganya gari linalojiendesha na kulifanya "kuona" alama ya kikomo cha mwendo.

- **Data Poisoning Attack**: **Training set** huchafuliwa kimakusudi kwa sampuli mbovu, na kuifundisha model kanuni zenye madhara.\
*Mfano*: Faili za binary za malware huwekewa lebo isiyo sahihi ya "benign" kwenye mkusanyiko wa data wa mafunzo ya antivirus, na kuruhusu malware zinazofanana kupenya baadaye.

- **Model Inversion Attack**: Kwa kuchunguza matokeo, mshambuliaji huunda **model ya kinyume** inayojenga upya vipengele nyeti vya ingizo asilia.\
*Mfano*: Kuunda upya picha ya MRI ya mgonjwa kutokana na utabiri wa model ya kugundua saratani.

- **Membership Inference Attack**: Mshambuliaji hujaribu kubaini kama **rekodi mahususi** ilitumika wakati wa mafunzo kwa kutambua tofauti za kiwango cha uhakika.\
*Mfano*: Kuthibitisha kuwa muamala wa benki wa mtu fulani umo kwenye data ya mafunzo ya model ya kugundua ulaghai.

- **Model Theft**: Kuuliza maswali mara kwa mara humwezesha mshambuliaji kujifunza mipaka ya maamuzi na **kunakili tabia ya model** (na IP).\
*Mfano*: Kukusanya jozi za kutosha za maswali na majibu kutoka kwa API ya ML-as-a-Service ili kujenga model ya ndani inayokaribia kufanana.

- **AI Supply‑Chain Attack**: Kuhatarisha kipengele chochote (data, maktaba, uzani uliofunzwa awali, CI/CD) kwenye **ML pipeline** ili kuharibu model za baadaye.\
*Mfano*: Dependency yenye sumu kwenye model-hub husakinisha model ya uchanganuzi wa hisia iliyo na backdoor kwenye programu nyingi.

- **Transfer Learning Attack**: Mantiki hasidi hupandikizwa kwenye **model iliyofunzwa awali** na hubaki baada ya fine-tuning kwa kazi ya mwathiriwa.\
*Mfano*: Model ya vision yenye kichochezi kilichofichwa bado hubadilisha lebo baada ya kurekebishwa kwa picha za kimatibabu.

- **Model Skewing**: Data yenye upendeleo au lebo zisizo sahihi hubadilisha **matokeo ya model** kwa ujanja ili kuunga mkono ajenda ya mshambuliaji.\
*Mfano*: Kuingiza barua pepe za spam "safi" zilizopewa lebo ya ham ili kichujio cha spam kiruhusu barua pepe zinazofanana zipite baadaye.

- **Output Integrity Attack**: Mshambuliaji **hubadilisha utabiri wa model wakati wa usafirishaji**, si model yenyewe, na kuidanganya mifumo inayotegemea matokeo hayo.\
*Mfano*: Kubadilisha uamuzi wa classifier ya malware kutoka "malicious" kuwa "benign" kabla hatua ya kuweka faili karantini haijaiona.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja na lengwa kwenye **vigezo vya model** yenyewe, mara nyingi baada ya kupata ruhusa ya kuandika, ili kubadilisha tabia yake.\
*Mfano*: Kurekebisha uzani kwenye model ya kugundua ulaghai inayotumika kwenye production ili miamala kutoka kwa kadi fulani iidhinishwe kila mara.


## Google SAIF Risks

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) ya Google inaeleza hatari mbalimbali zinazohusiana na mifumo ya AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Wahusika hasidi hubadilisha au kuingiza data ya mafunzo/tuning ili kupunguza usahihi, kupandikiza backdoor au kupotosha matokeo, na kudhoofisha uadilifu wa model katika mzunguko mzima wa maisha ya data.

- **Unauthorized Training Data**: Kutumia seti za data zilizo na hakimiliki, nyeti au zisizoruhusiwa huleta madeni ya kisheria, kimaadili na kiutendaji kwa sababu model hujifunza kutokana na data ambayo haikuruhusiwa kutumia.

- **Model Source Tampering**: Udanganyifu wa supply-chain au wa mtu wa ndani kwenye code, dependencies au uzani wa model kabla au wakati wa mafunzo unaweza kupachika mantiki iliyofichwa ambayo hubaki hata baada ya mafunzo kufanywa upya.

- **Excessive Data Handling**: Udhibiti dhaifu wa uhifadhi na usimamizi wa data husababisha mifumo kuhifadhi au kuchakata data binafsi zaidi ya inavyohitajika, na kuongeza hatari za kufichuliwa na kutofuata kanuni.

- **Model Exfiltration**: Washambuliaji huiba faili/uzani wa model, na kusababisha upotevu wa mali miliki na kuwezesha huduma za kuiga au mashambulizi yanayofuata.

- **Model Deployment Tampering**: Wapinzani hubadilisha artefact za model au miundombinu ya kuiendesha, ili model inayotumika itofautiane na toleo lililokaguliwa na huenda ikawa na tabia iliyobadilika.

- **Denial of ML Service**: Kujaza API maombi au kutuma ingizo za “sponge” kunaweza kumaliza uwezo wa kompyuta/nishati na kuifanya model isimame, sawa na mashambulizi ya kawaida ya DoS.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya jozi za ingizo na matokeo, washambuliaji wanaweza kunakili au kudistilisha model, na kuwezesha bidhaa za kuiga na mashambulizi ya adversarial yaliyobinafsishwa.

- **Insecure Integrated Component**: Plugins, agents au huduma za juu zilizo hatarini huwawezesha washambuliaji kuingiza code au kuongeza ruhusa ndani ya AI pipeline.

- **Prompt Injection**: Kutengeneza prompts (moja kwa moja au kwa njia isiyo ya moja kwa moja) ili kuficha maagizo yanayobatilisha nia ya mfumo na kuufanya model itekeleze amri zisizokusudiwa.

- **Model Evasion**: Ingizo zilizoundwa kwa uangalifu huifanya model kuainisha vibaya, kubuni taarifa au kutoa maudhui yasiyoruhusiwa, na kudhoofisha usalama na uaminifu.

- **Sensitive Data Disclosure**: Model hufichua taarifa za faragha au za siri kutoka kwenye data yake ya mafunzo au muktadha wa mtumiaji, na kukiuka faragha na kanuni.

- **Inferred Sensitive Data**: Model hukisia sifa binafsi ambazo hazikutolewa kamwe, na kusababisha madhara mapya ya faragha kupitia ukisiaji.

- **Insecure Model Output**: Majibu yasiyosafishwa hupitisha code hatari, taarifa potofu au maudhui yasiyofaa kwa watumiaji au mifumo inayofuata.

- **Rogue Actions**: Agents zilizounganishwa kwa uhuru hutekeleza shughuli zisizokusudiwa katika ulimwengu halisi (kuandika faili, kupiga API, kufanya manunuzi, n.k.) bila usimamizi wa kutosha wa mtumiaji.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) hutoa mfumo wa kina wa kuelewa na kupunguza hatari zinazohusiana na mifumo ya AI. Huainisha mbinu za mashambulizi na mbinu za kimkakati ambazo wapinzani wanaweza kutumia dhidi ya model za AI, na pia jinsi ya kutumia mifumo ya AI kutekeleza mashambulizi mbalimbali.<sup>[[3]](#references)</sup>

## LLMJacking (Wizi wa Token na Uuzaji Tena wa Ufikiaji wa LLM Zinazohostiwa kwenye Cloud)

Washambuliaji huiba token za session zinazotumika au credentials za cloud API na kutumia LLM zinazolipiwa na kuhostiwa kwenye cloud bila idhini. Mara nyingi ufikiaji huo huuzwa tena kupitia reverse proxy zinazotumia akaunti ya mwathiriwa, k.m. deployments za "oai-reverse-proxy". Madhara yake ni pamoja na hasara ya kifedha, matumizi ya model yanayokiuka sera na kuhusishwa kwa matumizi hayo na tenant wa mwathiriwa.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Kukusanya token kutoka kwenye mashine au browser za developer zilizoambukizwa; kuiba secrets za CI/CD; kununua cookies zilizovuja.<sup>[[5]](#references)</sup>
- Kuanzisha reverse proxy inayotuma maombi kwa mtoa huduma halisi, kuficha key ya upande wa juu na kuruhusu wateja wengi kuitumia.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Kutumia vibaya endpoints za moja kwa moja za base-model ili kukwepa guardrails za biashara na vikomo vya kiwango cha maombi.<sup>[[4]](#references)</sup>

**Matumizi tena ya API-key ndani ya host:** Baada ya host kuathiriwa, implant inaweza kutuma maombi ya model API moja kwa moja kutoka kwenye host ya mwathiriwa na kurudisha majibu kupitia C2, bila kuhamisha API key ya cloud au kuanzisha AI CLI ya ndani. Katika handler iliyochunguzwa, key iliyotolewa na C2 hutumika kwanza; ikiwa haipo, implant husoma `OPENAI_API_KEY` kutoka kwenye mazingira ya mchakato wake. Kwa hiyo, kutumia akaunti ya mwathiriwa kunahitaji key halali inayoonekana kwa mchakato huo na ufikiaji wa model API. Prompt ya operator hutumwa kwa Chat Completions API, huku matokeo ya model na matumizi ya token vikirejeshwa kupitia C2. Hii inaweza kutumia ufikiaji wa model unaolipiwa na mwathiriwa bila kuendesha AI tools za developer, tofauti na matumizi mabaya ya [local AI CLI or MCP configuration](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Hatua za kupunguza hatari:
- Funga token kwenye alama ya kipekee ya kifaa, safu za IP na uthibitishaji wa client; tumia muda mfupi wa kuisha na uhitaji MFA wakati wa kufanya refresh.
- Punguza ruhusa za key kadri iwezekanavyo (bila ufikiaji wa tool, read-only inapofaa); zibadilishe kukitokea hali isiyo ya kawaida.
- Elekeza trafiki yote kupitia upande wa server na kuiweka nyuma ya policy gateway inayotekeleza vichujio vya usalama, vikomo vya kila route na utenganishaji wa tenant.
- Fuatilia mifumo isiyo ya kawaida ya matumizi (ongezeko la ghafla la matumizi ya fedha, maeneo yasiyo ya kawaida, mifuatano ya UA) na ubatilishe kiotomatiki sessions zinazotiliwa shaka.
- Pendelea mTLS au JWT zilizotiwa saini na kutolewa na IdP yako badala ya API key tuli zinazodumu muda mrefu.

## Kuimarisha uendeshaji wa inference ya LLM inayohostiwa binafsi

Kuendesha server ya LLM ya ndani kwa data ya siri huleta sehemu tofauti za kushambulia kuliko API zinazohostiwa kwenye cloud: endpoints za inference/debug zinaweza kufichua prompts, stack ya uendeshaji kwa kawaida hufichua reverse proxy, na GPU device nodes hutoa ufikiaji wa sehemu kubwa za `ioctl()`. Ikiwa unakagua au kupeleka huduma ya inference ya ndani ya shirika, pitia angalau mambo yafuatayo.<sup>[[8]](#references)</sup>

### Kuvuja kwa prompt kupitia endpoints za debug na ufuatiliaji

Chukulia API ya inference kama **huduma nyeti ya watumiaji wengi**. Routes za debug au ufuatiliaji zinaweza kufichua maudhui ya prompt, hali ya slot, metadata ya model au taarifa za foleni za ndani. Katika `llama.cpp`, endpoint ya `/slots` ni nyeti hasa kwa sababu hufichua hali ya kila slot na imekusudiwa tu kwa ukaguzi/usimamizi wa slot.<sup>[[8]](#references)</sup>

Kwa fingerprinting na majaribio ya black-box ya model runner zilizo wazi na huduma zinazohusiana za AI, angalia [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Weka reverse proxy mbele ya inference server na **kataza kwa chaguomsingi**.
- Ruhusu tu mchanganyiko mahususi wa HTTP method + path unaohitajika na client/UI.
- Zima endpoints za introspection kwenye backend yenyewe inapowezekana, kwa mfano `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Funga reverse proxy kwenye `127.0.0.1` na uifikie kupitia usafirishaji uliothibitishwa kama SSH local port forwarding badala ya kuichapisha kwenye LAN.

Mfano wa allowlist kwa nginx:

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

### Rootless containers zisizo na mtandao na UNIX sockets

Ikiwa inference daemon inaweza kusikiliza kwenye UNIX socket, pendelea njia hiyo badala ya TCP na endesha container bila **network stack**:<sup>[[8]](#references)</sup>

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

Faida:
- `--network none` huondoa uwezekano wa kuwasiliana kupitia TCP/IP ndani/nje na huepusha kutumia wasaidizi wa user-mode ambao containers za rootless zingehitaji vinginevyo.
- UNIX socket hukuwezesha kutumia ruhusa/ACL za POSIX kwenye njia ya socket kama safu ya kwanza ya udhibiti wa ufikiaji.
- `--userns=keep-id` na rootless Podman hupunguza athari za container breakout kwa sababu root ndani ya container si root wa host.
- Model mounts za read-only hupunguza uwezekano wa kubadilishwa kwa modeli kutoka ndani ya container.

Kwa deployments zinazoendelea, vizuizi hivyo hivyo vinaweza kuwekwa kama vitengo vya Podman Quadlet. Ikiwa ufikiaji wa GPU umekabidhiwa kupitia Container Device Interface, weka vipimo vya kifaa vya CDI katika kiwango finyu iwezekanavyo badala ya kufichua kila kifaa cha accelerator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Kupunguza device-node za GPU

Kwa inference inayotumia GPU, faili za `/dev/nvidia*` ni attack surface za ndani zenye thamani kubwa kwa sababu zinafichua handlers kubwa za driver za `ioctl()` na huenda njia za usimamizi wa kumbukumbu ya GPU zinazoshirikiwa.<sup>[[8]](#references)</sup>

- Usiziache `/dev/nvidia*` zikiwa na ruhusa ya kuandikiwa na kila mtu.
- Zuia ufikiaji wa `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, sheria za udev, na ACL ili UID ya container iliyomappiwa pekee iweze kuzifungua.
- Zima moduli zisizohitajika kama `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye host za inference zisizo na display.
- Pakia mapema moduli zinazohitajika tu wakati wa boot badala ya kuruhusu runtime kuzitumia `modprobe` bila mpango wakati wa kuanzisha inference.

Mfano:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Jambo moja muhimu la kukagua ni **`/dev/nvidia-uvm`**. Hata kama workload haitumii `cudaMallocManaged()` moja kwa moja, CUDA runtimes za hivi karibuni bado zinaweza kuhitaji `nvidia-uvm`. Kwa kuwa kifaa hiki kinashirikiwa na hushughulikia usimamizi wa GPU virtual memory, kichukulie kama eneo linaloweza kusababisha data kufichuka kati ya tenants. Ikiwa inference backend inaiunga mkono, Vulkan backend inaweza kuwa chaguo lenye manufaa kwa sababu huenda ikaepusha kabisa kuipa container ufikiaji wa `nvidia-uvm`.<sup>[[8]](#references)</sup>

### Kuweka mipaka ya LSM kwa inference workers

AppArmor/SELinux/seccomp zinapaswa kutumiwa kama safu za ziada za ulinzi kuzunguka inference process:<sup>[[8]](#references)</sup>

- Ruhusu tu shared libraries, model paths, socket directory na GPU device nodes zinazohitajika.
- Kataza wazi capabilities zilizo hatarishi sana, kama vile `sys_admin`, `sys_module`, `sys_rawio` na `sys_ptrace`.
- Fanya model directory isomeke tu na uweke paths zinazoweza kuandikwa kwenye runtime socket/cache directories pekee.
- Fuatilia denial logs kwa sababu hutoa telemetry muhimu ya kutambua wakati model server au post-exploitation payload inapojaribu kutoka kwenye tabia inayotarajiwa.

Mfano wa AppArmor rules kwa worker inayotumia GPU:

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

## Phantom Squatting: Domains Zilizobuniwa na LLM kama Vector ya AI Supply-Chain

Phantom squatting ni **sawa na slopsquatting, lakini kwa domain/URL**. Badala ya kubuni jina la package lisilokuwepo, LLM hubuni **domain ya portal, API, webhook, billing, SSO, download au support** inayoonekana kuwa halisi kwa brand iliyopo, kisha mshambuliaji husajili namespace hiyo kabla ya binadamu au agent kuitumia.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Hili ni muhimu kwa sababu katika workflows nyingi zinazosaidiwa na AI, matokeo ya model huchukuliwa kuwa **dependency inayoaminika**:
- Developers hubandika endpoint iliyopendekezwa kwenye code au integrations za CI/CD.
- AI agents hupakua documentation, schemas, APKs, ZIPs au targets za webhook kiotomatiki.
- Runbooks au docs zilizozalishwa zinaweza kuwa na URL bandia kana kwamba ni ya mamlaka.

### Workflow ya ushambuliaji

1. **Chunguza sehemu zinazoweza kutoa hallucinations**: uliza maswali yanayohusu brand mahususi kuhusu workflows halisi kama portals za `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook`, au `mobile app`.<sup>[[12]](#references)</sup>
2. **Sanifisha candidates**: resolve URL zilizozalishwa, punguza majibu ya NXDOMAIN hadi parent domain inayoweza kusajiliwa, na ondoa prompt families zilizojirudia. Prompt corpora zinapaswa kuwa tofauti, kwa mfano kwa kuondoa zinazokaribiana kwa kutumia **Jaccard similarity**.
3. **Weka kipaumbele kwa hallucinations zinazotabirika**:
   - **Thermal Hallucination Persistence (THP)**: domain ileile bandia hujitokeza katika temperatures tofauti, ikiwemo temperature ya chini kama `T=0.1`.
   - **Makubaliano kati ya models**: familia nyingi za LLM huzalisha domain ileile bandia.
4. **Sajili na weka silaha kwenye** parent domain, kisha host phishing, downloads bandia za APK/ZIP, credential harvesters, docs hasidi, au API endpoints zinazokusanya secrets/webhook payloads. **Hallucinations za kiwango cha domain pekee** ndizo rahisi zaidi kupata faida nazo kwa sababu mshambuliaji hudhibiti namespace nzima; hallucinations za subdomain/path bado zinaweza kutumiwa vibaya wakati parent domain iliyonormalishwa haijasajiliwa.
5. **Tumia fursa ya kipindi cha sifa sifuri**: mara nyingi domains zilizosajiliwa hivi karibuni hazina historia ya blocklist, sifa ya URL, wala telemetry iliyokomaa, hivyo zinaweza kukwepa udhibiti hadi detections zifikie hali ya sasa. Washambuliaji wanaweza kurefusha kipindi hiki kwa majibu yasiyo na madhara yanayoonekana na crawlers pekee, redirect cloaking, CAPTCHA gates, au kuchelewesha uwekaji wa payload.

### Kwa nini ni hatari kwa agents

Kwa mwathirika binadamu, domain bandia bado huhitaji click na hatua nyingine. Kwa **workflow ya agentic**, LLM inaweza kuwa **kishawishi** na **tekelezaji** kwa wakati mmoja: agent hupokea URL iliyobuniwa, huipakua, huchanganua jibu, kisha huenda ikavuja tokens, kutekeleza instructions, kupakua dependency, au kusukuma data yenye sumu kwenye CI/CD bila ukaguzi wowote wa binadamu.<sup>[[12]](#references)</sup>

### Prompts za vitendo za mshambuliaji

Prompts zenye matokeo mazuri kwa kawaida huonekana kama kazi za kawaida za enterprise badala ya vishawishi vya wazi vya phishing:<sup>[[12]](#references)</sup>
- “URL ya payment sandbox ya integrations za `<brand>` ni ipi?”
- “Nitumie webhook endpoint ipi kwa build notifications za `<brand>`?”
- “Portal ya employee benefits / billing / SSO ya `<brand>` iko wapi?”
- “Nipe link ya moja kwa moja ya kupakua Android APK au desktop client ya `<brand>`.”

### Ugeuzaji wa ulinzi

Shughulikia hili kama tatizo la ufuatiliaji wa domains kwa njia ya kuzuia, si tatizo la prompt-injection pekee:<sup>[[12]](#references)</sup>
- Unda **brand prompt corpus** na uchunguze mara kwa mara LLMs ambazo users/agents wako hutegemea.
- Hifadhi URL zilizobuniwa na ufuatilie zile zinazobaki thabiti katika temperatures/models mbalimbali.
- Fuatilia **Adversarial Exploitation Window (AEW)**: muda kati ya hallucination ya kwanza na usajili wa mshambuliaji. AEW chanya humaanisha defenders wanaweza kusajili mapema, kuweka sinkhole, au kuzuia kabla domain haijawekewa silaha.
- Fuatilia mabadiliko ya **NXDOMAIN → registered** kwa parent domains.
- Domain inaposajiliwa, kagua registrar, tarehe ya kuundwa, nameservers, ulinzi wa faragha, maudhui ya ukurasa, screenshots, hali ya ukurasa wa matangazo, na ulinganifu wa brand assets.
- Ongeza policy gates ili agents/developers **wasiamini domains zilizozalishwa na LLM moja kwa moja**: hitaji allowlists, uthibitishaji wa umiliki, ukaguzi wa CT/RDAP, au idhini ya binadamu kabla ya matumizi ya kwanza.

Hili linahusiana na makundi kadhaa ya hatari za AI kwa wakati mmoja: **shambulio la AI supply-chain**, **matokeo ya model yasiyo salama**, na **vitendo vya rogue** wakati agents zinapotumia URL iliyobuniwa kiotomatiki.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP: Udhaifu 10 Bora wa Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Hatari](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Hatari za Code Assistant LLMs: Maudhui Yenye Madhara, Matumizi Mabaya na Udanganyifu](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Credentials za Cloud Zilizoibwa Zatumika katika Shambulio Jipya la AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Muhtasari wa mpango wa LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (kuuza tena ufikiaji wa LLM ulioibwa)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Uchambuzi wa kina wa uwekaji wa LLM server ya on-premise yenye ruhusa ndogo](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README ya llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Maelezo ya CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Domains Zilizobuniwa na AI kama Vector ya Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Jinsi Hallucinations za AI Zinavyochochea Aina Mpya ya Mashambulizi ya Supply Chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: Mfumo mpya wa command-and-control unaotumia AI](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
