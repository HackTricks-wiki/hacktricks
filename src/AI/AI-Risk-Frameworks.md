# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP imetambua vulnerabilities 10 kuu za machine learning zinazoweza kuathiri mifumo ya AI. Vulnerabilities hizi zinaweza kusababisha masuala mbalimbali ya usalama, ikiwemo data poisoning, model inversion na adversarial attacks. Kuzielewa ni muhimu kwa ajili ya kujenga mifumo salama ya AI.

Kwa orodha iliyosasishwa na yenye maelezo ya kina kuhusu vulnerabilities 10 kuu za machine learning, rejelea mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Mshambuliaji huongeza mabadiliko madogo, ambayo mara nyingi hayaonekani, kwenye **data inayoingia** ili model ifanye uamuzi usio sahihi.\
    *Mfano*: Madoa machache ya rangi kwenye alama ya kusimama hudanganya gari linalojiendesha na kulifanya "kuona" alama ya kikomo cha mwendo kasi.

- **Data Poisoning Attack**: **Training set** huchafuliwa kimakusudi kwa sampuli mbaya, na hivyo kuifundisha model kanuni zenye madhara.\
*Mfano*: Malware binaries huwekewa lebo isiyo sahihi ya "benign" kwenye mkusanyiko wa data wa mafunzo ya antivirus, na kufanya malware zinazofanana zipite baadaye.

- **Model Inversion Attack**: Kwa kuchunguza matokeo, mshambuliaji huunda **reverse model** inayorejesha vipengele nyeti vya ingizo asilia.\
*Mfano*: Kuunda upya picha ya MRI ya mgonjwa kutokana na utabiri wa model ya kugundua kansa.

- **Membership Inference Attack**: Mshambuliaji hupima ikiwa **rekodi mahususi** ilitumika wakati wa mafunzo kwa kutambua tofauti za confidence.\
*Mfano*: Kuthibitisha kuwa miamala ya benki ya mtu fulani ipo kwenye data ya mafunzo ya model ya kugundua fraud.

- **Model Theft**: Kuuliza maswali mara kwa mara humwezesha mshambuliaji kujifunza decision boundaries na **kuiga tabia ya model** (na IP).\
*Mfano*: Kukusanya jozi za kutosha za Q&A kutoka kwa API ya ML-as-a-Service ili kujenga model ya ndani inayokaribia kufanana.

- **AI Supply‑Chain Attack**: Kuweka hatarini kipengele chochote (data, libraries, pre-trained weights, CI/CD) kwenye **ML pipeline** ili kuharibu models zinazofuata.\
*Mfano*: Dependency iliyochafuliwa kwenye model-hub husakinisha model ya sentiment-analysis yenye backdoor kwenye apps nyingi.

- **Transfer Learning Attack**: Mantiki hasidi hupandikizwa kwenye **pre-trained model** na huendelea kuwepo hata baada ya fine-tuning kwa kazi ya mwathiriwa.\
*Mfano*: Vision backbone yenye kichochezi kilichofichwa bado hubadilisha labels baada ya kurekebishwa kwa picha za matibabu.

- **Model Skewing**: Data yenye upendeleo mdogo au iliyowekewa labels zisizo sahihi **hubadilisha matokeo ya model** ili kuunga mkono ajenda ya mshambuliaji.\
*Mfano*: Kuingiza barua pepe za spam "safi" zilizopewa lebo ya ham ili spam filter iruhusu barua pepe zinazofanana baadaye.

- **Output Integrity Attack**: Mshambuliaji **hubadilisha utabiri wa model wakati unasafirishwa**, si model yenyewe, na hivyo kudanganya mifumo inayofuata.\
*Mfano*: Kubadilisha uamuzi wa malware classifier kutoka "malicious" kuwa "benign" kabla ya kufika kwenye hatua ya kuweka faili karantini.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja, yaliyolengwa, kwenye **model parameters** zenyewe, mara nyingi baada ya kupata ruhusa ya kuandika, ili kubadilisha tabia.\
*Mfano*: Kurekebisha weights za model ya kugundua fraud inayotumika production ili miamala kutoka kwa kadi fulani iidhinishwe kila mara.


## Hatari za Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) ya Google inaeleza hatari mbalimbali zinazohusiana na mifumo ya AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Watendaji hasidi hubadilisha au kuingiza data ya mafunzo/tuning ili kupunguza usahihi, kupandikiza backdoors au kupotosha matokeo, na kudhoofisha uadilifu wa model katika mzunguko mzima wa maisha ya data.

- **Unauthorized Training Data**: Kutumia datasets zenye hakimiliki, nyeti au zisizoruhusiwa husababisha madeni ya kisheria, kimaadili na kiutendaji kwa sababu model hujifunza kutokana na data ambayo haikuruhusiwa kutumia.

- **Model Source Tampering**: Udukuzi wa supply-chain au wa ndani kwenye msimbo wa model, dependencies au weights kabla au wakati wa mafunzo unaweza kupachika mantiki iliyofichwa ambayo huendelea kuwepo hata baada ya mafunzo kufanywa upya.

- **Excessive Data Handling**: Udhibiti dhaifu wa uhifadhi na usimamizi wa data husababisha mifumo kuhifadhi au kuchakata data binafsi nyingi kuliko inavyohitajika, na kuongeza hatari za kufichuka na kutofuata kanuni.

- **Model Exfiltration**: Wavamizi huiba model files/weights, na kusababisha upotevu wa intellectual property na kuwezesha huduma za kuiga au mashambulizi yanayofuata.

- **Model Deployment Tampering**: Wapinzani hubadilisha model artifacts au miundombinu ya serving ili model inayoendeshwa iwe tofauti na toleo lililokaguliwa, na hivyo huenda kubadilisha tabia yake.

- **Denial of ML Service**: Kujaza APIs kwa maombi mengi au kutuma inputs za “sponge” kunaweza kumaliza rasilimali za compute/energy na kuizima model, sawa na mashambulizi ya kawaida ya DoS.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya jozi za input-output, wavamizi wanaweza kuiga au kudistil model, na hivyo kuchochea bidhaa za kuiga na adversarial attacks zilizobinafsishwa.

- **Insecure Integrated Component**: Plugins, agents au huduma za upstream zilizo hatarini huwawezesha wavamizi kuingiza msimbo au kuongeza privileges ndani ya AI pipeline.

- **Prompt Injection**: Kuunda prompts (moja kwa moja au kwa njia isiyo ya moja kwa moja) ili kupenyeza maagizo yanayobatilisha nia ya mfumo, na kuifanya model itekeleze amri zisizokusudiwa.

- **Model Evasion**: Inputs zilizoundwa kwa uangalifu huifanya model kuainisha vibaya, kutoa hallucinations au kutoa maudhui yasiyoruhusiwa, na kudhoofisha usalama na uaminifu.

- **Sensitive Data Disclosure**: Model hufichua taarifa binafsi au za siri kutoka kwenye data yake ya mafunzo au muktadha wa mtumiaji, na kukiuka faragha na kanuni.

- **Inferred Sensitive Data**: Model hukisia sifa binafsi ambazo hazikuwahi kutolewa, na kusababisha madhara mapya ya faragha kupitia inference.

- **Insecure Model Output**: Majibu ambayo hayajasafishwa hupitisha msimbo hatari, taarifa potofu au maudhui yasiyofaa kwa watumiaji au mifumo inayofuata.

- **Rogue Actions**: Agents zilizounganishwa kiotomatiki hutekeleza shughuli zisizokusudiwa katika ulimwengu halisi (kuandika faili, kuita APIs, kufanya manunuzi, n.k.) bila usimamizi wa kutosha wa mtumiaji.

## MITRE AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) hutoa mfumo mpana wa kuelewa na kupunguza hatari zinazohusiana na mifumo ya AI. Inaainisha mbinu na tactics mbalimbali za mashambulizi ambazo wapinzani wanaweza kutumia dhidi ya AI models, na pia jinsi ya kutumia mifumo ya AI kutekeleza mashambulizi mbalimbali.<sup>[[3]](#references)</sup>

## LLMJacking (Wizi wa Token na Uuzaji Upya wa Ufikiaji wa LLM Zinazopangishwa kwenye Cloud)

Wavamizi huiba session tokens zinazotumika au cloud API credentials na kutumia LLM zinazolipiwa, zinazopangishwa kwenye cloud, bila idhini. Mara nyingi ufikiaji huu huuzwa tena kupitia reverse proxies zinazoelekeza maombi kupitia akaunti ya mwathiriwa, kwa mfano, deployments za "oai-reverse-proxy". Madhara yake ni pamoja na hasara ya kifedha, matumizi mabaya ya model nje ya sera, na kuhusishwa kwa vitendo hivyo na tenant ya mwathiriwa.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Kukusanya tokens kutoka kwenye mashine za developers au browsers zilizoambukizwa; kuiba siri za CI/CD; kununua cookies zilizovuja.<sup>[[5]](#references)</sup>
- Kuanzisha reverse proxy inayosambaza maombi kwa provider halisi, kuficha key ya upstream na kuruhusu wateja wengi kuitumia.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Kutumia vibaya endpoints za moja kwa moja za base-model ili kukwepa guardrails za enterprise na vikomo vya kasi ya maombi.<sup>[[4]](#references)</sup>

Hatua za kupunguza hatari:
- Funga tokens kwenye alama za kifaa, safu za IP na client attestation; weka muda mfupi wa kuisha na utekeleze refresh kwa MFA.
- Weka keys kwenye ruhusa za chini kabisa (bila ufikiaji wa tools, read-only inapowezekana); zibadilishe kunapotokea anomaly.
- Pitisha trafiki yote kupitia upande wa server nyuma ya policy gateway inayotekeleza safety filters, quotas kwa kila route na utenganishaji wa tenants.
- Fuatilia mifumo isiyo ya kawaida ya matumizi (ongezeko la ghafla la gharama, maeneo yasiyo ya kawaida, UA strings) na ubatilishe sessions zinazotia shaka kiotomatiki.
- Pendelea mTLS au signed JWTs zinazotolewa na IdP yako badala ya API keys tuli za muda mrefu.

## Kuimarisha inference ya LLM inayojipangisha

Kuendesha server ya LLM ya ndani kwa data za siri huleta attack surface tofauti na APIs zinazopangishwa kwenye cloud: endpoints za inference/debug zinaweza kuvuja prompts, stack ya serving kwa kawaida huweka wazi reverse proxy, na GPU device nodes hutoa ufikiaji wa sehemu kubwa ya `ioctl()`. Ikiwa unakagua au kupeleka huduma ya inference ya on-prem, kagua angalau mambo yafuatayo.<sup>[[8]](#references)</sup>

### Kuvuja kwa prompt kupitia endpoints za debug na monitoring

Ichukulie inference API kama **huduma nyeti ya watumiaji wengi**. Routes za debug au monitoring zinaweza kufichua maudhui ya prompts, hali ya slots, metadata ya model au taarifa za ndani za foleni. Katika `llama.cpp`, endpoint ya `/slots` ni nyeti hasa kwa sababu hufichua hali ya kila slot na imekusudiwa tu kwa ukaguzi/usimamizi wa slots.<sup>[[8]](#references)</sup>

Kwa fingerprinting ya black-box na majaribio ya model runners zilizo wazi na huduma zinazohusiana za AI, angalia [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Weka reverse proxy mbele ya inference server na **kataza kwa chaguo-msingi**.
- Ruhusu tu mchanganyiko mahususi wa HTTP method + path unaohitajika na client/UI.
- Zima endpoints za introspection kwenye backend yenyewe inapowezekana, kwa mfano `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Funga reverse proxy kwenye `127.0.0.1` na uifikie kupitia transport yenye uthibitishaji kama SSH local port forwarding badala ya kuichapisha kwenye LAN.

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

### Rootless containers bila mtandao na UNIX sockets

Ikiwa inference daemon inaauni kusikiliza kwenye UNIX socket, pendelea hiyo badala ya TCP na endesha container bila **network stack**:<sup>[[8]](#references)</sup>

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
- `--network none` huondoa uwezekano wa kuingia/kutoka kupitia TCP/IP na huepusha wasaidizi wa user-mode ambao containers zisizo root zingehitaji vinginevyo.
- UNIX socket hukuwezesha kutumia ruhusa/ACL za POSIX kwenye njia ya socket kama safu ya kwanza ya udhibiti wa ufikiaji.
- `--userns=keep-id` na rootless Podman hupunguza athari za container breakout kwa sababu root ndani ya container si root wa host.
- Mounts za model za kusoma tu hupunguza uwezekano wa model kuchezewa kutoka ndani ya container.

Kwa deployments zinazoendelea, vizuizi vilevile vinaweza kuonyeshwa kama Podman Quadlet units. Ikiwa ufikiaji wa GPU unakabidhiwa kupitia Container Device Interface, weka vipimo vya kifaa vya CDI kuwa finyu iwezekanavyo badala ya kufichua kila nodi ya accelerator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Kupunguza nodi za kifaa za GPU

Kwa inference inayotumia GPU, faili za `/dev/nvidia*` ni sehemu za mashambulizi za ndani zenye thamani kubwa kwa sababu hufichua `ioctl()` handlers kubwa za driver na huenda zikafichua njia za usimamizi wa kumbukumbu ya GPU zinazoshirikiwa.<sup>[[8]](#references)</sup>

- Usiziache `/dev/nvidia*` zikiwa na ruhusa za kuandika kwa kila mtu.
- Zuia `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, sheria za udev, na ACLs ili UID ya container iliyopangwa pekee iweze kuzifungua.
- Zuia kupakiwa kwa modules zisizohitajika kama `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye hosts za inference zisizo na skrini.
- Pakia mapema modules zinazohitajika tu wakati wa boot badala ya kuruhusu runtime iendeshe `modprobe` kwa bahati wakati inference inaanza.

Mfano:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Jambo moja muhimu la kukagua ni **`/dev/nvidia-uvm`**. Hata kama workload haitumii `cudaMallocManaged()` moja kwa moja, CUDA runtimes za hivi karibuni bado zinaweza kuhitaji `nvidia-uvm`. Kwa kuwa kifaa hiki kinashirikiwa na hushughulikia usimamizi wa GPU virtual memory, kichukulie kama eneo linaloweza kusababisha kufichuka kwa data kati ya tenants. Ikiwa inference backend inakiunga mkono, Vulkan backend inaweza kuwa chaguo la kuvutia kwa sababu huenda ikaepusha kabisa kuipa container ufikiaji wa `nvidia-uvm`.<sup>[[8]](#references)</sup>

### Uwekaji wa mipaka wa LSM kwa inference workers

AppArmor/SELinux/seccomp zinapaswa kutumiwa kama ulinzi wa tabaka nyingi kuzunguka mchakato wa inference:<sup>[[8]](#references)</sup>

- Ruhusu tu shared libraries, model paths, socket directory, na GPU device nodes zinazohitajika.
- Kataa waziwazi capabilities zenye hatari kubwa kama `sys_admin`, `sys_module`, `sys_rawio`, na `sys_ptrace`.
- Weka model directory katika hali ya kusomeka pekee na punguza paths zinazoweza kuandikwa ziwe runtime socket/cache directories pekee.
- Fuatilia denial logs kwa sababu hutoa telemetry muhimu ya ugunduzi wakati model server au post-exploitation payload inapojaribu kukwepa tabia inayotarajiwa.

Mfano wa sheria za AppArmor kwa worker inayotumia GPU:

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

## Phantom Squatting: Vikoa Vilivyobuniwa na LLM kama Njia ya Mashambulizi ya Msururu wa Ugavi wa AI

Phantom squatting ni **sawa na slopsquatting, lakini kwa domain/URL**. Badala ya kubuni jina la kifurushi lisilokuwepo, LLM hubuni **domain ya portal, API, webhook, billing, SSO, download au support** inayoonekana kuaminika kwa chapa halisi, kisha mshambuliaji husajili namespace hiyo kabla ya mtu au agent kuitumia.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Hili ni muhimu kwa sababu katika workflows nyingi zinazosaidiwa na AI, matokeo ya modeli huchukuliwa kama **dependency inayoaminika**:
- Developers huweka endpoint iliyopendekezwa kwenye code au miunganisho ya CI/CD.
- AI agents hupakua kiotomatiki documentation, schemas, APKs, ZIPs au malengo ya webhook.
- Runbooks au docs zilizozalishwa zinaweza kujumuisha URL bandia kana kwamba ni rasmi.

### Workflow ya kushambulia

1. **Chunguza sehemu zinazoweza kubuniwa**: uliza maswali yanayohusu chapa kuhusu workflows za kawaida kama portal za `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` au `mobile app`.<sup>[[12]](#references)</sup>
2. **Sanifisha chaguo**: tatua URLs zilizozalishwa, badilisha majibu ya NXDOMAIN kuwa parent domain inayoweza kusajiliwa, na ondoa marudio ya makundi ya prompts. Prompt corpora zinapaswa kuwa tofauti, kwa mfano kwa kuondoa zinazokaribiana kwa kutumia **Jaccard similarity**.
3. **Panga hallucinations zinazotabirika kwa kipaumbele**:
   - **Thermal Hallucination Persistence (THP)**: domain ileile bandia hujitokeza katika temperatures tofauti, ikiwemo temperature ya chini kama `T=0.1`.
   - **Makubaliano kati ya models**: familia nyingi za LLM huzalisha domain ileile bandia.
4. **Sajili na uitumie kwa mashambulizi** parent domain, kisha weka phishing, downloads za APK/ZIP bandia, credential harvesters, docs hasidi au endpoints za API zinazokusanya secrets/webhook payloads. **Hallucinations zilizo kwenye kiwango cha domain pekee** ndizo rahisi zaidi kupata faida nazo kwa sababu mshambuliaji anadhibiti namespace nzima; hallucinations za subdomain/path bado zinaweza kutumiwa vibaya ikiwa parent iliyosanifishwa haijasajiliwa.
5. **Tumia fursa ya kipindi cha zero-reputation**: domains zilizosajiliwa hivi karibuni mara nyingi hazina historia ya blocklist, sifa ya URL na telemetry iliyokomaa, kwa hiyo zinaweza kupita kwenye controls hadi detections zianze kuzitambua. Washambuliaji wanaweza kurefusha kipindi hiki kwa majibu yasiyo na madhara yanayoonekana na crawlers pekee, redirect cloaking, CAPTCHA gates au kuchelewesha kuandaa payload.

### Kwa nini ni hatari kwa agents

Kwa mwathiriwa binadamu, domain bandia kwa kawaida bado huhitaji kubofya na kuchukua hatua nyingine. Katika **workflow ya agentic**, LLM inaweza kuwa **chambo** na pia **mtekelezaji**: agent hupokea URL iliyobuniwa, huifungua, huchanganua jibu, kisha inaweza ku-leak tokens, kutekeleza instructions, kupakua dependency au kusukuma data iliyotiwa sumu kwenye CI/CD bila ukaguzi wowote wa binadamu.<sup>[[12]](#references)</sup>

### Prompts za vitendo za mshambuliaji

Prompts zenye mafanikio zaidi kwa kawaida huonekana kama kazi za kawaida za biashara badala ya chambo wazi cha phishing:<sup>[[12]](#references)</sup>
- “URL ya sandbox ya malipo ya miunganisho ya `<brand>` ni ipi?”
- “Nitumie endpoint gani ya webhook kwa notifications za build za `<brand>`?”
- “Portal ya benefits za wafanyakazi / billing / SSO ya `<brand>` iko wapi?”
- “Nipe kiungo cha moja kwa moja cha kupakua Android APK au desktop client ya `<brand>`.”

### Kugeuza mtazamo wa ulinzi

Chukulia hili kama tatizo la ufuatiliaji wa domain wa mapema, si tatizo la prompt-injection pekee:<sup>[[12]](#references)</sup>
- Unda **brand prompt corpus** na ujaribu mara kwa mara LLMs ambazo users/agents wako hutegemea.
- Hifadhi URLs zilizobuniwa na ufuatilie ambazo zinabaki thabiti katika temperatures/models tofauti.
- Fuatilia **Adversarial Exploitation Window (AEW)**: muda kati ya hallucination ya kwanza na usajili wa mshambuliaji. AEW chanya humaanisha defenders wanaweza kusajili mapema, kuweka sinkhole au kuzuia kabla ya domain kutumiwa kwa mashambulizi.
- Fuatilia mabadiliko ya **NXDOMAIN → registered** kwa parent domains.
- Baada ya usajili, kagua registrar, tarehe ya kuundwa, nameservers, privacy shielding, maudhui ya ukurasa, screenshots, hali ya parked-page na kufanana kwa brand assets.
- Weka policy gates ili agents/developers **wasiamini domains zilizozalishwa na LLM kwa chaguo-msingi**: hitaji allowlists, uthibitishaji wa umiliki, ukaguzi wa CT/RDAP au idhini ya binadamu kabla ya matumizi ya kwanza.

Hili linahusiana na maeneo kadhaa ya hatari za AI kwa wakati mmoja: **shambulio la AI supply-chain**, **matokeo yasiyo salama ya modeli**, na **vitendo vya rogue** wakati agents zinapotumia URL iliyobuniwa kiotomatiki.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Hatari](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Hatari za Code Assistant LLMs: Maudhui Yenye Madhara, Matumizi Mabaya na Udanganyifu](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Wizi wa Cloud Credentials Zilizotumika katika Shambulio Jipya la AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Muhtasari wa mpango wa LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (uuzaji upya wa ufikiaji wa LLM ulioibiwa)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Uchambuzi wa kina wa uwekaji wa seva ya LLM ya on-premise yenye ruhusa chache](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README ya seva ya llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Vipimo vya CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Vikoa Vilivyobuniwa na AI kama Njia ya Mashambulizi ya Msururu wa Ugavi wa Programu](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Jinsi Hallucinations za AI Zinavyochochea Aina Mpya ya Mashambulizi ya Msururu wa Ugavi](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
