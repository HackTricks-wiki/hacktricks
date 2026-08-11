# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## Udhaifu 10 Bora wa Machine Learning wa OWASP

Owasp imebainisha udhaifu 10 bora wa machine learning ambao unaweza kuathiri mifumo ya AI. Udhaifu huu unaweza kusababisha masuala mbalimbali ya usalama, yakiwemo data poisoning, model inversion, na adversarial attacks. Kuelewa udhaifu huu ni muhimu kwa ajili ya kujenga mifumo salama ya AI.

Kwa orodha iliyosasishwa na yenye maelezo ya kina ya udhaifu 10 bora wa machine learning, rejelea mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Mshambuliaji huongeza mabadiliko madogo, ambayo mara nyingi hayaonekani, kwenye **data inayoingia** ili model ifanye uamuzi usio sahihi.\
*Mfano*: Matone machache ya rangi kwenye alama ya kusimama huifanya gari linalojiendesha "kuona" alama ya kikomo cha kasi.

- **Data Poisoning Attack**: **Training set** huchafuliwa kimakusudi kwa samples mbaya, na hivyo kuifundisha model sheria zenye madhara.\
*Mfano*: Binaries za malware huwekewa lebo kimakosa kuwa "benign" katika mkusanyiko wa data wa mafunzo wa antivirus, na kuruhusu malware zinazofanana kupita baadaye.

- **Model Inversion Attack**: Kwa kuchunguza matokeo, mshambuliaji huunda **reverse model** inayorejesha features nyeti za inputs asili.\
*Mfano*: Kuunda upya picha ya MRI ya mgonjwa kutokana na predictions za model ya kugundua cancer.

- **Membership Inference Attack**: Mpinzani hujaribu kubaini ikiwa **record maalum** ilitumika wakati wa training kwa kutambua tofauti za confidence.\
*Mfano*: Kuthibitisha kuwa muamala wa benki wa mtu fulani unaonekana katika training data ya model ya kugundua udanganyifu.

- **Model Theft**: Kuuliza maswali mara kwa mara humwezesha mshambuliaji kujifunza mipaka ya maamuzi na **kuiga tabia ya model** (pamoja na IP).\
*Mfano*: Kukusanya jozi za kutosha za Q&A kutoka kwa API ya ML-as-a-Service ili kujenga model ya ndani inayokaribiana nayo.

- **AI Supply-Chain Attack**: Kuhatarisha component yoyote (data, libraries, pre-trained weights, CI/CD) katika **ML pipeline** ili kuharibu models zinazotokana nayo.\
*Mfano*: Dependency iliyochafuliwa kwenye model-hub husakinisha model ya sentiment-analysis yenye backdoor katika apps nyingi.

- **Transfer Learning Attack**: Logic hasidi hupandikizwa kwenye **pre-trained model** na huendelea kuwepo baada ya fine-tuning kwenye task ya mwathirika.\
*Mfano*: Vision backbone yenye trigger iliyofichwa bado hubadilisha labels baada ya kurekebishwa kwa ajili ya medical imaging.

- **Model Skewing**: Data yenye upendeleo au labels zisizo sahihi **hubadilisha outputs za model** ili kuunga mkono ajenda ya mshambuliaji.\
*Mfano*: Kuingiza emails za spam "safi" zilizopewa lebo ya ham ili spam filter ziruhusu emails zinazofanana baadaye.

- **Output Integrity Attack**: Mshambuliaji **hubadilisha predictions za model wakati wa usafirishaji**, bila kuibadilisha model yenyewe, na hivyo kupotosha mifumo inayofuata.\
*Mfano*: Kubadilisha uamuzi wa malware classifier kutoka "malicious" kuwa "benign" kabla ya hatua ya file-quarantine kuuona.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja na yaliyolengwa kwenye **model parameters** zenyewe, mara nyingi baada ya kupata write access, ili kubadilisha tabia.\
*Mfano*: Kubadilisha weights za model ya kugundua udanganyifu iliyo production ili miamala kutoka kwa kadi fulani iidhinishwe kila mara.


## Hatari za Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework) ya Google inaeleza hatari mbalimbali zinazohusishwa na mifumo ya AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Wahusika hasidi hubadilisha au kuingiza training/tuning data ili kupunguza usahihi, kupandikiza backdoors, au kupotosha matokeo, na hivyo kudhoofisha uadilifu wa model katika mzunguko mzima wa data.

- **Unauthorized Training Data**: Kuingiza datasets zenye hakimiliki, nyeti, au zisizoruhusiwa huleta madeni ya kisheria, kimaadili, na kiutendaji kwa sababu model hujifunza kutokana na data ambayo haikuruhusiwa kutumia.

- **Model Source Tampering**: Supply-chain au insider manipulation ya model code, dependencies, au weights kabla au wakati wa training inaweza kupachika logic iliyofichwa ambayo huendelea kuwepo hata baada ya retraining.

- **Excessive Data Handling**: Udhibiti dhaifu wa kuhifadhi data na governance husababisha mifumo kuhifadhi au kuchakata data ya kibinafsi zaidi ya inavyohitajika, na kuongeza hatari ya kufichuka na ya kutotii kanuni.

- **Model Exfiltration**: Washambuliaji huiba model files/weights, na kusababisha kupotea kwa intellectual property na kuwezesha services za kuiga au mashambulizi yanayofuata.

- **Model Deployment Tampering**: Wapinzani hubadilisha model artifacts au serving infrastructure ili model inayoendesha itofautiane na toleo lililokaguliwa, na hivyo kubadilisha behaviour.

- **Denial of ML Service**: Kufurika kwa APIs au kutuma inputs za “sponge” kunaweza kumaliza compute/energy na kuifanya model isitumikike, sawa na mashambulizi ya kawaida ya DoS.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya jozi za input-output, washambuliaji wanaweza kuiga au kudistil model, na hivyo kuwezesha bidhaa za kuiga na adversarial attacks zilizobinafsishwa.

- **Insecure Integrated Component**: Plugins, agents, au upstream services zilizo hatarini huwawezesha washambuliaji kuingiza code au kuongeza privileges ndani ya AI pipeline.

- **Prompt Injection**: Kuunda prompts (moja kwa moja au kwa njia isiyo ya moja kwa moja) ili kuficha instructions zinazopuuza dhamira ya mfumo, na kuifanya model itekeleze commands zisizotarajiwa.

- **Model Evasion**: Inputs zilizoundwa kwa uangalifu huifanya model iweke classification isiyo sahihi, ihallucinate, au itoe maudhui yasiyoruhusiwa, na hivyo kupunguza usalama na uaminifu.

- **Sensitive Data Disclosure**: Model hufichua taarifa za kibinafsi au za siri kutoka kwenye training data au user context yake, na kukiuka faragha na kanuni.

- **Inferred Sensitive Data**: Model hubaini attributes za kibinafsi ambazo hazikutolewa kamwe, na hivyo kusababisha madhara mapya ya faragha kupitia inference.

- **Insecure Model Output**: Responses ambazo hazijasafishwa hupitisha code yenye madhara, misinformation, au maudhui yasiyofaa kwa users au mifumo inayofuata.

- **Rogue Actions**: Agents zilizounganishwa kwa uhuru hutekeleza operations za ulimwengu halisi zisizotarajiwa (file writes, API calls, purchases, n.k.) bila usimamizi wa kutosha wa user.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) hutoa framework pana ya kuelewa na kupunguza hatari zinazohusishwa na mifumo ya AI. Inaainisha attack techniques na tactics mbalimbali ambazo wapinzani wanaweza kutumia dhidi ya AI models, pamoja na jinsi ya kutumia mifumo ya AI kutekeleza mashambulizi tofauti.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Washambuliaji huiba active session tokens au cloud API credentials na kutumia LLMs za kulipia, zinazohifadhiwa kwenye cloud, bila idhini. Mara nyingi access huuzwa tena kupitia reverse proxies zinazotumia account ya mwathirika, kwa mfano deployments za "oai-reverse-proxy". Madhara yanajumuisha hasara ya kifedha, matumizi ya model kinyume na policy, na attribution kwa victim tenant.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Kukusanya tokens kutoka kwenye developer machines au browsers zilizoambukizwa; kuiba CI/CD secrets; kununua cookies zilizovuja.<sup>[[5]](#references)</sup>
- Kuanzisha reverse proxy inayopitisha requests kwa provider halisi, ikificha upstream key na ku-multiplex customers wengi.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Kutumia vibaya direct base-model endpoints ili kupita enterprise guardrails na rate limits.<sup>[[4]](#references)</sup>

Mitigations:
- Funga tokens kwenye device fingerprint, IP ranges, na client attestation; tumia expirations fupi na refresh kupitia MFA.
- Punguza scope ya keys kwa kiwango cha chini (bila tool access, read-only inapowezekana); zizungushe unapogundua anomaly.
- Sitisha traffic yote upande wa server nyuma ya policy gateway inayotekeleza safety filters, quotas za kila route, na tenant isolation.
- Fuatilia matumizi yasiyo ya kawaida (ongezeko la ghafla la matumizi ya fedha, regions zisizo za kawaida, UA strings) na auto-revoke sessions zinazotiliwa shaka.
- Pendelea mTLS au signed JWTs zinazotolewa na IdP yako badala ya static API keys zenye muda mrefu.

## Kuimarisha usalama wa self-hosted LLM inference

Kuendesha local LLM server kwa data za siri huunda attack surface tofauti na APIs za cloud-hosted: inference/debug endpoints zinaweza kuvuja prompts, serving stack kwa kawaida hufichua reverse proxy, na GPU device nodes hutoa access kwa `ioctl()` surfaces kubwa. Ikiwa unatathmini au ku-deploy on-prem inference service, kagua angalau mambo yafuatayo.<sup>[[8]](#references)</sup>

### Prompt leakage kupitia debug na monitoring endpoints

Ichukulie inference API kama **multi-user sensitive service**. Debug au monitoring routes zinaweza kufichua prompt contents, slot state, model metadata, au taarifa za internal queue. Katika `llama.cpp`, endpoint ya `/slots` ni nyeti hasa kwa sababu hufichua per-slot state na inalenga tu ukaguzi/udhibiti wa slots.<sup>[[8]](#references)</sup>

- Weka reverse proxy mbele ya inference server na **ukatae kwa default**.
- Ruhusu tu combinations halisi za HTTP method + path zinazohitajika na client/UI.
- Zima introspection endpoints kwenye backend yenyewe inapowezekana, kwa mfano `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Funga reverse proxy kwenye `127.0.0.1` na uifichue kupitia authenticated transport kama SSH local port forwarding badala ya kuichapisha kwenye LAN.

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
### Containers zisizo na root bila network na UNIX sockets

Ikiwa inference daemon inaunga mkono kusikiliza kwenye UNIX socket, pendelea hiyo badala ya TCP na endesha container bila **network stack**:<sup>[[8]](#references)</sup>
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
- `--network none` huondoa mwonekano wa TCP/IP wa inbound/outbound na huepuka user-mode helpers ambazo rootless containers zingehitaji vinginevyo.
- UNIX socket hukuruhusu kutumia POSIX permissions/ACLs kwenye socket path kama safu ya kwanza ya access control.
- `--userns=keep-id` na rootless Podman hupunguza athari za container breakout kwa sababu container root si host root.
- Read-only model mounts hupunguza uwezekano wa model tampering kutoka ndani ya container.

Kwa deployments zinazoendelea, vizuizi vilevile vinaweza kuonyeshwa kupitia Podman Quadlet units. Ikiwa GPU access imekabidhiwa kupitia Container Device Interface, weka CDI device specification iwe finyu iwezekanavyo badala ya kufichua kila accelerator node.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Kupunguza GPU device-node

Kwa inference inayotegemea GPU, faili za `/dev/nvidia*` ni local attack surfaces zenye thamani kubwa kwa sababu zinafichua `ioctl()` handlers kubwa za driver na huenda zikafichua shared GPU memory-management paths.<sup>[[8]](#references)</sup>

- Usiziache `/dev/nvidia*` zikiwa world writable.
- Zuia `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, udev rules, na ACLs ili tu mapped container UID iweze kuzifungua.
- Blacklist modules zisizohitajika kama `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye headless inference hosts.
- Preload modules zinazohitajika pekee wakati wa boot badala ya kuruhusu runtime kuzifanyia `modprobe` opportunistically wakati wa inference startup.

Mfano:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jambo moja muhimu la kukagua ni **`/dev/nvidia-uvm`**. Hata kama workload haitumii waziwazi `cudaMallocManaged()`, CUDA runtimes za hivi karibuni bado zinaweza kuhitaji `nvidia-uvm`. Kwa kuwa device hii inashirikiwa na hushughulikia usimamizi wa GPU virtual memory, ichukulie kama surface ya cross-tenant data exposure. Ikiwa inference backend inaiunga mkono, Vulkan backend inaweza kuwa trade-off ya kuvutia kwa sababu inaweza kuepuka kabisa kuanika `nvidia-uvm` kwa container.<sup>[[8]](#references)</sup>

### LSM confinement kwa inference workers

AppArmor/SELinux/seccomp inapaswa kutumiwa kama defense in depth kuzunguka inference process:<sup>[[8]](#references)</sup>

- Ruhusu tu shared libraries, model paths, socket directory, na GPU device nodes zinazohitajika kwa kweli.
- Kataa wazi capabilities zenye hatari kubwa kama `sys_admin`, `sys_module`, `sys_rawio`, na `sys_ptrace`.
- Weka model directory ikiwa read-only na punguza writable paths kwa runtime socket/cache directories pekee.
- Fuatilia denial logs kwa sababu hutoa detection telemetry muhimu wakati model server au post-exploitation payload inapojaribu kutoroka kutoka kwenye behaviour inayotarajiwa.

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
## Phantom Squatting: Domains Zinazobuniwa na LLM kama Vector ya AI Supply-Chain

Phantom squatting ni **sawa na domain/URL ya slopsquatting**. Badala ya kubuni jina la package lisilokuwepo, LLM hubuni **portal, API, webhook, billing, SSO, download au support domain** inayoonekana halali kwa brand halisi, kisha mshambuliaji husajili namespace hiyo kabla ya binadamu au agent kuitumia.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Hili ni muhimu kwa sababu katika workflows nyingi zinazosaidiwa na AI, output ya model huchukuliwa kuwa **trusted dependency**:
- Developers hubandika endpoint iliyopendekezwa kwenye code au miunganisho ya CI/CD.
- AI agents hufetch documentation, schemas, APKs, ZIPs au webhook targets automatically.
- Runbooks au docs zinazozalishwa zinaweza kuingiza fake URL kana kwamba ni authoritative.

### Offensive workflow

1. **Probe hallucination surface**: uliza maswali mahususi kuhusu brand yanayohusu workflows halisi kama `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook`, au portal za `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalize candidates**: resolve URLs zilizozalishwa, collapse majibu ya NXDOMAIN hadi parent registerable domain, na deduplicate prompt families. Prompt corpora zinapaswa kubaki diverse, kwa mfano kwa kuondoa near-duplicates zenye **Jaccard similarity**.
3. **Prioritize hallucinations zinazotabirika**:
- **Thermal Hallucination Persistence (THP)**: fake domain ileile huonekana katika temperatures mbalimbali, ikiwemo temperature ya chini kama `T=0.1`.
- **Cross-model consensus**: familia nyingi za LLM huzalisha fake domain ileile.
4. **Register and weaponize** parent domain, kisha host phishing, fake APK/ZIP downloads, credential harvesters, malicious docs, au API endpoints zinazokusanya secrets/webhook payloads. **Pure domain-level hallucinations** ndizo rahisi zaidi ku-monetize kwa sababu mshambuliaji anadhibiti namespace nzima; subdomain/path hallucinations bado zinaweza kutumiwa vibaya wakati parent iliyonenormalishwa haijasajiliwa.
5. **Exploit zero-reputation window**: domains zilizosajiliwa hivi karibuni mara nyingi hazina blocklist history, URL reputation, wala telemetry iliyokomaa, hivyo zinaweza kupita controls hadi detections zifikie. Attackers wanaweza kurefusha window hii kwa crawler-only benign responses, redirect cloaking, CAPTCHA gates, au delayed payload staging.

### Kwa nini ni hatari kwa agents

Kwa victim wa binadamu, fake domain kwa kawaida bado huhitaji kubofya na kufanya kitendo kingine. Kwa **agentic workflow**, LLM inaweza kuwa **lure** na **executor** kwa wakati mmoja: agent hupokea hallucinated URL, huifetch, huparse response, na baadaye inaweza ku-leak tokens, kutekeleza instructions, kudownload dependency, au kusukuma poisoned data kwenye CI/CD bila human review yoyote.<sup>[[12]](#references)</sup>

### Practical attacker prompts

High-yield prompts kwa kawaida huonekana kama enterprise tasks za kawaida badala ya phishing lures zilizo wazi:<sup>[[12]](#references)</sup>
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Chukulia hili kama tatizo la proactive domain-monitoring, si tatizo la prompt-injection pekee:<sup>[[12]](#references)</sup>
- Unda **brand prompt corpus** na mara kwa mara probe LLMs ambazo users/agents wako wanategemea.
- Hifadhi hallucinated URLs na fuatilia zipi zilizo stable katika temperatures/models mbalimbali.
- Fuatilia **Adversarial Exploitation Window (AEW)**: muda kati ya hallucination ya kwanza na attacker registration. AEW chanya humaanisha defenders wanaweza pre-register, sinkhole, au pre-block kabla ya weaponization.
- Fuatilia transitions za **NXDOMAIN → registered** kwa parent domains.
- Baada ya registration, triage registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status, na brand-asset similarity.
- Ongeza policy gates ili agents/developers **wasiamini LLM-generated domains by default**: hitaji allowlists, ownership validation, CT/RDAP checks, au human approval kabla ya matumizi ya kwanza.

Hili linaingia katika AI risk buckets kadhaa kwa wakati mmoja: **AI supply-chain attack**, **insecure model output**, na **rogue actions** wakati agents hutumia hallucinated URL autonomously.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Risks za Code Assistant LLMs: Harmful Content, Misuse na Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Stolen Cloud Credentials Zilizotumiwa katika AI Attack Mpya](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Muhtasari wa LLMJacking scheme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Deep-dive katika deployment ya on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Domains Zinazobuniwa na AI kama Vector ya Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Jinsi AI Hallucinations Zinavyochochea Aina Mpya ya Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
