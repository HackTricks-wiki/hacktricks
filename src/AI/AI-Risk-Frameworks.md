# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp imebainisha udhaifu 10 bora wa machine learning unaoweza kuathiri mifumo ya AI. Udhaifu huu unaweza kusababisha masuala mbalimbali ya usalama, yakiwemo data poisoning, model inversion, na adversarial attacks. Kuelewa udhaifu huu ni muhimu katika kujenga mifumo salama ya AI.

Kwa orodha iliyosasishwa na yenye maelezo ya kina kuhusu udhaifu 10 bora wa machine learning, rejelea mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: Mshambulizi huongeza mabadiliko madogo, ambayo mara nyingi hayaonekani, kwenye **data inayoingia** ili model ifanye uamuzi usio sahihi.\
*Example*: Madoadoa machache ya rangi kwenye alama ya kusimama huifanya gari linalojiendesha "kuona" alama ya kikomo cha kasi.

- **Data Poisoning Attack**: **training set** huchafuliwa kimakusudi kwa samples mbaya, na hivyo kuifundisha model kanuni hatari.\
*Example*: Faili za malware huwekewa lebo isiyo sahihi ya "benign" katika corpus ya mafunzo ya antivirus, na kuruhusu malware zinazofanana kupita baadaye.

- **Model Inversion Attack**: Kwa kuchunguza outputs, mshambulizi huunda **reverse model** inayorejesha vipengele nyeti vya inputs za awali.\
*Example*: Kuunda tena picha ya MRI ya mgonjwa kutokana na predictions za model ya kutambua saratani.

- **Membership Inference Attack**: Mpinzani hujaribu kubaini ikiwa **record maalum** ilitumika wakati wa training kwa kutambua tofauti za confidence.\
*Example*: Kuthibitisha kuwa muamala wa benki wa mtu fulani upo kwenye training data ya model ya kutambua udanganyifu.

- **Model Theft**: Kuuliza maswali mara kwa mara humwezesha mshambulizi kujifunza decision boundaries na **kunakili tabia ya model** (pamoja na IP).\
*Example*: Kukusanya Q&A pairs za kutosha kutoka kwa ML-as-a-Service API ili kujenga model ya ndani inayokaribiana nayo.

- **AI Supply-Chain Attack**: Kuhatarisha component yoyote (data, libraries, pre-trained weights, CI/CD) katika **ML pipeline** ili kuharibu models zinazotegemea mfumo huo.\
*Example*: Dependency yenye sumu kwenye model-hub husakinisha model ya sentiment-analysis yenye backdoor katika apps nyingi.

- **Transfer Learning Attack**: Logic hasidi hupandikizwa kwenye **pre-trained model** na huendelea kuwepo baada ya fine-tuning kwa task ya mwathiriwa.\
*Example*: Vision backbone yenye trigger iliyofichwa bado hubadilisha labels baada ya kurekebishwa kwa medical imaging.

- **Model Skewing**: Data yenye upendeleo au labels zisizo sahihi **hubadilisha outputs za model** ili kuunga mkono ajenda ya mshambulizi.\
*Example*: Kuingiza barua pepe za spam "safi" zilizopewa lebo ya ham ili spam filter ziruhusu barua pepe zinazofanana baadaye.

- **Output Integrity Attack**: Mshambulizi **hubadilisha predictions za model wakati wa usafirishaji**, bila kubadilisha model yenyewe, na kuzipotosha mifumo inayofuata.\
*Example*: Kubadilisha uamuzi wa malware classifier kutoka "malicious" kuwa "benign" kabla ya hatua ya file-quarantine kuuona.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja na yaliyolengwa kwenye **model parameters** zenyewe, mara nyingi baada ya kupata write access, ili kubadilisha tabia.\
*Example*: Kubadilisha weights kwenye model ya kutambua udanganyifu iliyo production ili miamala kutoka kwa kadi fulani iidhinishwe kila mara.


## Hatari za Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) ya Google inaeleza hatari mbalimbali zinazohusishwa na mifumo ya AI:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Wahusika hasidi hubadilisha au kuingiza training/tuning data ili kupunguza usahihi, kupandikiza backdoors, au kupotosha matokeo, na kudhoofisha uadilifu wa model katika data-lifecycle yote.

- **Unauthorized Training Data**: Kuingiza datasets zilizo na hakimiliki, nyeti, au zisizoruhusiwa huleta madhara ya kisheria, kimaadili, na ya utendaji kwa sababu model hujifunza kutokana na data ambayo haikuruhusiwa kamwe kuitumia.

- **Model Source Tampering**: Supply-chain au insider manipulation ya model code, dependencies, au weights kabla au wakati wa training inaweza kupandikiza logic iliyofichwa ambayo huendelea kuwepo hata baada ya retraining.

- **Excessive Data Handling**: Udhibiti dhaifu wa data-retention na governance husababisha mifumo kuhifadhi au kuchakata personal data nyingi kuliko inavyohitajika, na kuongeza exposure na compliance risk.

- **Model Exfiltration**: Washambuliaji huiba model files/weights, na kusababisha upotevu wa intellectual property huku ikiwezesha huduma za kunakili na mashambulizi yanayofuata.

- **Model Deployment Tampering**: Wapinzani hubadilisha model artifacts au serving infrastructure ili model inayoendeshwa itofautiane na toleo lililokaguliwa, na hivyo kubadilisha behaviour.

- **Denial of ML Service**: Kufurika kwa APIs au kutuma inputs za “sponge” kunaweza kumaliza compute/energy na kuiweka model offline, sawa na mashambulizi ya kawaida ya DoS.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya input-output pairs, washambuliaji wanaweza kunakili au kutengeneza distillation ya model, na hivyo kuwezesha bidhaa za kuiga na adversarial attacks zilizobinafsishwa.

- **Insecure Integrated Component**: Plugins, agents, au upstream services zilizo hatarini huwawezesha washambuliaji kuingiza code au kuongeza privileges ndani ya AI pipeline.

- **Prompt Injection**: Kuunda prompts (moja kwa moja au kwa njia isiyo ya moja kwa moja) ili kusafirisha kwa siri instructions zinazopuuza nia ya mfumo, na kuifanya model itekeleze commands zisizokusudiwa.

- **Model Evasion**: Inputs zilizoundwa kwa uangalifu husababisha model kufanya mis-classification, hallucinate, au kutoa content isiyoruhusiwa, na kudhoofisha usalama na trust.

- **Sensitive Data Disclosure**: Model hufichua taarifa za faragha au za siri kutoka kwenye training data yake au user context, na kukiuka faragha na kanuni.

- **Inferred Sensitive Data**: Model hutambua sifa za kibinafsi ambazo hazikuwahi kutolewa, na kusababisha madhara mapya ya faragha kupitia inference.

- **Insecure Model Output**: Responses ambazo hazijasafishwa hupitisha code hatari, misinformation, au content isiyofaa kwa users au mifumo inayofuata.

- **Rogue Actions**: Agents zilizounganishwa kwa uhuru hutekeleza operations zisizokusudiwa katika ulimwengu halisi (file writes, API calls, purchases, n.k.) bila uangalizi wa kutosha wa user.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) hutoa framework pana ya kuelewa na kupunguza hatari zinazohusishwa na mifumo ya AI. Inaweka katika makundi attack techniques na tactics mbalimbali ambazo adversaries wanaweza kutumia dhidi ya AI models, pamoja na jinsi ya kutumia mifumo ya AI kutekeleza mashambulizi tofauti.<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Washambuliaji huiba active session tokens au cloud API credentials na kutumia LLMs za cloud-hosted zinazolipiwa bila idhini. Access mara nyingi huuzwa tena kupitia reverse proxies zinazoelekeza traffic ya akaunti ya mwathiriwa, kwa mfano deployments za "oai-reverse-proxy". Madhara yanajumuisha hasara ya kifedha, matumizi mabaya ya model kinyume na policy, na kuhusishwa kwa vitendo hivyo na victim tenant.<sup>[[2]](#references)[[3]](#references)</sup>

TTPs:
- Kukusanya tokens kutoka kwenye developer machines au browsers zilizoambukizwa; kuiba CI/CD secrets; kununua cookies zilizofanya leak.
- Kuanzisha reverse proxy inayosambaza requests kwa provider halisi, ikificha upstream key na kutumia multiplexing kwa customers wengi.
- Kutumia vibaya direct base-model endpoints ili kupita enterprise guardrails na rate limits.

Mitigations:
- Funga tokens kwenye device fingerprint, IP ranges, na client attestation; tumia expirations fupi na refresh yenye MFA.
- Punguza scope ya keys kadiri iwezekanavyo (bila tool access, read-only inapowezekana); zungusha keys kunapogunduliwa anomaly.
- Sitisha traffic yote upande wa server nyuma ya policy gateway inayotekeleza safety filters, quotas za kila route, na tenant isolation.
- Fuatilia matumizi yasiyo ya kawaida (ongezeko la ghafla la gharama, regions zisizo za kawaida, UA strings) na ubatilie kiotomatiki sessions zinazotiliwa shaka.
- Pendelea mTLS au signed JWTs zinazotolewa na IdP yako badala ya static API keys za muda mrefu.

## Self-hosted LLM inference hardening

Kuendesha local LLM server kwa data ya siri huunda attack surface tofauti na APIs za cloud-hosted: inference/debug endpoints zinaweza kufanya prompts ziwe na leak, serving stack kwa kawaida hufichua reverse proxy, na GPU device nodes hutoa access kwa surfaces kubwa za `ioctl()`. Ikiwa unatathmini au ku-deploy inference service ya on-prem, kagua angalau mambo yafuatayo.<sup>[[4]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

Chukulia inference API kama **multi-user sensitive service**. Debug au monitoring routes zinaweza kufichua prompt contents, slot state, model metadata, au taarifa za internal queue. Katika `llama.cpp`, endpoint ya `/slots` ni nyeti hasa kwa sababu hufichua per-slot state na imekusudiwa tu kwa slot inspection/management.<sup>[[4]](#references)[[5]](#references)</sup>

- Weka reverse proxy mbele ya inference server na **kataa kwa default**.
- Ruhusu tu orodha ya allowlist yenye mchanganyiko sahihi wa HTTP method + path unaohitajika na client/UI.
- Zima introspection endpoints ndani ya backend yenyewe inapowezekana, kwa mfano `llama-server --no-slots`.
- Bind reverse proxy kwenye `127.0.0.1` na uifikie kupitia authenticated transport kama SSH local port forwarding badala ya kuichapisha kwenye LAN.

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
### Kontena zisizo na root zisizo na network na UNIX sockets

Ikiwa inference daemon inaauni kusikiliza kwenye UNIX socket, ipendelee badala ya TCP na endesha kontena ikiwa na **network stack**:
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
- `--network none` huondoa uwazi wa TCP/IP wa kuingia/kutoka na huepuka user-mode helpers ambazo containers zisizo na root zingehitaji vinginevyo.
- UNIX socket hukuruhusu kutumia POSIX permissions/ACLs kwenye njia ya socket kama safu ya kwanza ya access control.
- `--userns=keep-id` na rootless Podman hupunguza athari za container breakout kwa sababu container root si host root.
- Mounts za model za kusomeka tu hupunguza uwezekano wa model tampering kutoka ndani ya container.

### Kupunguza GPU device nodes

Kwa inference inayotumia GPU, faili za `/dev/nvidia*` ni attack surfaces za ndani zenye thamani kubwa kwa sababu zinaweka wazi `ioctl()` handlers kubwa za driver na huenda zikafichua njia zinazoshirikiwa za usimamizi wa memory ya GPU.<sup>[[4]](#references)</sup>

- Usiziache `/dev/nvidia*` zikiwa world writable.
- Zuia `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, udev rules, na ACLs ili tu container UID iliyomapishwa iweze kuzifungua.
- Blacklist modules zisizo za lazima kama vile `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye inference hosts zisizo na display.
- Preload modules zinazohitajika tu wakati wa boot badala ya kuruhusu runtime kuziendesha `modprobe` kwa njia ya opportunistic wakati wa kuanzisha inference.

Mfano:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jambo moja muhimu la kukagua ni **`/dev/nvidia-uvm`**. Hata kama workload haitumii waziwazi `cudaMallocManaged()`, CUDA runtimes za hivi karibuni bado zinaweza kuhitaji `nvidia-uvm`. Kwa sababu kifaa hiki kinashirikiwa na kushughulikia usimamizi wa GPU virtual memory, kichukulie kama eneo la cross-tenant data-exposure. Ikiwa inference backend inakiunga mkono, Vulkan backend inaweza kuwa trade-off ya kuvutia kwa sababu inaweza kuepuka kuonyesha `nvidia-uvm` kwa container kabisa.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp inapaswa kutumiwa kama defense in depth kuzunguka inference process:<sup>[[4]](#references)</sup>

- Ruhusu tu shared libraries, model paths, socket directory, na GPU device nodes zinazohitajika kwa kweli.
- Kataa waziwazi capabilities zenye hatari kubwa kama vile `sys_admin`, `sys_module`, `sys_rawio`, na `sys_ptrace`.
- Weka model directory katika hali ya read-only na punguza writable paths kwa runtime socket/cache directories pekee.
- Fuatilia denial logs kwa sababu hutoa detection telemetry yenye manufaa wakati model server au post-exploitation payload inapojaribu kutoroka kwenye behaviour inayotarajiwa.

Mfano wa AppArmor rules kwa GPU-backed worker:
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
## Phantom Squatting: Domains Zilizobuniwa na LLM kwa Hallucination kama Vector ya AI Supply-Chain

Phantom squatting ni **sawa na slopsquatting katika kiwango cha domain/URL**. Badala ya kubuni kwa hallucination jina la package lisilokuwepo, LLM hubuni kwa hallucination **domain inayoweza kuaminika ya portal, API, webhook, billing, SSO, download au support** ya brand halisi, kisha mshambulizi husajili namespace hiyo kabla ya binadamu au agent kuitumia.<sup>[[8]](#references)[[9]](#references)</sup>

Hili ni muhimu kwa sababu katika workflows nyingi zinazosaidiwa na AI, matokeo ya model huchukuliwa kama **dependency inayoaminika**:
- Developers hubandika endpoint iliyopendekezwa kwenye code au integrations za CI/CD.
- AI agents hufetch documentation, schemas, APKs, ZIPs au webhook targets kiotomatiki.
- Runbooks au docs zilizozalishwa zinaweza kuingiza URL feki kana kwamba ni ya mamlaka.

### Offensive workflow

1. **Probe the hallucination surface**: uliza maswali mahususi kwa brand kuhusu workflows halisi kama `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook`, au portals za `mobile app`.
2. **Normalize candidates**: resolve generated URLs, punguza majibu ya NXDOMAIN hadi parent registerable domain, na ondoa prompt families zinazorudiwa. Prompt corpora zinapaswa kubaki tofauti, kwa mfano kwa kuondoa near-duplicates zenye **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: domain hiyo hiyo feki huonekana katika temperatures mbalimbali, ikiwemo temperature ya chini kama `T=0.1`.
- **Cross-model consensus**: familia nyingi za LLM huzalisha domain hiyo hiyo feki.
4. **Register and weaponize** parent domain, kisha host phishing, fake APK/ZIP downloads, credential harvesters, malicious docs, au API endpoints zinazokusanya secrets/webhook payloads. **Pure domain-level hallucinations** ndizo rahisi zaidi ku-monetize kwa sababu mshambulizi anadhibiti namespace yote; subdomain/path hallucinations bado zinaweza kutumiwa vibaya wakati parent iliyonormalishwa haijasajiliwa.
5. **Exploit the zero-reputation window**: domains zilizosajiliwa hivi karibuni mara nyingi hazina blocklist history, URL reputation, wala telemetry iliyokomaa, hivyo zinaweza kupita controls hadi detections zifuatilie. Attackers wanaweza kurefusha kipindi hiki kwa crawler-only benign responses, redirect cloaking, CAPTCHA gates, au delayed payload staging.

### Kwa nini ni hatari kwa agents

Kwa victim wa binadamu, domain feki kwa kawaida bado huhitaji click na kitendo kingine. Katika **agentic workflow**, LLM inaweza kuwa **lure** na pia **executor**: agent hupokea URL iliyobuniwa kwa hallucination, huifetch, huchanganua response, na kisha inaweza ku-leak tokens, kutekeleza instructions, kudownload dependency, au kusukuma data iliyotiwa sumu kwenye CI/CD bila human review.<sup>[[8]](#references)</sup>

### Practical attacker prompts

High-yield prompts kwa kawaida huonekana kama tasks za kawaida za enterprise badala ya phishing lures zilizo wazi:
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Chukulia hili kama tatizo la proactive domain-monitoring, si tatizo la prompt-injection pekee:
- Tengeneza **brand prompt corpus** na mara kwa mara probe LLMs ambazo users/agents wako hutegemea.
- Hifadhi URLs zilizobuniwa kwa hallucination na fuatilia zipi zinabaki stable katika temperatures/models tofauti.
- Fuatilia **Adversarial Exploitation Window (AEW)**: muda kati ya hallucination ya kwanza na registration ya mshambulizi. AEW chanya inamaanisha defenders wanaweza pre-register, sinkhole, au pre-block kabla ya weaponization.
- Fuatilia mabadiliko ya **NXDOMAIN → registered** kwa parent domains.
- Baada ya registration, triage registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status, na brand-asset similarity.
- Ongeza policy gates ili agents/developers **wasiamini domains zilizozalishwa na LLM kwa default**: hitaji allowlists, ownership validation, CT/RDAP checks, au human approval kabla ya matumizi ya kwanza.

Hili linaingia kwenye AI risk buckets kadhaa kwa wakati mmoja: **AI supply-chain attack**, **insecure model output**, na **rogue actions** wakati agents hutumia URL iliyobuniwa kwa hallucination bila usimamizi.

## References
- [1] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risks](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
