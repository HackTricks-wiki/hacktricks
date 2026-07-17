# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## Udhaifu 10 Bora wa OWASP wa Machine Learning

Owasp imetambua udhaifu 10 bora wa machine learning unaoweza kuathiri mifumo ya AI. Udhaifu huu unaweza kusababisha masuala mbalimbali ya usalama, ikiwa ni pamoja na data poisoning, model inversion, na adversarial attacks. Kuelewa udhaifu huu ni muhimu katika kujenga mifumo salama ya AI.

Kwa orodha iliyosasishwa na yenye maelezo ya kina ya udhaifu 10 bora wa machine learning, rejelea mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Mshambuliaji huongeza mabadiliko madogo, ambayo mara nyingi hayaonekani, kwenye **data inayoingia** ili model ifanye uamuzi usio sahihi.\
*Mfano*: Mabaka machache ya rangi kwenye alama ya stop humfanya gari linalojiendesha "ione" alama ya kikomo cha mwendo.

- **Data Poisoning Attack**: **Training set** huchafuliwa kimakusudi kwa samples mbaya, na kuifundisha model kanuni zenye madhara.\
*Mfano*: Malware binaries huwekewa lebo kimakosa kama "benign" katika antivirus training corpus, na kuruhusu malware zinazofanana kupita baadaye.

- **Model Inversion Attack**: Kwa kuchunguza outputs, mshambuliaji huunda **reverse model** inayorejesha vipengele nyeti vya inputs za awali.\
*Mfano*: Kuunda upya picha ya MRI ya mgonjwa kutokana na predictions za model ya kutambua saratani.

- **Membership Inference Attack**: Mshambuliaji hujaribu kubaini kama **record maalum** ilitumika wakati wa training kwa kutambua tofauti za confidence.\
*Mfano*: Kuthibitisha kuwa transaction ya benki ya mtu fulani inaonekana katika training data ya model ya kutambua fraud.

- **Model Theft**: Kuuliza maswali mara kwa mara humwezesha mshambuliaji kujifunza decision boundaries na **ku-clone tabia ya model** (pamoja na IP).\
*Mfano*: Kukusanya Q&A pairs za kutosha kutoka kwa ML-as-a-Service API ili kujenga model ya ndani inayokaribia kuwa sawa.

- **AI Supply-Chain Attack**: Kuhujumu component yoyote (data, libraries, pre-trained weights, CI/CD) katika **ML pipeline** ili kuharibu models zinazotegemea hiyo component.\
*Mfano*: Dependency yenye sumu kwenye model-hub husakinisha model ya sentiment-analysis iliyo na backdoor katika apps nyingi.

- **Transfer Learning Attack**: Logic hasidi hupandikizwa kwenye **pre-trained model** na kuendelea kuwepo baada ya fine-tuning kwenye task ya mwathiriwa.\
*Mfano*: Vision backbone yenye trigger iliyofichwa bado hubadilisha labels baada ya kutumiwa kwa medical imaging.

- **Model Skewing**: Data yenye bias ndogo au iliyowekewa labels kimakosa **hubadilisha outputs za model** ili kuunga mkono ajenda ya mshambuliaji.\
*Mfano*: Kuingiza spam emails "safi" zilizo na lebo ya ham ili spam filter ziruhusu emails zinazofanana baadaye.

- **Output Integrity Attack**: Mshambuliaji **hubadilisha predictions za model wakati wa transit**, bila kubadilisha model yenyewe, na kuzipotosha downstream systems.\
*Mfano*: Kubadilisha verdict ya malware classifier kutoka "malicious" kuwa "benign" kabla ya hatua ya file-quarantine kuiona.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja na yaliyolengwa kwenye **model parameters** zenyewe, mara nyingi baada ya kupata write access, ili kubadilisha tabia.\
*Mfano*: Kubadilisha weights kwenye model ya kutambua fraud iliyo production ili transactions kutoka kwa cards fulani ziidhinishwe kila mara.


## Hatari za Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) ya Google inaeleza hatari mbalimbali zinazohusishwa na mifumo ya AI:

- **Data Poisoning**: Watu hasidi hubadilisha au kuingiza training/tuning data ili kupunguza usahihi, kupandikiza backdoors, au kupotosha matokeo, na kudhoofisha uadilifu wa model katika data-lifecycle nzima.

- **Unauthorized Training Data**: Kuingiza datasets zilizo na hakimiliki, nyeti, au zisizoruhusiwa husababisha madeni ya kisheria, kimaadili, na ya utendaji kwa sababu model hujifunza kutokana na data ambayo haikuruhusiwa kutumia.

- **Model Source Tampering**: Supply-chain au insider manipulation ya model code, dependencies, au weights kabla au wakati wa training inaweza kupandikiza logic iliyofichwa ambayo huendelea kuwepo hata baada ya retraining.

- **Excessive Data Handling**: Udhibiti dhaifu wa data-retention na governance husababisha systems kuhifadhi au kuchakata personal data nyingi kuliko inavyohitajika, na kuongeza exposure na compliance risk.

- **Model Exfiltration**: Attackers huiba model files/weights, na kusababisha kupotea kwa intellectual property na kuwezesha copy-cat services au follow-on attacks.

- **Model Deployment Tampering**: Adversaries hubadilisha model artifacts au serving infrastructure ili model inayoendesha itofautiane na toleo lililokaguliwa, jambo linaloweza kubadilisha behaviour.

- **Denial of ML Service**: Kufurika kwa APIs au kutuma inputs za “sponge” kunaweza kumaliza compute/energy na kuifanya model isiwe online, sawa na classic DoS attacks.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya input-output pairs, attackers wanaweza ku-clone au ku-distil model, na kuwezesha imitation products pamoja na customized adversarial attacks.

- **Insecure Integrated Component**: Plugins, agents, au upstream services zilizo hatarini huwawezesha attackers kuingiza code au kuongeza privileges ndani ya AI pipeline.

- **Prompt Injection**: Kuunda prompts moja kwa moja au kwa njia isiyo ya moja kwa moja ili kuficha instructions zinazobatilisha nia ya mfumo, na kuifanya model itekeleze commands zisizokusudiwa.

- **Model Evasion**: Inputs zilizoundwa kwa uangalifu huifanya model i-classify vibaya, ihallucinate, au itoe content isiyoruhusiwa, na hivyo kupunguza usalama na trust.

- **Sensitive Data Disclosure**: Model hufichua taarifa binafsi au za siri kutoka kwenye training data au user context yake, na kukiuka privacy na regulations.

- **Inferred Sensitive Data**: Model hukisia attributes binafsi ambazo hazikuwahi kutolewa, na kuunda madhara mapya ya privacy kupitia inference.

- **Insecure Model Output**: Responses ambazo hazijasafishwa hupitisha code yenye madhara, misinformation, au content isiyofaa kwa users au downstream systems.

- **Rogue Actions**: Agents zilizounganishwa kwa njia ya autonomous hutekeleza operations zisizokusudiwa katika ulimwengu halisi (file writes, API calls, purchases, n.k.) bila user oversight ya kutosha.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) hutoa framework pana ya kuelewa na kupunguza hatari zinazohusishwa na mifumo ya AI. Inaainisha attack techniques na tactics mbalimbali ambazo adversaries wanaweza kutumia dhidi ya AI models, pamoja na jinsi ya kutumia AI systems kufanya attacks tofauti.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers huiba active session tokens au cloud API credentials na kutumia LLMs za cloud-hosted zinazolipiwa bila authorization. Access mara nyingi huuzwa tena kupitia reverse proxies zinazotumia account ya mwathiriwa, kwa mfano deployments za "oai-reverse-proxy". Madhara yake ni pamoja na hasara ya kifedha, matumizi mabaya ya model kinyume na policy, na attribution kwa victim tenant.

TTPs:
- Kukusanya tokens kutoka kwenye developer machines au browsers zilizoambukizwa; kuiba CI/CD secrets; kununua leaked cookies.
- Kuanzisha reverse proxy inayoforward requests kwa provider halisi, ikificha upstream key na ku-multiplex customers wengi.
- Kutumia vibaya direct base-model endpoints ili kukwepa enterprise guardrails na rate limits.

Mitigations:
- Funga tokens kwenye device fingerprint, IP ranges, na client attestation; tekeleza expirations fupi na refresh kwa MFA.
- Punguza scope ya keys (bila tool access, read-only inapofaa); rotate inapotokea anomaly.
- Maliza traffic yote upande wa server nyuma ya policy gateway inayotekeleza safety filters, per-route quotas, na tenant isolation.
- Fuatilia unusual usage patterns (sudden spend spikes, regions zisizo za kawaida, UA strings) na auto-revoke suspicious sessions.
- Pendelea mTLS au signed JWTs zinazotolewa na IdP yako badala ya static API keys zenye muda mrefu.

## Self-hosted LLM inference hardening

Kuendesha local LLM server kwa data ya siri huunda attack surface tofauti na cloud-hosted APIs: inference/debug endpoints zinaweza ku-leak prompts, serving stack kwa kawaida hufichua reverse proxy, na GPU device nodes hutoa access kwa `ioctl()` surfaces kubwa. Ikiwa unatathmini au ku-deploy inference service ya on-prem, kagua angalau mambo yafuatayo.

### Prompt leakage kupitia debug na monitoring endpoints

Chukulia inference API kama **multi-user sensitive service**. Debug au monitoring routes zinaweza kufichua prompt contents, slot state, model metadata, au internal queue information. Katika `llama.cpp`, endpoint ya `/slots` ni nyeti hasa kwa sababu hufichua per-slot state na imekusudiwa tu kwa slot inspection/management.

- Weka reverse proxy mbele ya inference server na **deny by default**.
- Ruhusu tu exact HTTP method + path combinations zinazohitajika na client/UI.
- Zima introspection endpoints kwenye backend yenyewe inapowezekana, kwa mfano `llama-server --no-slots`.
- Bind reverse proxy kwenye `127.0.0.1` na ifikie kupitia authenticated transport kama SSH local port forwarding badala ya kuipublish kwenye LAN.

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
### Containers zisizo na root zilizo na mtandao uliowezwa na UNIX sockets

Ikiwa inference daemon inaauni kusikiliza kwenye UNIX socket, ipendelee badala ya TCP na endesha container bila **network stack**:
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
- `--network none` huondoa mwonekano wa TCP/IP wa kuingia/kutoka na huepuka wasaidizi wa user-mode ambao containers zisizo na root zingeuhitaji vinginevyo.
- UNIX socket hukuruhusu kutumia ruhusa za POSIX/ACL kwenye njia ya socket kama safu ya kwanza ya access control.
- `--userns=keep-id` na rootless Podman hupunguza athari za container breakout kwa sababu root wa container si root wa host.
- Mounts za modeli za kusomeka tu hupunguza uwezekano wa model tampering kutoka ndani ya container.

### Upunguzaji wa GPU device-node

Kwa inference inayotumia GPU, faili za `/dev/nvidia*` ni local attack surfaces zenye thamani kubwa kwa sababu zinaweka wazi `ioctl()` handlers kubwa za driver na huenda zikafichua njia za pamoja za GPU memory management.

- Usiziache `/dev/nvidia*` ziwe writable kwa kila mtu.
- Zuia `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, udev rules, na ACLs ili tu mapped container UID iweze kuzifungua.
- Blacklist modules zisizo za lazima kama vile `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye headless inference hosts.
- Preload modules zinazohitajika tu wakati wa boot badala ya kuruhusu runtime kufanya `modprobe` kwa njia ya opportunistic wakati wa inference startup.

Mfano:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jambo moja muhimu la kukagua ni **`/dev/nvidia-uvm`**. Hata kama workload haitumii waziwazi `cudaMallocManaged()`, CUDA runtimes za hivi karibuni bado zinaweza kuhitaji `nvidia-uvm`. Kwa kuwa kifaa hiki kinashirikiwa na hushughulikia usimamizi wa GPU virtual memory, kichukulie kama surface ya cross-tenant data-exposure. Ikiwa inference backend inaiunga mkono, Vulkan backend inaweza kuwa trade-off ya kuvutia kwa sababu huenda ikaepusha kabisa kuanika `nvidia-uvm` kwa container.

### LSM confinement kwa inference workers

AppArmor/SELinux/seccomp inapaswa kutumiwa kama defense in depth kuzunguka inference process:

- Ruhusu tu shared libraries, model paths, socket directory, na GPU device nodes zinazohitajika kweli.
- Kataa wazi capabilities zenye hatari kubwa kama `sys_admin`, `sys_module`, `sys_rawio`, na `sys_ptrace`.
- Weka model directory katika hali ya kusomeka pekee na punguza writable paths kwenye runtime socket/cache directories pekee.
- Fuatilia denial logs kwa sababu hutoa detection telemetry muhimu wakati model server au post-exploitation payload inapojaribu kutoroka kutoka kwenye behaviour inayotarajiwa.

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
## Phantom Squatting: Domains Zinazobuniwa na LLM kama Njia ya AI Supply-Chain

Phantom squatting ni **sawa na slopsquatting katika kiwango cha domain/URL**. Badala ya kubuni jina la package lisilokuwepo, LLM hubuni **domain ya portal, API, webhook, billing, SSO, download au support inayoonekana halali** kwa brand halisi, kisha mshambuliaji husajili namespace hiyo kabla ya binadamu au agent kuitumia.

Hili ni muhimu kwa sababu katika workflows nyingi zinazosaidiwa na AI, matokeo ya model huchukuliwa kuwa **dependency inayoaminika**:
- Developers hubandika endpoint iliyopendekezwa kwenye code au miunganisho ya CI/CD.
- AI agents huchukua documentation, schemas, APKs, ZIPs au webhook targets kiotomatiki.
- Runbooks au docs zilizozalishwa zinaweza kujumuisha URL bandia kana kwamba ni ya mamlaka halali.

### Offensive workflow

1. **Chunguza hallucination surface**: uliza maswali yanayohusiana na brand kuhusu workflows halisi kama `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook`, au portals za `mobile app`.
2. **Sanifisha candidates**: resolve URLs zilizozalishwa, badilisha majibu ya NXDOMAIN kuwa parent registerable domain, na ondoa marudio ya prompt families. Prompt corpora zinapaswa kubaki tofauti, kwa mfano kwa kuondoa near-duplicates zenye **Jaccard similarity**.
3. **Panga hallucinations zinazotabirika kwa kipaumbele**:
- **Thermal Hallucination Persistence (THP)**: domain hiyo hiyo bandia huonekana katika temperatures tofauti, ikiwemo temperature ya chini kama `T=0.1`.
- **Cross-model consensus**: familia nyingi za LLM huzalisha domain hiyo hiyo bandia.
4. **Sajili na weaponize** parent domain, kisha host phishing, fake APK/ZIP downloads, credential harvesters, malicious docs, au API endpoints zinazokusanya secrets/webhook payloads. **Pure domain-level hallucinations** ndizo rahisi zaidi ku-monetize kwa sababu mshambuliaji anadhibiti namespace yote; subdomain/path hallucinations bado zinaweza kutumiwa vibaya wakati parent iliyonormalize haijasajiliwa.
5. **Tumia vibaya zero-reputation window**: domains zilizosajiliwa hivi karibuni mara nyingi hazina historia ya blocklist, URL reputation, wala telemetry iliyokomaa, hivyo zinaweza kupita controls hadi detections zifikie. Attackers wanaweza kurefusha kipindi hiki kwa crawler-only benign responses, redirect cloaking, CAPTCHA gates, au delayed payload staging.

### Kwa nini ni hatari kwa agents

Kwa mwathiriwa wa binadamu, domain bandia kwa kawaida bado huhitaji click na hatua nyingine. Katika **agentic workflow**, LLM inaweza kuwa **lure** na pia **executor**: agent hupokea URL iliyohallucinate, huitembelea, huchanganua response, na kisha inaweza ku-leak tokens, kutekeleza instructions, kupakua dependency, au kusukuma data yenye sumu kwenye CI/CD bila human review yoyote.

### Practical attacker prompts

Prompts zenye matokeo mazuri kwa kawaida huonekana kama tasks za kawaida za enterprise badala ya phishing lures zilizo wazi:
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Ichukulie hii kama tatizo la proactive domain-monitoring, si tatizo la prompt-injection pekee:
- Unda **brand prompt corpus** na uchunguze mara kwa mara LLMs ambazo users/agents wako hutegemea.
- Hifadhi URLs zilizohallucinate na fuatilia zipi huwa stable katika temperatures/models tofauti.
- Fuatilia **Adversarial Exploitation Window (AEW)**: muda kati ya hallucination ya kwanza na usajili wa mshambuliaji. AEW chanya inamaanisha defenders wanaweza kusajili mapema, sinkhole, au kuzuia kabla ya weaponization.
- Fuatilia mabadiliko ya **NXDOMAIN → registered** kwa parent domains.
- Baada ya usajili, chunguza registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status, na ufanano wa brand assets.
- Ongeza policy gates ili agents/developers **wasiamini domains zinazozalishwa na LLM kwa default**: hitaji allowlists, ownership validation, CT/RDAP checks, au human approval kabla ya matumizi ya kwanza.

Hili linaingia kwa wakati mmoja katika makundi kadhaa ya AI risk: **AI supply-chain attack**, **insecure model output**, na **rogue actions** wakati agents hutumia URL iliyohallucinate kwa kujitegemea.

## References
- [Unit 42 – Hatari za Code Assistant LLMs: Maudhui Yenye Madhara, Matumizi Mabaya na Udanganyifu](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Muhtasari wa mpango wa LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (uuzaji upya wa ufikiaji wa LLM ulioibiwa)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Uchambuzi wa kina wa deployment ya low-privileged LLM server ya on-premise](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [README ya llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Uainishaji wa CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: Domains Zinazohallucinate na AI kama Njia ya Software Supply Chain](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: Jinsi AI Hallucinations Zinavyochochea Aina Mpya ya Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
