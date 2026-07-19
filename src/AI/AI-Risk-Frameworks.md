# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp imetambua vulnerabilities 10 kuu za machine learning zinazoweza kuathiri mifumo ya AI. Vulnerabilities hizi zinaweza kusababisha masuala mbalimbali ya usalama, ikiwemo data poisoning, model inversion, na adversarial attacks. Kuelewa vulnerabilities hizi ni muhimu kwa ajili ya kujenga mifumo salama ya AI.

Kwa orodha iliyosasishwa na yenye maelezo ya kina ya vulnerabilities 10 kuu za machine learning, tazama mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Mshambuliaji huongeza mabadiliko madogo, ambayo mara nyingi hayaonekani, kwenye **data inayoingia** ili model ifanye uamuzi usio sahihi.\
*Mfano*: Madoa machache ya rangi kwenye alama ya kusimama huifanya gari linalojiendesha "ione" alama ya kikomo cha kasi.

- **Data Poisoning Attack**: **training set** huchafuliwa kimakusudi kwa samples mbaya, na kuifundisha model kanuni hatari.\
*Mfano*: Malware binaries huwekewa lebo kimakosa kama "benign" kwenye antivirus training corpus, na kuruhusu malware zinazofanana zipite baadaye.

- **Model Inversion Attack**: Kwa kuchunguza outputs, mshambuliaji huunda **reverse model** inayorejesha features nyeti za inputs za awali.\
*Mfano*: Kuunda upya picha ya MRI ya mgonjwa kutokana na predictions za model ya kutambua cancer.

- **Membership Inference Attack**: Mpinzani hujaribu kubaini ikiwa **record mahususi** ilitumika wakati wa training kwa kutambua tofauti za confidence.\
*Mfano*: Kuthibitisha kuwa muamala wa benki wa mtu fulani unaonekana kwenye training data ya model ya kutambua fraud.

- **Model Theft**: Kuuliza queries mara kwa mara humwezesha mshambuliaji kujifunza decision boundaries na **ku-clone tabia ya model** (pamoja na IP).\
*Mfano*: Kukusanya Q&A pairs za kutosha kutoka kwenye ML-as-a-Service API ili kujenga model ya karibu sawa inayofanya kazi locally.

- **AI Supply-Chain Attack**: Kuhatarisha component yoyote (data, libraries, pre-trained weights, CI/CD) ndani ya **ML pipeline** ili kuharibu downstream models.\
*Mfano*: Dependency iliyo poisoned kwenye model-hub husakinisha model ya sentiment-analysis yenye backdoor kwenye apps nyingi.

- **Transfer Learning Attack**: Logic hasidi hupandikizwa kwenye **pre-trained model** na hubaki baada ya fine-tuning kwenye task ya mwathiriwa.\
*Mfano*: Vision backbone yenye trigger iliyofichwa bado hubadilisha labels baada ya kurekebishwa kwa medical imaging.

- **Model Skewing**: Data yenye bias iliyofichwa au labels zisizo sahihi **hubadilisha outputs za model** ili kuunga mkono ajenda ya mshambuliaji.\
*Mfano*: Kuingiza spam emails "safi" zilizo na label ya ham ili spam filter iruhusu emails zinazofanana baadaye.

- **Output Integrity Attack**: Mshambuliaji **hubadilisha predictions za model wakati wa transit**, si model yenyewe, na kuzipotosha downstream systems.\
*Mfano*: Kubadilisha hukumu ya malware classifier kutoka "malicious" kuwa "benign" kabla ya file-quarantine stage kuiona.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja na yanayolengwa kwenye **model parameters** zenyewe, mara nyingi baada ya kupata write access, ili kubadilisha tabia.\
*Mfano*: Kubadilisha weights kwenye model ya kutambua fraud iliyo production ili miamala kutoka kwa cards fulani iidhinishwe kila mara.


## Google SAIF Risks

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) ya Google inaeleza risks mbalimbali zinazohusishwa na mifumo ya AI:

- **Data Poisoning**: Wahusika hasidi hubadilisha au kuingiza training/tuning data ili kupunguza usahihi, kupandikiza backdoors, au kupotosha matokeo, na kudhoofisha uadilifu wa model katika data-lifecycle nzima.

- **Unauthorized Training Data**: Kuingiza datasets zenye copyright, nyeti, au zisizoruhusiwa huleta liabilities za kisheria, kimaadili, na kiutendaji kwa sababu model hujifunza kutoka kwa data ambayo haikuruhusiwa kamwe kutumia.

- **Model Source Tampering**: Supply-chain au insider manipulation ya model code, dependencies, au weights kabla au wakati wa training inaweza kupachika logic iliyofichwa ambayo hubaki hata baada ya retraining.

- **Excessive Data Handling**: Vidhibiti dhaifu vya data-retention na governance husababisha mifumo kuhifadhi au kuchakata personal data nyingi kuliko inavyohitajika, na kuongeza exposure na compliance risk.

- **Model Exfiltration**: Attackers huiba model files/weights, na kusababisha upotevu wa intellectual property pamoja na kuwezesha copy-cat services au follow-on attacks.

- **Model Deployment Tampering**: Adversaries hubadilisha model artifacts au serving infrastructure ili model inayoendesha itofautiane na toleo lililothibitishwa, na hivyo kubadilisha behaviour.

- **Denial of ML Service**: Kufurika APIs au kutuma inputs za “sponge” kunaweza kumaliza compute/energy na kuifanya model isiwe online, kama ilivyo kwenye DoS attacks za kawaida.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya input-output pairs, attackers wanaweza ku-clone au ku-distil model, na kuwezesha imitation products na customized adversarial attacks.

- **Insecure Integrated Component**: Plugins, agents, au upstream services zenye vulnerabilities huwawezesha attackers kuingiza code au kuongeza privileges ndani ya AI pipeline.

- **Prompt Injection**: Kuunda prompts (moja kwa moja au kwa njia isiyo ya moja kwa moja) ili kusafirisha kwa siri instructions zinazopuuza system intent, na kuifanya model itekeleze commands zisizokusudiwa.

- **Model Evasion**: Inputs zilizoundwa kwa uangalifu huifanya model itoe classification isiyo sahihi, hallucinate, au kutoa content isiyoruhusiwa, na kudhoofisha safety na trust.

- **Sensitive Data Disclosure**: Model hufichua taarifa za private au confidential kutoka kwenye training data au user context yake, na kukiuka privacy na regulations.

- **Inferred Sensitive Data**: Model hugundua personal attributes ambazo hazikuwahi kutolewa, na kuunda madhara mapya ya privacy kupitia inference.

- **Insecure Model Output**: Responses ambazo hazijasafishwa hupitisha harmful code, misinformation, au inappropriate content kwa users au downstream systems.

- **Rogue Actions**: Agents zilizounganishwa kwa njia ya autonomous hutekeleza operations zisizokusudiwa katika ulimwengu halisi (file writes, API calls, purchases, n.k.) bila user oversight ya kutosha.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) hutoa framework pana ya kuelewa na kupunguza risks zinazohusishwa na mifumo ya AI. Inaweka katika makundi attack techniques na tactics mbalimbali ambazo adversaries wanaweza kutumia dhidi ya AI models, na pia jinsi ya kutumia mifumo ya AI kutekeleza attacks mbalimbali.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers huiba active session tokens au cloud API credentials na kutumia cloud-hosted LLMs zinazolipiwa bila authorization. Mara nyingi access huuzwa tena kupitia reverse proxies zinazoelekeza traffic ya victim’s account, kwa mfano deployments za "oai-reverse-proxy". Madhara yake ni pamoja na financial loss, matumizi ya model kinyume na policy, na attribution kwa victim tenant.

TTPs:
- Kusanya tokens kutoka kwenye developer machines au browsers zilizoambukizwa; iba CI/CD secrets; nunua cookies zilizovuja.
- Simamisha reverse proxy inayotuma requests kwa provider halisi, ikificha upstream key na kuunganisha customers wengi.
- Tumia vibaya direct base-model endpoints ili kupita enterprise guardrails na rate limits.

Mitigations:
- Funga tokens kwenye device fingerprint, IP ranges, na client attestation; tumia expirations fupi na refresh yenye MFA.
- Punguza scope ya keys kwa kiwango cha chini (bila tool access, read-only inapofaa); zungusha keys kunapokuwa na anomaly.
- Elekeza traffic yote upande wa server nyuma ya policy gateway inayotekeleza safety filters, per-route quotas, na tenant isolation.
- Fuatilia usage patterns zisizo za kawaida (sudden spend spikes, regions zisizozoeleka, UA strings) na auto-revoke sessions zenye shaka.
- Pendelea mTLS au signed JWTs zinazotolewa na IdP yako badala ya static API keys za muda mrefu.

## Self-hosted LLM inference hardening

Kuendesha local LLM server kwa confidential data huunda attack surface tofauti na cloud-hosted APIs: inference/debug endpoints zinaweza kuvuja prompts, serving stack kwa kawaida hufichua reverse proxy, na GPU device nodes hutoa access kwa `ioctl()` surfaces kubwa. Ikiwa unatathmini au ku-deploy on-prem inference service, kagua angalau mambo yafuatayo.

### Prompt leakage via debug and monitoring endpoints

Chukulia inference API kama **multi-user sensitive service**. Debug au monitoring routes zinaweza kufichua prompt contents, slot state, model metadata, au internal queue information. Kwenye `llama.cpp`, endpoint ya `/slots` ni nyeti hasa kwa sababu hufichua per-slot state na imekusudiwa tu kwa slot inspection/management.

- Weka reverse proxy mbele ya inference server na **ukatae kwa default**.
- Ruhusu tu exact HTTP method + path combinations zinazohitajika na client/UI.
- Zima introspection endpoints kwenye backend yenyewe inapowezekana, kwa mfano `llama-server --no-slots`.
- Bind reverse proxy kwenye `127.0.0.1` na expose kupitia authenticated transport kama SSH local port forwarding badala ya kuichapisha kwenye LAN.

Mfano wa allowlist yenye nginx:
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
### Kontena za rootless zisizo na network na UNIX sockets

Ikiwa inference daemon inaunga mkono kusikiliza kwenye UNIX socket, ipendelee badala ya TCP na endesha kontena bila **network stack**:
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
- `--network none` huondoa mwanya wa TCP/IP wa kuingia/kutoka na huepuka wasaidizi wa user-mode ambao rootless containers zingehitaji vinginevyo.
- UNIX socket hukuruhusu kutumia POSIX permissions/ACLs kwenye njia ya socket kama safu ya kwanza ya udhibiti wa ufikiaji.
- `--userns=keep-id` na rootless Podman hupunguza athari za container breakout kwa sababu container root si host root.
- Model mounts za kusoma pekee hupunguza uwezekano wa model tampering kutoka ndani ya container.

### Kupunguza GPU device nodes

Kwa inference inayotumia GPU, faili za `/dev/nvidia*` ni attack surfaces za ndani zenye thamani kubwa kwa sababu zinaweka wazi handlers kubwa za driver za `ioctl()` na huenda njia za pamoja za usimamizi wa kumbukumbu ya GPU.

- Usiziache `/dev/nvidia*` ziwe writable kwa kila mtu.
- Zuia `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, udev rules, na ACLs ili tu container UID iliyomapishwa iweze kuzifungua.
- Blacklist modules zisizo za lazima kama `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye headless inference hosts.
- Preload modules zinazohitajika tu wakati wa boot badala ya kuruhusu runtime kuziendesha `modprobe` kwa fursa wakati wa kuanzisha inference.

Mfano:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jambo moja muhimu la kukagua ni **`/dev/nvidia-uvm`**. Hata kama workload haitumii waziwazi `cudaMallocManaged()`, CUDA runtimes za hivi karibuni bado zinaweza kuhitaji `nvidia-uvm`. Kwa sababu device hii inashirikiwa na hushughulikia usimamizi wa GPU virtual memory, ichukulie kama sehemu ya hatari ya data-exposure kati ya tenants. Ikiwa inference backend inaiunga mkono, Vulkan backend inaweza kuwa trade-off ya kuvutia kwa sababu huenda ikaepusha kabisa ku-expose `nvidia-uvm` kwa container.

### LSM confinement kwa inference workers

AppArmor/SELinux/seccomp zinapaswa kutumiwa kama defense in depth kuzunguka inference process:

- Ruhusu shared libraries, model paths, socket directory, na GPU device nodes zinazohitajika kwa kweli pekee.
- Kataa waziwazi capabilities zenye hatari kubwa kama `sys_admin`, `sys_module`, `sys_rawio`, na `sys_ptrace`.
- Weka model directory katika hali ya read-only na punguza writable paths kwa runtime socket/cache directories pekee.
- Fuatilia denial logs kwa sababu hutoa detection telemetry muhimu wakati model server au post-exploitation payload inapojaribu kutoroka tabia inayotarajiwa.

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
## Phantom Squatting: Domains Zinazobuniwa na LLM kama Vector ya AI Supply-Chain

Phantom squatting ni **sawa na domain/URL ya slopsquatting**. Badala ya kubuni jina la package lisilokuwepo, LLM hubuni **portal, API, webhook, billing, SSO, download au support domain** inayoonekana halali kwa brand halisi, kisha mshambuliaji husajili namespace hiyo kabla ya binadamu au agent kuitumia.

Hili ni muhimu kwa sababu katika workflows nyingi zinazosaidiwa na AI, matokeo ya model huchukuliwa kama **trusted dependency**:
- Developers hubandika endpoint iliyopendekezwa kwenye code au miunganisho ya CI/CD.
- AI agents hufetch documentation, schemas, APKs, ZIPs au webhook targets kiotomatiki.
- Runbooks au docs zilizotengenezwa zinaweza kuingiza fake URL kana kwamba ni authoritative.

### Offensive workflow

1. **Chunguza hallucination surface**: uliza maswali yanayohusu brand mahususi kuhusu workflows halisi kama `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook`, au `mobile app` portals.
2. **Normalize candidates**: resolve generated URLs, badilisha majibu ya NXDOMAIN kuwa parent registerable domain, na deduplicate prompt families. Prompt corpora zinapaswa kubaki diverse, kwa mfano kwa kuondoa near-duplicates zenye **Jaccard similarity**.
3. **Prioritize predictable hallucinations**:
- **Thermal Hallucination Persistence (THP)**: fake domain ileile huonekana kwenye temperatures mbalimbali, ikiwemo temperature ya chini kama `T=0.1`.
- **Cross-model consensus**: familia nyingi za LLM huzalisha fake domain ileile.
4. **Register and weaponize** parent domain, kisha host phishing, fake APK/ZIP downloads, credential harvesters, malicious docs, au API endpoints zinazokusanya secrets/webhook payloads. **Pure domain-level hallucinations** ndizo rahisi zaidi ku-monetize kwa sababu mshambuliaji anadhibiti namespace nzima; subdomain/path hallucinations bado zinaweza kutumiwa vibaya wakati normalized parent haijasajiliwa.
5. **Exploit the zero-reputation window**: domains zilizosajiliwa hivi karibuni mara nyingi hazina blocklist history, URL reputation, na telemetry iliyokomaa, hivyo zinaweza kupita controls hadi detections ziwafikie. Attackers wanaweza kurefusha window hii kwa crawler-only benign responses, redirect cloaking, CAPTCHA gates, au delayed payload staging.

### Why it is dangerous for agents

Kwa victim wa binadamu, fake domain kwa kawaida bado huhitaji click na hatua nyingine. Kwa **agentic workflow**, LLM inaweza kuwa **lure** na pia **executor**: agent hupokea hallucinated URL, huifetch, huparse response, na kisha inaweza ku-leak tokens, kutekeleza instructions, kudownload dependency, au kusukuma poisoned data kwenye CI/CD bila human review yoyote.

### Practical attacker prompts

High-yield prompts kwa kawaida huonekana kama kazi za kawaida za enterprise badala ya phishing lures zilizo wazi:
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Ichukulie hii kama tatizo la proactive domain-monitoring, si tatizo la prompt-injection pekee:
- Unda **brand prompt corpus** na mara kwa mara probe LLMs ambazo users/agents wako hutegemea.
- Hifadhi hallucinated URLs na fuatilia zipi ni stable kwenye temperatures/models mbalimbali.
- Fuatilia **Adversarial Exploitation Window (AEW)**: muda kati ya hallucination ya kwanza na attacker registration. Positive AEW inamaanisha defenders wanaweza pre-register, sinkhole, au pre-block kabla ya weaponization.
- Fuatilia mabadiliko ya **NXDOMAIN → registered** kwa parent domains.
- Wakati wa registration, triage registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status, na brand-asset similarity.
- Ongeza policy gates ili agents/developers **wasiamini LLM-generated domains kwa default**: hitaji allowlists, ownership validation, CT/RDAP checks, au human approval kabla ya matumizi ya kwanza.

Hii inaingia kwenye AI risk buckets kadhaa kwa wakati mmoja: **AI supply-chain attack**, **insecure model output**, na **rogue actions** wakati agents zinatumia hallucinated URL kiotomatiki.

## References
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
