# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## Udhaifu 10 Bora wa Machine Learning wa OWASP

OWASP imetambua udhaifu 10 bora wa machine learning unaoweza kuathiri mifumo ya AI. Udhaifu huu unaweza kusababisha masuala mbalimbali ya usalama, ikiwa ni pamoja na data poisoning, model inversion, na adversarial attacks. Kuelewa udhaifu huu ni muhimu kwa ajili ya kujenga mifumo salama ya AI.

Kwa orodha iliyosasishwa na yenye maelezo ya kina ya udhaifu 10 bora wa machine learning, rejelea mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Mshambuliaji huongeza mabadiliko madogo, ambayo mara nyingi hayaonekani, kwenye **data inayoingia** ili model ifanye uamuzi usio sahihi.\
*Mfano*: Chembe chache za rangi kwenye alama ya kusimama huifanya gari linalojiendesha "ione" alama ya kikomo cha kasi.

- **Data Poisoning Attack**: **Training set** huchafuliwa kimakusudi kwa samples mbaya, na kuifundisha model kanuni zenye madhara.\
*Mfano*: Malware binaries huwekewa lebo kimakosa kama "benign" katika mkusanyiko wa data wa mafunzo wa antivirus, hivyo malware zinazofanana hupita baadaye.

- **Model Inversion Attack**: Kwa kuchunguza outputs, mshambuliaji huunda **reverse model** inayorejesha vipengele nyeti vya inputs za awali.\
*Mfano*: Kuunda upya picha ya MRI ya mgonjwa kutokana na predictions za model ya kugundua saratani.

- **Membership Inference Attack**: Mpinzani hujaribu kubaini kama **rekodi maalum** ilitumika wakati wa training kwa kutambua tofauti za confidence.\
*Mfano*: Kuthibitisha kuwa muamala wa benki wa mtu fulani unaonekana katika training data ya model ya kugundua udanganyifu.

- **Model Theft**: Kuuliza model mara kwa mara humwezesha mshambuliaji kujifunza decision boundaries na **kuiga tabia ya model** (pamoja na IP).\
*Mfano*: Kukusanya Q&A pairs za kutosha kutoka kwa ML‑as‑a‑Service API ili kujenga model ya karibu sawa inayotumika locally.

- **AI Supply‑Chain Attack**: Kuhujumu component yoyote (data, libraries, pre‑trained weights, CI/CD) katika **ML pipeline** ili kuharibu downstream models.\
*Mfano*: Dependency iliyotiwa sumu kwenye model-hub husakinisha model ya sentiment-analysis yenye backdoor katika apps nyingi.

- **Transfer Learning Attack**: Logic yenye madhara hupandikizwa kwenye **pre‑trained model** na huendelea kuwepo baada ya fine‑tuning kwa task ya mwathiriwa.\
*Mfano*: Vision backbone yenye trigger iliyofichwa bado hubadilisha labels baada ya kubadilishwa kwa matumizi ya medical imaging.

- **Model Skewing**: Data yenye upendeleo au iliyowekewa lebo kimakosa **hubadilisha outputs za model** ili kupendelea ajenda ya mshambuliaji.\
*Mfano*: Kuingiza spam emails "safi" zenye lebo ya ham ili spam filter ziruhusu emails zinazofanana baadaye.

- **Output Integrity Attack**: Mshambuliaji **hubadilisha model predictions wakati wa usafirishaji**, bila kubadilisha model yenyewe, na kuzipotosha downstream systems.\
*Mfano*: Kubadilisha uamuzi wa malware classifier kutoka "malicious" kuwa "benign" kabla ya hatua ya file-quarantine kuuona.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja na yaliyolengwa kwenye **model parameters** zenyewe, mara nyingi baada ya kupata write access, ili kubadilisha tabia.\
*Mfano*: Kubadilisha weights kwenye model ya kugundua udanganyifu iliyo production ili miamala kutoka kwa kadi fulani iidhinishwe kila mara.


## Hatari za Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) ya Google inaeleza hatari mbalimbali zinazohusishwa na mifumo ya AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Wahusika wenye nia mbaya hubadilisha au kuingiza training/tuning data ili kupunguza usahihi, kupandikiza backdoors, au kupotosha matokeo, na kudhoofisha uadilifu wa model katika data-lifecycle nzima.

- **Unauthorized Training Data**: Kuingiza datasets zilizo na hakimiliki, nyeti, au zisizoruhusiwa husababisha majukumu ya kisheria, kimaadili, na kiutendaji kwa sababu model hujifunza kutokana na data ambayo haikuruhusiwa kamwe kutumia.

- **Model Source Tampering**: Supply-chain au insider manipulation ya model code, dependencies, au weights kabla au wakati wa training inaweza kupachika logic iliyofichwa ambayo huendelea kuwepo hata baada ya retraining.

- **Excessive Data Handling**: Udhibiti dhaifu wa kuhifadhi data na governance husababisha systems kuhifadhi au kuchakata personal data nyingi kuliko inavyohitajika, na kuongeza exposure na compliance risk.

- **Model Exfiltration**: Washambuliaji huiba model files/weights, na kusababisha upotevu wa intellectual property pamoja na kuwezesha copy-cat services au follow-on attacks.

- **Model Deployment Tampering**: Wapinzani hubadilisha model artifacts au serving infrastructure ili model inayotumika itofautiane na toleo lililokaguliwa, na huenda wakabadilisha behaviour.

- **Denial of ML Service**: Kufurika APIs au kutuma inputs za “sponge” kunaweza kutumia kumaliza compute/energy na kuifanya model isiwe online, sawa na mashambulizi ya kawaida ya DoS.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya input-output pairs, washambuliaji wanaweza kuclone au kudistil model, na hivyo kuwezesha imitation products na customized adversarial attacks.

- **Insecure Integrated Component**: Plugins, agents, au upstream services zilizo hatarini huwawezesha washambuliaji kuingiza code au kuongeza privileges ndani ya AI pipeline.

- **Prompt Injection**: Kuunda prompts (moja kwa moja au kwa njia isiyo ya moja kwa moja) ili kusafirisha kwa siri instructions zinazopuuza system intent, na kuifanya model itekeleze commands zisizokusudiwa.

- **Model Evasion**: Inputs zilizoundwa kwa uangalifu huifanya model iainishe kimakosa, ihallucinate, au itoe content isiyoruhusiwa, na kudhoofisha safety na trust.

- **Sensitive Data Disclosure**: Model hufichua taarifa binafsi au za siri kutoka kwenye training data au user context yake, na kukiuka privacy na regulations.

- **Inferred Sensitive Data**: Model hugundua personal attributes ambazo hazikutolewa kamwe, na kuunda madhara mapya ya privacy kupitia inference.

- **Insecure Model Output**: Responses ambazo hazijasafishwa hupitisha harmful code, misinformation, au inappropriate content kwa users au downstream systems.

- **Rogue Actions**: Agents zilizounganishwa kwa njia ya autonomous hutekeleza operations zisizokusudiwa katika ulimwengu halisi (file writes, API calls, purchases, n.k.) bila user oversight ya kutosha.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) hutoa framework pana ya kuelewa na kupunguza hatari zinazohusishwa na mifumo ya AI. Inaainisha attack techniques na tactics mbalimbali ambazo adversaries wanaweza kutumia dhidi ya AI models, pamoja na jinsi ya kutumia mifumo ya AI kutekeleza mashambulizi mbalimbali.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Washambuliaji huiba active session tokens au cloud API credentials na kuinvoke cloud-hosted LLMs zinazolipiwa bila authorization. Access mara nyingi huuzwa tena kupitia reverse proxies zinazotumia account ya mwathiriwa, kwa mfano deployments za "oai-reverse-proxy". Madhara yanajumuisha hasara ya kifedha, matumizi mabaya ya model nje ya policy, na attribution kwa victim tenant.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Kukusanya tokens kutoka kwenye developer machines au browsers zilizoambukizwa; kuiba CI/CD secrets; kununua cookies zilizovuja.<sup>[[5]](#references)</sup>
- Kuanzisha reverse proxy inayoforward requests kwa provider halisi, kuficha upstream key na ku-multiplex customers wengi.<sup>[[5]](#references)[[7]](#references)</sup>
- Kutumia vibaya direct base-model endpoints ili kupita enterprise guardrails na rate limits.<sup>[[4]](#references)</sup>

Mitigations:
- Funga tokens kwa device fingerprint, IP ranges, na client attestation; tumia expirations fupi na refresh yenye MFA.
- Punguza scope ya keys kadiri iwezekanavyo (bila tool access, read-only inapowezekana); zungusha keys unapogundua anomaly.
- Maliza traffic yote upande wa server nyuma ya policy gateway inayotekeleza safety filters, per-route quotas, na tenant isolation.
- Fuatilia unusual usage patterns (sudden spend spikes, maeneo yasiyo ya kawaida, UA strings) na u-revoke suspicious sessions automatically.
- Pendelea mTLS au signed JWTs zinazotolewa na IdP yako badala ya static API keys za muda mrefu.

## Kuimarisha usalama wa self-hosted LLM inference

Kuendesha local LLM server kwa data ya siri huunda attack surface tofauti na cloud-hosted APIs: inference/debug endpoints zinaweza kuvuja prompts, serving stack kwa kawaida hufichua reverse proxy, na GPU device nodes hutoa access kwa `ioctl()` surfaces kubwa. Ikiwa unafanya assessment au ku-deploy inference service ya on-prem, kagua angalau vipengele vifuatavyo.<sup>[[8]](#references)</sup>

### Prompt leakage kupitia debug na monitoring endpoints

Chukulia inference API kama **multi-user sensitive service**. Debug au monitoring routes zinaweza kufichua prompt contents, slot state, model metadata, au internal queue information. Katika `llama.cpp`, endpoint ya `/slots` ni nyeti hasa kwa sababu hufichua per-slot state na imekusudiwa tu kwa slot inspection/management.<sup>[[8]](#references)</sup>

- Weka reverse proxy mbele ya inference server na **ukatae kwa default**.
- Ruhusu pekee mchanganyiko halisi wa HTTP method + path unaohitajika na client/UI.
- Zima introspection endpoints kwenye backend yenyewe inapowezekana, kwa mfano `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Bind reverse proxy kwa `127.0.0.1` na uifikishe kupitia authenticated transport kama SSH local port forwarding badala ya kuichapisha kwenye LAN.

Mfano wa allowlist kwa kutumia nginx:
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
### Containers zisizo na rootless zenye kutokuwa na mtandao na UNIX sockets

Ikiwa inference daemon inaunga mkono kusikiliza kwenye UNIX socket, ipendelee hiyo badala ya TCP na endesha container ikiwa na **network stack**: <sup>[[8]](#references)</sup>
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
- `--network none` huondoa mwonekano wa inbound/outbound TCP/IP na huepuka user-mode helpers ambazo rootless containers zingehitaji vinginevyo.
- UNIX socket hukuruhusu kutumia POSIX permissions/ACLs kwenye socket path kama safu ya kwanza ya access control.
- `--userns=keep-id` na rootless Podman hupunguza athari za container breakout kwa sababu container root si host root.
- Read-only model mounts hupunguza uwezekano wa model tampering kutoka ndani ya container.

### Kupunguza GPU device-node

Kwa inference inayotumia GPU, faili za `/dev/nvidia*` ni attack surfaces muhimu za ndani kwa sababu zinafichua `ioctl()` handlers kubwa za driver na uwezekano wa shared GPU memory-management paths.<sup>[[8]](#references)</sup>

- Usiachie `/dev/nvidia*` zikiwa world writable.
- Zuia `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, udev rules, na ACLs ili tu mapped container UID iweze kuzifungua.
- Blacklist modules zisizo za lazima kama vile `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye headless inference hosts.
- Preload modules zinazohitajika pekee wakati wa boot badala ya kuruhusu runtime kuzifanyia `modprobe` opportunistically wakati wa inference startup.

Mfano:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Jambo moja muhimu la kukagua ni **`/dev/nvidia-uvm`**. Hata kama workload haitumii waziwazi `cudaMallocManaged()`, CUDA runtimes za hivi karibuni bado zinaweza kuhitaji `nvidia-uvm`. Kwa sababu device hii inashirikiwa na inashughulikia usimamizi wa GPU virtual memory, ichukulie kama sehemu ya cross-tenant data-exposure. Ikiwa inference backend inaiunga mkono, Vulkan backend inaweza kuwa trade-off ya kuvutia kwa sababu huenda ikaepusha kuifanya container ionyeshe `nvidia-uvm` kabisa.<sup>[[8]](#references)</sup>

### LSM confinement kwa inference workers

AppArmor/SELinux/seccomp zinapaswa kutumiwa kama defense in depth kuzunguka inference process:<sup>[[8]](#references)</sup>

- Ruhusu shared libraries, model paths, socket directory, na GPU device nodes zinazohitajika pekee.
- Kataa waziwazi capabilities zenye hatari kubwa kama vile `sys_admin`, `sys_module`, `sys_rawio`, na `sys_ptrace`.
- Weka model directory katika hali ya read-only na punguza writable paths kwa runtime socket/cache directories pekee.
- Fuatilia denial logs kwa sababu hutoa detection telemetry muhimu wakati model server au post-exploitation payload inapojaribu kutoka kwenye behaviour inayotarajiwa.

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
## Phantom Squatting: Domains Zilizohallucinate na LLM kama Vector ya AI Supply-Chain

Phantom squatting ni **sawa na slopsquatting katika kiwango cha domain/URL**. Badala ya kuhallucinate jina la package ambalo halipo, LLM inahallucinate **domain inayoweza kuaminika ya portal, API, webhook, billing, SSO, download au support** ya brand halisi, kisha mshambuliaji anasajili namespace hiyo kabla ya binadamu au agent kuitumia.<sup>[[12]](#references)[[13]](#references)</sup>

Hili ni muhimu kwa sababu katika workflows nyingi zinazosaidiwa na AI, matokeo ya model huchukuliwa kama **dependency inayoaminika**:
- Developers hubandika endpoint iliyopendekezwa kwenye code au integrations za CI/CD.
- AI agents hufetch documentation, schemas, APKs, ZIPs au webhook targets kiotomatiki.
- Runbooks au docs zilizozalishwa zinaweza kuingiza URL fake kana kwamba ni ya mamlaka.

### Mtiririko wa mashambulizi

1. **Chunguza hallucination surface**: uliza maswali yanayolenga brand kuhusu workflows halisi kama `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook`, au portal za `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalise candidates**: resolve URLs zilizozalishwa, badilisha majibu ya NXDOMAIN kuwa parent registerable domain, na ondoa prompt families zinazojirudia. Prompt corpora zinapaswa kubaki diverse, kwa mfano kwa kuondoa near-duplicates zenye **Jaccard similarity**.
3. **Panga hallucinations zinazotabirika kwa kipaumbele**:
- **Thermal Hallucination Persistence (THP)**: domain fake ileile huonekana katika temperatures mbalimbali, ikiwemo temperature ya chini kama `T=0.1`.
- **Cross-model consensus**: familia nyingi za LLM hutengeneza domain fake ileile.
4. **Sajili na weaponize** parent domain, kisha host phishing, fake APK/ZIP downloads, credential harvesters, malicious docs, au API endpoints zinazokusanya secrets/webhook payloads. **Pure domain-level hallucinations** ndizo rahisi zaidi ku-monetize kwa sababu mshambuliaji anadhibiti namespace yote; subdomain/path hallucinations bado zinaweza kutumiwa vibaya wakati parent iliyonormalise haijasajiliwa.
5. **Tumia zero-reputation window**: domains zilizosajiliwa hivi karibuni mara nyingi hazina historia ya blocklist, URL reputation, wala telemetry iliyokomaa, hivyo zinaweza kupita controls hadi detections zifikie. Attackers wanaweza kurefusha window hii kwa crawler-only benign responses, redirect cloaking, CAPTCHA gates, au delayed payload staging.

### Kwa nini ni hatari kwa agents

Kwa victim binadamu, domain fake kwa kawaida bado inahitaji click na hatua nyingine. Kwa **agentic workflow**, LLM inaweza kuwa **lure** na **executor** kwa pamoja: agent hupokea URL iliyohallucinate, huifetch, huchanganua response, na kisha inaweza ku-leak tokens, kutekeleza instructions, kudownload dependency, au kusukuma data yenye sumu kwenye CI/CD bila human review yoyote.<sup>[[12]](#references)</sup>

### Attacker prompts za vitendo

Prompts zenye yield kubwa kwa kawaida huonekana kama tasks za kawaida za enterprise badala ya lures za wazi za phishing:<sup>[[12]](#references)</sup>
- “What is the payment sandbox URL for `<brand>` integrations?”
- “What webhook endpoint should I use for `<brand>` build notifications?”
- “Where is the employee benefits / billing / SSO portal for `<brand>`?”
- “Give me the direct Android APK or desktop client download for `<brand>`.”

### Defensive inversion

Chukulia hili kama tatizo la proactive domain-monitoring, si tatizo la prompt-injection pekee:<sup>[[12]](#references)</sup>
- Tengeneza **brand prompt corpus** na mara kwa mara probe LLMs ambazo users/agents wako hutegemea.
- Hifadhi URLs zilizohallucinate na fuatilia ni zipi zilizo stable katika temperatures/models mbalimbali.
- Fuatilia **Adversarial Exploitation Window (AEW)**: muda kati ya hallucination ya kwanza na usajili wa mshambuliaji. AEW chanya inamaanisha defenders wanaweza kusajili mapema, kusinkhole, au kuzuia mapema kabla ya weaponization.
- Fuatilia mabadiliko ya **NXDOMAIN → registered** kwa parent domains.
- Wakati wa usajili, chunguza registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status, na ufanano wa brand assets.
- Ongeza policy gates ili agents/developers **wasiamini domains zilizozalishwa na LLM kwa default**: hitaji allowlists, ownership validation, CT/RDAP checks, au human approval kabla ya matumizi ya kwanza.

Hili linaingia kwenye AI risk buckets kadhaa kwa wakati mmoja: **AI supply-chain attack**, **insecure model output**, na **rogue actions** wakati agents wanapotumia URL iliyohallucinate kwa kujitegemea.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – Risks za Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Stolen Cloud Credentials Zilizotumika katika New AI Attack](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Muhtasari wa LLMJacking scheme – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
