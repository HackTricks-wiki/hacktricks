# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp imebaini udhaifu 10 kuu wa machine learning unaoweza kuathiri mifumo ya AI. Udhaifu hizi zinaweza kusababisha masuala mbalimbali ya usalama, ikiwa ni pamoja na data poisoning, model inversion, na adversarial attacks. Kuelewa udhaifu hizi ni muhimu kwa kujenga mifumo ya AI yenye usalama.

Kwa orodha iliyosasishwa na ya kina ya top 10 machine learning vulnerabilities, rejea mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Mshambuliaji anaongeza mabadiliko madogo, mara nyingi yasiyoonekana, kwa **incoming data** ili model ifanye uamuzi mbaya.\
*Mfano*: Madoa machache ya rangi kwenye stop‑sign yanamshawishi self‑driving car "kuuona" sign ya kiwango cha mwendo wa kasi.

- **Data Poisoning Attack**: **training set** inachafuliwa kwa makusudi na sampuli mbaya, ikifundisha model sheria hatarishi.\
*Mfano*: Malware binaries zinatambulishwa vibaya kama "benign" katika corpus ya mafunzo ya antivirus, kuruhusu malware kama hiyo kupita baadaye.

- **Model Inversion Attack**: kwa kujaribu outputs, mshambuliaji hujenga **reverse model** inayoweza kurekebisha sifa nyeti za inputs asili.\
*Mfano*: Kuunda tena picha ya MRI ya mgonjwa kutoka kwenye utabiri wa model ya kugundua saratani.

- **Membership Inference Attack**: Mwadui hujaribu kujua kama **specific record** ilitumika wakati wa mafunzo kwa kutambua tofauti za confidence.\
*Mfano*: Kutathmini kuwa muamala wa benki wa mtu uko katika data za mafunzo ya model ya kugundua udanganyifu.

- **Model Theft**: Kuuliza mara kwa mara kunamruhusu mshambuliaji kujifunza mipaka ya uamuzi na **clone the model's behavior** (na IP).\
*Mfano*: Kuharibu jozi za Q&A za ML‑as‑a‑Service API ili kujenga model karibu sawa kwa matumizi ya ndani.

- **AI Supply‑Chain Attack**: Kudhuru kipengele chochote (data, libraries, pre‑trained weights, CI/CD) katika **ML pipeline** ili kuharibu models zinazofuata.\
*Mfano*: Dependency iliyo poisoned kwenye model‑hub inasakinisha sentiment‑analysis model iliyowekwa backdoor katika apps nyingi.

- **Transfer Learning Attack**: Mantiki hasi inaingizwa katika **pre‑trained model** na inadumu hata baada ya fine‑tuning kwenye kazi ya mwathiriwa.\
*Mfano*: vision backbone yenye trigger iliyofichwa bado ina badilisha labels baada ya kuadaptishwa kwa medical imaging.

- **Model Skewing**: Data yenye ubaguzi mdogo au iliyo na label vibaya **inahamisha outputs za model** ili kupendelea agenda ya mshambuliaji.\
*Mfano*: Kuingiza barua pepe za spam "safi" zilizo labeled kama ham ili spam filter iruhusu barua sawa za baadaye kupita.

- **Output Integrity Attack**: Mshambuliaji **anabadilisha model predictions in transit**, sio model yenyewe, akidanganya mifumo inayofuata.\
*Mfano*: Kubadilisha hukumu ya classifier ya malware kutoka "malicious" hadi "benign" kabla ya hatua ya file‑quarantine kuiziona.

- **Model Poisoning** --- Mabadiliko ya moja‑kwa‑moja, yaliyolengwa kwenye **model parameters** yenyewe, mara nyingi baada ya kupata write access, ili kubadilisha tabia.\
*Mfano*: Kurekebisha weights kwenye model ya kugundua udanganyifu inayofanya miamala ya kadi fulani kuidhinishwa kila mara.

## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) inaelezea hatari mbalimbali zinazohusiana na mifumo ya AI:

- **Data Poisoning**: Watu wenye nia mbaya hubadilisha au kuingiza training/tuning data ili kudhoofisha accuracy, kuingiza backdoors, au kuibadilisha matokeo, na hivyo kuharibu uadilifu wa model katika mzunguko mzima wa data.

- **Unauthorized Training Data**: Kuingiza datasets zenye hakimiliki, nyeti, au zisizoruhusiwa huleta wajibu wa kisheria, maadili, na utendaji kwa sababu model inajifunza kutoka kwa data ambayo haikuruhusiwa kutumia.

- **Model Source Tampering**: Uharibifu wa supply‑chain au uingiliaji kutoka kwa insider wa code ya model, dependencies, au weights kabla au wakati wa mafunzo unaweza kuweka mantiki fiche inayodumu hata baada ya retraining.

- **Excessive Data Handling**: Udhibiti duni wa data‑retention na governance hufanya mifumo kuhifadhi au kusindika data binafsi zaidi ya inavyohitajika, kuongezea exposure na hatari za compliance.

- **Model Exfiltration**: Washambuliaji huiba model files/weights, kusababisha hasara ya intellectual property na kuwezesha huduma za kunakili au mashambulizi ya kuja baadaye.

- **Model Deployment Tampering**: Wadau wanaweza kubadilisha artifacts za model au serving infrastructure ili model inayoendesha iwe tofauti na toleo lililothibitishwa, na hivyo kubadilisha behaviour.

- **Denial of ML Service**: Kufunika APIs au kutuma inputs za “sponge” kunaweza kumaliza compute/energy na kuifanya model kushindwa, ikifanana na mashambulizi ya DoS ya kawaida.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya input‑output pairs, washambuliaji wanaweza clone au distil model, kuchochea bidhaa za kuiga na mashambulizi maalum ya adversarial.

- **Insecure Integrated Component**: Plugins, agents, au huduma za upstream zilizo na udhaifu zinawaruhusu washambuliaji kuingiza code au kuinua idhini ndani ya AI pipeline.

- **Prompt Injection**: Kutengeneza prompts (moja kwa moja au kwa njia isiyo ya moja kwa moja) kuingiza maelekezo yanayoweza kupita system intent, kufanya model ifanye amri ambazo hazikutarajiwa.

- **Model Evasion**: Inputs zilizoundwa kwa uangalifu zinaweza kusababisha model ku‑mis‑classify, hallucinate, au kutoa maudhui yasiyoruhusiwa, zikidhoofisha usalama na uaminifu.

- **Sensitive Data Disclosure**: Model inaweka wazi taarifa za faragha au siri kutoka kwa training data yake au muktadha wa mtumiaji, ikikiuka faragha na kanuni.

- **Inferred Sensitive Data**: Model hutambua sifa za kibinafsi ambazo hazikutolewa kabisa, kuleta madhara mapya ya faragha kupitia inference.

- **Insecure Model Output**: Majibu yasiyosafishwa hupitisha code hatarishi, misinformation, au maudhui yasiyofaa kwa watumiaji au mifumo inayofuata.

- **Rogue Actions**: Agents zilizoingizwa kwa uendeshaji wa kujitegemea hufanya shughuli zisizotarajiwa za dunia halisi (kuandika files, API calls, kununua, nk.) bila usimamizi wa kutosha kutoka kwa mtumiaji.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) inatoa framework kamili ya kuelewa na kupunguza hatari zinazohusiana na mifumo ya AI. Inakataqwa mbinu na tactics mbalimbali za mashambulizi ambazo wadukuzi wanaweza kutumia dhidi ya models ya AI na pia jinsi ya kutumia mifumo ya AI kutekeleza mashambulizi tofauti.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Washambuliaji huiba active session tokens au cloud API credentials na kuitumia paid, cloud‑hosted LLMs bila idhini. Access mara nyingi inauzwa tena kupitia reverse proxies zinazoficha akaunti ya mwathiriwa, mfano deployments za "oai-reverse-proxy". Matokeo ni pamoja na hasara za kifedha, matumizi mabaya ya model nje ya sera, na attribution kwa tenant mwenyeji.

TTPs:
- Harvest tokens kutoka kwa developer machines au browsers zilizo infected; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy ambayo inapeleka requests kwa provider halisi, ikificha upstream key na kuwasha multiplexing ya wateja wengi.
- Abuse direct base-model endpoints ili bypass enterprise guardrails na rate limits.

Mitigations:
- Bind tokens kwa device fingerprint, IP ranges, na client attestation; enforce short expirations na refresh na MFA.
- Scope keys minimally (no tool access, read‑only pale inapofaa); rotate on anomaly.
- Terminate all traffic server‑side nyuma ya policy gateway inayotekeleza safety filters, per‑route quotas, na tenant isolation.
- Monitor kwa unusual usage patterns (sudden spend spikes, atypical regions, UA strings) na auto‑revoke suspicious sessions.
- Prefer mTLS au signed JWTs issued by your IdP kuliko long‑lived static API keys.

## Self-hosted LLM inference hardening

Kukimbia local LLM server kwa data za siri kunaunda uso wa shambulizi tofauti na cloud‑hosted APIs: inference/debug endpoints yanaweza leak prompts, serving stack kawaida inaonyesha reverse proxy, na GPU device nodes zinatoa access kwa uso mkubwa wa `ioctl()`. Ikiwa unafanyia tathmini au kupeleka on‑prem inference service, pitia angalau pointi zifuatazo.

### Prompt leakage via debug and monitoring endpoints

Tafuta inference API kama **multi-user sensitive service**. Debug au monitoring routes zinaweza kufichua maudhui ya prompt, slot state, model metadata, au taarifa za internal queue. Katika `llama.cpp`, endpoint ya `/slots` ni maalum hatarishi kwa sababu inaonyesha per‑slot state na inakusudiwa tu kwa slot inspection/management.

- Weka reverse proxy mbele ya inference server na **deny by default**.
- Ruhusu tu exact HTTP method + path combinations zinazohitajika na client/UI.
- Zima introspection endpoints katika backend yenyewe pale inapowezekana, kwa mfano `llama-server --no-slots`.
- Bind reverse proxy kwa `127.0.0.1` na uitoe kupitia transport yenye authentication kama SSH local port forwarding badala ya kuichapisha kwenye LAN.

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
### Rootless containers zisizo na mtandao na UNIX sockets

Ikiwa inference daemon inaunga mkono kusikiliza kwenye UNIX socket, tumia hilo badala ya TCP na endesha container bila **safu ya mtandao**:
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
Manufaa:
- `--network none` huondoa mfichuko wa TCP/IP wa kuingia/kuondoka na huzuia user-mode helpers ambazo rootless containers vingetumia vinginevyo.
- UNIX socket inakuruhusu kutumia ruhusa za POSIX/ACLs kwenye njia ya socket kama safu ya kwanza ya udhibiti wa upatikanaji.
- `--userns=keep-id` na rootless Podman hupunguza athari za container breakout kwa sababu root ya container si root ya host.
- Mounts za modeli zenye read-only hupunguza uwezekano wa kuharibu au kubadilisha modeli kutoka ndani ya container.

### Kupunguza device-node za GPU

Kwa inference inayotegemea GPU, faili za `/dev/nvidia*` ni nyuso za kushambuliwa za thamani kubwa kwa ndani kwa sababu zinafunua handlers kubwa za driver za `ioctl()` na pengine njia za usimamizi wa kumbukumbu ya GPU zilizoshirikiwa.

- Usiwaache `/dev/nvidia*` ziandikwe na kila mtu.
- Weka vikwazo kwenye `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, udev rules, na ACLs ili UID ya container iliyopangwa tu ndiyo iweze kuziweka wazi.
- Blacklist modules zisizohitajika kama `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye hosts za inference zisizo na GUI.
- Preload tu modules zinazohitajika wakati wa boot badala ya kumruhusu runtime kuzifanyia `modprobe` kwa fursa wakati wa kuanzisha inference.

Mfano:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Moja ya pointi muhimu za ukaguzi ni **`/dev/nvidia-uvm`**. Hata kama workload haiongei wazi `cudaMallocManaged()`, runtimes za hivi karibuni za CUDA zinaweza bado kuhitaji `nvidia-uvm`. Kwa kuwa kifaa hiki kinashirikiwa na kinashughulikia usimamizi wa virtual memory ya GPU, chukulia kama uso wa kufichuliwa kwa data kati ya tenants. Ikiwa inference backend inaunga mkono, Vulkan backend inaweza kuwa trade-off ya kuvutia kwa sababu inaweza kuepuka kufichua `nvidia-uvm` kwenye container kabisa.

### Kuzuia LSM kwa inference workers

AppArmor/SELinux/seccomp zinapaswa kutumika kama ulinzi wa kina kuzunguka mchakato wa inference:

- Ruhusu tu shared libraries, model paths, socket directory, na GPU device nodes ambazo zinahitajika kweli.
- Kataa waziwazi capabilities zenye hatari kubwa kama `sys_admin`, `sys_module`, `sys_rawio`, na `sys_ptrace`.
- Weka model directory kuwa read-only na panga njia zinazoweza kuandikwa (writable) kwa runtime socket/cache directories pekee.
- Fuatilia denial logs kwa sababu zinatoa telemetry muhimu za utambuzi wakati model server au post-exploitation payload inajaribu kutoroka tabia inayotarajiwa.

Mfano wa sheria za AppArmor kwa mfanyakazi aliyeungwa mkono na GPU:
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
## Marejeo
- [Unit 42 – Hatari za Code Assistant LLMs: Yaliyomo Yenye Hatari, Matumizi Mabaya na Udanganyifu](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Muhtasari wa mpango wa LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (kuuza tena ufikiaji wa LLM ulioporwa)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Uchunguzi wa kina juu ya usakinishaji wa server ya LLM ya on-premise yenye ruhusa ndogo](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
