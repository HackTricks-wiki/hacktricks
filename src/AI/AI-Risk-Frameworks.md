# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP imebaini top 10 za udhaifu katika machine learning ambazo zinaweza kuathiri mifumo ya AI. Udhaifu hizi zinaweza kusababisha matatizo mbalimbali ya usalama, ikiwa ni pamoja na data poisoning, model inversion, na adversarial attacks. Kuelewa udhaifu hizi ni muhimu kwa kujenga mifumo salama ya AI.

Kwa orodha iliyosasishwa na ya kina ya top 10 machine learning vulnerabilities, rejea mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Mshambuliaji anaongeza mabadiliko madogo, mara nyingi yasiyoonekana, kwenye **incoming data** ili model ifanye uamuzi mbaya.\
*Mfano*: Madoa machache ya rangi kwenye stop‑sign yanamfanya gari la self‑driving "lione" sign ya speed‑limit.

- **Data Poisoning Attack**: The **training set** inachomwamo makusudi sampuli mbaya, ikimfundisha model sheria hatarishi.\
*Mfano*: Malware binaries zinamilikiwa vibaya kama "benign" katika corpus ya mafunzo ya antivirus, zikiruhusu malware iliyofanana kupitishwa baadaye.

- **Model Inversion Attack**: Kwa kujaribu outputs, mshambuliaji hujenga **reverse model** ambayo hujirkaa sifa za siri za input asilia.\
*Mfano*: Kuunda tena picha ya MRI ya mgonjwa kutoka utabiri wa model ya kugundua kansa.

- **Membership Inference Attack**: Mshambulizi hujaribu kuona kama rekodi **maalum** ilitumika wakati wa mafunzo kwa kutambua tofauti za confidence.\
*Mfano*: Kuhakiki kuwa muamala wa benki wa mtu ulijumuishwa katika data ya mafunzo ya model ya kugundua udanganyifu.

- **Model Theft**: Kuuliza mara kwa mara kunaruhusu mshambuliaji kujifunza mipaka ya uamuzi na **kuclone tabia ya model** (na IP).\
*Mfano*: Kuvuna jozi za Q&A za kutosha kutoka kwenye API ya ML‑as‑a‑Service ili kujenga model karibu sawa lokal.

- **AI Supply‑Chain Attack**: Kudhoofisha sehemu yoyote (data, libraries, pre‑trained weights, CI/CD) katika **ML pipeline** ili kuharibu models zinazoendelea.\
*Mfano*: Dependency iliyopoisia kwenye model‑hub inayosakinisha sentiment‑analysis model yenye backdoor katika apps nyingi.

- **Transfer Learning Attack**: Mantiki ya uharibu huwekwa kwenye **pre‑trained model** na huendelea hata baada ya fine‑tuning kwa kazi ya mwathiriwa.\
*Mfano*: Vision backbone yenye trigger iliyofichwa bado inabadilisha lebo baada ya kuadaptishwa kwa medical imaging.

- **Model Skewing**: Data yenye upendeleo mdogo au iliyoamilishwa vibaya **hubadilisha outputs za model** ili kufavoria ajenda ya mshambuliaji.\
*Mfano*: Kuingiza barua pepe za spam "safi" zilizoelezwa kama ham ili spam filter iruhusu barua pepe za aina hiyo baadae kupitia.

- **Output Integrity Attack**: Mshambuliaji **hubadilisha utabiri wa model wakati wa usafirishaji**, si model yenyewe, akudanganya mifumo inayofuata.\
*Mfano*: Kubadilisha hukumu ya classifier ya malware kutoka "malicious" kwenda "benign" kabla ya hatua ya file‑quarantine kuiwona.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja, yaliyolengwa kwenye **model parameters** wenyewe, mara nyingi baada ya kupata ufikiaji wa kuandika, ili kubadilisha tabia.\
*Mfano*: Kukandamiza weights kwenye model ya kugundua udanganyifu katika uzalishaji ili muamala kutoka kwa kadi fulani uruhusiwe kila wakati.


## Google SAIF Risks

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) ya Google inaelezea hatari mbalimbali zinazohusiana na mifumo ya AI:

- **Data Poisoning**: Wahalifu hubadilisha au kuingiza data za mafunzo/tuning ili kupunguza usahihi, kuweka backdoors, au kupotosha matokeo, na kuharibu uadilifu wa model katika mzunguko mzima wa data.

- **Unauthorized Training Data**: Kumeza datasets zilizochapishwa kwa hakimiliki, nyeti, au zisizoruhusiwa kunaweza kuleta wajibu wa kisheria, maadili, na utendaji kwa sababu model inajifunza kutoka kwa data ambayo haikuwezekana kutumiwa.

- **Model Source Tampering**: Udanganyifu wa supply‑chain au mfanyikazi ndani kupindua code ya model, dependencies, au weights kabla au wakati wa mafunzo unaweza kuweka mantiki iliyofichwa ambayo inabaki hata baada ya retraining.

- **Excessive Data Handling**: Udhibiti dhaifu wa retention na governance ya data hufanya mifumo kuhifadhi au kushughulikia data binafsi zaidi ya inavyohitajika, ikiongeza mfiduo na hatari za uzingatiaji.

- **Model Exfiltration**: Washambuliaji wananakili faili/weights za model, kusababisha kupoteza mali ya kiakili na kuwezesha huduma za kuiga au mashambulizi ya kufuata.

- **Model Deployment Tampering**: Watesi hubadilisha artifacts za model au miundombinu ya serving ili model inayotumika iwe tofauti na toleo lililothibitishwa, labda kubadilisha tabia.

- **Denial of ML Service**: Kufagia APIs au kutuma input “sponge” kunaweza kuchosha compute/energy na kuondoa model mtandaoni, ikifanana na mashambulizi ya DoS ya jadi.

- **Model Reverse Engineering**: Kwa kuvuna idadi kubwa ya jozi input‑output, washambuliaji wanaweza kuclone au kutafsiri model, kuchochea bidhaa za kuiga na mashambulizi ya kibinafsi ya adversarial.

- **Insecure Integrated Component**: Plugins dhaifu, agents, au huduma za upstream zinaweza kumruhusu mshambuliaji kuingiza code au kupanua vibali ndani ya pipeline ya AI.

- **Prompt Injection**: Kuunda prompts (kwa moja kwa moja au kwa njia isiyo ya moja kwa moja) ili kuficha maagizo yanayobadilisha system intent, na kufanya model ifanye amri zisizokusudiwa.

- **Model Evasion**: Input zilizoundwa kwa umakini huamsha model kutofasiri kwa usahihi, kutoa hallucinations, au kutoa maudhui yasiyoruhusiwa, zikiharibu usalama na uaminifu.

- **Sensitive Data Disclosure**: Model inafichua taarifa binafsi au za siri kutoka kwenye data yake ya mafunzo au muktadha wa mtumiaji, ikivunja faragha na kanuni.

- **Inferred Sensitive Data**: Model inatabiri sifa za kibinafsi ambazo hazikutolewa, ikileta madhara mapya ya faragha kupitia inference.

- **Insecure Model Output**: Majibu yasiyosafishwa hupitisha code hatarishi, misinformation, au maudhui yasiyofaa kwa watumiaji au mifumo inayofuata.

- **Rogue Actions**: Agents waliounganishwa kwa kujitegemea hufanya operesheni zisizokusudiwa za dunia halisi (kuandika files, API calls, ununuzi, n.k.) bila usimamizi wa kutosha wa mtumiaji.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) inatoa mfumo kamili wa kuelewa na kupunguza hatari zinazohusiana na mifumo ya AI. Inagawanya mbinu na tactic mbalimbali za mashambulizi ambazo washambuliaji wanaweza kutumia dhidi ya models za AI na pia jinsi ya kutumia mifumo ya AI kufanya mashambulizi tofauti.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Washambuliaji wananakili tokens za vikao zinazoendelea au credentials za cloud API na kuwaitisha LLM zilizohifadhiwa kwenye cloud zilizolipiwa bila idhini. Ufikiaji mara nyingi huuzwa tena kupitia reverse proxies zinazochukua akaunti ya mwathiriwa, kwa mfano deployments za "oai-reverse-proxy". Matokeo ni pamoja na hasara za kifedha, matumizi mabaya ya model nje ya sera, na kuhusishwa kwa tenant wa mwathiriwa.

TTPs:
- Kuvuna tokens kutoka kwa mashine za developers zilizo infected au browsers; kuiba siri za CI/CD; kununua cookies zilizoleak.
- Kuendesha reverse proxy inayotuma ombi kwa provider halisi, ikificha upstream key na kupaqa wateja wengi.
- Kufanya miss‑use ya base‑model endpoints ili kupita guardrails za enterprise na rate limits.

Mitigations:
- Bind tokens kwa device fingerprint, IP ranges, na client attestation; laana expires fupi na refresha kwa MFA.
- Scope keys kwa kiwango cha chini (no tool access, read‑only pale inapofaa); rotate on anomaly.
- Terminate all traffic server‑side nyuma ya policy gateway inayetekeleza safety filters, per‑route quotas, na tenant isolation.
- Monitor kwa usage patterns zisizo za kawaida (ghafla spikes za matumizi, mikoa isiyo ya kawaida, UA strings) na auto‑revoke sessions zinazoshukiwa.
- Prefer mTLS au signed JWTs zilizotolewa na IdP yako badala ya long‑lived static API keys.

## Self-hosted LLM inference hardening

Kuendesha server ya LLM lokal kwa data za siri kunaunda uso mpya wa mashambulizi tofauti na APIs zilizo kwenye cloud: inference/debug endpoints zinaweza leak prompts, serving stack kawaida inaonyesha reverse proxy, na GPU device nodes zinatoa ufikiaji kwa surfaces kubwa za `ioctl()`. Kama unafanya assessment au kuendesha huduma ya inference on‑prem, hakiki angalau mambo yafuatayo.

### Prompt leakage via debug and monitoring endpoints

Zingatia inference API kama **multi-user sensitive service**. Debug au monitoring routes zinaweza kufichua yaliyomo ya prompt, slot state, model metadata, au taarifa za queue ya ndani. Katika `llama.cpp`, endpoint ya `/slots` ni hatari hasa kwa sababu inaonyesha per‑slot state na ilikusudiwa tu kwa uchunguzi/usimamizi wa slot.

- Weka reverse proxy mbele ya inference server na **deny by default**.
- Ruhusu tu mchanganyiko sahihi wa HTTP method + path zinazohitajika na client/UI.
- Zima introspection endpoints katika backend yenyewe kadri inavyowezekana, kwa mfano `llama-server --no-slots`.
- Bind reverse proxy kwa `127.0.0.1` na uitumbe kupitia authenticated transport kama SSH local port forwarding badala ya kuifuata kwenye LAN.

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
### Rootless containers bila mtandao na UNIX sockets

Ikiwa inference daemon inasaidia kusikiliza kwenye UNIX socket, itumie badala ya TCP na endesha container ukiwa na **no network stack**:
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
- `--network none` huondoa mfiduo wa TCP/IP unaoingia/unaotoka na huzuia user-mode helpers ambazo rootless containers vingehitaji vinginevyo.
- UNIX socket inakuwezesha kutumia POSIX permissions/ACLs kwenye njia ya socket kama safu ya kwanza ya udhibiti wa ufikiaji.
- `--userns=keep-id` na rootless Podman hupunguza athari za container breakout kwa sababu container root si host root.
- Read-only model mounts hupunguza nafasi ya kuharibu modeli kutoka ndani ya container.

### Kupunguza node za kifaa za GPU

Kwa inference inayoungwa mkono na GPU, faili za `/dev/nvidia*` ni nyuso za mashambulizi za ndani zenye thamani kubwa kwa sababu zinafunua handler kubwa za driver `ioctl()` na uwezekano wa njia za usimamizi wa kumbukumbu za GPU zinazoshirikiwa.

- Usiachie `/dev/nvidia*` iwe writable kwa kila mtu.
- Kuzuia `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, udev rules, na ACLs ili UID ya container iliyopangwa tu iweze kuzifungua.
- Weka kwenye blacklist moduli zisizohitajika kama `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye host za inference zisizo na head (headless).
- Preload moduli zinazohitajika tu wakati wa boot badala ya kuwaruhusu runtime kufanya `modprobe` kwao wakati wa kuanzisha inference.

Mfano:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Kipengele muhimu cha mapitio ni **`/dev/nvidia-uvm`**. Hata kama workload haiongelei kutumia `cudaMallocManaged()`, runtime za hivi karibuni za CUDA zinaweza bado kuhitaji `nvidia-uvm`. Kwa kuwa kifaa hiki kinashirikiwa na kinashughulikia usimamizi wa virtual memory ya GPU, kitazamiwe kama eneo la kufichua data kwa tenants mbalimbali. Ikiwa inference backend inaunga mkono, Vulkan backend inaweza kuwa kompromisi ya kuvutia kwa sababu inaweza kuzuia kufichuliwa kwa `nvidia-uvm` kwenye container kabisa.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp zinapaswa kutumika kama utaratibu wa kinga kwa kina kuzunguka mchakato wa inference:

- Ruhusu tu shared libraries, model paths, socket directory, na GPU device nodes ambazo zinahitajika kwa kweli.
- Katae waziwazi capabilities zenye hatari kubwa kama `sys_admin`, `sys_module`, `sys_rawio`, na `sys_ptrace`.
- Weka model directory kuwa read-only na punguza njia zinazoweza kuandikwa (writable) kwa socket/cache za runtime pekee.
- Fuatilia denial logs kwa sababu zinatoa telemetry ya utambuzi yenye manufaa wakati model server au post-exploitation payload inajaribu kutoroka kutoka tabia inayotarajiwa.

Example AppArmor rules for a GPU-backed worker:
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
- [Unit 42 – Hatari za Code Assistant LLMs: Maudhui Yenye Madhara, Matumizi Mabaya na Udanganyifu](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Muhtasari wa mpango wa LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (kuuza tena upatikanaji wa LLM ulioporwa)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Uchunguzi wa kina kuhusu uanzishaji wa server ya LLM yenye ruhusa ndogo iliyowekwa ndani ya eneo la shirika (on-premise)](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [README ya server ya llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Spesifikisho ya CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
