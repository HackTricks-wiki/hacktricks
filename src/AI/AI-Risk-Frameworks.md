# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP imetambua udhaifu 10 wa juu wa machine learning unaoweza kuathiri mifumo ya AI. Udhaifu huu unaweza kusababisha masuala mbalimbali ya usalama, yakiwemo data poisoning, model inversion na adversarial attacks. Kuelewa udhaifu huu ni muhimu katika kujenga mifumo salama ya AI.

Kwa orodha iliyosasishwa na ya kina ya udhaifu 10 wa juu wa machine learning, rejelea mradi wa [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Mshambulizi huongeza mabadiliko madogo, ambayo mara nyingi hayaonekani, kwenye **data inayoingia** ili modeli ifanye uamuzi usio sahihi.\
    *Mfano*: Matone machache ya rangi kwenye alama ya stop hudanganya gari linalojiendesha na kulifanya "kuona" alama ya kikomo cha mwendo.

- **Data Poisoning Attack**: **Training set** huchafuliwa kimakusudi kwa sampuli zisizofaa, na hivyo kufundisha modeli kanuni hatari.\
*Mfano*: Faili hasidi za programu hasidi huwekewa lebo isiyo sahihi ya "benign" kwenye mkusanyiko wa data ya mafunzo ya antivirus, na hivyo kuruhusu programu hasidi zinazofanana kupenya baadaye.

- **Model Inversion Attack**: Kwa kuchunguza matokeo, mshambulizi huunda **reverse model** inayorejesha sifa nyeti za ingizo asilia.\
*Mfano*: Kuunda upya picha ya MRI ya mgonjwa kutokana na utabiri wa modeli ya kugundua saratani.

- **Membership Inference Attack**: Mshambuliaji hujaribu kubaini kama **rekodi mahususi** ilitumika wakati wa mafunzo kwa kutambua tofauti za confidence.\
*Mfano*: Kuthibitisha kuwa muamala wa benki wa mtu fulani upo kwenye data ya mafunzo ya modeli ya kugundua ulaghai.

- **Model Theft**: Kuuliza modeli mara kwa mara humwezesha mshambuliaji kujifunza decision boundaries na **kunakili tabia ya modeli** (na IP).\
*Mfano*: Kukusanya Q&A pairs za kutosha kutoka kwenye API ya ML-as-a-Service ili kujenga modeli ya ndani inayokaribiana sana na ya awali.

- **AI Supply‑Chain Attack**: Kukiuka sehemu yoyote (data, libraries, pre-trained weights, CI/CD) ya **ML pipeline** ili kuharibu modeli zinazofuata.\
*Mfano*: Dependency iliyotiwa sumu kwenye model-hub husakinisha modeli ya sentiment-analysis yenye backdoor kwenye programu nyingi.

- **Transfer Learning Attack**: Mantiki hasidi hupandikizwa kwenye **pre-trained model** na kubaki baada ya fine-tuning kwa kazi ya mwathiriwa.\
*Mfano*: Vision backbone yenye trigger iliyofichwa bado hubadilisha lebo baada ya kurekebishwa kwa ajili ya picha za kimatibabu.

- **Model Skewing**: Data yenye upendeleo mdogo au lebo zisizo sahihi **hubadilisha matokeo ya modeli** ili kuunga mkono ajenda ya mshambuliaji.\
*Mfano*: Kuingiza barua pepe za spam "safi" zilizowekewa lebo ya ham, ili kichujio cha spam kiruhusu barua pepe zinazofanana kupita baadaye.

- **Output Integrity Attack**: Mshambuliaji **hubadilisha utabiri wa modeli wakati wa uwasilishaji**, si modeli yenyewe, na hivyo kudanganya mifumo inayofuata.\
*Mfano*: Kubadilisha uamuzi wa malware classifier kutoka "malicious" hadi "benign" kabla mfumo wa kuweka faili karantini haujauona.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja na lengwa kwenye **model parameters** zenyewe, mara nyingi baada ya kupata ruhusa ya kuandika, ili kubadilisha tabia.\
*Mfano*: Kurekebisha weights za modeli ya kugundua ulaghai iliyo production ili miamala kutoka kwa kadi fulani iidhinishwe kila wakati.


## Hatari za Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) ya Google inaeleza hatari mbalimbali zinazohusishwa na mifumo ya AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Watu hasidi hubadilisha au kuingiza data ya mafunzo/tuning ili kupunguza usahihi, kupandikiza backdoors au kupotosha matokeo, na hivyo kudhoofisha uadilifu wa modeli katika mzunguko mzima wa maisha ya data.

- **Unauthorized Training Data**: Kutumia datasets zenye hakimiliki, nyeti au zisizoruhusiwa husababisha hatari za kisheria, kimaadili na kiutendaji kwa sababu modeli hujifunza kutokana na data ambayo haikuruhusiwa kuitumia.

- **Model Source Tampering**: Uingiliaji wa supply-chain au wa mtu wa ndani kwenye code, dependencies au weights za modeli kabla au wakati wa mafunzo unaweza kupandikiza mantiki iliyofichwa ambayo hubaki hata baada ya mafunzo kufanywa upya.

- **Excessive Data Handling**: Udhibiti dhaifu wa uhifadhi na usimamizi wa data husababisha mifumo kuhifadhi au kuchakata data binafsi zaidi ya inavyohitajika, na kuongeza hatari za ufichuzi na kutofuata kanuni.

- **Model Exfiltration**: Washambuliaji huiba faili/weights za modeli, na kusababisha upotevu wa intellectual property na kuwezesha huduma zinazoiga modeli au mashambulizi yanayofuata.

- **Model Deployment Tampering**: Washambuliaji hubadilisha model artifacts au serving infrastructure ili modeli inayoendeshwa iwe tofauti na toleo lililokaguliwa, na hivyo huenda kubadilisha tabia yake.

- **Denial of ML Service**: Kufurika kwa maombi kwenye APIs au kutuma ingizo za “sponge” kunaweza kumaliza rasilimali za compute/energy na kuizima modeli, sawa na mashambulizi ya kawaida ya DoS.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya jozi za ingizo na matokeo, washambuliaji wanaweza kunakili au kudistil modeli, na hivyo kuwezesha bidhaa za kuiga na adversarial attacks zilizobinafsishwa.

- **Insecure Integrated Component**: Plugins, agents au huduma za upstream zilizo hatarini huwaruhusu washambuliaji kuingiza code au kuongeza ruhusa ndani ya AI pipeline.

- **Prompt Injection**: Kuunda prompts (moja kwa moja au kwa njia isiyo ya moja kwa moja) ili kupitisha kwa siri maagizo yanayobatilisha nia ya mfumo, na kuifanya modeli itekeleze amri zisizotarajiwa.

- **Model Evasion**: Ingizo zilizoundwa kwa umakini huifanya modeli iainishe vibaya, itoe hallucinations au maudhui yaliyopigwa marufuku, na hivyo kudhoofisha usalama na uaminifu.

- **Sensitive Data Disclosure**: Modeli hufichua taarifa binafsi au za siri kutoka kwenye data yake ya mafunzo au muktadha wa mtumiaji, na kukiuka faragha na kanuni.

- **Inferred Sensitive Data**: Modeli hukisia sifa binafsi ambazo hazikuwahi kutolewa, na kusababisha madhara mapya ya faragha kupitia inference.

- **Insecure Model Output**: Majibu ambayo hayajasafishwa hupitisha code hatari, taarifa potofu au maudhui yasiyofaa kwa watumiaji au mifumo inayofuata.

- **Rogue Actions**: Agents zilizounganishwa kwa uhuru hutekeleza shughuli zisizotarajiwa katika ulimwengu halisi (kuandika faili, kuita API, kufanya manunuzi, n.k.) bila uangalizi wa kutosha wa mtumiaji.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) hutoa mfumo wa kina wa kuelewa na kupunguza hatari zinazohusishwa na mifumo ya AI. Inaweka katika makundi mbinu na mikakati mbalimbali ya mashambulizi ambayo washambuliaji wanaweza kutumia dhidi ya modeli za AI, na pia jinsi ya kutumia mifumo ya AI kutekeleza mashambulizi mbalimbali.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Washambuliaji huiba session tokens zinazotumika au cloud API credentials na kutumia LLM za kulipia zinazopangishwa kwenye cloud bila idhini. Mara nyingi ufikiaji huo huuzwa tena kupitia reverse proxies zinazotumia akaunti ya mwathiriwa, kama vile deployment za "oai-reverse-proxy". Madhara yake ni pamoja na hasara ya kifedha, matumizi ya modeli kinyume na sera, na kuhusishwa kwa shughuli hizo na tenant ya mwathiriwa.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Kukusanya tokens kutoka kwenye mashine za developer au browsers zilizoambukizwa; kuiba secrets za CI/CD; kununua cookies zilizovuja.<sup>[[5]](#references)</sup>
- Kuanzisha reverse proxy inayotuma maombi kwa mtoa huduma halisi, kuficha upstream key na kushughulikia wateja wengi kwa pamoja.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Kutumia vibaya endpoints za base-model za moja kwa moja ili kukwepa guardrails za biashara na vikomo vya kasi.<sup>[[4]](#references)</sup>

Mitigations:
- Funga tokens kwenye device fingerprint, safu za IP na client attestation; weka muda mfupi wa kuisha na uhitaji MFA ili kuzisasisha.
- Punguza ruhusa za keys kadiri iwezekanavyo (bila ufikiaji wa tools, read-only inapowezekana); zizungushe panapotokea hitilafu isiyo ya kawaida.
- Elekeza trafiki yote upande wa server kupitia policy gateway inayotekeleza safety filters, quotas kwa kila route na utenganishaji wa tenants.
- Fuatilia mifumo isiyo ya kawaida ya matumizi (ongezeko la ghafla la gharama, maeneo yasiyo ya kawaida, UA strings) na ubatilishe kiotomatiki sessions zinazotiliwa shaka.
- Pendelea mTLS au signed JWTs zinazotolewa na IdP yako badala ya API keys tuli za muda mrefu.

## Kuimarisha inference ya LLM inayopangishwa ndani

Kuendesha server ya LLM ya ndani kwa data za siri huleta attack surface tofauti na APIs zinazopangishwa kwenye cloud: endpoints za inference/debug zinaweza kuvuja prompts, stack ya serving kwa kawaida hufichua reverse proxy, na GPU device nodes hutoa ufikiaji wa `ioctl()` surfaces nyingi. Ikiwa unakagua au kupeleka huduma ya inference ya on-prem, pitia angalau mambo yafuatayo.<sup>[[8]](#references)</sup>

### Kuvuja kwa prompts kupitia endpoints za debug na monitoring

Chukulia inference API kama **huduma nyeti ya watumiaji wengi**. Routes za debug au monitoring zinaweza kufichua maudhui ya prompt, hali ya slot, metadata ya modeli au taarifa za ndani za foleni. Katika `llama.cpp`, endpoint ya `/slots` ni nyeti hasa kwa sababu hufichua hali ya kila slot na imekusudiwa tu kukagua/kudhibiti slots.<sup>[[8]](#references)</sup>

- Weka reverse proxy mbele ya inference server na **kataza kwa chaguo-msingi**.
- Ruhusu tu mchanganyiko mahususi wa HTTP method + path unaohitajika na client/UI.
- Zima introspection endpoints kwenye backend yenyewe inapowezekana, kwa mfano `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Funga reverse proxy kwenye `127.0.0.1` na uifikie kupitia njia ya usafirishaji iliyothibitishwa kama SSH local port forwarding badala ya kuichapisha kwenye LAN.

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

### Containers zisizo na root zisizo na mtandao na UNIX sockets

Ikiwa daemon ya inference inaweza kusikiliza kwenye UNIX socket, pendelea kutumia hiyo badala ya TCP na endesha container bila **network stack**:<sup>[[8]](#references)</sup>

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
- `--network none` huondoa uwezekano wa kuwasiliana kupitia TCP/IP zinazoingia/kutoka na huepusha kutumia wasaidizi wa user-mode ambao vinginevyo kontena zisizo na root zingehitaji.
- UNIX socket hukuwezesha kutumia ruhusa/ACL za POSIX kwenye njia ya socket kama safu ya kwanza ya udhibiti wa ufikiaji.
- `--userns=keep-id` na Podman isiyo na root hupunguza athari za kuvunja kontena kwa sababu root ya kontena si root ya host.
- Mounts za modeli za kusoma pekee hupunguza uwezekano wa modeli kuchezewa kutoka ndani ya kontena.

Kwa deployments zinazoendelea, vikwazo vilevile vinaweza kuwakilishwa kama vitengo vya Podman Quadlet. Ikiwa ufikiaji wa GPU unatolewa kupitia Container Device Interface, weka maelezo ya kifaa cha CDI kuwa finyu iwezekanavyo badala ya kufichua kila nodi ya accelerator.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Kupunguza idadi ya nodi za vifaa vya GPU

Kwa inference inayotumia GPU, faili za `/dev/nvidia*` ni maeneo muhimu ya mashambulizi ya ndani kwa sababu zinafichua vishikizo vikubwa vya driver `ioctl()` na huenda njia za usimamizi wa kumbukumbu ya GPU zinazoshirikiwa.<sup>[[8]](#references)</sup>

- Usiziache `/dev/nvidia*` zikiwa na ruhusa za kuandikwa na kila mtu.
- Zuia `nvidia`, `nvidiactl`, na `nvidia-uvm` kwa kutumia `NVreg_DeviceFileUID/GID/Mode`, sheria za udev, na ACL ili UID ya kontena iliyopangwa pekee iweze kuzifungua.
- Zima moduli zisizohitajika kama vile `nvidia_drm`, `nvidia_modeset`, na `nvidia_peermem` kwenye host za inference zisizo na skrini.
- Pakia mapema moduli zinazohitajika tu wakati wa kuwasha badala ya kuiacha runtime iendeshe `modprobe` kwa fursa wakati wa kuanzisha inference.

Mfano:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Jambo moja muhimu la kukagua ni **`/dev/nvidia-uvm`**. Hata kama workload haitumii `cudaMallocManaged()` moja kwa moja, CUDA runtimes za hivi karibuni bado zinaweza kuhitaji `nvidia-uvm`. Kwa kuwa kifaa hiki kinashirikiwa na hushughulikia usimamizi wa kumbukumbu pepe ya GPU, kichukulie kama eneo linaloweza kusababisha data kufichuliwa kati ya tenants. Ikiwa inference backend inaiunga mkono, Vulkan backend inaweza kuwa chaguo la kuvutia kwa sababu inaweza kuepusha kabisa kuipa container ufikiaji wa `nvidia-uvm`.<sup>[[8]](#references)</sup>

### Kuweka wafanyakazi wa inference chini ya vizuizi vya LSM

AppArmor/SELinux/seccomp inapaswa kutumiwa kama safu ya ziada ya ulinzi kuzunguka mchakato wa inference:<sup>[[8]](#references)</sup>

- Ruhusu tu shared libraries, njia za model, saraka ya socket na nodi za kifaa cha GPU zinazohitajika.
- Kataa waziwazi uwezo ulio hatarishi sana kama `sys_admin`, `sys_module`, `sys_rawio` na `sys_ptrace`.
- Weka saraka ya model katika hali ya kusomwa tu na uruhusu uandishi kwenye njia za saraka za runtime socket/cache pekee.
- Fuatilia denial logs kwa sababu hutoa telemetry muhimu ya ugunduzi pale model server au payload ya post-exploitation inapojaribu kukwepa tabia inayotarajiwa.

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

## Phantom Squatting: Vikoa Vinavyobuniwa na LLM kama Njia ya Kushambulia Mnyororo wa Ugavi wa AI

Phantom squatting ni **sawa na slopsquatting kwa vikoa/URL**. Badala ya kubuni jina la kifurushi lisilokuwepo, LLM hubuni **kikoa cha portal, API, webhook, billing, SSO, download au support** kinachoonekana kuwa halisi kwa chapa iliyopo, na mshambuliaji husajili nafasi hiyo ya majina kabla ya binadamu au agent kuitumia.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Hili ni muhimu kwa sababu katika mifumo mingi ya kazi inayosaidiwa na AI, matokeo ya modeli huchukuliwa kama **tegemezi linaloaminika**:
- Wasanidi programu hubandika endpoint iliyopendekezwa kwenye msimbo au miunganisho ya CI/CD.
- AI agents hupakua nyaraka, schemas, APKs, ZIPs au lengwa za webhook kiotomatiki.
- Runbooks au nyaraka zinazozalishwa zinaweza kujumuisha URL bandia kana kwamba ni rasmi.

### Mtiririko wa mashambulizi

1. **Chunguza sehemu zinazoweza kubuniwa**: uliza maswali yanayohusu chapa kuhusu mifumo halisi ya kazi kama portal za `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` au `mobile app`.<sup>[[12]](#references)</sup>
2. **Sanifisha zinazowezekana**: tatua URL zilizozalishwa, geuza majibu ya NXDOMAIN kuwa kikoa cha juu zaidi kinachoweza kusajiliwa, na ondoa marudio ya familia za prompt. Prompt corpus zinapaswa kuwa tofauti; kwa mfano, ondoa zinazokaribiana kwa kutumia **Jaccard similarity**.
3. **Panga kwa kipaumbele uvumbuzi unaotabirika**:
   - **Thermal Hallucination Persistence (THP)**: kikoa kilekile cha bandia hujitokeza katika viwango tofauti vya joto, ikiwemo joto la chini kama `T=0.1`.
   - **Makubaliano kati ya modeli**: familia nyingi za LLM huzalisha kikoa kilekile cha bandia.
4. **Sajili na geuza kikoa cha juu kuwa silaha**, kisha weka phishing, upakuaji wa APK/ZIP bandia, zana za kukusanya taarifa za kuingia, nyaraka hasidi au endpoints za API zinazokusanya siri/payload za webhook. **Vikoa vinavyobuniwa pekee** ndivyo rahisi zaidi kupata faida kwa sababu mshambuliaji anadhibiti nafasi nzima ya majina; uvumbuzi wa subdomain/path bado unaweza kutumiwa vibaya ikiwa kikoa cha juu kilichosanifishwa hakijasajiliwa.
5. **Tumia fursa ya kipindi ambacho sifa haijulikani**: vikoa vipya vilivyosajiliwa mara nyingi havina historia ya blocklist, sifa ya URL na telemetry iliyokomaa, hivyo vinaweza kupita udhibiti hadi utambuzi uanze kufanya kazi. Washambuliaji wanaweza kurefusha kipindi hiki kwa majibu salama kwa crawler pekee, kuficha uelekezaji upya, vizuizi vya CAPTCHA au kuchelewesha uandaaji wa payload.

### Kwa nini ni hatari kwa agents

Kwa mwathiriwa binadamu, kikoa bandia kwa kawaida bado kinahitaji kubofya na hatua nyingine. Katika **mchakato wa kazi unaoendeshwa na agent**, LLM inaweza kuwa **chambo** na pia **mtekelezaji**: agent hupokea URL iliyobuniwa, huitembelea, huchanganua jibu, kisha inaweza kuvuja tokeni, kutekeleza maagizo, kupakua tegemezi au kusukuma data yenye sumu kwenye CI/CD bila ukaguzi wowote wa binadamu.<sup>[[12]](#references)</sup>

### Prompts za vitendo za mshambuliaji

Prompts zenye matokeo mengi kwa kawaida huonekana kama kazi za kawaida za biashara badala ya chambo za wazi za phishing:<sup>[[12]](#references)</sup>
- “URL ya payment sandbox kwa miunganisho ya `<brand>` ni ipi?”
- “Nitumie endpoint gani ya webhook kwa arifa za build za `<brand>`?”
- “Portal ya employee benefits / billing / SSO ya `<brand>` iko wapi?”
- “Nipe APK ya Android au upakuaji wa moja kwa moja wa desktop client ya `<brand>`.”

### Mbinu ya kujilinda

Chukulia hili kama tatizo la ufuatiliaji wa vikoa wa mapema, si tatizo la prompt-injection pekee:<sup>[[12]](#references)</sup>
- Tengeneza **brand prompt corpus** na uchunguze mara kwa mara LLM ambazo watumiaji/agents wako huzitegemea.
- Hifadhi URL zilizobuniwa na ufuatilie zile zinazobaki thabiti katika viwango tofauti vya joto/modeli.
- Fuatilia **Adversarial Exploitation Window (AEW)**: muda kati ya uvumbuzi wa kwanza na usajili wa mshambuliaji. AEW chanya humaanisha watetezi wanaweza kusajili mapema, kuelekeza kwenye sinkhole au kuzuia kabla ya kutumiwa kwa mashambulizi.
- Fuatilia mabadiliko ya **NXDOMAIN → kimesajiliwa** kwa vikoa vya juu.
- Kikoa kinaposajiliwa, kagua msajili, tarehe ya kuundwa, nameservers, ufichaji wa taarifa za mmiliki, maudhui ya ukurasa, picha za skrini, hali ya ukurasa wa matangazo na ufanano wa vipengee vya chapa.
- Ongeza vizuizi vya sera ili agents/wasanidi **wasiamini vikoa vilivyozalishwa na LLM kwa chaguomsingi**: hitaji orodha za ruhusa, uthibitishaji wa umiliki, ukaguzi wa CT/RDAP au idhini ya binadamu kabla ya matumizi ya kwanza.

Hili linahusiana na makundi kadhaa ya hatari za AI kwa wakati mmoja: **shambulio la mnyororo wa ugavi wa AI**, **matokeo ya modeli yasiyo salama**, na **vitendo vya kiholela** wakati agents zinapotumia URL iliyobuniwa kiotomatiki.

## References

- [1] [OWASP Top 10 ya Udhaifu wa Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Mfumo Salama wa AI) – Hatari](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS: Matriki ya Vitisho](https://atlas.mitre.org/)
- [4] [Unit 42 – Hatari za Code Assistant LLMs: Maudhui Yenye Madhara, Matumizi Mabaya na Udanganyifu](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Sifa za Kuingia Zilizoibwa za Cloud Zatumika katika Shambulio Jipya la AI](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Muhtasari wa mpango wa LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (kuuza tena ufikiaji wa LLM ulioibwa)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Uchambuzi wa kina wa uwekaji wa seva ya LLM ya ndani yenye ruhusa ndogo](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README ya seva ya llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Vipimo vya CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Vikoa Vinavyobuniwa na AI kama Njia ya Kushambulia Mnyororo wa Ugavi wa Programu](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: Jinsi Uvumbuzi wa AI Unavyochochea Aina Mpya ya Mashambulizi ya Mnyororo wa Ugavi](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
