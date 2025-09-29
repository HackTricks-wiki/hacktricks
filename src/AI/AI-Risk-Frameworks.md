# Hatari za AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Udhaifu za Machine Learning

Owasp imebaini udhaifu 10 muhimu za machine learning zinazoweza kuathiri mifumo ya AI. Udhaifu hizi zinaweza kusababisha masuala mbalimbali ya usalama, ikiwa ni pamoja na data poisoning, model inversion, na adversarial attacks. Kuelewa udhaifu hizi ni muhimu kwa kujenga mifumo ya AI iliyo salama.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: Mshambuliaji anaongeza mabadiliko madogo, mara nyingi yasiyoonekana, kwenye **incoming data** ili model ifanye uamuzi mbaya.\
*Mfano*: Doa chache za rangi kwenye alama ya stop‑sign zinafanya gari linaloendesha kwa kujitegemea "kuona" alama ya speed‑limit.

- **Data Poisoning Attack**: **training set** inachafwa kwa makusudi na sampuli mbaya, ikimfundisha model kanuni zenye madhara.\
*Mfano*: Malware binaries zinatajwa kuwa "benign" katika korpasi ya mafunzo ya antivirus, zikimruhusu malware sawa kupita baadaye.

- **Model Inversion Attack**: Kwa kuchunguza outputs, mshambuliaji anajenga **reverse model** inayorekebusha vigezo nyeti vya ingizo za awali.\
*Mfano*: Kutengeneza upya picha ya MRI ya mgonjwa kutoka kwa utabiri wa model ya ugunduzi wa saratani.

- **Membership Inference Attack**: Aduversary hufanya mtihani kuona kama **specific record** ilitumiwa wakati wa mafunzo kwa kugundua tofauti za confidence.\
*Mfano*: Kuhakiki kwamba muamala wa benki wa mtu unaonekana katika data ya mafunzo ya model ya kugundua udanganyifu.

- **Model Theft**: Kuuliza kwa kurudia huruhusu mshambuliaji kujifunza mipaka ya uamuzi na **clone the model's behavior** (na IP).\
*Mfano*: Kukusanya jozi za Q&A kutoka kwa ML‑as‑a‑Service API hadi kujenga model karibu sawa kwa ndani.

- **AI Supply‑Chain Attack**: Kuingiliwa kwa sehemu yoyote (data, libraries, pre‑trained weights, CI/CD) katika **ML pipeline** kunaharibisha models zinazofuata.\
*Mfano*: Dependency iliyopoisheni kwenye model‑hub kusanidi model ya sentiment‑analysis iliyo na backdoor kwenye apps nyingi.

- **Transfer Learning Attack**: Mantiki hatarishi imepandikizwa katika **pre‑trained model** na inaendelea kuwepo hata baada ya fine‑tuning kwa kazi ya mwathiriwa.\
*Mfano*: Vision backbone yenye trigger iliyofichwa bado inabadilisha lebo baada ya kuadaptishwa kwa imaging ya matibabu.

- **Model Skewing**: Data yenye upendeleo kidogo au iliyolebeshwa vibaya **shifts the model's outputs** ili kuipendezesha ajenda ya mshambuliaji.\
*Mfano*: Kuingiza barua pepe za spam "safi" zilizotambulishwa kama ham ili spam filter iruhusu barua pepe sawa za baadaye kupita.

- **Output Integrity Attack**: Mshambuliaji **alters model predictions in transit**, sio model yenyewe, akudanganya mifumo inayofuata.\
*Mfano*: Kubadilisha hukumu ya classifier ya malware kutoka "malicious" kuwa "benign" kabla ya hatua ya file‑quarantine kuitazamia.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja, yaliyolengwa, kwenye **model parameters** yenyewe, mara nyingi baada ya kupata haki ya kuandika, ili kubadilisha tabia.\
*Mfano*: Kufanyia tweak weights kwenye model ya kugundua udanganyifu inayotumika ili miamala kutoka kwa kadi fulani ikubaliwe kila wakati.


## Google SAIF Hatari

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) inaelezea hatari mbalimbali zinazohusiana na mifumo ya AI:

- **Data Poisoning**: Watu wenye nia mbaya hubadilisha au kuingiza data za mafunzo/tuning ili kudhoofisha usahihi, kuweka backdoors, au kulebeshya matokeo, hivyo kuharibu uadilifu wa model kote katika mzunguko wa data.

- **Unauthorized Training Data**: Kumeza seti za data zilizo na hakimiliki, nyeti, au zisizoruhusiwa kunasababisha masuala ya kisheria, maadili, na utendaji kwa sababu model inajifunza kutoka kwa data ambayo haikupewa ruhusa kutumia.

- **Model Source Tampering**: Kuingiliwa kwa supply‑chain au manipulations za insider kwa code ya model, dependencies, au weights kabla au wakati wa mafunzo kunaweza kuweka mantiki iliyofichwa inayodumu hata baada ya retraining.

- **Excessive Data Handling**: Udhibiti dhaifu wa kuhifadhi data na governance husababisha mifumo kuhifadhi au kusindika data binafsi zaidi ya inavyohitajika, kuongeza mfiduo na hatari ya uzingatiaji.

- **Model Exfiltration**: Washambuliaji huchoma faili/weights za model, kusababisha upotevu wa mali ya kiakili na kuwezesha huduma za kopi au mashambulizi ya kuendelea.

- **Model Deployment Tampering**: Aduversary hubadilisha artifacts za model au miundombinu ya serving ili model inayotumika iwe tofauti na toleo lililotathminiwa, inaweza kubadilisha tabia.

- **Denial of ML Service**: Kuchomeka APIs au kutuma input za "sponge" kunaweza kuisha rasilimali za compute/energy na kupelekea model kuzimwa, ikifanana na mashambulizi ya DoS ya jadi.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya jozi input‑output, washambuliaji wanaweza clone au distil model, kuendesha bidhaa za kumnakili na mashambulizi yaliyoibazwa kwa njia maalum.

- **Insecure Integrated Component**: Plugins, agents, au huduma za upstream zilizo na udhaifu zinaweza kumruhusu mshambuliaji kuingiza code au kuongeza idhini ndani ya pipeline ya AI.

- **Prompt Injection**: Kuunda prompts (wazi au kwa njia isiyo ya moja kwa moja) kusafirisha maelekezo yanayovuka system intent, kufanya model ifanye amri zisizokusudiwa.

- **Model Evasion**: Inputs zilizoundwa kwa umakini zinaamsha model kutofasiri vizuri (mis‑classify), kuhalusin, au kutoa maudhui yaliyokataliwa, kuharibu usalama na uaminifu.

- **Sensitive Data Disclosure**: Model inafichua taarifa za kibinafsi au za siri kutoka kwa data yake ya mafunzo au muktadha wa mtumiaji, kuukiuka faragha na kanuni.

- **Inferred Sensitive Data**: Model inatoa sifa za kibinafsi ambazo hazikutolewa, ikileta madhara mapya ya faragha kupitia inference.

- **Insecure Model Output**: Majibu yasiyosafishwa hupita code hatari, misinformation, au maudhui yasiyofaa kwa watumiaji au mifumo inayofuata.

- **Rogue Actions**: Agents walioungwa kwa uendeshaji wenye uhuru hufanya operesheni zisizokusudiwa duniani halisi (kuandika faili, API calls, manunuzi, n.k.) bila ukaguzi wa kutosha wa mtumiaji.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) inatoa mfumo mpana wa kuelewa na kupunguza hatari zinazohusiana na mifumo ya AI. Inakokokorea mbinu na tactics mbalimbali ambazo advesary anaweza kutumia dhidi ya models za AI na pia jinsi ya kutumia mifumo ya AI kutekeleza mashambulizi tofauti.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Washambuliaji huchoma active session tokens au cloud API credentials na kuwaitisha cloud-hosted LLMs zilizolipishwa bila idhini. Upatikanaji mara nyingi huuzwa tena kupitia reverse proxies zinazoficha akaunti ya mwathiriwa, mfano deployments za "oai-reverse-proxy". Matokeo ni pamoja na hasara za kifedha, matumizi mabaya ya model nje ya sera, na kutambuliwa kwa tenanti hafifu.

TTPs:
- Harvest tokens kutoka kwa mashine za developer zilizovamiwa au browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy ambayo inaweka mbele requests kwa provider halisi, ikificha upstream key na kuendeshwa kwa wateja wengi.
- Abuse direct base-model endpoints ili kupita enterprise guardrails na rate limits.

Mitigations:
- Bind tokens kwa device fingerprint, IP ranges, na client attestation; enforce short expirations na refresh kwa MFA.
- Scope keys kwa kiwango cha chini (no tool access, read-only pale inapofaa); rotate pale panapotokea anomaly.
- Terminate all traffic server-side nyuma ya policy gateway inayotekeleza safety filters, per-route quotas, na tenant isolation.
- Monitor kwa mifumo isiyo ya kawaida ya matumizi (sudden spend spikes, atypical regions, UA strings) na auto-revoke sessions zenye shaka.
- Prefer mTLS au signed JWTs zinazotolewa na IdP yako juu ya API keys za muda mrefu zisizobadilika.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
