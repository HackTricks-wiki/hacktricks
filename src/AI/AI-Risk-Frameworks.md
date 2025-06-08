# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp imebaini udhaifu 10 bora wa kujifunza mashine ambao unaweza kuathiri mifumo ya AI. Udhaifu huu unaweza kusababisha masuala mbalimbali ya usalama, ikiwa ni pamoja na uchafuzi wa data, urekebishaji wa mfano, na mashambulizi ya adui. Kuelewa udhaifu huu ni muhimu kwa ajili ya kujenga mifumo ya AI salama.

Kwa orodha iliyo na maelezo ya kisasa ya udhaifu 10 bora wa kujifunza mashine, rejelea [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) mradi.

- **Input Manipulation Attack**: Mshambuliaji anaongeza mabadiliko madogo, mara nyingi yasiyoonekana, kwenye **data inayoingia** ili mfano ufanye uamuzi mbaya.\
*Mfano*: Madoa machache ya rangi kwenye alama ya kusimama yanamfanya gari linalojiendesha "kuona" alama ya kikomo cha kasi.

- **Data Poisoning Attack**: **Seti ya mafunzo** inachafuka kwa makusudi na sampuli mbaya, ikifundisha mfano sheria hatari.\
*Mfano*: Faili za malware zimewekwa alama kama "salama" katika mkusanyiko wa mafunzo ya antivirus, zikimruhusu malware kufanikiwa baadaye.

- **Model Inversion Attack**: Kwa kuchunguza matokeo, mshambuliaji anajenga **mfano wa kinyume** unaorejesha vipengele nyeti vya ingizo la asili.\
*Mfano*: Kuunda tena picha ya MRI ya mgonjwa kutoka kwa makadirio ya mfano wa kugundua saratani.

- **Membership Inference Attack**: Adui anajaribu kuthibitisha ikiwa **rekodi maalum** ilitumika wakati wa mafunzo kwa kutambua tofauti za kujiamini.\
*Mfano*: Kuthibitisha kwamba muamala wa benki wa mtu unaonekana katika data ya mafunzo ya mfano wa kugundua udanganyifu.

- **Model Theft**: Kuuliza mara kwa mara kunamruhusu mshambuliaji kujifunza mipaka ya maamuzi na **kuiga tabia ya mfano** (na IP).\
*Mfano*: Kukusanya jozi za maswali na majibu kutoka kwa API ya ML‑as‑a‑Service ili kujenga mfano wa karibu sawa wa ndani.

- **AI Supply‑Chain Attack**: Kuathiri sehemu yoyote (data, maktaba, uzito wa awali, CI/CD) katika **mchakato wa ML** ili kuharibu mifano ya chini.\
*Mfano*: Kuweka utegemezi uliochafuka kwenye kituo cha mfano kunasakinisha mfano wa uchambuzi wa hisia wenye nyuma ya mlango katika programu nyingi.

- **Transfer Learning Attack**: Mantiki mbaya imepandikizwa katika **mfano wa awali** na inabaki hata baada ya kurekebishwa kwa kazi ya mwathirika.\
*Mfano*: Msingi wa maono wenye kichocheo kilichofichwa bado unabadilisha lebo baada ya kubadilishwa kwa picha za matibabu.

- **Model Skewing**: Data iliyo na upendeleo au alama mbaya **inasogeza matokeo ya mfano** ili kufaidika na ajenda ya mshambuliaji.\
*Mfano*: Kuingiza barua pepe za "safi" zilizowekwa alama kama ham ili chujio la barua taka liwaruhusu barua pepe zinazofanana zijazo.

- **Output Integrity Attack**: Mshambuliaji **anabadilisha makadirio ya mfano wakati wa usafirishaji**, si mfano wenyewe, akidanganya mifumo ya chini.\
*Mfano*: Kubadilisha uamuzi wa "hatari" wa mchanganuzi wa malware kuwa "salama" kabla ya hatua ya karantini ya faili kuiona.

- **Model Poisoning** --- Mabadiliko ya moja kwa moja, yaliyolengwa kwenye **parameta za mfano** wenyewe, mara nyingi baada ya kupata ufikiaji wa kuandika, ili kubadilisha tabia.\
*Mfano*: Kubadilisha uzito kwenye mfano wa kugundua udanganyifu katika uzalishaji ili muamala kutoka kwa kadi fulani kila wakati uidhinishwe.

## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) inaelezea hatari mbalimbali zinazohusiana na mifumo ya AI:

- **Data Poisoning**: Watu wabaya hubadilisha au kuingiza data za mafunzo/urekebishaji ili kupunguza usahihi, kupandikiza milango ya nyuma, au kupotosha matokeo, ikiharibu uaminifu wa mfano katika mzunguko mzima wa data.

- **Unauthorized Training Data**: Kuingiza seti za data zilizo na hakimiliki, nyeti, au zisizo ruhusiwa kunasababisha wajibu wa kisheria, kimaadili, na utendaji kwa sababu mfano unajifunza kutoka kwa data ambayo haukuruhusiwa kuitumia.

- **Model Source Tampering**: Ubadilishaji wa mnyororo wa usambazaji au ndani wa msimbo wa mfano, utegemezi, au uzito kabla au wakati wa mafunzo unaweza kuingiza mantiki iliyofichwa ambayo inabaki hata baada ya kurekebishwa.

- **Excessive Data Handling**: Udhaifu wa kudumisha data na udhibiti wa utawala unapelekea mifumo kuhifadhi au kushughulikia data zaidi ya binafsi kuliko inavyohitajika, ikiongeza hatari ya kufichuliwa na hatari za kufuata.

- **Model Exfiltration**: Wavamizi wanapata faili/uzito wa mfano, wakisababisha kupoteza mali ya akili na kuwezesha huduma za kunakili au mashambulizi yanayofuata.

- **Model Deployment Tampering**: Adui hubadilisha vitu vya mfano au miundombinu ya huduma ili mfano unaotumika tofauti na toleo lililothibitishwa, huenda ikabadilisha tabia.

- **Denial of ML Service**: Kujaa kwa APIs au kutuma "sponge" inputs kunaweza kuchoma kompyuta/energia na kuondoa mfano mtandaoni, ikifanana na mashambulizi ya DoS ya kawaida.

- **Model Reverse Engineering**: Kwa kukusanya idadi kubwa ya jozi za ingizo-kutoa, wavamizi wanaweza kuiga au kuondoa mfano, wakichochea bidhaa za nakala na mashambulizi ya adui yaliyobinafsishwa.

- **Insecure Integrated Component**: Viongezeo, wakala, au huduma za juu zisizo salama zinawaruhusu wavamizi kuingiza msimbo au kuongeza mamlaka ndani ya mchakato wa AI.

- **Prompt Injection**: Kuunda maelekezo (moja kwa moja au kwa njia isiyo ya moja kwa moja) ili kupitisha maagizo yanayopindua nia ya mfumo, na kufanya mfano ufanye amri zisizokusudiwa.

- **Model Evasion**: Ingizo lililoundwa kwa uangalifu linachochea mfano kutofautisha vibaya, kuota, au kutoa maudhui yasiyoruhusiwa, ikiharibu usalama na uaminifu.

- **Sensitive Data Disclosure**: Mfano unafichua taarifa za kibinafsi au za siri kutoka kwa data yake ya mafunzo au muktadha wa mtumiaji, ukiuka faragha na kanuni.

- **Inferred Sensitive Data**: Mfano unakadiria sifa za kibinafsi ambazo hazikuwahi kutolewa, kuunda madhara mapya ya faragha kupitia uelewa.

- **Insecure Model Output**: Majibu yasiyo salama yanapitisha msimbo hatari, habari potofu, au maudhui yasiyofaa kwa watumiaji au mifumo ya chini.

- **Rogue Actions**: Wakala waliojumuishwa kwa uhuru wanafanya shughuli zisizokusudiwa za ulimwengu halisi (kuandika faili, kuita API, manunuzi, nk.) bila uangalizi wa kutosha wa mtumiaji.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) inatoa mfumo mpana wa kuelewa na kupunguza hatari zinazohusiana na mifumo ya AI. Inagawanya mbinu mbalimbali za mashambulizi na mbinu ambazo maadui wanaweza kutumia dhidi ya mifano ya AI na pia jinsi ya kutumia mifumo ya AI kufanya mashambulizi tofauti.

{{#include ../banners/hacktricks-training.md}}
