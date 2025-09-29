# AI जोखिम

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ने उन शीर्ष 10 machine learning कमजोरियों की पहचान की है जो AI सिस्टम को प्रभावित कर सकती हैं। ये कमजोरियाँ विभिन्न सुरक्षा समस्याओं जैसे डेटा poisoning, model inversion, और adversarial attacks का कारण बन सकती हैं। सुरक्षित AI सिस्टम बनाने के लिए इन कमजोरियों को समझना बहुत ज़रूरी है।

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: एक हमलावर incoming data में छोटे, अक्सर दिखाई न देने वाले बदलाव जोड़ता है ताकि मॉडल गलत निर्णय ले।\
*उदाहरण*: एक stop‑sign पर कुछ रंग‑के दाग एक self‑driving car को धोखा दे कर उसे speed‑limit sign "देखने" पर मजबूर कर देते हैं।

- **Data Poisoning Attack**: **प्रशिक्षण सेट** जानबूझकर खराब नमूनों से दूषित कर दिया जाता है, जिससे मॉडल हानिकारक नियम सीख लेता है।\
*उदाहरण*: एक antivirus प्रशिक्षण कॉर्पस में malware binaries को गलत तरीके से "benign" लेबल कर देना ताकि बाद में समान malware बायपास कर सके।

- **Model Inversion Attack**: आउटपुट्स को probe करके, एक हमलावर एक **reverse model** बनाता है जो मूल इनपुट्स की संवेदनशील विशेषताओं को reconstruct कर लेता है।\
*उदाहरण*: एक cancer‑detection मॉडल की predictions से किसी रोगी की MRI छवि फिर से बनाना।

- **Membership Inference Attack**: विरोधी यह परीक्षण कर सकता है कि कोई **विशिष्ट रिकॉर्ड** प्रशिक्षण के दौरान उपयोग हुआ था या नहीं, confidence के अंतर देखकर।\
*उदाहरण*: यह पुष्टि करना कि किसी व्यक्ति का बैंक लेन‑देन fraud‑detection मॉडल के प्रशिक्षण डेटा में मौजूद है।

- **Model Theft**: बार‑बार क्वेरी करके एक हमलावर decision boundaries सीख लेता है और **model's behavior** की नकल कर लेता है (और IP चुरा लेता है)।\
*उदाहरण*: ML‑as‑a‑Service API से पर्याप्त Q&A जोड़े इकट्ठा कर के लगभग समकक्ष local मॉडल बनाना।

- **AI Supply‑Chain Attack**: किसी भी घटक (data, libraries, pre‑trained weights, CI/CD) को compromise करके ML pipeline में downstream मॉडलों को दूषित कर देना।\
*उदाहरण*: model‑hub पर एक poisoned dependency एक backdoored sentiment‑analysis मॉडल इंस्टॉल कर देती है जो कई ऐप्स में फैल जाता है।

- **Transfer Learning Attack**: एक malicious logic किसी **pre‑trained model** में छिपा दिया जाता है और victim के task पर fine‑tuning के बाद भी जीवित रहता है।\
*उदाहरण*: एक vision backbone जिसमें hidden trigger है, medical imaging के लिए प्रयोग करने के बाद भी labels को उलट देता है।

- **Model Skewing**: सूक्ष्म रूप से biased या mislabeled डेटा **मॉडल के आउटपुट्स को शिफ्ट** कर देता है जिससे हमलावर के एजेंडा को लाभ होता है।\
*उदाहरण*: "clean" spam ई‑मेल्स को ham के रूप में लेबल कर के spam filter में समान future ई‑मेल्स को पास कराना।

- **Output Integrity Attack**: हमलावर मॉडल के predictions को transit में **बदल देता है**, मॉडल को नहीं, जिससे downstream सिस्टम धोखा खा जाते हैं।\
*उदाहरण*: एक malware classifier के "malicious" निर्णय को "benign" में बदल देना इससे पहले कि file‑quarantine स्टेज उसे देखे।

- **Model Poisoning** --- सीधे, लक्षित बदलाव **मॉडल पैरामीटर** में करना, अक्सर write access प्राप्त करने के बाद, व्यवहार बदलने के लिए।\
*उदाहरण*: production में fraud‑detection मॉडल के weights को tweak कर देना ताकि कुछ कार्ड्स के लेन‑देन हमेशा मंजूर हो जाएं।


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) विभिन्न जोखिमों की रूपरेखा देता है जो AI सिस्टम से संबंधित हैं:

- **Data Poisoning**: malicious actors प्रशिक्षण/ट्यूनिंग डेटा को बदलते या इंजेक्ट करते हैं ताकि accuracy घटे, backdoors implant हों, या परिणाम skew हो जाएँ, जिससे मॉडल की अखंडता पूरे डेटा‑लाइफसाइकल में कमजोर पड़ती है।

- **Unauthorized Training Data**: copyrighted, sensitive, या अनधिकृत datasets को ingest करने से कानूनी, नैतिक, और प्रदर्शन संबंधी जोखिम बनते हैं क्योंकि मॉडल ऐसे डेटा से सीखता है जिसका उपयोग अनुमति के बिना किया गया।

- **Model Source Tampering**: सप्लाई‑चेन या insider द्वारा model code, dependencies, या weights को training से पहले या दौरान manipulate करके hidden logic embed किया जा सकता है जो retraining के बाद भी बनी रहती है।

- **Excessive Data Handling**: कमजोर data‑retention और governance controls सिस्टम को आवश्यक से अधिक personal data स्टोर या प्रोसेस करने देते हैं, जिससे exposure और अनुपालन जोखिम बढ़ता है।

- **Model Exfiltration**: हमलावर model files/weights चुरा लेते हैं, जिससे intellectual property का नुकसान होता है और copy‑cat सेवाएँ या follow‑on attacks संभव होते हैं।

- **Model Deployment Tampering**: विरोधी model artifacts या serving infrastructure को modify कर देते हैं ताकि चल रहा मॉडल vetted version से अलग हो और संभावित रूप से व्यवहार बदल जाए।

- **Denial of ML Service**: APIs को flood करना या “sponge” inputs भेजना compute/energy को ख़त्म कर सकता है और मॉडल को offline कर सकता है, जो classic DoS attacks की तरह है।

- **Model Reverse Engineering**: बहुत सारी input‑output जोड़ियाँ harvest करके, हमलावर मॉडल की नकल या distill कर सकते हैं, जो imitation products और customized adversarial attacks को जन्म देते हैं।

- **Insecure Integrated Component**: vulnerable plugins, agents, या upstream services हमलावरों को code inject करने या AI pipeline के भीतर privileges escalate करने देते हैं।

- **Prompt Injection**: prompts (seedirectly या indirectly) craft करके ऐसे निर्देश smuggle किए जाते हैं जो system intent को override कर देते हैं और मॉडल को unintended commands करने पर मजबूर करते हैं।

- **Model Evasion**: सावधानीपूर्वक डिज़ाइन किए गए inputs मॉडल को mis‑classify, hallucinate, या disallowed content आउटपुट करने के लिए trigger करते हैं, जिससे safety और trust erode होते हैं।

- **Sensitive Data Disclosure**: मॉडल अपने training डेटा या user context से निजी या गोपनीय जानकारी प्रकट कर देता है, जिससे privacy और नियमों का उल्लंघन होता है।

- **Inferred Sensitive Data**: मॉडल ऐसे personal attributes का अनुमान लगा लेता है जो कभी प्रदान नहीं किये गये थे, जिससे inference के माध्यम से नए privacy नुकसान उत्पन्न होते हैं।

- **Insecure Model Output**: unsanitized responses users या downstream systems को हानिकारक code, misinformation, या अनुचित सामग्री पास कर देते हैं।

- **Rogue Actions**: स्वायत्त रूप से integrated agents unintended real‑world operations (file writes, API calls, purchases, आदि) execute कर देते हैं बिना पर्याप्त user oversight के।


## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI सिस्टम से जुड़े जोखिमों को समझने और कम करने के लिए एक व्यापक फ्रेमवर्क प्रदान करता है। यह विभिन्न attack techniques और tactics को श्रेणीबद्ध करता है जो विरोधी AI मॉडलों के खिलाफ उपयोग कर सकते हैं और साथ ही यह बताता है कि AI सिस्टम का उपयोग विभिन्न attacks को निष्पादित करने के लिए कैसे किया जा सकता है।


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers सक्रिय session tokens या cloud API credentials चुरा लेते हैं और बिना authorization के paid, cloud‑hosted LLMs को invoke करते हैं। Access अक्सर reverse proxies के माध्यम से resale की जाती है जो victim के account को front करते हैं, उदाहरण के लिए "oai-reverse-proxy" deployments। परिणामों में वित्तीय नुकसान, नीति के बाहर मॉडल का दुरुपयोग, और victim tenant पर attribution शामिल हैं।

TTPs:
- संक्रमित developer machines या browsers से tokens harvest करना; CI/CD secrets चुराना; leaked cookies खरीदना।
- एक reverse proxy खड़ी करना जो requests को genuine provider की तरफ forward करे, upstream key छुपाए और कई ग्राहकों को multiplex करे।
- enterprise guardrails और rate limits को bypass करने के लिए direct base‑model endpoints का दुरुपयोग करना।

Mitigations:
- tokens को device fingerprint, IP ranges, और client attestation से bind करें; short expirations लागू करें और MFA के साथ refresh करें।
- keys को न्यूनतम scope दें (कोई tool access न दें, जहाँ लागू हो वहां read‑only रखें); anomaly पर rotate करें।
- एक policy gateway के पीछे server‑side पर सभी ट्रैफ़िक terminate करें जो safety filters, per‑route quotas, और tenant isolation लागू करे।
- असामान्य उपयोग पैटर्न (अचानक खर्च में spike, असामान्य regions, UA strings) की निगरानी करें और suspicious sessions को auto‑revoke करें।
- long‑lived static API keys की बजाय अपने IdP द्वारा जारी mTLS या signed JWTs को प्राथमिकता दें।


## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
