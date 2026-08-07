# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

## Threat Modeling

HackTricks की Threat Modeling पर व्यापक guide में आपका स्वागत है! Cybersecurity के इस महत्वपूर्ण पहलू की खोज शुरू करें, जहां हम किसी system में मौजूद संभावित vulnerabilities की पहचान, समझ और उनके विरुद्ध रणनीति तैयार करते हैं। यह thread वास्तविक उदाहरणों, उपयोगी software और आसानी से समझ आने वाली व्याख्याओं से भरपूर step-by-step guide के रूप में है। यह अपनी cybersecurity defenses को मजबूत करने के इच्छुक beginners और experienced practitioners, दोनों के लिए उपयोगी है।

### आमतौर पर उपयोग किए जाने वाले scenarios

1. **Software Development**: Secure Software Development Life Cycle (SSDLC) के हिस्से के रूप में, threat modeling development के शुरुआती चरणों में **vulnerabilities के संभावित स्रोतों की पहचान** करने में सहायता करता है।
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) framework में test करने से पहले **system की vulnerabilities को समझने के लिए threat modeling** आवश्यक है।

### संक्षेप में Threat Model

Threat Model को आमतौर पर किसी diagram, image या किसी अन्य visual illustration के रूप में दर्शाया जाता है, जो किसी application की planned architecture या existing build को प्रदर्शित करता है। यह **data flow diagram** जैसा दिखता है, लेकिन मुख्य अंतर इसके security-oriented design में होता है।

Threat models में अक्सर red रंग से चिह्नित elements होते हैं, जो संभावित vulnerabilities, risks या barriers का प्रतीक होते हैं। Risk identification की प्रक्रिया को सरल बनाने के लिए CIA (Confidentiality, Integrity, Availability) triad का उपयोग किया जाता है। यह कई threat modeling methodologies का आधार है, जिनमें STRIDE सबसे सामान्य methodologies में से एक है। हालांकि, चुनी गई methodology specific context और requirements के आधार पर अलग हो सकती है।

### CIA Triad

CIA Triad information security के क्षेत्र में व्यापक रूप से मान्यता प्राप्त model है, जो Confidentiality, Integrity और Availability के लिए प्रयुक्त होता है। ये तीन pillars कई security measures और policies का आधार बनाते हैं, जिनमें threat modeling methodologies भी शामिल हैं।

1. **Confidentiality**: यह सुनिश्चित करना कि data या system को unauthorized individuals द्वारा access न किया जाए। यह security का एक केंद्रीय पहलू है, जिसके लिए data breaches को रोकने हेतु उचित access controls, encryption और अन्य measures आवश्यक होते हैं।
2. **Integrity**: अपने lifecycle के दौरान data की accuracy, consistency और trustworthiness। यह principle सुनिश्चित करता है कि unauthorized parties द्वारा data को बदला या tamper न किया जाए। इसमें अक्सर checksums, hashing और अन्य data verification methods का उपयोग किया जाता है।
3. **Availability**: यह सुनिश्चित करता है कि आवश्यकता पड़ने पर authorized users data और services को access कर सकें। Systems को disruptions के बावजूद चालू रखने के लिए इसमें अक्सर redundancy, fault tolerance और high-availability configurations का उपयोग किया जाता है।

### Threat Modeling Methodlogies

1. **STRIDE**: Microsoft द्वारा विकसित STRIDE, **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service और Elevation of Privilege** का acronym है। प्रत्येक category एक प्रकार के threat को दर्शाती है और potential threats की पहचान करने के लिए इस methodology का उपयोग आमतौर पर किसी program या system के design phase में किया जाता है।
2. **DREAD**: यह Microsoft की एक अन्य methodology है, जिसका उपयोग identified threats के risk assessment के लिए किया जाता है। DREAD का अर्थ **Damage potential, Reproducibility, Exploitability, Affected users और Discoverability** है। इनमें से प्रत्येक factor को score दिया जाता है और result का उपयोग identified threats को प्राथमिकता देने के लिए किया जाता है।
3. **PASTA** (Process for Attack Simulation and Threat Analysis): यह एक सात-चरणीय, **risk-centric** methodology है। इसमें security objectives को define और identify करना, technical scope बनाना, application decomposition, threat analysis, vulnerability analysis और risk/triage assessment शामिल हैं।
4. **Trike**: यह एक risk-based methodology है, जो assets की रक्षा करने पर केंद्रित है। इसकी शुरुआत **risk management** perspective से होती है और इसी context में threats और vulnerabilities का अध्ययन किया जाता है।
5. **VAST** (Visual, Agile, and Simple Threat modeling): इस approach का उद्देश्य अधिक accessible होना और Agile development environments में integrate होना है। यह अन्य methodologies के elements को combine करती है और **threats के visual representations** पर केंद्रित है।
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): CERT Coordination Center द्वारा विकसित यह framework specific systems या software के बजाय **organizational risk assessment पर केंद्रित** है।

## Tools

कई tools और software solutions उपलब्ध हैं, जो threat models बनाने और manage करने में **सहायता** कर सकते हैं। यहां कुछ tools दिए गए हैं जिन पर आप विचार कर सकते हैं।

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Cyber security professionals के लिए एक advanced cross-platform और multi-feature GUI web spider/crawler। Spider Suite का उपयोग attack surface mapping और analysis के लिए किया जा सकता है।

**उपयोग**

1. URL चुनें और Crawl करें

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph देखें

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP का एक open-source project, Threat Dragon एक web और desktop application है, जिसमें system diagramming के साथ-साथ threats/mitigations को auto-generate करने के लिए rule engine भी शामिल है।

**उपयोग**

1. New Project बनाएं

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

कभी-कभी यह इस तरह दिखाई दे सकता है:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. New Project Launch करें

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. New Project Save करें

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. अपना model बनाएं

आप inspiration के लिए SpiderSuite Crawler जैसे tools का उपयोग कर सकते हैं। एक basic model कुछ इस तरह दिखाई देगा

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Entities के बारे में थोड़ी व्याख्या:

- Process (Entity स्वयं, जैसे Webserver या web functionality)
- Actor (कोई व्यक्ति, जैसे Website Visitor, User या Administrator)
- Data Flow Line (Interaction का indicator)
- Trust Boundary (अलग-अलग network segments या scopes।)
- Store (वे स्थान जहां data store किया जाता है, जैसे Databases)

5. Threat बनाएं (Step 1)

सबसे पहले आपको वह layer चुननी होगी जिसमें आप threat add करना चाहते हैं

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

अब आप threat create कर सकते हैं

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

ध्यान रखें कि Actor Threats और Process Threats के बीच अंतर होता है। यदि आप किसी Actor में threat add करते हैं, तो आप केवल "Spoofing" और "Repudiation" चुन पाएंगे। हालांकि, हमारे example में हम किसी Process entity में threat add कर रहे हैं, इसलिए threat creation box में हमें यह दिखाई देगा:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. पूर्ण

अब आपका finished model कुछ इस तरह दिखाई देना चाहिए। OWASP Threat Dragon के साथ एक simple threat model बनाने का तरीका यही है।

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

यह Microsoft का एक free tool है, जो software projects के design phase में threats खोजने में सहायता करता है। यह STRIDE methodology का उपयोग करता है और Microsoft stack पर development करने वालों के लिए विशेष रूप से उपयुक्त है।

{{#include ../banners/hacktricks-training.md}}
