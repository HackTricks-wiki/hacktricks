# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

HackTricks की Threat Modeling पर व्यापक गाइड में आपका स्वागत है! Cybersecurity के इस महत्वपूर्ण पहलू की खोज शुरू करें, जिसमें हम किसी system में संभावित vulnerabilities की पहचान, समझ और उनके विरुद्ध रणनीति बनाते हैं। यह thread वास्तविक उदाहरणों, उपयोगी software और आसानी से समझ आने वाली व्याख्याओं से भरपूर step-by-step guide है। यह अपनी cybersecurity defenses को मजबूत करने के इच्छुक शुरुआती और अनुभवी practitioners, दोनों के लिए उपयोगी है।

### आमतौर पर उपयोग किए जाने वाले परिदृश्य

1. **Software Development**: Secure Software Development Life Cycle (SSDLC) के भाग के रूप में, threat modeling development के शुरुआती चरणों में **vulnerabilities के संभावित स्रोतों की पहचान** करने में सहायता करता है।<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES), सही execution के लिए threat modeling को आवश्यक मानता है और business assets, business processes, threat communities तथा उनकी capabilities को document करने का आह्वान करता है।<sup>[[2]](#references)</sup>

### संक्षेप में Threat Model

Threat model को आमतौर पर planned architecture या existing application के diagram, image या किसी अन्य visual illustration के रूप में प्रस्तुत किया जाता है। Data-flow diagrams (DFDs) किसी system और उसके interactions को model करने का एक सामान्य तरीका हैं, जबकि threat modeling इसमें security-focused analysis जोड़ता है।<sup>[[1]](#references)</sup>

Microsoft के Threat Modeling Tool में red dotted lines trust boundaries को दर्शाती हैं; अन्य tools अलग visual conventions का उपयोग कर सकते हैं।<sup>[[4]](#references)</sup> Risk identification को सुव्यवस्थित करने के लिए teams CIA (Confidentiality, Integrity, Availability) triad या STRIDE threat categories का उपयोग कर सकती हैं, लेकिन उपयुक्त methodology project के context और requirements पर निर्भर करती है।<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA Triad

CIA Triad एक व्यापक रूप से मान्यता प्राप्त information-security model है, जिसका अर्थ Confidentiality, Integrity और Availability है। इन properties का उपयोग आमतौर पर data और systems के security goals का वर्णन करने के लिए किया जाता है।<sup>[[3]](#references)</sup>

1. **Confidentiality**: यह सुनिश्चित करना कि data या system को unauthorized individuals द्वारा access न किया जाए। यह security का एक केंद्रीय पहलू है, जिसमें data breaches को रोकने के लिए उपयुक्त access controls, encryption और अन्य measures की आवश्यकता होती है।
2. **Integrity**: पूरे lifecycle के दौरान data की accuracy, consistency और trustworthiness। यह principle सुनिश्चित करता है कि unauthorized parties द्वारा data को बदला या tamper न किया जाए। इसमें अक्सर checksums, hashing और data verification की अन्य methods शामिल होती हैं।
3. **Availability**: यह सुनिश्चित करती है कि आवश्यकता पड़ने पर authorized users data और services को access कर सकें। Systems को disruptions के बावजूद चालू रखने के लिए इसमें अक्सर redundancy, fault tolerance और high-availability configurations शामिल होते हैं।

### Threat Modeling Methodologies

1. **STRIDE**: Microsoft का STRIDE approach software threats को **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service और Elevation of Privilege** के रूप में categorize करता है। ये categories analysts को design के प्रत्येक vulnerable point पर संभावित threats की पहचान करने में सहायता करती हैं।<sup>[[5]](#references)</sup>
2. **DREAD**: यह Microsoft assessment approach threats को **Damage, Reproducibility, Exploitability, Affected users और Discoverability** का उपयोग करके score करता है। प्राप्त score mitigation के लिए threats को prioritize करने में सहायता कर सकता है।<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): यह सात चरणों वाली, **risk-centric** methodology है, जिसमें objectives, technical scope, application decomposition, threat analysis, vulnerability और weakness analysis, attack modeling तथा risk/impact analysis शामिल हैं।<sup>[[8]](#references)</sup>
4. **Trike**: यह security-audit framework **risk-management** और defensive perspective से threat modeling करता है।<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): यह method application और operational views के लिए scalable, usable threat models पर जोर देती है और development तथा DevOps lifecycles के साथ integrate हो सकती है।<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Carnegie Mellon's Software Engineering Institute के CERT Division द्वारा निर्मित, OCTAVE एक risk-based strategic assessment और planning method है, जो केवल technology के बजाय organizational risk पर केंद्रित है।<sup>[[10]](#references)</sup>

## Tools

Threat models के creation और management में **सहायता** करने वाले कई tools और software solutions उपलब्ध हैं। यहां कुछ tools दिए गए हैं जिन पर आप विचार कर सकते हैं।

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite security professionals के लिए एक cross-platform web crawler है, जो attack-surface mapping, endpoint discovery और web-application analysis को support करता है।<sup>[[6]](#references)</sup>

**Usage**

1. एक URL चुनें और Crawl करें

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph देखें

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon diagrams बनाने, threats suggest करने और mitigations record करने के लिए एक free, open-source, cross-platform threat-modeling application है। यह web और desktop applications के रूप में उपलब्ध है।<sup>[[7]](#references)</sup>

**Usage**

1. New Project बनाएं

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

कभी-कभी यह इस तरह दिखाई दे सकता है:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. New Project Launch करें

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. New Project Save करें

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. अपना model बनाएं

आप inspiration के लिए SpiderSuite Crawler जैसे tools का उपयोग कर सकते हैं। एक basic model कुछ इस तरह दिखाई देगा।

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Entities के बारे में थोड़ी-सी व्याख्या:

- Process (Entity स्वयं, जैसे Webserver या web functionality)
- Actor (एक व्यक्ति, जैसे Website Visitor, User या Administrator)
- Data Flow Line (Interaction का indicator)
- Trust Boundary (अलग network segments या scopes)
- Store (वे स्थान जहां data store किया जाता है, जैसे Databases)

5. Threat बनाएं (Step 1)

सबसे पहले आपको उस layer को चुनना होगा जिसमें आप threat जोड़ना चाहते हैं।

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

अब आप threat बना सकते हैं।

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

ध्यान रखें कि Actor Threats और Process Threats के बीच अंतर होता है। यदि आप किसी Actor में threat जोड़ते हैं, तो आप केवल "Spoofing" और "Repudiation" चुन पाएंगे। हालांकि हमारे example में हम किसी Process entity में threat जोड़ते हैं, इसलिए threat creation box में हमें यह दिखाई देगा:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. पूर्ण

अब आपका finished model कुछ इस तरह दिखाई देना चाहिए। इस प्रकार आप OWASP Threat Dragon के साथ एक simple threat model बनाते हैं।

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool software design analysis के लिए एक free downloadable tool है। इसका workflow एक diagram बनाता है, threats की पहचान करता है और STRIDE approach का उपयोग करके mitigation तथा validation को support करता है।<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Security fundamentals - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Getting Started with the Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Threat Modeling for Drivers - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA Threat Modeling: The 7 Stages Explained](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 Methodology Document](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: A Summary of Available Methods](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
