# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

## Threat Modeling

HackTricks के Threat Modeling पर व्यापक गाइड में आपका स्वागत है! साइबर सुरक्षा के इस महत्वपूर्ण पहलू की खोज पर निकलें, जहां हम एक प्रणाली में संभावित कमजोरियों की पहचान, समझ और रणनीति बनाते हैं। यह थ्रेड वास्तविक दुनिया के उदाहरणों, सहायक सॉफ़्टवेयर और समझने में आसान व्याख्याओं के साथ भरा हुआ एक चरण-दर-चरण गाइड के रूप में कार्य करता है। यह नवागंतुकों और अनुभवी प्रैक्टिशनरों दोनों के लिए आदर्श है जो अपनी साइबर सुरक्षा रक्षा को मजबूत करना चाहते हैं।

### Commonly Used Scenarios

1. **Software Development**: Secure Software Development Life Cycle (SSDLC) के हिस्से के रूप में, थ्रेट मॉडलिंग विकास के प्रारंभिक चरणों में **संभावित कमजोरियों के स्रोतों की पहचान** करने में मदद करती है।
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) ढांचा **थ्रेट मॉडलिंग की आवश्यकता करता है ताकि प्रणाली की कमजोरियों को समझा जा सके** परीक्षण करने से पहले।

### Threat Model in a Nutshell

एक थ्रेट मॉडल आमतौर पर एक आरेख, छवि, या किसी अन्य प्रकार की दृश्य चित्रण के रूप में प्रस्तुत किया जाता है जो एक एप्लिकेशन की योजनाबद्ध आर्किटेक्चर या मौजूदा निर्माण को दर्शाता है। यह **डेटा फ्लो आरेख** के समान होता है, लेकिन इसकी सुरक्षा-उन्मुख डिज़ाइन में मुख्य अंतर होता है।

थ्रेट मॉडल अक्सर लाल रंग में चिह्नित तत्वों को प्रदर्शित करते हैं, जो संभावित कमजोरियों, जोखिमों या बाधाओं का प्रतीक होते हैं। जोखिम पहचान की प्रक्रिया को सरल बनाने के लिए, CIA (Confidentiality, Integrity, Availability) त्रिकोण का उपयोग किया जाता है, जो कई थ्रेट मॉडलिंग पद्धतियों का आधार बनाता है, जिसमें STRIDE सबसे सामान्य है। हालाँकि, चुनी गई पद्धति विशिष्ट संदर्भ और आवश्यकताओं के आधार पर भिन्न हो सकती है।

### The CIA Triad

CIA त्रिकोण सूचना सुरक्षा के क्षेत्र में एक व्यापक रूप से मान्यता प्राप्त मॉडल है, जो Confidentiality, Integrity, और Availability के लिए खड़ा है। ये तीन स्तंभ उन सुरक्षा उपायों और नीतियों की नींव बनाते हैं जिन पर थ्रेट मॉडलिंग पद्धतियाँ आधारित होती हैं।

1. **Confidentiality**: यह सुनिश्चित करना कि डेटा या प्रणाली को अनधिकृत व्यक्तियों द्वारा एक्सेस नहीं किया जा सके। यह सुरक्षा का एक केंद्रीय पहलू है, जिसमें डेटा उल्लंघनों को रोकने के लिए उचित एक्सेस नियंत्रण, एन्क्रिप्शन, और अन्य उपायों की आवश्यकता होती है।
2. **Integrity**: डेटा की सटीकता, स्थिरता, और विश्वसनीयता इसके जीवन चक्र के दौरान। यह सिद्धांत सुनिश्चित करता है कि डेटा को अनधिकृत पक्षों द्वारा परिवर्तित या छेड़छाड़ नहीं किया गया है। इसमें अक्सर चेकसम, हैशिंग, और अन्य डेटा सत्यापन विधियाँ शामिल होती हैं।
3. **Availability**: यह सुनिश्चित करता है कि डेटा और सेवाएँ आवश्यकतानुसार अधिकृत उपयोगकर्ताओं के लिए सुलभ हैं। इसमें अक्सर प्रणाली को बाधाओं के बावजूद चलाने के लिए पुनरावृत्ति, दोष सहिष्णुता, और उच्च उपलब्धता कॉन्फ़िगरेशन शामिल होते हैं।

### Threat Modeling Methodlogies

1. **STRIDE**: Microsoft द्वारा विकसित, STRIDE **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, और Elevation of Privilege** के लिए एक संक्षिप्त नाम है। प्रत्येक श्रेणी एक प्रकार के खतरे का प्रतिनिधित्व करती है, और यह पद्धति आमतौर पर एक कार्यक्रम या प्रणाली के डिज़ाइन चरण में संभावित खतरों की पहचान के लिए उपयोग की जाती है।
2. **DREAD**: यह Microsoft से एक और पद्धति है जो पहचाने गए खतरों के जोखिम मूल्यांकन के लिए उपयोग की जाती है। DREAD का अर्थ है **Damage potential, Reproducibility, Exploitability, Affected users, और Discoverability**। इनमें से प्रत्येक कारक को स्कोर किया जाता है, और परिणाम का उपयोग पहचाने गए खतरों को प्राथमिकता देने के लिए किया जाता है।
3. **PASTA** (Process for Attack Simulation and Threat Analysis): यह एक सात-चरणीय, **जोखिम-केंद्रित** पद्धति है। इसमें सुरक्षा उद्देश्यों को परिभाषित और पहचानना, तकनीकी दायरा बनाना, एप्लिकेशन विघटन, खतरे का विश्लेषण, कमजोरियों का विश्लेषण, और जोखिम/ट्रायज मूल्यांकन शामिल है।
4. **Trike**: यह एक जोखिम-आधारित पद्धति है जो संपत्तियों की रक्षा पर ध्यान केंद्रित करती है। यह **जोखिम प्रबंधन** के दृष्टिकोण से शुरू होती है और उस संदर्भ में खतरों और कमजोरियों को देखती है।
5. **VAST** (Visual, Agile, and Simple Threat modeling): यह दृष्टिकोण अधिक सुलभ होने का लक्ष्य रखता है और Agile विकास वातावरण में एकीकृत होता है। यह अन्य पद्धतियों के तत्वों को जोड़ता है और **खतरों के दृश्य प्रतिनिधित्व** पर ध्यान केंद्रित करता है।
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): CERT Coordination Center द्वारा विकसित, यह ढांचा **विशिष्ट प्रणालियों या सॉफ़्टवेयर के बजाय संगठनात्मक जोखिम मूल्यांकन** की ओर केंद्रित है।

## Tools

थ्रेट मॉडल बनाने और प्रबंधित करने में **सहायता** करने के लिए कई उपकरण और सॉफ़्टवेयर समाधान उपलब्ध हैं। यहाँ कुछ हैं जिन्हें आप विचार कर सकते हैं।

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

साइबर सुरक्षा पेशेवरों के लिए एक उन्नत क्रॉस-प्लेटफ़ॉर्म और मल्टी-फीचर GUI वेब स्पाइडर/क्रॉलर। Spider Suite का उपयोग हमले की सतह को मानचित्रित और विश्लेषण करने के लिए किया जा सकता है।

**Usage**

1. एक URL चुनें और क्रॉल करें

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. ग्राफ़ देखें

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP से एक ओपन-सोर्स प्रोजेक्ट, Threat Dragon एक वेब और डेस्कटॉप एप्लिकेशन है जिसमें सिस्टम आरेखण के साथ-साथ स्वचालित रूप से खतरों/निवारणों को उत्पन्न करने के लिए एक नियम इंजन शामिल है।

**Usage**

1. नया प्रोजेक्ट बनाएं

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

कभी-कभी यह इस तरह दिख सकता है:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. नया प्रोजेक्ट लॉन्च करें

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. नए प्रोजेक्ट को सहेजें

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. अपना मॉडल बनाएं

आप SpiderSuite Crawler जैसे उपकरणों का उपयोग कर सकते हैं ताकि आपको प्रेरणा मिल सके, एक बुनियादी मॉडल कुछ इस तरह दिखेगा

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

संस्थाओं के बारे में थोड़ी व्याख्या:

- Process (स्वयं संस्था जैसे Webserver या वेब कार्यक्षमता)
- Actor (एक व्यक्ति जैसे वेबसाइट विज़िटर, उपयोगकर्ता या प्रशासक)
- Data Flow Line (इंटरएक्शन का संकेत)
- Trust Boundary (विभिन्न नेटवर्क खंड या दायरे।)
- Store (वे चीजें जहां डेटा संग्रहीत होते हैं जैसे Databases)

5. एक खतरा बनाएं (चरण 1)

पहले आपको उस परत का चयन करना होगा जिसमें आप एक खतरा जोड़ना चाहते हैं

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

अब आप खतरा बना सकते हैं

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

ध्यान रखें कि Actor Threats और Process Threats के बीच एक अंतर है। यदि आप एक Actor में खतरा जोड़ते हैं तो आप केवल "Spoofing" और "Repudiation" चुन सकेंगे। हालाँकि, हमारे उदाहरण में हम एक Process संस्था में खतरा जोड़ते हैं इसलिए हम खतरा निर्माण बॉक्स में यह देखेंगे:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. समाप्त

अब आपका पूरा मॉडल कुछ इस तरह दिखना चाहिए। और इस तरह आप OWASP Threat Dragon के साथ एक सरल थ्रेट मॉडल बनाते हैं।

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

यह Microsoft का एक मुफ्त उपकरण है जो सॉफ़्टवेयर परियोजनाओं के डिज़ाइन चरण में खतरों को खोजने में मदद करता है। यह STRIDE पद्धति का उपयोग करता है और विशेष रूप से उन लोगों के लिए उपयुक्त है जो Microsoft के स्टैक पर विकास कर रहे हैं।

{{#include ../banners/hacktricks-training.md}}
