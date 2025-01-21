# BloodHound & Other AD Enum Tools

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) Sysinternal Suite से है:

> एक उन्नत Active Directory (AD) दर्शक और संपादक। आप AD Explorer का उपयोग AD डेटाबेस में आसानी से नेविगेट करने, पसंदीदा स्थानों को परिभाषित करने, ऑब्जेक्ट गुणों और विशेषताओं को बिना संवाद बॉक्स खोले देखने, अनुमतियों को संपादित करने, एक ऑब्जेक्ट का स्कीमा देखने, और जटिल खोजें करने के लिए कर सकते हैं जिन्हें आप सहेज सकते हैं और पुनः निष्पादित कर सकते हैं।

### Snapshots

AD Explorer एक AD के स्नैपशॉट बना सकता है ताकि आप इसे ऑफ़लाइन चेक कर सकें।\
इसे ऑफ़लाइन कमजोरियों का पता लगाने के लिए या समय के साथ AD DB की विभिन्न अवस्थाओं की तुलना करने के लिए उपयोग किया जा सकता है।

आपको कनेक्ट करने के लिए उपयोगकर्ता नाम, पासवर्ड, और दिशा की आवश्यकता होगी (किसी भी AD उपयोगकर्ता की आवश्यकता है)।

AD का स्नैपशॉट लेने के लिए, `File` --> `Create Snapshot` पर जाएं और स्नैपशॉट के लिए एक नाम दर्ज करें।

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) एक उपकरण है जो AD वातावरण से विभिन्न कलाकृतियों को निकालता और संयोजित करता है। जानकारी को एक **विशेष रूप से प्रारूपित** Microsoft Excel **रिपोर्ट** में प्रस्तुत किया जा सकता है जिसमें विश्लेषण को सुविधाजनक बनाने और लक्षित AD वातावरण की वर्तमान स्थिति का समग्र चित्र प्रदान करने के लिए मेट्रिक्स के साथ सारांश दृश्य शामिल होते हैं।
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound एक एकल पृष्ठ Javascript वेब एप्लिकेशन है, जो [Linkurious](http://linkurio.us/) के शीर्ष पर बनाया गया है, [Electron](http://electron.atom.io/) के साथ संकलित किया गया है, जिसमें एक [Neo4j](https://neo4j.com/) डेटाबेस है जिसे C# डेटा कलेक्टर द्वारा फीड किया गया है।

BloodHound ग्राफ सिद्धांत का उपयोग करके Active Directory या Azure वातावरण के भीतर छिपे हुए और अक्सर अनपेक्षित संबंधों को प्रकट करता है। हमलावर BloodHound का उपयोग करके आसानी से अत्यधिक जटिल हमले के रास्तों की पहचान कर सकते हैं, जिन्हें अन्यथा जल्दी पहचानना असंभव होगा। रक्षक BloodHound का उपयोग करके उन ही हमले के रास्तों की पहचान और समाप्ति कर सकते हैं। दोनों नीली और लाल टीमें BloodHound का उपयोग करके Active Directory या Azure वातावरण में विशेषाधिकार संबंधों की गहरी समझ प्राप्त कर सकती हैं।

तो, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound) एक अद्भुत उपकरण है जो स्वचालित रूप से एक डोमेन को सूचीबद्ध कर सकता है, सभी जानकारी को सहेज सकता है, संभावित विशेषाधिकार वृद्धि के रास्तों को खोज सकता है और सभी जानकारी को ग्राफ के माध्यम से दिखा सकता है।

Booldhound 2 मुख्य भागों से बना है: **ingestors** और **visualisation application**।

**ingestors** का उपयोग **डोमेन को सूचीबद्ध करने और सभी जानकारी को निकालने** के लिए किया जाता है, एक प्रारूप में जिसे विज़ुअलाइजेशन एप्लिकेशन समझेगा।

**visualisation application neo4j का उपयोग करता है** यह दिखाने के लिए कि सभी जानकारी कैसे संबंधित है और डोमेन में विशेषाधिकार बढ़ाने के विभिन्न तरीकों को दिखाने के लिए।

### Installation

BloodHound CE के निर्माण के बाद, पूरे प्रोजेक्ट को Docker के साथ उपयोग में आसानी के लिए अपडेट किया गया था। शुरू करने का सबसे आसान तरीका इसकी पूर्व-निर्धारित Docker Compose कॉन्फ़िगरेशन का उपयोग करना है।

1. Docker Compose स्थापित करें। यह [Docker Desktop](https://www.docker.com/products/docker-desktop/) स्थापना के साथ शामिल होना चाहिए।
2. चलाएँ:
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. टर्मिनल आउटपुट में Docker Compose में यादृच्छिक रूप से उत्पन्न पासवर्ड को खोजें।  
4. एक ब्राउज़र में, http://localhost:8080/ui/login पर जाएं। उपयोगकर्ता नाम **`admin`** और एक **`यादृच्छिक रूप से उत्पन्न पासवर्ड`** के साथ लॉगिन करें जिसे आप docker compose के लॉग में पा सकते हैं।  

इसके बाद, आपको यादृच्छिक रूप से उत्पन्न पासवर्ड को बदलने की आवश्यकता होगी और आपके पास नया इंटरफ़ेस तैयार होगा, जिससे आप सीधे ingestors डाउनलोड कर सकते हैं।  

### SharpHound  

उनके पास कई विकल्प हैं लेकिन यदि आप डोमेन से जुड़े पीसी से SharpHound चलाना चाहते हैं, अपने वर्तमान उपयोगकर्ता का उपयोग करके और सभी जानकारी निकालना चाहते हैं, तो आप कर सकते हैं:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> आप **CollectionMethod** और लूप सत्र के बारे में अधिक पढ़ सकते हैं [यहाँ](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

यदि आप विभिन्न क्रेडेंशियल का उपयोग करके SharpHound को निष्पादित करना चाहते हैं, तो आप एक CMD netonly सत्र बना सकते हैं और वहां से SharpHound चला सकते हैं:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhound के बारे में अधिक जानें ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) एक उपकरण है जो **Active Directory** से संबंधित **Group Policy** में **vulnerabilities** खोजने के लिए है। \
आपको **group3r** को डोमेन के अंदर किसी भी **domain user** का उपयोग करके एक होस्ट से **चलाना** होगा।
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **एक AD वातावरण की सुरक्षा स्थिति का मूल्यांकन करता है** और **ग्राफ** के साथ एक अच्छा **रिपोर्ट** प्रदान करता है।

इसे चलाने के लिए, बाइनरी `PingCastle.exe` को निष्पादित कर सकते हैं और यह विकल्पों का एक मेनू प्रस्तुत करते हुए एक **इंटरएक्टिव सत्र** शुरू करेगा। उपयोग करने के लिए डिफ़ॉल्ट विकल्प **`healthcheck`** है जो **डोमेन** का एक बुनियादी **अवलोकन** स्थापित करेगा, और **गलत कॉन्फ़िगरेशन** और **कमजोरियों** को खोजेगा।

{{#include ../../banners/hacktricks-training.md}}
