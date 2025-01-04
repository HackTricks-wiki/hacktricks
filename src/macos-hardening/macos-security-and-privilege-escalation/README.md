# macOS सुरक्षा और विशेषाधिकार वृद्धि

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी MacOS

यदि आप macOS से परिचित नहीं हैं, तो आपको macOS के मूल बातें सीखना शुरू करना चाहिए:

- विशेष macOS **फाइलें और अनुमतियाँ:**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- सामान्य macOS **उपयोगकर्ता**

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- **kernel** की **संरचना**

{{#ref}}
mac-os-architecture/
{{#endref}}

- सामान्य macOS n**etwork सेवाएँ और प्रोटोकॉल**

{{#ref}}
macos-protocols.md
{{#endref}}

- **ओपनसोर्स** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- `tar.gz` डाउनलोड करने के लिए एक URL को इस प्रकार बदलें: [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) को [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) में।

### MacOS MDM

कंपनियों में **macOS** सिस्टम उच्च संभावना के साथ **MDM के साथ प्रबंधित** होंगे। इसलिए, एक हमलावर के दृष्टिकोण से यह जानना दिलचस्प है कि **यह कैसे काम करता है**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - निरीक्षण, डिबगिंग और फज़िंग

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS सुरक्षा सुरक्षा

{{#ref}}
macos-security-protections/
{{#endref}}

## हमले की सतह

### फ़ाइल अनुमतियाँ

यदि एक **प्रक्रिया जो रूट के रूप में चल रही है** एक फ़ाइल लिखती है जिसे एक उपयोगकर्ता द्वारा नियंत्रित किया जा सकता है, तो उपयोगकर्ता इसका दुरुपयोग करके **विशेषाधिकार बढ़ा सकता है**।\
यह निम्नलिखित स्थितियों में हो सकता है:

- फ़ाइल का उपयोग पहले से एक उपयोगकर्ता द्वारा किया गया था (उपयोगकर्ता द्वारा स्वामित्व)
- फ़ाइल का उपयोग उपयोगकर्ता द्वारा एक समूह के कारण लिखने योग्य है
- फ़ाइल का उपयोग एक निर्देशिका के अंदर है जो उपयोगकर्ता के स्वामित्व में है (उपयोगकर्ता फ़ाइल बना सकता है)
- फ़ाइल का उपयोग एक निर्देशिका के अंदर है जो रूट के स्वामित्व में है लेकिन उपयोगकर्ता को एक समूह के कारण उस पर लिखने की अनुमति है (उपयोगकर्ता फ़ाइल बना सकता है)

एक **फ़ाइल बनाने** में सक्षम होना जो **रूट द्वारा उपयोग की जाने वाली है**, एक उपयोगकर्ता को **इसके सामग्री का लाभ उठाने** या यहां तक कि **सिंबलिंक/हार्डलिंक** बनाने की अनुमति देता है जो इसे किसी अन्य स्थान पर इंगित करता है।

इस प्रकार की कमजोरियों के लिए **कमजोर `.pkg` इंस्टॉलर** की जांच करना न भूलें:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### फ़ाइल एक्सटेंशन और URL स्कीम ऐप हैंडलर

फाइल एक्सटेंशन द्वारा पंजीकृत अजीब ऐप्स का दुरुपयोग किया जा सकता है और विभिन्न अनुप्रयोगों को विशिष्ट प्रोटोकॉल खोलने के लिए पंजीकृत किया जा सकता है

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP विशेषाधिकार वृद्धि

macOS में **अनुप्रयोगों और बाइनरीज़ के पास फ़ोल्डरों या सेटिंग्स तक पहुँचने के लिए अनुमतियाँ हो सकती हैं** जो उन्हें दूसरों की तुलना में अधिक विशेषाधिकार प्राप्त बनाती हैं।

इसलिए, एक हमलावर जो macOS मशीन को सफलतापूर्वक समझौता करना चाहता है, उसे **अपने TCC विशेषाधिकार बढ़ाने** की आवश्यकता होगी (या यहां तक कि **SIP को बायपास करना**, उसकी आवश्यकताओं के आधार पर)।

ये विशेषाधिकार आमतौर पर **अधिकारों** के रूप में दिए जाते हैं जिनसे अनुप्रयोग पर हस्ताक्षर किया जाता है, या अनुप्रयोग कुछ पहुँचों का अनुरोध कर सकता है और उसके बाद **उपयोगकर्ता द्वारा उन्हें अनुमोदित करने** के बाद उन्हें **TCC डेटाबेस** में पाया जा सकता है। एक अन्य तरीका जिससे एक प्रक्रिया इन विशेषाधिकारों को प्राप्त कर सकती है वह है **एक प्रक्रिया का बच्चा होना** जिसके पास वे **विशेषाधिकार** होते हैं क्योंकि वे आमतौर पर **विरासत में मिलते हैं**।

इन लिंक का पालन करें ताकि विभिन्न तरीकों को [**TCC में विशेषाधिकार बढ़ाने के लिए**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**TCC को बायपास करने के लिए**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) और कैसे अतीत में [**SIP को बायपास किया गया है**](macos-security-protections/macos-sip.md#sip-bypasses)।

## macOS पारंपरिक विशेषाधिकार वृद्धि

बेशक, एक रेड टीम के दृष्टिकोण से आपको रूट तक बढ़ने में भी रुचि होनी चाहिए। कुछ संकेतों के लिए निम्नलिखित पोस्ट देखें:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS अनुपालन

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## संदर्भ

- [**OS X घटना प्रतिक्रिया: स्क्रिप्टिंग और विश्लेषण**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
