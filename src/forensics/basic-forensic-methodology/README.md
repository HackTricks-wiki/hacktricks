# बेसिक फॉरेंसिक मेथोडोलॉजी

{{#include ../../banners/hacktricks-training.md}}

## इमेज बनाना और माउंट करना

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## मैलवेयर विश्लेषण

यह **छवि प्राप्त करने के बाद करने के लिए पहला कदम जरूरी नहीं है**। लेकिन आप इस मैलवेयर विश्लेषण तकनीकों का स्वतंत्र रूप से उपयोग कर सकते हैं यदि आपके पास एक फ़ाइल, एक फ़ाइल-प्रणाली छवि, मेमोरी छवि, pcap... है, इसलिए यह **इन क्रियाओं को ध्यान में रखना अच्छा है**:

{{#ref}}
malware-analysis.md
{{#endref}}

## इमेज का निरीक्षण करना

यदि आपको एक **फॉरेंसिक इमेज** दी गई है, तो आप **पार्टीशनों, फ़ाइल-प्रणाली** का विश्लेषण करना शुरू कर सकते हैं और **संभावित रूप से** **दिलचस्प फ़ाइलों** (यहां तक कि हटाई गई फ़ाइलों) को **पुनर्प्राप्त** कर सकते हैं। जानें कैसे:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

उपयोग किए गए OSs और यहां तक कि प्लेटफ़ॉर्म के आधार पर विभिन्न दिलचस्प कलाकृतियों की खोज की जानी चाहिए:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## विशिष्ट फ़ाइल-प्रकारों और सॉफ़्टवेयर की गहरी जांच

यदि आपके पास बहुत **संदिग्ध** **फ़ाइल** है, तो **फ़ाइल-प्रकार और सॉफ़्टवेयर** के आधार पर जो इसे बनाया है, कई **तरकीबें** उपयोगी हो सकती हैं।\
कुछ दिलचस्प तरकीबें जानने के लिए निम्नलिखित पृष्ठ पढ़ें:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

मैं पृष्ठ का विशेष उल्लेख करना चाहता हूं:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## मेमोरी डंप निरीक्षण

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap निरीक्षण

{{#ref}}
pcap-inspection/
{{#endref}}

## **एंटी-फॉरेंसिक तकनीकें**

एंटी-फॉरेंसिक तकनीकों के संभावित उपयोग को ध्यान में रखें:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## खतरे की खोज

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
