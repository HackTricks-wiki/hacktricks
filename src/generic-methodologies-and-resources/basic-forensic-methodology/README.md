# बेसिक फॉरेंसिक कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## इमेज बनाना और माउंट करना


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

यह **जरूरी नहीं कि यह इमेज मिलने के बाद करने वाला पहला कदम हो**। लेकिन आप इन malware analysis techniques को स्वतंत्र रूप से उपयोग कर सकते हैं अगर आपके पास कोई file, file-system image, memory image, pcap... हो, इसलिए इन क्रियाओं को **ध्यान में रखना** अच्छा है:


{{#ref}}
malware-analysis.md
{{#endref}}

## इमेज का निरीक्षण

यदि आपको किसी डिवाइस की **forensic image** दी गई है तो आप उपयोग किए गए **partitions, file-system** का विश्लेषण शुरू कर सकते हैं और संभावित रूप से **interesting files** (यहाँ तक कि deleted ones) को **recover** कर सकते हैं। यह सीखें:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# बेसिक फॉरेंसिक कार्यप्रणाली



## इमेज बनाना और माउंट करना


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

यह **जरूरी नहीं कि यह इमेज मिलने के बाद करने वाला पहला कदम हो**। लेकिन आप इन malware analysis techniques को स्वतंत्र रूप से उपयोग कर सकते हैं अगर आपके पास कोई file, file-system image, memory image, pcap... हो, इसलिए इन क्रियाओं को **ध्यान में रखना** अच्छा है:


{{#ref}}
malware-analysis.md
{{#endref}}

## इमेज का निरीक्षण

यदि आपको किसी डिवाइस की **forensic image** दी गई है तो आप उपयोग किए गए **partitions, file-system** का विश्लेषण शुरू कर सकते हैं और संभावित रूप से **interesting files** (यहाँ तक कि deleted ones) को **recover** कर सकते हैं। यह सीखें:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

उपयोग किए गए OSs और प्लेटफ़ॉर्म के अनुसार अलग-अलग रोचक artifacts खोजे जाने चाहिए:


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

## विशिष्ट फाइल-प्रकार और सॉफ़्टवेयर का गहरा निरीक्षण

यदि आपके पास बहुत ही **suspicious** **file** है, तो इसे बनाने वाले **file-type और software** के आधार पर कई **tricks** उपयोगी हो सकते हैं।\
कुछ रोचक tricks सीखने के लिए निम्न पृष्ठ पढ़ें:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

मैं विशेष रूप से इस पृष्ठ का उल्लेख करना चाहूँगा:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump Inspection


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap Inspection


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

anti-forensic techniques के संभावित उपयोग को ध्यान में रखें:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## विशिष्ट फाइल-प्रकार और सॉफ़्टवेयर का गहरा निरीक्षण

यदि आपके पास बहुत ही **suspicious** **file** है, तो इसे बनाने वाले **file-type और software** के आधार पर कई **tricks** उपयोगी हो सकते हैं।\
कुछ रोचक tricks सीखने के लिए निम्न पृष्ठ पढ़ें:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

मैं विशेष रूप से इस पृष्ठ का उल्लेख करना चाहूँगा:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump Inspection


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap Inspection


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

anti-forensic techniques के संभावित उपयोग को ध्यान में रखें:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
