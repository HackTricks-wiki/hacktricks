# Basic Forensic Methodology

{{#include ../../banners/hacktricks-training.md}}

## Image बनाना और Mount करना


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

Image प्राप्त होने के बाद यह **पहला आवश्यक कदम नहीं है**। लेकिन यदि आपके पास कोई file, file-system image, memory image, pcap... हो, तो आप इन malware analysis techniques का स्वतंत्र रूप से उपयोग कर सकते हैं, इसलिए इन actions को **ध्यान में रखना अच्छा है**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Image का निरीक्षण

यदि आपको किसी device की **forensic image** दी गई है, तो आप उपयोग किए गए **partitions, file-system** का **विश्लेषण** करना और संभावित रूप से **महत्वपूर्ण files** (हटाई गई files सहित) **recover** करना शुरू कर सकते हैं। इसका तरीका यहां जानें:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

उपयोग किए गए OSs और platform के आधार पर अलग-अलग महत्वपूर्ण artifacts की खोज की जानी चाहिए:


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

## विशिष्ट file-types और Software का गहन निरीक्षण

यदि आपके पास कोई बहुत **suspicious** **file** है, तो उसे बनाने वाले **file-type और software** के आधार पर कई **tricks** उपयोगी हो सकती हैं।\
कुछ interesting tricks जानने के लिए निम्नलिखित page पढ़ें:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

मैं इस page का विशेष उल्लेख करना चाहता हूं:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump का निरीक्षण


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap का निरीक्षण


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

Anti-forensic techniques के संभावित उपयोग को ध्यान में रखें:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
