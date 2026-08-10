# Basic Forensic Methodology

## Image बनाना और Mount करना


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

जब आपके पास **image** हो, तो Malware Analysis करना **आवश्यक नहीं कि पहला कदम हो**। लेकिन यदि आपके पास कोई file, file-system image, memory image, pcap... हो, तो आप इन Malware Analysis techniques का स्वतंत्र रूप से उपयोग कर सकते हैं; इसलिए इन actions को **ध्यान में रखना अच्छा है**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Image का निरीक्षण

यदि आपको किसी device की **forensic image** दी गई है, तो आप उपयोग किए गए **partitions और file-system का analysis** शुरू कर सकते हैं और संभावित रूप से **महत्वपूर्ण files को recover** कर सकते हैं (deleted files को भी)। इसका तरीका यहां जानें:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

उपयोग किए गए OSs और platform के आधार पर खोजे जाने वाले अलग-अलग महत्वपूर्ण artifacts हो सकते हैं:


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

## Specific file-types और Software का गहन निरीक्षण

यदि आपके पास कोई बहुत **suspicious** **file** है, तो उसे बनाने वाले **file-type और software के आधार पर** कई **tricks** उपयोगी हो सकती हैं।\
कुछ रोचक tricks जानने के लिए निम्नलिखित page पढ़ें:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

मैं विशेष रूप से इस page का उल्लेख करना चाहता हूं:


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

Anti-forensic techniques के संभावित उपयोग को ध्यान में रखें:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
