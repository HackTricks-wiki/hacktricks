# बुनियादी फॉरेंसिक कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## इमेज बनाना और माउंट करना


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

**इमेज मिलने के बाद यह ज़रूरी नहीं कि सबसे पहला कदम यही हो।** लेकिन अगर आपके पास कोई फ़ाइल, file-system image, memory image, pcap... हो, तो आप इन malware analysis techniques का स्वतंत्र रूप से इस्तेमाल कर सकते हैं। इसलिए **इन कार्रवाइयों को ध्यान में रखना अच्छा है**:


{{#ref}}
malware-analysis.md
{{#endref}}

## इमेज की जाँच करना

अगर आपको किसी डिवाइस की **forensic image** दी गई है, तो आप इस्तेमाल किए गए **partitions और file-system का विश्लेषण** करना शुरू कर सकते हैं और संभावित रूप से **दिलचस्प फ़ाइलें** (यहाँ तक कि हटाई गई फ़ाइलें भी) **रिकवर** कर सकते हैं। इसका तरीका यहाँ जानें:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

इस्तेमाल किए गए OS और platform के आधार पर, अलग-अलग दिलचस्प artifacts खोजने चाहिए:


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

लॉक किए गए Android डिवाइस, acquisition paths और memory imaging के लिए, [Android forensics](android-forensics.md) देखें।

## विशिष्ट file-types और Software की गहराई से जाँच

अगर आपके पास कोई बहुत **संदिग्ध** **फ़ाइल** है, तो उसे बनाने वाले **file-type और software के आधार पर**, कई **तरकीबें** काम आ सकती हैं।\
कुछ दिलचस्प तरकीबें जानने के लिए यह पेज पढ़ें:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

मैं इस पेज का खास ज़िक्र करना चाहता हूँ:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump की जाँच


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap की जाँच


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

Anti-forensic techniques के संभावित इस्तेमाल को ध्यान में रखें:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
