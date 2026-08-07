# Mbinu ya Msingi ya Forensic

{{#include ../../banners/hacktricks-training.md}}

## Kuunda na Kuweka Image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

Hii **si lazima iwe hatua ya kwanza ya kufanya baada ya kupata image**. Lakini unaweza kutumia mbinu hizi za malware analysis kwa kujitegemea ikiwa una faili, image ya file-system, memory image, pcap... kwa hiyo ni vizuri **kuzingatia hatua hizi**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Kuchunguza Image

ukipewa **forensic image** ya kifaa, unaweza kuanza **kuchanganua partitions na file-system** iliyotumika, na **kurejesha** **faili zinazoweza kuwa za kuvutia** (hata zilizofutwa). Jifunze jinsi ya kufanya hivyo katika:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Kulingana na OSs zilizotumika na hata platform, artifacts tofauti za kuvutia zinapaswa kutafutwa:


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

## Uchunguzi wa Kina wa Aina Maalum za Faili na Software

Ikiwa una **faili** yenye **mashaka makubwa**, basi **kulingana na aina ya faili na software** iliyoiunda, **tricks** kadhaa zinaweza kuwa muhimu.\
Soma ukurasa ufuatao ili ujifunze tricks zinazovutia:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ningependa kutaja hasa ukurasa huu:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Uchunguzi wa Memory Dump


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Uchunguzi wa Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Mbinu za Anti-Forensic**

Kumbuka uwezekano wa kutumika kwa mbinu za anti-forensic:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
