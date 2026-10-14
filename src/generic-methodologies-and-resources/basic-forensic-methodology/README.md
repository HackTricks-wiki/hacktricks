# Mbinu za Msingi za Uchunguzi wa Kidijitali

{{#include ../../banners/hacktricks-training.md}}

## Kuunda na Kupachika Image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Uchambuzi wa Malware

Hili **si lazima liwe hatua ya kwanza ya kufanya baada ya kupata image**. Lakini unaweza kutumia mbinu hizi za uchambuzi wa malware kivyake ikiwa una faili, image ya file-system, image ya memory, pcap... kwa hiyo ni vyema **kukumbuka hatua hizi**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Kukagua Image

Ikiwa umepewa **forensic image** ya kifaa, unaweza kuanza **kuchanganua partitions na file-system** iliyotumika, na **kurejesha** faili zinazoweza kuwa **za kuvutia** (hata zilizofutwa). Jifunze jinsi ya kufanya hivyo hapa:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Kulingana na OS zilizotumika na hata platform, unapaswa kutafuta artifacts tofauti zinazoweza kuvutia:


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

Kwa kifaa cha Android kilichofungwa, njia za kupata data na kutengeneza memory image, angalia [uchunguzi wa Android](android-forensics.md).

## Ukaguzi wa Kina wa Aina Mahususi za Faili na Software

Ikiwa una **faili** yenye **mashaka makubwa**, basi **kulingana na aina ya faili na software** iliyoiunda, **mbinu** kadhaa zinaweza kusaidia.\
Soma ukurasa ufuatao ili ujifunze mbinu kadhaa za kuvutia:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ningependa kutaja ukurasa huu hasa:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ukaguzi wa Memory Dump


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Ukaguzi wa Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Mbinu za Anti-Forensic**

Kumbuka uwezekano wa matumizi ya mbinu za anti-forensic:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Uwindaji wa Vitisho


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
