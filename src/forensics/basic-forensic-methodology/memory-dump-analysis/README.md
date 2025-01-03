# Uchambuzi wa dump ya kumbukumbu

{{#include ../../../banners/hacktricks-training.md}}

## Anza

Anza **kutafuta** **malware** ndani ya pcap. Tumia **zana** zilizotajwa katika [**Uchambuzi wa Malware**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility ni mfumo mkuu wa chanzo wazi kwa uchambuzi wa dump ya kumbukumbu**. Zana hii ya Python inachambua dumps kutoka vyanzo vya nje au VMware VMs, ikitambua data kama mchakato na nywila kulingana na wasifu wa OS wa dump. Inaweza kupanuliwa kwa plugins, na kuifanya kuwa na matumizi mengi kwa uchunguzi wa forensics.

**[Pata hapa cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Ripoti ya ajali ya mini dump

Wakati dump ni ndogo (kama KB chache, labda MB chache) basi huenda ni ripoti ya ajali ya mini dump na sio dump ya kumbukumbu.

![](<../../../images/image (216).png>)

Ikiwa una Visual Studio imewekwa, unaweza kufungua faili hii na kuunganisha taarifa za msingi kama jina la mchakato, usanifu, taarifa za makosa na moduli zinazotekelezwa:

![](<../../../images/image (217).png>)

Unaweza pia kupakia makosa na kuona maagizo yaliyotafsiriwa

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

Hata hivyo, Visual Studio si zana bora kwa ajili ya kufanya uchambuzi wa kina wa dump.

Unapaswa **kuifungua** kwa kutumia **IDA** au **Radare** ili kuikagua kwa **undani**.

​

{{#include ../../../banners/hacktricks-training.md}}
