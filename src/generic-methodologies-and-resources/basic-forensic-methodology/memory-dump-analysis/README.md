# Geheugenaflaai-analise

{{#include ../../../banners/hacktricks-training.md}}

## Begin

Begin **soek** vir **kwaadaardige sagteware** binne die pcap. Gebruik die **gereedskap** genoem in [**Kwaadaardige sagteware analise**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility is die hoof oopbronraamwerk vir geheugenaflaai-analise**. Hierdie Python-gereedskap analiseer aflaaie van eksterne bronne of VMware VM's, en identifiseer data soos prosesse en wagwoorde gebaseer op die aflaai se OS-profiel. Dit is uitbreidbaar met plugins, wat dit baie veelsydig maak vir forensiese ondersoeke.

[**Vind hier 'n cheatsheet**](volatility-cheatsheet.md)

## Mini aflaai krashverslag

Wanneer die aflaai klein is (net 'n paar KB, dalk 'n paar MB) dan is dit waarskynlik 'n mini aflaai krashverslag en nie 'n geheugenaflaai nie.

![](<../../../images/image (532).png>)

As jy Visual Studio geïnstalleer het, kan jy hierdie lêer oopmaak en 'n paar basiese inligting soos prosesnaam, argitektuur, uitsondering inligting en modules wat uitgevoer word bind:

![](<../../../images/image (263).png>)

Jy kan ook die uitsondering laai en die gedecompileerde instruksies sien

![](<../../../images/image (142).png>)

![](<../../../images/image (610).png>)

In elk geval, Visual Studio is nie die beste gereedskap om 'n analise van die diepte van die aflaai uit te voer nie.

Jy moet dit **oopmaak** met **IDA** of **Radare** om dit in **diepte** te inspekteer.

​

{{#include ../../../banners/hacktricks-training.md}}
