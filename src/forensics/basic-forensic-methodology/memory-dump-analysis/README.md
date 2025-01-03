# Geheugen dump analise

{{#include ../../../banners/hacktricks-training.md}}

## Begin

Begin **soek** vir **malware** binne die pcap. Gebruik die **gereedskap** genoem in [**Malware Analise**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility is die hoof oopbron raamwerk vir geheue dump analise**. Hierdie Python-gereedskap analiseer dumps van eksterne bronne of VMware VM's, en identifiseer data soos prosesse en wagwoorde gebaseer op die dump se OS-profiel. Dit is uitbreidbaar met plugins, wat dit baie veelsydig maak vir forensiese ondersoeke.

**[Vind hier 'n cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Mini dump crash verslag

Wanneer die dump klein is (net 'n paar KB, dalk 'n paar MB) dan is dit waarskynlik 'n mini dump crash verslag en nie 'n geheue dump nie.

![](<../../../images/image (216).png>)

As jy Visual Studio geïnstalleer het, kan jy hierdie lêer oopmaak en basiese inligting soos prosesnaam, argitektuur, uitsondering inligting en modules wat uitgevoer word, bind:

![](<../../../images/image (217).png>)

Jy kan ook die uitsondering laai en die gedecompileerde instruksies sien

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

In elk geval, Visual Studio is nie die beste gereedskap om 'n analise van die diepte van die dump uit te voer nie.

Jy moet dit **oopmaak** met **IDA** of **Radare** om dit in **diepte** te inspekteer.

​

{{#include ../../../banners/hacktricks-training.md}}
