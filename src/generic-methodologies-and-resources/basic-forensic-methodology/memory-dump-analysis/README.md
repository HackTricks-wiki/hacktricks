# Geheue-dump-analise

{{#include ../../../banners/hacktricks-training.md}}

## Begin

Begin om binne die **pcap** vir **malware** te **soek**. Gebruik die **tools** wat in [**Malware Analysis**](../malware-analysis.md) genoem word.

## [Volatility](volatility-cheatsheet.md)

**Volatility is die belangrikste open-source framework vir geheue-dump-analise**. Hierdie Python-tool ontleed dumps van eksterne bronne of VMware-VM's en identifiseer data soos prosesse en wagwoorde gebaseer op die dump se OS-profiel. Dit is uitbreibaar met plugins, wat dit baie veelsydig maak vir forensiese ondersoeke.

[**Vind hier 'n cheatsheet**](volatility-cheatsheet.md)

## Mini dump crash report

Wanneer die dump klein is (net 'n paar KB, moontlik 'n paar MB), is dit waarskynlik 'n mini dump crash report en nie 'n geheue-dump nie.

![Volatility - Mini dump crash report: Wanneer die dump klein is (net 'n paar KB, moontlik 'n paar MB), is dit waarskynlik 'n mini dump crash report en nie 'n geheue-dump nie](<../../../images/image (532).png>)

As jy Visual Studio geïnstalleer het, kan jy hierdie lêer oopmaak en basiese inligting soos die prosesnaam, argitektuur, uitsonderingsinligting en modules wat uitgevoer word, bekom:

![Volatility - Mini dump crash report: As jy Visual Studio geïnstalleer het, kan jy hierdie lêer oopmaak en basiese inligting soos die prosesnaam, argitektuur, uitsonderingsinligting en...](<../../../images/image (263).png>)

Jy kan ook die uitsondering laai en die gedekompileerde instruksies sien

![Volatility - Mini dump crash report: Jy kan ook die uitsondering laai en die gedekompileerde instruksies sien](<../../../images/image (142).png>)

![Volatility - Mini dump crash report: Jy kan ook die uitsondering laai en die gedekompileerde instruksies sien](<../../../images/image (610).png>)

In elk geval is Visual Studio nie die beste tool om 'n diepgaande analise van die dump uit te voer nie.

Jy behoort dit met **IDA** of **Radare** oop te maak om dit **diepgaand** te inspekteer.

{{#include ../../../banners/hacktricks-training.md}}
