# Ontleding van memory dump

{{#include ../../../banners/hacktricks-training.md}}

## Begin

Begin deur binne die pcap na **malware** te **soek**. Gebruik die **tools** wat in [**Malware Analysis**](../malware-analysis.md) genoem word.

## [Volatility](volatility-cheatsheet.md)

**Volatility is 'n open-source framework vir memory dump-ontleding**. Hierdie Python-tool ontleed dumps vanaf eksterne bronne of VMware-VM's en identifiseer data soos prosesse en wagwoorde gebaseer op die dump se OS-profiel. Dit kan met plugins uitgebrei word, wat dit hoogs veelsydig maak vir forensiese ondersoeke.<sup>[[1]](#references)[[2]](#references)</sup>

[**Vind hier 'n cheatsheet**](volatility-cheatsheet.md)

## Mini dump-ongelukverslag

Wanneer die dump klein is (slegs 'n paar KB, moontlik 'n paar MB), kan dit 'n mini dump-ongelukverslag eerder as 'n volledige memory dump wees.<sup>[[3]](#references)</sup>

![Volatility - Mini dump-ongelukverslag: 'n Klein dump-lêer wat as 'n Mini DuMP-ongelukverslag geïdentifiseer is](<../../../images/image (532).png>)

As Visual Studio geïnstalleer is, kan jy hierdie lêer oopmaak om basiese inligting soos die prosesnaam, argitektuur, uitsonderingsbesonderhede en gelaaide modules te sien:<sup>[[4]](#references)</sup>

![Volatility - Mini dump-ongelukverslag: As Visual Studio geïnstalleer is, kan jy hierdie lêer oopmaak en basiese inligting soos prosesnaam, argitektuur, uitsonderingsinligting en... verkry](<../../../images/image (263).png>)

Jy kan ook die uitsondering inspekteer en die module se disassembly sien.<sup>[[4]](#references)</sup>

![Visual Studio-minidump se Actions-paneel met opsies om inheems te debug en simboolpaaie in te stel](<../../../images/image (142).png>)

![Visual Studio-disassembly van instruksies uit die minidump-uitsondering](<../../../images/image (610).png>)

In elk geval is Visual Studio nie die beste tool om 'n ontleding van die dump se diepte uit te voer nie.

Jy behoort dit met **IDA** of **Radare** oop te maak om dit **in diepte** te inspekteer.

## References

- [1] [Volatility-raamwerk](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility-gebruik](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump-lêers](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Gebruik dump-lêers in die Visual Studio-debugger](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
