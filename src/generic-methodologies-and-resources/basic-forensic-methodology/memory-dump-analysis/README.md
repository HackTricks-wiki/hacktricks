# Memory dump analizi

## Start

pcap içinde **malware** **aramaya** başlayın. [**Malware Analysis**](../malware-analysis.md) bölümünde bahsedilen **tools** araçlarını kullanın.

## [Volatility](volatility-cheatsheet.md)

**Volatility, memory dump analizi için açık kaynaklı bir framework'tür**. Bu Python aracı, harici kaynaklardan veya VMware VM'lerinden alınan dump'ları analiz eder ve dump'ın işletim sistemi profiline göre process'ler ve password'ler gibi verileri belirler. Plugin'lerle genişletilebilir olması, arşiv incelemeleri için onu oldukça çok yönlü hale getirir.<sup>[[1]](#references)[[2]](#references)</sup>

[**Burada bir cheatsheet bulun**](volatility-cheatsheet.md)

## Mini dump crash report

Dump küçük olduğunda (yalnızca birkaç KB, belki birkaç MB), tam bir memory dump yerine mini dump crash report olabilir.<sup>[[3]](#references)</sup>

![Volatility - Mini dump crash report: Mini DuMP crash report olarak tanımlanan küçük bir dump dosyası](<../../../images/image (532).png>)

Visual Studio kuruluysa bu dosyayı açarak process adı, architecture, exception ayrıntıları ve yüklenen module'ler gibi temel bilgileri görüntüleyebilirsiniz:<sup>[[4]](#references)</sup>

![Volatility - Mini dump crash report: Visual Studio kuruluysa bu dosyayı açabilir ve process adı, architecture, exception bilgileri ve... gibi bazı temel bilgileri alabilirsiniz](<../../../images/image (263).png>)

Ayrıca exception'ı inceleyebilir ve module'ün disassembly'sini görüntüleyebilirsiniz.<sup>[[4]](#references)</sup>

![Visual Studio minidump Actions panel with options to debug natively and set symbol paths](<../../../images/image (142).png>)

![Visual Studio disassembly of instructions from the minidump exception](<../../../images/image (610).png>)

Her neyse, Visual Studio dump'ın derinlemesine analizini gerçekleştirmek için en iyi araç değildir.

**IDA** veya **Radare** kullanarak onu **açmalı** ve **derinlemesine** incelemelisiniz.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility Kullanımı](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump Dosyaları](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Visual Studio debugger'da dump dosyalarını kullanma](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
