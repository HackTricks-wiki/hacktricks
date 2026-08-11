# Bellek dökümü analizi

{{#include ../../../banners/hacktricks-training.md}}

## Başlangıç

pcap içinde **malware** aramaya başlayın. [**Malware Analizi**](../malware-analysis.md) bölümünde belirtilen **tools** araçlarını kullanın.

## [Volatility](volatility-cheatsheet.md)

**Volatility, bellek dökümlerini analiz etmek için kullanılan açık kaynaklı bir framework'tür**. Bu Python aracı, harici kaynaklardan veya VMware VM'lerinden alınan dökümleri analiz eder ve dökümün işletim sistemi profiline göre işlemler ve parolalar gibi verileri tanımlar. Plugin'lerle genişletilebilmesi, onu forensic araştırmalar için son derece çok yönlü hâle getirir.<sup>[[1]](#references)[[2]](#references)</sup>

[**Burada bir cheatsheet bulabilirsiniz**](volatility-cheatsheet.md)

## Mini dump crash raporu

Döküm küçük olduğunda (yalnızca birkaç KB, belki birkaç MB), tam bir bellek dökümü yerine mini dump crash raporu olabilir.<sup>[[3]](#references)</sup>

![Volatility - Mini dump crash raporu: Mini DuMP crash raporu olarak tanımlanan küçük bir döküm dosyası](<../../../images/image (532).png>)

Visual Studio yüklüyse bu dosyayı açarak işlem adı, mimari, exception ayrıntıları ve yüklenen modüller gibi temel bilgileri görüntüleyebilirsiniz:<sup>[[4]](#references)</sup>

![Volatility - Mini dump crash raporu: Visual Studio yüklüyse dosyayı açabilir ve işlem adı, mimari, exception bilgileri gibi bazı temel bilgileri görüntüleyebilirsiniz](<../../../images/image (263).png>)

Ayrıca exception'ı inceleyebilir ve modülün disassembly görünümünü görüntüleyebilirsiniz.<sup>[[4]](#references)</sup>

![Visual Studio minidump Actions panel with options to debug natively and set symbol paths](<../../../images/image (142).png>)

![Visual Studio disassembly of instructions from the minidump exception](<../../../images/image (610).png>)

Her hâlükârda Visual Studio, dökümü derinlemesine analiz etmek için en iyi araç değildir.

Dökümü derinlemesine incelemek için **IDA** veya **Radare** kullanarak **açmalısınız**.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Volatility Kullanımı](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump Dosyaları](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Visual Studio debugger'da dump dosyalarını kullanma](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
