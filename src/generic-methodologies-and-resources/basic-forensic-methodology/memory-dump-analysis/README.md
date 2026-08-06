# Memory dump analysis

{{#include ../../../banners/hacktricks-training.md}}

## Başlangıç

pcap içinde **malware** aramaya **başlayın**. [**Malware Analysis**](../malware-analysis.md) bölümünde belirtilen **tools** araçlarını kullanın.

## [Volatility](volatility-cheatsheet.md)

**Volatility, memory dump analysis için kullanılan ana open-source framework'tür**. Bu Python aracı, harici kaynaklardan veya VMware VM'lerinden alınan dump'ları analiz eder ve dump'ın işletim sistemi profiline göre process'ler ve password'ler gibi verileri belirler. Plugin'lerle genişletilebilir olması, onu forensic investigation'lar için son derece çok yönlü hâle getirir.

[**Burada bir cheatsheet bulabilirsiniz**](volatility-cheatsheet.md)

## Mini dump crash report

Dump küçükse (yalnızca birkaç KB, belki birkaç MB), bu muhtemelen bir memory dump değil, bir mini dump crash report'tur.

![Volatility - Mini dump crash report: Dump küçükse (yalnızca birkaç KB, belki birkaç MB), bu muhtemelen bir memory dump değil, bir mini dump crash report'tur](<../../../images/image (532).png>)

Visual Studio kuruluysa bu dosyayı açabilir ve process adı, architecture, exception bilgileri ve yürütülen module'ler gibi bazı temel bilgileri görüntüleyebilirsiniz:

![Volatility - Mini dump crash report: Visual Studio kuruluysa bu dosyayı açabilir ve process adı, architecture, exception bilgileri ve... gibi bazı temel bilgileri görüntüleyebilirsiniz](<../../../images/image (263).png>)

Ayrıca exception'ı yükleyebilir ve decompile edilmiş instruction'ları görebilirsiniz

![Volatility - Mini dump crash report: Ayrıca exception'ı yükleyebilir ve decompile edilmiş instruction'ları görebilirsiniz](<../../../images/image (142).png>)

![Volatility - Mini dump crash report: Ayrıca exception'ı yükleyebilir ve decompile edilmiş instruction'ları görebilirsiniz](<../../../images/image (610).png>)

Her hâlükârda Visual Studio, dump'ı derinlemesine analiz etmek için en iyi tool değildir.

Dump'ı **derinlemesine** incelemek için **IDA** veya **Radare** kullanarak **açmalısınız**.

{{#include ../../../banners/hacktricks-training.md}}
