# Uchambuzi wa memory dump

## Anza

Anza **kutafuta** **malware** ndani ya pcap. Tumia **tools** zilizotajwa katika [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility ni framework ya open-source ya kuchanganua memory dump**. Tool hii ya Python huchanganua dumps kutoka vyanzo vya nje au VMware VMs, na kutambua data kama processes na passwords kulingana na OS profile ya dump. Inaweza kupanuliwa kwa plugins, hivyo kuifanya iwe yenye uwezo mkubwa kwa uchunguzi wa forensic.<sup>[[1]](#references)[[2]](#references)</sup>

[**Pata cheatsheet hapa**](volatility-cheatsheet.md)

## Ripoti ya crash ya mini dump

Wakati dump ni ndogo (KB chache tu, labda MB chache), huenda ikawa ripoti ya crash ya mini dump badala ya memory dump kamili.<sup>[[3]](#references)</sup>

![Volatility - Ripoti ya crash ya mini dump: Faili ndogo ya dump iliyotambuliwa kama ripoti ya crash ya Mini DuMP](<../../../images/image (532).png>)

Ikiwa Visual Studio imewekwa, unaweza kufungua faili hii ili kuona taarifa za msingi kama vile jina la process, architecture, maelezo ya exception, na modules zilizopakiwa:<sup>[[4]](#references)</sup>

![Volatility - Ripoti ya crash ya mini dump: Ikiwa Visual Studio imewekwa, unaweza kufungua faili hii na kuona taarifa za msingi kama vile jina la process, architecture, maelezo ya exception na...](<../../../images/image (263).png>)

Unaweza pia kukagua exception na kuona disassembly ya module.<sup>[[4]](#references)</sup>

![Visual Studio minidump Actions panel yenye chaguo za ku-debug natively na kuweka symbol paths](<../../../images/image (142).png>)

![Disassembly ya Visual Studio ya instructions kutoka kwenye exception ya minidump](<../../../images/image (610).png>)

Hata hivyo, Visual Studio si tool bora zaidi ya kufanya uchanganuzi wa kina wa dump.

Unapaswa **kuifungua** ukitumia **IDA** au **Radare** ili kuikagua kwa **kina**.

## References

- [1] [Framework ya Volatility](https://github.com/volatilityfoundation/volatility)
- [2] [Matumizi ya Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Faili za Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Tumia faili za dump katika Visual Studio debugger](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
