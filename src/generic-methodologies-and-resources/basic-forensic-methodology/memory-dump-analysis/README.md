# Uchambuzi wa memory dump

{{#include ../../../banners/hacktricks-training.md}}

## Anza

Anza **kutafuta** **malware** ndani ya pcap. Tumia **tools** zilizotajwa katika [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility ni open-source framework kuu ya uchambuzi wa memory dump**. Python tool hii huchanganua dumps kutoka vyanzo vya nje au VMware VMs, ikitambua data kama processes na passwords kulingana na OS profile ya dump. Inaweza kupanuliwa kwa plugins, jambo linaloifanya iwe yenye matumizi mengi katika uchunguzi wa forensic.

[**Pata cheatsheet hapa**](volatility-cheatsheet.md)

## Mini dump crash report

Wakati dump ni ndogo (KB chache tu, labda MB chache), basi huenda ni mini dump crash report na si memory dump.

![Volatility - Mini dump crash report: Wakati dump ni ndogo (KB chache tu, labda MB chache), basi huenda ni mini dump crash report na si memory dump](<../../../images/image (532).png>)

Ikiwa una Visual Studio iliyosakinishwa, unaweza kufungua faili hii na kuonyesha taarifa za msingi kama jina la process, architecture, exception info na modules zinazotekelezwa:

![Volatility - Mini dump crash report: Ikiwa una Visual Studio iliyosakinishwa, unaweza kufungua faili hii na kuonyesha taarifa za msingi kama jina la process, architecture, exception info na...](<../../../images/image (263).png>)

Unaweza pia kupakia exception na kuona instructions zilizodecompileiwa

![Volatility - Mini dump crash report: Unaweza pia kupakia exception na kuona instructions zilizodecompileiwa](<../../../images/image (142).png>)

![Volatility - Mini dump crash report: Unaweza pia kupakia exception na kuona instructions zilizodecompileiwa](<../../../images/image (610).png>)

Hata hivyo, Visual Studio si tool bora zaidi ya kufanya uchambuzi wa kina wa dump.

Unapaswa **kuifungua** ukitumia **IDA** au **Radare** ili kuichunguza kwa **kina**.

{{#include ../../../banners/hacktricks-training.md}}
