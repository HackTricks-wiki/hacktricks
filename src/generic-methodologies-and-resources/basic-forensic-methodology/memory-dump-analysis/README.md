# Analiza memory dump-a

{{#include ../../../banners/hacktricks-training.md}}

## Početak

Počnite da **pretražujete** pcap u potrazi za **malware-om**. Koristite **alate** navedene u odeljku [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility je open-source framework za analizu memory dump-ova**. Ovaj Python alat analizira dump-ove iz eksternih izvora ili VMware VM-ova, identifikujući podatke kao što su procesi i lozinke na osnovu OS profila dump-a. Proširiv je pomoću plugin-ova, što ga čini veoma svestranim za forenzičke istrage.<sup>[[1]](#references)[[2]](#references)</sup>

[**Cheatsheet pronađite ovde**](volatility-cheatsheet.md)

## Izveštaj o padu za mini dump

Kada je dump mali (samo nekoliko KB, možda nekoliko MB), možda je u pitanju izveštaj o padu u obliku mini dump-a, a ne kompletan memory dump.<sup>[[3]](#references)</sup>

![Volatility - Izveštaj o padu za mini dump: Mali dump fajl identifikovan kao Mini DuMP izveštaj o padu](<../../../images/image (532).png>)

Ako imate instaliran Visual Studio, možete otvoriti ovaj fajl da biste videli osnovne informacije, kao što su naziv procesa, arhitektura, detalji izuzetka i učitani moduli:<sup>[[4]](#references)</sup>

![Volatility - Izveštaj o padu za mini dump: Ako imate instaliran Visual Studio, možete otvoriti ovaj fajl i prikazati osnovne informacije kao što su naziv procesa, arhitektura, informacije o izuzetku i...](<../../../images/image (263).png>)

Takođe možete pregledati izuzetak i videti disassembly modula.<sup>[[4]](#references)</sup>

![Visual Studio panel Actions za minidump sa opcijama za native debugging i podešavanje putanja do simbola](<../../../images/image (142).png>)

![Visual Studio disassembly instrukcija iz izuzetka minidump-a](<../../../images/image (610).png>)

U svakom slučaju, Visual Studio nije najbolji alat za sprovođenje detaljne analize dump-a.

Trebalo bi da ga **otvorite** pomoću alata **IDA** ili **Radare** kako biste ga pregledali **detaljno**.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Upotreba alata Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump fajlovi](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Korišćenje dump fajlova u Visual Studio debugger-u](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
