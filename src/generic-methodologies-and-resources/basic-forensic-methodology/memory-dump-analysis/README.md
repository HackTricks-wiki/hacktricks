# Analiza memorijskog dump-a

## Početak

Počnite da **pretražujete** **malware** unutar pcap-a. Koristite **alate** navedene u odeljku [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility je open-source framework za analizu memorijskih dump-ova**. Ovaj Python alat analizira dump-ove iz eksternih izvora ili VMware VM-ova i identifikuje podatke kao što su procesi i lozinke na osnovu profila OS-a dump-a. Proširiv je pomoću pluginova, što ga čini veoma svestranim za forenzičke istrage.<sup>[[1]](#references)[[2]](#references)</sup>

[**Cheatsheet pronađite ovde**](volatility-cheatsheet.md)

## Izveštaj o padu u mini dump-u

Kada je dump mali (samo nekoliko KB, možda nekoliko MB), moguće je da je u pitanju izveštaj o padu u mini dump-u, a ne kompletan memorijski dump.<sup>[[3]](#references)</sup>

![Volatility - Izveštaj o padu u mini dump-u: Mala dump datoteka identifikovana kao izveštaj o padu u Mini DuMP-u](<../../../images/image (532).png>)

Ako imate instaliran Visual Studio, možete otvoriti ovu datoteku da biste pregledali osnovne informacije kao što su naziv procesa, arhitektura, detalji izuzetka i učitani moduli:<sup>[[4]](#references)</sup>

![Volatility - Izveštaj o padu u mini dump-u: Ako imate instaliran Visual Studio, možete otvoriti ovu datoteku i prikazati osnovne informacije kao što su naziv procesa, arhitektura, informacije o izuzetku i...](<../../../images/image (263).png>)

Takođe možete pregledati izuzetak i prikazati disasemblirani kod modula.<sup>[[4]](#references)</sup>

![Visual Studio panel Actions za minidump sa opcijama za izvorno debagovanje i podešavanje putanja do simbola](<../../../images/image (142).png>)

![Visual Studio disasembliranje instrukcija iz izuzetka minidump-a](<../../../images/image (610).png>)

U svakom slučaju, Visual Studio nije najbolji alat za obavljanje detaljne analize dump-a.

Trebalo bi da ga **otvorite** pomoću alata **IDA** ili **Radare** kako biste ga pregledali **detaljno**.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Korišćenje alata Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Minidump datoteke](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Korišćenje dump datoteka u Visual Studio debuggeru](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
