# Analiza memory dump-a

{{#include ../../../banners/hacktricks-training.md}}

## Početak

Počnite da **pretražujete** pcap u potrazi za **malware-om**. Koristite **alate** navedene u [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility je glavni open-source framework za analizu memory dump-ova**. Ovaj Python alat analizira dump-ove iz eksternih izvora ili VMware VM-ova, identifikujući podatke kao što su procesi i lozinke na osnovu OS profila dump-a. Proširiv je pomoću plugin-ova, što ga čini veoma prilagodljivim za forenzičke istrage.

[**Cheatsheet pronađite ovde**](volatility-cheatsheet.md)

## Izveštaj o padu mini dump-a

Kada je dump mali (samo nekoliko KB, možda nekoliko MB), onda je verovatno u pitanju izveštaj o padu mini dump-a, a ne memory dump.

![Volatility - Izveštaj o padu mini dump-a: Kada je dump mali (samo nekoliko KB, možda nekoliko MB), onda je verovatno u pitanju izveštaj o padu mini dump-a, a ne memory dump](<../../../images/image (532).png>)

Ako imate instaliran Visual Studio, možete otvoriti ovaj fajl i prikupiti neke osnovne informacije, kao što su naziv procesa, arhitektura, informacije o izuzetku i moduli koji se izvršavaju:

![Volatility - Izveštaj o padu mini dump-a: Ako imate instaliran Visual Studio, možete otvoriti ovaj fajl i prikupiti neke osnovne informacije, kao što su naziv procesa, arhitektura, informacije o izuzetku i...](<../../../images/image (263).png>)

Takođe možete učitati izuzetak i videti dekompajlirane instrukcije

![Volatility - Izveštaj o padu mini dump-a: Takođe možete učitati izuzetak i videti dekompajlirane instrukcije](<../../../images/image (142).png>)

![Volatility - Izveštaj o padu mini dump-a: Takođe možete učitati izuzetak i videti dekompajlirane instrukcije](<../../../images/image (610).png>)

U svakom slučaju, Visual Studio nije najbolji alat za detaljnu analizu dump-a.

Trebalo bi da ga **otvorite** pomoću alata **IDA** ili **Radare** kako biste ga **detaljno** analizirali.

{{#include ../../../banners/hacktricks-training.md}}
