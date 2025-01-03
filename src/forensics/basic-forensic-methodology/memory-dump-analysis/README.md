# Analiza memorijskih dump-ova

{{#include ../../../banners/hacktricks-training.md}}

## Početak

Počnite **pretragu** za **malverom** unutar pcap-a. Koristite **alate** navedene u [**Analiza malvera**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility je glavni open-source okvir za analizu memorijskih dump-ova**. Ovaj Python alat analizira dump-ove iz spoljašnjih izvora ili VMware VM-ova, identifikujući podatke kao što su procesi i lozinke na osnovu OS profila dump-a. Proširiv je sa plugin-ovima, što ga čini veoma svestranim za forenzičke istrage.

**[Ovde pronađite cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Izveštaj o mini dump-u

Kada je dump mali (samo nekoliko KB, možda nekoliko MB), onda je verovatno reč o izveštaju o mini dump-u, a ne o memorijskom dump-u.

![](<../../../images/image (216).png>)

Ako imate instaliran Visual Studio, možete otvoriti ovu datoteku i povezati neke osnovne informacije kao što su ime procesa, arhitektura, informacije o izuzecima i moduli koji se izvršavaju:

![](<../../../images/image (217).png>)

Takođe možete učitati izuzetak i videti dekompilovane instrukcije

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

U svakom slučaju, Visual Studio nije najbolji alat za izvođenje analize dubine dump-a.

Trebalo bi da ga **otvorite** koristeći **IDA** ili **Radare** da biste ga pregledali u **dubini**.

​

{{#include ../../../banners/hacktricks-training.md}}
