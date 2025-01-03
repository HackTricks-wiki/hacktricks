# Analiza memorijskog ispisa

{{#include ../../../banners/hacktricks-training.md}}

## Početak

Počnite **pretragu** za **malverom** unutar pcap-a. Koristite **alate** navedene u [**Analiza malvera**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility je glavni open-source okvir za analizu memorijskih ispisa**. Ovaj Python alat analizira ispise iz spoljašnjih izvora ili VMware VM-ova, identifikujući podatke kao što su procesi i lozinke na osnovu OS profila ispisa. Proširiv je sa dodacima, što ga čini veoma svestranim za forenzičke istrage.

[**Ovde pronađite cheatsheet**](volatility-cheatsheet.md)

## Izveštaj o mini ispadu

Kada je ispis mali (samo nekoliko KB, možda nekoliko MB), onda je verovatno reč o izveštaju o mini ispadu, a ne o memorijskom ispustu.

![](<../../../images/image (532).png>)

Ako imate instaliran Visual Studio, možete otvoriti ovu datoteku i povezati neke osnovne informacije kao što su naziv procesa, arhitektura, informacije o izuzecima i moduli koji se izvršavaju:

![](<../../../images/image (263).png>)

Takođe možete učitati izuzetak i videti dekompilirane instrukcije

![](<../../../images/image (142).png>)

![](<../../../images/image (610).png>)

U svakom slučaju, Visual Studio nije najbolji alat za izvođenje analize dubine ispisa.

Trebalo bi da ga **otvorite** koristeći **IDA** ili **Radare** da biste ga pregledali u **dubini**.

​

{{#include ../../../banners/hacktricks-training.md}}
