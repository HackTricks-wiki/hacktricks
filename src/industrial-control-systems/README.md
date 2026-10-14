# Hakovanje industrijskih kontrolnih sistema

{{#include ../banners/hacktricks-training.md}}

## O ovom odeljku

Ovaj odeljak predstavlja komponente, arhitekture, protokole i metode procene bezbednosti industrijskih kontrolnih sistema (ICS). ICS je deo šireg domena operativne tehnologije (OT): programabilnih sistema i uređaja koji nadgledaju fizičke procese ili izazivaju promene u njima. Uobičajeni primeri obuhvataju sisteme za nadzor, upravljanje i prikupljanje podataka (SCADA), distribuirane kontrolne sisteme (DCS) i programabilne logičke kontrolere (PLC).<sup>[[1]](#references)</sup>

Bezbednosni rad u ovim okruženjima mora uzeti u obzir zahteve koji se razlikuju od uobičajenih IT okruženja, uključujući bezbednost procesa, pouzdanost, dostupnost, deterministički rad i životni vek opreme. Tehnički ispravna bezbednosna mera i dalje može biti neprikladna ako ometa fizički proces, zato testiranje i sanaciju treba koordinisati s vlasnikom sistema i operativnim osobljem.<sup>[[1]](#references)</sup>

Kompromitovanje ili slučajan prekid rada mogu zaustaviti proizvodnju, oštetiti opremu, izazvati ispuštanje opasnih materija, naštetiti životnoj sredini ili dovesti do povreda i gubitka života. Zbog mogućeg fizičkog uticaja, razumevanje kontrolisanog procesa i njegovih bezbednih radnih granica mora prethoditi aktivnom testiranju.<sup>[[1]](#references)</sup>

Mnoga OT okruženja i dalje koriste zastarele operativne sisteme, aplikacije i protokole jer oprema ima dug radni vek, a izmene zahtevaju operativno testiranje i testiranje bezbednosti. Neki protokoli su projektovani bez savremenih mehanizama autentifikacije ili šifrovanja, a mogućnost instaliranja zakrpa može biti ograničena podrškom dobavljača ili terminima za održavanje; kada direktne nadogradnje nisu izvodljive, primenite segmentaciju, kontrolu pristupa i nadzor.<sup>[[1]](#references)</sup>

## Prioriteti procene

Počnite razumevanjem kontrolisanog procesa, granica sistema, topologije mreže, imovine, tokova podataka, odnosa poverenja i spoljnih veza. Slični tipovi uređaja mogu imati različite funkcije na različitim lokacijama, zato nemojte pretpostavljati da se arhitektura ili model uticaja jednog okruženja mogu primeniti na drugo.<sup>[[1]](#references)</sup>

Kad god je moguće, dajte prednost pasivnom otkrivanju i postojećoj inženjerskoj dokumentaciji. Svako aktivno skeniranje ili eksploatacija treba da se sprovodi prema odobrenom planu testiranja koji definiše bezbednosna ograničenja, termine održavanja, procedure oporavka i uslove za prekid. Nalaze treba proceniti i u pogledu uticaja na sajber-bezbednost i mogućih posledica po fizički proces.<sup>[[1]](#references)</sup>

Isto znanje o arhitekturi podržava i odbrambene aktivnosti, kao što su popis imovine, segmentacija mreže, nadzor, odgovor na incidente i upravljanje ranjivostima zasnovano na riziku.<sup>[[1]](#references)</sup>

## Ulazne tačke protokola

- [Testiranje Modbus-a](../network-services-pentesting/pentesting-modbus.md) obuhvata Modbus TCP, serijske varijante, funkcijske kodove i pristup registrima.
- [Testiranje OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) obuhvata industrijsku uslugu za razmenu podataka.
- [Testiranje BACnet-a](../network-services-pentesting/47808-udp-bacnet.md) obuhvata kontrolne mreže automatizacije zgrada.

## References

- [1] [NIST SP 800-82 Rev. 3 - Vodič za bezbednost operativne tehnologije (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
