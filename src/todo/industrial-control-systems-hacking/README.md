# Hakovanje industrijskih upravljačkih sistema

{{#include ../../banners/hacktricks-training.md}}

## O ovom odeljku

Ovaj odeljak predstavlja komponente, arhitekture, protokole i metode procene bezbednosti industrijskih upravljačkih sistema (ICS). ICS je deo šireg domena operativne tehnologije (OT): programabilnih sistema i uređaja koji nadgledaju fizičke procese ili izazivaju promene u njima. Uobičajeni primeri obuhvataju supervisory control and data acquisition (SCADA) sisteme, distribuirane upravljačke sisteme (DCS) i programabilne logičke kontrolere (PLC).<sup>[[1]](#references)</sup>

Bezbednosni rad u ovim okruženjima mora uzeti u obzir zahteve koji se razlikuju od konvencionalnog IT-a, uključujući bezbednost procesa, pouzdanost, dostupnost, deterministički rad i životne cikluse opreme. Tehnički validna bezbednosna kontrola i dalje može biti neprikladna ako ometa fizički proces, zato testiranje i otklanjanje problema treba koordinisati sa vlasnikom sistema i osobljem zaduženim za operacije.<sup>[[1]](#references)</sup>

Kompromitovanje ili slučajni prekid rada mogu zaustaviti proizvodnju, oštetiti opremu, izazvati ispuštanje opasnog materijala, ugroziti životnu sredinu ili prouzrokovati povrede i gubitak života. Ovaj potencijalni fizički uticaj je razlog zbog kog razumevanje kontrolisanog procesa i njegovih bezbednih radnih ograničenja mora prethoditi aktivnom testiranju.<sup>[[1]](#references)</sup>

Mnoge OT implementacije i dalje koriste zastarele operativne sisteme, aplikacije i protokole jer oprema ima dug radni vek, a promene zahtevaju operativno i bezbednosno testiranje. Neki protokoli su projektovani bez moderne autentikacije ili enkripcije, a patching može biti ograničen podrškom proizvođača ili terminima za održavanje; tamo gde direktne nadogradnje nisu izvodljive, rizik treba ublažiti segmentacijom, kontrolom pristupa i monitoringom.<sup>[[1]](#references)</sup>

## Prioriteti procene

Započnite razumevanjem kontrolisanog procesa, granica sistema, topologije mreže, sredstava, tokova podataka, odnosa poverenja i eksternih veza. Slični tipovi uređaja mogu imati različite funkcije na različitim lokacijama, zato izbegavajte pretpostavku da se arhitektura ili model uticaja jedne implementacije može primeniti na drugu.<sup>[[1]](#references)</sup>

Gde god je moguće, prednost dajte pasivnom otkrivanju i postojećoj inženjerskoj dokumentaciji. Svako aktivno skeniranje ili exploitation treba da prati odobreni plan testiranja koji definiše bezbednosna ograničenja, termine za održavanje, procedure oporavka i uslove za obustavljanje. Nalaze treba procenjivati i prema uticaju na cybersecurity i prema potencijalnim efektima na fizički proces.<sup>[[1]](#references)</sup>

Isto arhitektonsko znanje podržava odbrambene aktivnosti kao što su inventar sredstava, segmentacija mreže, monitoring, odgovor na incidente i upravljanje ranjivostima zasnovano na riziku.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Vodič za bezbednost operativne tehnologije (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
