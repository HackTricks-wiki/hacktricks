# Hakovanje industrijskih upravljačkih sistema

{{#include ../../banners/hacktricks-training.md}}

## O ovom odeljku

Ovaj odeljak predstavlja komponente, arhitekture, protokole i metode procene bezbednosti industrijskih upravljačkih sistema (ICS). ICS je deo šireg domena operativne tehnologije (OT): programabilnih sistema i uređaja koji nadgledaju fizičke procese ili izazivaju promene u njima. Uobičajeni primeri obuhvataju sisteme za nadzor, upravljanje i prikupljanje podataka (SCADA), distribuirane upravljačke sisteme (DCS) i programabilne logičke kontrolere (PLC).<sup>[[1]](#references)</sup>

Bezbednosni rad u ovim okruženjima mora uzeti u obzir zahteve koji se razlikuju od konvencionalnog IT-a, uključujući bezbednost procesa, pouzdanost, dostupnost, deterministički rad i životne cikluse opreme. Tehnički ispravna bezbednosna kontrola i dalje može biti neprikladna ako poremeti fizički proces, zato testiranje i otklanjanje problema treba koordinirati sa vlasnikom sistema i osobljem zaduženim za operacije.<sup>[[1]](#references)</sup>

## Prioriteti procene

Počnite razumevanjem kontrolisanog procesa, granica sistema, topologije mreže, imovine, tokova podataka, odnosa poverenja i spoljnih veza. Slični tipovi uređaja mogu imati različite funkcije na različitim lokacijama, zato nemojte pretpostavljati da se arhitektura ili model uticaja jedne implementacije primenjuje na drugu.<sup>[[1]](#references)</sup>

Kad god je moguće, prednost dajte pasivnom otkrivanju i postojećoj inženjerskoj dokumentaciji. Svako aktivno skeniranje ili exploitation treba da prati odobren plan testiranja koji definiše bezbednosna ograničenja, periode održavanja, procedure oporavka i uslove za prekid. Nalaze treba procenjivati i prema uticaju na cybersecurity i prema potencijalnim efektima na fizički proces.<sup>[[1]](#references)</sup>

Isto arhitektonsko znanje podržava odbrambene aktivnosti kao što su inventar imovine, segmentacija mreže, monitoring, odgovor na incidente i upravljanje ranjivostima zasnovano na riziku.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Vodič za bezbednost operativne tehnologije (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
