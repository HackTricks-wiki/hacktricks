# Hakovanje industrijskih kontrolnih sistema

{{#include ../banners/hacktricks-training.md}}

## O ovom odeljku

Ovaj odeljak predstavlja komponente, arhitekture i protokole industrijskih kontrolnih sistema (ICS), kao i metode za procenu njihove bezbednosti. ICS je deo šire oblasti operativne tehnologije (OT): programabilnih sistema i uređaja koji nadgledaju fizičke procese ili izazivaju promene u njima. Uobičajeni primeri su sistemi za nadzor, upravljanje i prikupljanje podataka (SCADA), distribuirani kontrolni sistemi (DCS) i programabilni logički kontroleri (PLC).<sup>[[1]](#references)</sup>

Bezbednosni rad u ovim okruženjima mora da uzme u obzir zahteve koji se razlikuju od uobičajenih IT sistema, uključujući bezbednost procesa, pouzdanost, dostupnost, deterministički rad i životni vek opreme. Tehnički validna bezbednosna kontrola i dalje može biti neprikladna ako ometa fizički proces, zato testiranje i otklanjanje problema treba koordinisati sa vlasnikom sistema i osobljem zaduženim za rad sistema.<sup>[[1]](#references)</sup>

Kompromitovanje ili slučajni prekid rada mogu zaustaviti proizvodnju, oštetiti opremu, izazvati ispuštanje opasnih materija, naškoditi životnoj sredini ili dovesti do povreda i gubitka života. Zbog mogućeg fizičkog uticaja, razumevanje kontrolisanog procesa i njegovih bezbednih radnih granica mora prethoditi aktivnom testiranju.<sup>[[1]](#references)</sup>

Mnoge OT implementacije i dalje koriste zastarele operativne sisteme, aplikacije i protokole jer oprema ima dug radni vek, a promene zahtevaju operativno testiranje i testiranje bezbednosti. Neki protokoli su projektovani bez savremene autentifikacije ili šifrovanja, a primena zakrpa može biti ograničena podrškom dobavljača ili terminima održavanja; tamo gde direktne nadogradnje nisu izvodljive, primenite segmentaciju, kontrolu pristupa i nadzor.<sup>[[1]](#references)</sup>

## Prioriteti procene

Počnite razumevanjem kontrolisanog procesa, granica sistema, topologije mreže, sredstava, tokova podataka, odnosa poverenja i spoljnih veza. Slični tipovi uređaja mogu imati različite funkcije na različitim lokacijama, zato nemojte pretpostavljati da se arhitektura ili model uticaja jedne implementacije mogu primeniti na drugu.<sup>[[1]](#references)</sup>

Kad god je moguće, dajte prednost pasivnom otkrivanju i postojećoj inženjerskoj dokumentaciji. Svako aktivno skeniranje ili iskorišćavanje ranjivosti treba da prati odobren plan testiranja koji definiše bezbednosna ograničenja, termine održavanja, postupke oporavka i uslove za prekid. Nalaze treba proceniti i u pogledu uticaja na sajber-bezbednost i mogućih posledica po fizički proces.<sup>[[1]](#references)</sup>

Isto arhitektonsko znanje podržava i odbrambene aktivnosti, kao što su inventarisanje sredstava, segmentacija mreže, nadzor, odgovor na incidente i upravljanje ranjivostima zasnovano na riziku.<sup>[[1]](#references)</sup>

## Zloupotreba nadzornog kontrolera za hlađenje

Menadžer rashladnog sistema koordinira kontrolere kompresora i rashladnih vitrina, ali sam ne hladi vitrine. Pristup njegovom interfejsu za upravljanje zato može omogućiti kontrolu nad mnogim podređenim uređajima putem uobičajene distribucije konfiguracije. Ovo se razlikuje od promene jednog termostata ili direktnog upravljanja kompresorom.<sup>[[3]](#references)[[4]](#references)</sup>

### Prijava pomoću koda za održavanje izvedenog iz datuma

Na pogođenim sistemskim menadžerima kompanije Danfoss, alternativna XML prijava prihvata kod izveden iz datuma kontrolera umesto lozinke naloga.<sup>[[2]](#references)[[3]](#references)</sup> Na modelima SM800 i SC255, Synacktiv je pratio atribute `eds_only` i `quantum_only` kroz `xml_load_file` i `check_authorize` do funkcije `check_code_of_day`. Njihovo savetodavno obaveštenje takođe pokazuje da `read_date_time` na `xml.cgi` otkriva datum kontrolera bez autentifikacije.<sup>[[2]](#references)</sup> Claroty je pronašao odgovarajuću putanju `getauth` na modelu AK-SM 800A, ali je izostavio njene okidačke atribute; ne treba pretpostaviti da će nazivi atributa sa starijih modela raditi na toj platformi.<sup>[[3]](#references)</sup>

Synacktiv dokumentuje upit za datum bez autentifikacije na sledeći način:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

Kod ne sadrži tajnu specifičnu za uređaj: izdvajanje algoritma iz [firmware](../hardware-physical-access/firmware-analysis/) može da obezbedi vremenski važeće akreditive za uređaje sa istom ranjivom implementacijom.<sup>[[2]](#references)[[3]](#references)</sup> Najpre potvrdite model i verziju firmware-a. Sam odgovor koji zavisi od datuma ne dokazuje da je alternativna prijava dostupna niti da je sesija uspostavljena.

### Masovna konfiguracija i zloupotreba grejača za odmrzavanje

Nakon dobijanja administratorskog pristupa, utvrdite koji su kontroleri rashladnih vitrina mapirani u sistemskom menadžeru i da li njegova funkcija distribucije konfiguracije može istovremeno da ih ažurira. Promena zadate temperature vitrine obično je zagreva samo do sobne temperature. Da bi se zagrejala iznad temperature okoline, koristi se električni grejač isparivača kontrolera vitrine: odmrzavanje zaustavlja hlađenje i uključuje grejač dok senzor ili tajmer ne prekine ciklus. Promenom načina odmrzavanja, rasporeda, temperature prekida i vremenskог ограничења grejač може да остане укључен. Менаџер може да дистрибуира те промене на многе витрине и потисне повезане аларме, претварајући компромитацију једног надзорног система у промену процеса у целој продавници.<sup>[[4]](#references)</sup>

Ово је опасност по физички процес, а не безбедан доказ концепта на систему који је у раду. Тамо где постоје, термички прекидачи могу да ограниче рад грејача, али непрекидан рад и даље може да прегреје постојећи ослабљени електрични спој. Конфигурацију и утицај проверавајте само у одобреној лабораторији или у складу са планом оператера за безбедност процеса.<sup>[[4]](#references)</sup>

## Protocol entry points

- [Тестирање Modbus-а](../network-services-pentesting/pentesting-modbus.md) обухвата Modbus TCP, серијске варијанте, кодове функција и приступ регистрима.
- [Тестирање OPC UA-а](../network-services-pentesting/4840-pentesting-opc-ua.md) обухвата индустријску услугу за размену података.
- [Тестирање BACnet-а](../network-services-pentesting/47808-udp-bacnet.md) обухвата мреже за контролу аутоматизације зграда.

## References

- [1] [NIST SP 800-82 Rev. 3 - Водич за безбедност оперативне технологије (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Заобилажење аутентификације у Danfoss System-Managers SM800 и SC255](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Замрзните контролер, одмрзните храну](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Не треба вам државни актер да бисте загрејали фрижидер](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
