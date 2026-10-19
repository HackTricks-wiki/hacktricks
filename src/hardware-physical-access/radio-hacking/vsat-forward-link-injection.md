# VSAT-seininspuiting op die voorwaartse skakel

{{#include ../../banners/hacktricks-training.md}}

’n VSAT-terminaal behandel gewoonlik sy satelliet-afskakel as verkeer vanaf die operateur se spilpunt. In ’n DVB-RCS-stelsel kan daardie voorwaartse skakel sowel gebruiker-IP-pakkette as modembeheerboodskappe dra. As die ontvanger nie ’n boodskap staaf voordat dit verwerk word nie, kan ’n plaaslik ingespuite sein die vertrouensgrens tussen radio en beheervlak oorsteek. Dit is **afskakel-inspuiting by die terminaal**, nie ’n opskakel na die satelliet of passiewe onderskepping van die afskakel nie. Die gedemonstreerde uitkoms hang af van die modem se protokolimplementering en boodskapstawing, nie net van DVB-RCS nie.<sup>[[1]](#references)[[2]](#references)</sup>

## Toets in ’n RF-ingeslote laboratorium

Gebruik ’n terminaal wat jy besit, sy firmware en ’n SDR wat via gepaste verswakking aan die modem se ontvangsinvoer gekoppel is, of gebruik ’n afgeskermde RF-opstelling. Moenie op ’n aktiewe satellietkanaal uitsaai nie. Teken eers die terminaal se ingestelde opstartdraer, simbooltempo en populasie-ID aan; dit help met die verkryging van die voorwaartse skakel.<sup>[[1]](#references)[[3]](#references)</sup> Die DVB-RCS-verkrygingsketting gebruik die Network Information Table (NIT) om die RCS Map Table (RMT) op te spoor, en daarna die Program Association Table (PAT) en Program Map Table (PMT) om die seinstromings vir die voorwaartse skakel op te spoor. ’n Terminaal kan deur verskeie vervoerstroomdraers instel voordat dit die datastroom bereik.<sup>[[3]](#references)</sup>

1. Dekodeer of rekonstrueer die teiken se opstart-vervoerstroom en ondersoek sy NIT, RMT, diens-ID’s, pakket-ID’s (PID’s) en klokverwysingshantering. Vergelyk die standaard met die teiken se ontleder en logs; verskafferspesifieke volgordes of beskrywings kan keer dat ’n andersins geldige stroom aanvaar word.
2. Kapsuleer in die laboratoriumsender ’n onskadelike UDP-sondepakket as `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` en stuur dit deur ’n SDR-sink na die geïsoleerde ontvangspad. Hou die vervoerstroom se Program Clock Reference (PCR) in pas met die greepkoers, anders kan die modem sinchronisasie verloor voordat dit die sondepakket verwerk.
3. Bevestig sowel **demodulator-sluiting** as ontvangs van die sondepakket by ’n interne eindpunt wat jy besit. Sluiting alleen bewys net dat die fisiese laag die golfvorm aanvaar het. Kyk dan of ongestaafde bestuurs- of opdatering-*seinverkeer* blootgestel word, sonder om ’n beeld te installeer of dienskapasiteit te verander.

Die gepubliseerde MDM2200-geval het ’n GNU Radio-bronmodule vir DVB-RCS/MPE/MPEG-TS en `gr-dtv` vir DVB-S2-modulasie gebruik. Die modem het teikenspesifieke inisialiseringbesonderhede vereis: ’n SDT voor die PAT/PMT, ’n RCS-inhoudbeskrywing met tabel-ID `0x3E` en ’n private RMT-greep van `0x01` vir sy GSE/4CPM-modus. Moenie aanvaar dat dié waardes op ’n ander terminaal sal werk nie.<sup>[[1]](#references)</sup> Die navorsers het ook waargeneem dat multicast-MPE-pakkette in hul opstelling ontvangende modems bereik het; teikening was dus nie beperk tot ’n bekende unicast-MAC-adres nie.<sup>[[1]](#references)</sup> ’n Afsonderlike ontleding het onbeskermde beheer- en sagteware-opdateringseinverkeer op die bestudeerde stelsel gevind, maar dié bevinding moet vir elke implementering afsonderlik bevestig word.<sup>[[2]](#references)</sup>

’n IPsec- of VPN-tonnel vir gebruiker-verkeer staaf nie vroeëre DVB-RCS-seinverkeer of die modem se eie opdateringsontleder nie. Onderskei in ’n gemagtigde assessering tussen die kriptografiese beskerming van **gebruiker-IP**, **beheer op die voorwaartse skakel** en **onderhoud-/herstelverkeer**, eerder as om ’n veilige gebruikerstonnel as bewys te beskou dat radio-inspuiting geblokkeer word.<sup>[[1]](#references)[[2]](#references)</sup>

Sien [radioseinanalisering](../hardware-hacking/radio.md) vir aanvanklike I/Q-ondersoek. Sien [firmware-ontleding](../firmware-analysis/) vir ontleding van firmware en ontleders aan die bordkant. Gaan terug na die [oorsig van Radio Hacking](./) vir ander koppelvlakke.

## References

- [1] [Bisping et al. - Draadlose seininspuitingsaanvalle op VSAT-satellietmodems (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: Blootlegging van inherente sekuriteitsprobleme in huidige VSAT-stelselpraktyke (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - DVB-interaksiekanaal vir satellietverspreidingstelsels](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
