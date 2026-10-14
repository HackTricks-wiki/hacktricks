# Hacking van Industriële Beheerstelsels

{{#include ../banners/hacktricks-training.md}}

## Oor hierdie afdeling

Hierdie afdeling stel komponente, argitekture, protokolle en metodes vir sekuriteitsevaluering van industriële beheerstelsels (ICS) bekend. ICS is deel van die breër domein van operasionele tegnologie (OT): programmeerbare stelsels en toestelle wat fisiese prosesse monitor of veranderinge daarin teweegbring. Algemene voorbeelde sluit in toesighoudende beheer- en data-verkrygingstelsels (SCADA), verspreide beheerstelsels (DCS'e) en programmeerbare logiese beheerders (PLC's).<sup>[[1]](#references)</sup>

Sekuriteitswerk in hierdie omgewings moet vereistes in ag neem wat van konvensionele IT verskil, insluitend prosesveiligheid, betroubaarheid, beskikbaarheid, deterministiese werking en toerustinglewensiklusse. 'n Sekuriteitsbeheer kan tegnies geldig wees, maar steeds ongeskik wees as dit die fisiese proses ontwrig. Toetsing en remediëring moet dus met die stelseleienaar en bedryfspersoneel gekoördineer word.<sup>[[1]](#references)</sup>

'n Kompromittering of toevallige ontwrigting kan produksie stop, toerusting beskadig, gevaarlike materiaal vrystel, die omgewing benadeel, of beserings en lewensverlies veroorsaak. Hierdie moontlike fisiese impak is waarom begrip van die beheerde proses en sy veilige bedryfsgrense noodsaaklik is voordat aktiewe toetsing begin.<sup>[[1]](#references)</sup>

Baie OT-ontplooiings behou verouderde bedryfstelsels, toepassings en protokolle omdat toerusting 'n lang dienslewe het en veranderinge bedryfs- en veiligheidstoetsing vereis. Sommige protokolle is ontwerp sonder moderne verifikasie of enkripsie, en die installering van regstellings kan beperk word deur verskafferondersteuning of onderhoudsvensters. Gebruik netwerksegmentering, toegangsbeheer en monitering as direkte opgraderings nie haalbaar is nie.<sup>[[1]](#references)</sup>

## Prioriteite vir evaluering

Begin deur die beheerde proses, stelselgrense, netwerktopologie, bates, datavloei, vertrouensverhoudings en eksterne verbindings te verstaan. Soortgelyke toesteltipes kan verskillende funksies op verskillende terreine vervul; moenie aanvaar dat een ontplooiing se argitektuur of impakmodel op 'n ander van toepassing is nie.<sup>[[1]](#references)</sup>

Gee waar moontlik voorkeur aan passiewe ontdekking en bestaande ingenieursdokumentasie. Enige aktiewe scanning of exploitation moet 'n goedgekeurde toetsplan volg wat veiligheidsbeperkings, onderhoudsvensters, herstelprosedures en stopvoorwaardes bepaal. Bevindinge moet geëvalueer word vir beide kuberveiligheidsimpak en moontlike uitwerking op die fisiese proses.<sup>[[1]](#references)</sup>

Dieselfde argitektoniese kennis ondersteun verdedigingsaktiwiteite soos bate-inventarisering, netwerksegmentering, monitering, voorvalreaksie en risikogebaseerde kwesbaarheidsbestuur.<sup>[[1]](#references)</sup>

## Protokol-ingangspunte

- [Modbus-toetsing](../network-services-pentesting/pentesting-modbus.md) dek Modbus TCP, seriële variante, funksiekodes en registertoegang.
- [OPC UA-toetsing](../network-services-pentesting/4840-pentesting-opc-ua.md) dek die industriële data-uitruildiens.
- [BACnet-toetsing](../network-services-pentesting/47808-udp-bacnet.md) dek beheernetwerke vir gebou-outomatisering.

## References

- [1] [NIST SP 800-82 Rev. 3 - Gids tot sekuriteit vir operasionele tegnologie (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
