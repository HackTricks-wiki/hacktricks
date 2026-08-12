# Hacking van Industriële Beheerstelsels

{{#include ../../banners/hacktricks-training.md}}

## Oor Hierdie Afdeling

Hierdie afdeling stel industriële beheerstelsel-komponente (ICS), argitekture, protokolle en sekuriteitsassesseringsmetodes bekend. ICS is deel van die breër operasionele tegnologie (OT)-domein: programmeerbare stelsels en toestelle wat fisiese prosesse monitor of veranderinge daarin veroorsaak. Algemene voorbeelde sluit toesighoudende beheer- en data-insamelingstelsels (SCADA), verspreide beheerstelsels (DCSs) en programmeerbare logiese beheerders (PLCs) in.<sup>[[1]](#references)</sup>

Sekuriteitswerk in hierdie omgewings moet vereistes in ag neem wat van konvensionele IT verskil, insluitend prosesveiligheid, betroubaarheid, beskikbaarheid, deterministiese werking en toerustinglewensiklusse. ’n Tegnies geldige sekuriteitsbeheer kan steeds ongeskik wees indien dit die fisiese proses ontwrig; daarom moet toetsing en remediëring met die stelseleienaar en bedryfspersoneel gekoördineer word.<sup>[[1]](#references)</sup>

’n Kompromittering of toevallige ontwrigting kan produksie stop, toerusting beskadig, gevaarlike materiaal vrystel, die omgewing benadeel, of besering en lewensverlies veroorsaak. Hierdie moontlike fisiese impak is waarom begrip van die beheerde proses en sy veilige bedryfsperke vóór aktiewe toetsing moet kom.<sup>[[1]](#references)</sup>

Baie OT-ontplooiings behou verouderde bedryfstelsels, toepassings en protokolle omdat toerusting ’n lang dienslewe het en veranderinge operasionele en veiligheidstoetsing vereis. Sommige protokolle is ontwerp sonder moderne verifikasie of encryption, en patching kan deur verskafferondersteuning of onderhoudsvensters beperk word; vergoed hiervoor met segmentering, toegangsbeheer en monitering waar direkte opgraderings nie haalbaar is nie.<sup>[[1]](#references)</sup>

## Assesseringsprioriteite

Begin deur die beheerde proses, stelselgrense, netwerktopologie, bates, datavloeie, vertrouensverhoudings en eksterne verbindings te verstaan. Soortgelyke toestelsoorte kan verskillende funksies op verskillende terreine verrig; vermy dus die aanname dat een ontplooiing se argitektuur of impakmodel op ’n ander van toepassing is.<sup>[[1]](#references)</sup>

Verkies passiewe ontdekking en bestaande ingenieursdokumentasie waar moontlik. Enige aktiewe scanning of exploitation moet ’n goedgekeurde toetsplan volg wat veiligheidsbeperkings, onderhoudsvensters, herstelprosedures en stoptoestande definieer. Bevindings moet geëvalueer word vir sowel kuberveiligheidsimpak as moontlike uitwerkings op die fisiese proses.<sup>[[1]](#references)</sup>

Dieselfde argitektoniese kennis ondersteun verdedigingsaktiwiteite soos bate-inventaris, netwerksegmentering, monitering, insidentreaksie en risiko-gebaseerde vulnerability management.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Gids tot Sekuriteit van Operasionele Tegnologie (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
