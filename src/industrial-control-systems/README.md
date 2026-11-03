# Hacking van industriële beheerstelsels

{{#include ../banners/hacktricks-training.md}}

## Oor hierdie afdeling

Hierdie afdeling stel komponente, argitekture, protokolle en sekuriteitsbeoordelingsmetodes vir industriële beheerstelsels (ICS) bekend. ICS is deel van die breër domein van operasionele tegnologie (OT): programmeerbare stelsels en toestelle wat fisiese prosesse monitor of veranderinge daarin veroorsaak. Algemene voorbeelde sluit in toesigbeheer- en data-insamelingstelsels (SCADA), verspreide beheerstelsels (DCSs) en programmeerbare logiese beheerders (PLCs).<sup>[[1]](#references)</sup>

Sekuriteitswerk in hierdie omgewings moet vereistes in ag neem wat van konvensionele IT verskil, insluitend prosesveiligheid, betroubaarheid, beskikbaarheid, deterministiese werking en toerustinglewensiklusse. ’n Tegnies geldige sekuriteitsbeheer kan steeds ongeskik wees as dit die fisiese proses ontwrig, daarom moet toetsing en remediëring met die stelseleienaar en bedryfspersoneel gekoördineer word.<sup>[[1]](#references)</sup>

Kompromittering of toevallige ontwrigting kan produksie stop, toerusting beskadig, gevaarlike materiaal vrystel, die omgewing benadeel, of beserings en lewensverlies veroorsaak. Hierdie moontlike fisiese impak is waarom begrip van die beheerde proses en sy veilige bedryfsgrense voor aktiewe toetsing moet kom.<sup>[[1]](#references)</sup>

Baie OT-ontplooiings behou verouderde bedryfstelsels, toepassings en protokolle omdat toerusting ’n lang dienslewe het en veranderinge operasionele en veiligheidstoetsing vereis. Sommige protokolle is ontwerp sonder moderne verifikasie of enkripsie, en regstelling van kwesbaarhede kan deur verskafferondersteuning of onderhoudsvensters beperk word; gebruik segmentering, toegangsbeheer en monitering as direkte opgraderings nie haalbaar is nie.<sup>[[1]](#references)</sup>

## Beoordelingsprioriteite

Begin deur die beheerde proses, stelselgrense, netwerktopologie, bates, datavloei, vertrouensverhoudings en eksterne verbindings te verstaan. Soortgelyke toesteltipes kan op verskillende terreine verskillende funksies hê, moet dus nie aanvaar dat een ontplooiing se argitektuur of impakmodel op ’n ander van toepassing is nie.<sup>[[1]](#references)</sup>

Verkies passiewe ontdekking en bestaande ingenieursdokumentasie waar moontlik. Enige aktiewe skandering of uitbuiting moet ’n goedgekeurde toetsplan volg wat veiligheidsbeperkings, onderhoudsvensters, herstelprosedures en stopvoorwaardes definieer. Bevindings moet beoordeel word vir sowel kuberveiligheidsimpak as moontlike uitwerking op die fisiese proses.<sup>[[1]](#references)</sup>

Dieselfde argitektoniese kennis ondersteun verdedigingsaktiwiteite soos bate-inventarisering, netwerksegmentering, monitering, insidentreaksie en risikogebaseerde kwesbaarheidsbestuur.<sup>[[1]](#references)</sup>

## Misbruik van toesighoudende verkoelingsbeheerder

’n Verkoelingstelselbestuurder koördineer kompressor- en verkoelingskasbeheerders, maar verkoel nie self die kaste nie. Toegang tot sy bestuurskoppelvlak kan dus beheer oor baie ondergeskikte toestelle moontlik maak deur normale konfigurasieverspreiding. Dit verskil van die verandering van een termostaat of die direkte aandrywing van ’n kompressor.<sup>[[3]](#references)[[4]](#references)</sup>

### Aanmelding met ’n datumafgeleide onderhoudskode

Op geraakte Danfoss-stelselbestuurders aanvaar ’n alternatiewe XML-aanmelding ’n kode wat van die beheerder se datum afgelei is, in plaas van ’n rekeningwagwoord.<sup>[[2]](#references)[[3]](#references)</sup> Op die SM800 en SC255 het Synacktiv die `eds_only`- en `quantum_only`-kenmerke deur `xml_load_file` en `check_authorize` tot by `check_code_of_day` opgespoor. Sy advies wys ook dat `read_date_time` op `xml.cgi` die beheerder se datum sonder verifikasie openbaar maak.<sup>[[2]](#references)</sup> Claroty het ’n ooreenstemmende `getauth`-pad op die AK-SM 800A gevind, maar die snellerkenmerke daarvan geredigeer; daar moet nie aanvaar word dat die kenmerkname van die ouer modelle op daardie platform werk nie.<sup>[[3]](#references)</sup>

Synacktiv dokumenteer die onverifieerde datumnavraag soos volg:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

Die kode het geen toestellingspesifieke geheim nie: deur die algoritme uit [firmware](../hardware-physical-access/firmware-analysis/) te herwin, kan ’n datumgeldige geloofsbrief verkry word vir toestelle met dieselfde kwesbare implementering.<sup>[[2]](#references)[[3]](#references)</sup> Bevestig eers die model en firmware. ’n Datumrespons alleen bewys nie dat die alternatiewe aanmelding beskikbaar is of dat ’n sessie verkry is nie.

### Grootmaatkonfigurasie en misbruik van ontdooiingsverwarmers

Ná administratiewe toegang, identifiseer die stelselbestuurder se gekarteerde kasbeheerders en bepaal of sy konfigurasieverspreidingsfunksie hulle gelyktydig kan opdateer. ’n Verandering aan die kas se stelpunt maak die kas normaalweg net warmer tot kamertemperatuur. Om dit bo die omgewingstemperatuur te verhit, is die elektriese verdamper-ontdooiingsverwarmer van die kasbeheerder die toepaslike beheer: ontdooiing stop die verkoeling en skakel dié verwarmer aan totdat ’n sensor of tydhouer die siklus beëindig. Deur eerder die ontdooiingsmetode, skedule, beëindigingstemperatuur en tydsbeperking te verander, kan die verwarmer aan die gang gehou word. Die bestuurder kan dié veranderinge oor baie kaste versprei en die gepaardgaande alarms onderdruk, sodat een kompromittering van die toesigstelsel in ’n prosesverandering oor die hele winkel ontaard.<sup>[[4]](#references)</sup>

Dit hou ’n gevaar vir die fisiese proses in en is nie ’n veilige bewys-van-konsep op ’n lewendige stelsel nie. Waar dit voorkom, kan termiese afskakelaars die werking van die verwarmer beperk, maar deurlopende werking kan steeds ’n bestaande swak elektriese verbinding oorverhit. Bevestig die konfigurasie en impak slegs in ’n goedgekeurde laboratorium of volgens die operateur se prosesveiligheidsplan.<sup>[[4]](#references)</sup>

## Protokol-toegangspunte

- [Modbus-toetsing](../network-services-pentesting/pentesting-modbus.md) dek Modbus TCP, variante vir seriële verbindings, funksiekodes en toegang tot registers.
- [OPC UA-toetsing](../network-services-pentesting/4840-pentesting-opc-ua.md) dek die industriële data-uitruildiens.
- [BACnet-toetsing](../network-services-pentesting/47808-udp-bacnet.md) dek beheernetwerke vir gebou-outomatisering.

## References

- [1] [NIST SP 800-82 Rev. 3 - Gids tot sekuriteit vir operasionele tegnologie (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Omseiling van verifikasie in Danfoss System-Managers SM800 en SC255](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Vries die beheerder, ontdooi die kos](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Jy het nie ’n nasiestaat nodig om ’n yskas warm te maak nie](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
