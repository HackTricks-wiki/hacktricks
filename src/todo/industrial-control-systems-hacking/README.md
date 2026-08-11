# Hacking van Industriële Beheerstelsels

{{#include ../../banners/hacktricks-training.md}}

## Oor Hierdie Afdeling

Hierdie afdeling stel komponente, argitekture, protokolle en metodes vir sekuriteitsassessering van industriële beheerstelsels (ICS) bekend. ICS is deel van die breër operasionele tegnologie-domein (OT): programmeerbare stelsels en toestelle wat fisiese prosesse monitor of veranderinge daarin veroorsaak. Algemene voorbeelde sluit toesighoudende beheer- en data-insamelingstelsels (SCADA), verspreide beheerstelsels (DCSs) en programmeerbare logiese beheerders (PLCs) in.<sup>[[1]](#references)</sup>

Sekuriteitswerk in hierdie omgewings moet vereistes in ag neem wat van konvensionele IT verskil, insluitend prosesveiligheid, betroubaarheid, beskikbaarheid, deterministiese werking en toerustinglewensiklusse. ’n Tegnies geldige sekuriteitsbeheer kan steeds ongeskik wees indien dit die fisiese proses ontwrig; daarom moet testing en remediëring met die stelseleienaar en bedryfspersoneel gekoördineer word.<sup>[[1]](#references)</sup>

## Assesseringprioriteite

Begin deur die beheerde proses, stelselgrense, netwerktopologie, bates, datavloei, vertrouensverhoudings en eksterne verbindings te verstaan. Soortgelyke toestelsoorte kan verskillende funksies oor terreine heen verrig; vermy dus die aanname dat een ontplooiing se argitektuur of impakmodel op ’n ander van toepassing is.<sup>[[1]](#references)</sup>

Verkies passiewe ontdekking en bestaande ingenieursdokumentasie waar moontlik. Enige aktiewe scanning of exploitation moet ’n goedgekeurde toetsplan volg wat veiligheidsbeperkings, instandhoudingsvensters, herstelprosedures en stoptoestande definieer. Bevindings moet geëvalueer word vir sowel kuberveiligheidsimpak as moontlike uitwerking op die fisiese proses.<sup>[[1]](#references)</sup>

Dieselfde argitektoniese kennis ondersteun defensiewe aktiwiteite soos bate-inventaris, netwerksegmentering, monitering, insidentrespons en risiko-gebaseerde kwesbaarheidsbestuur.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Gids tot Operasionele Tegnologie (OT)-sekuriteit](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
