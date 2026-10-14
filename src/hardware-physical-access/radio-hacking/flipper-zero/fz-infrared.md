# FZ - Infrarooi

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Vir meer inligting oor hoe infrarooi werk, kyk na:


{{#ref}}
../infrared.md
{{#endref}}

## IR-seinontvanger in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero gebruik 'n demodulerende IR-ontvanger om seine van algemene IR-afstandbeheerders op te vang. Sommige fone, insluitend sekere Xiaomi-modelle, het 'n IR-sender, maar die meeste kan nie afstandbeheerseine ontvang en dekodeer nie.<sup>[[1]](#references)</sup>

Die Flipper-infrarooi-**ontvanger is taamlik sensitief**. Jy kan selfs die **sein opvang** terwyl jy **iewers tussen** die afstandbeheerder en die TV staan. Dit is nie nodig om die afstandbeheerder direk op Flipper se IR-poort te rig nie. Dit kom handig te pas wanneer iemand van kanaal verander terwyl hulle naby die TV staan, en jy en Flipper albei 'n entjie weg is.

Protokoldekodering vind in sagteware plaas. Herkende protokolle kan as gedekodeerde opdragte gestoor word; nieondersteunde protokolle kan as rou tydsberekeningdata opgevang en weer gespeel word, binne die hardeware se beperkings vir drafrekwensie en tydsberekening.<sup>[[1]](#references)</sup>

## Aksies

### Universele afstandbeheerders

Flipper Zero se universele-afstandbeheermodus siklus deur bekende opdragte uit sy infrarooi-databasis vir ondersteunde TV's, klanktoerusting, projektors en lugversorgers. Dit is nie gewaarborg om elke toestel te beheer nie, en moet slegs gebruik word op toerusting wat jy besit of gemagtig is om te toets.<sup>[[1]](#references)</sup>

Dit is genoeg om die aan/af-knoppie in Universele-afstandbeheermodus te druk, waarna Flipper **agtereenvolgens "Skakel af"-opdragte** sal stuur vir al die TV's waarvan dit weet: Sony, Samsung, Panasonic... en so aan. Wanneer die TV sy sein ontvang, sal dit daarop reageer en afskakel.

Sulke brute-force neem tyd. Hoe groter die woordeboek, hoe langer neem dit om klaar te maak. Dit is onmoontlik om uit te vind presies watter sein die TV herken het, aangesien die TV geen terugvoer gee nie.

### Leer nuwe afstandbeheer

Flipper Zero kan 'n **infrarooi sein opvang**. As dit die protokol en opdrag herken, stoor dit 'n gedekodeerde voorstelling; anders kan dit die rou tydsberekeningdata stoor om later weer te speel.<sup>[[1]](#references)</sup>

## References

- [1] [Neem TV's oor met Flipper Zero se infrarooi poort](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
