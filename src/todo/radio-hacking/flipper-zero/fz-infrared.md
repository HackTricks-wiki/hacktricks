# FZ - Infrarooi

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Vir meer inligting oor hoe Infrarooi werk, kyk:


{{#ref}}
../infrared.md
{{#endref}}

## IR-seinontvanger in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero gebruik 'n demodulerende IR-ontvanger om seine vanaf algemene IR-afstandbeheerders vas te vang. Sommige fone, insluitend sekere Xiaomi-modelle, bevat 'n IR-sender, maar die meeste kan nie afstandbeheerseine ontvang en dekodeer nie.<sup>[[1]](#references)</sup>

Die Flipper-infrarooi **ontvanger is redelik sensitief**. Jy kan selfs die **sein opvang** terwyl jy **iewers tussenin** die afstandbeheerder en die TV staan. Dit is onnodig om die afstandbeheerder direk na Flipper se IR-poort te rig. Dit is handig wanneer iemand kanale verander terwyl hy naby die TV staan, en jy sowel as Flipper 'n entjie daarvandaan is.

Protokol-dekodering gebeur in sagteware. Herkende protokolle kan as gedekodeerde opdragte gestoor word; protokolle wat nie ondersteun word nie, kan as rou tydsberekeningsdata vasgelê en weer afgespeel word, onderhewig aan die hardeware se draerfrekwensie- en tydsberekeningsbeperkings.<sup>[[1]](#references)</sup>

## Aksies

### Universele afstandbeheerders

Flipper Zero se universele-afstandbeheer-modus siklus deur bekende opdragte uit sy infrarooi-databasis vir ondersteunde TV's, oudiotoerusting, projektors en lugversorgers. Dit is nie gewaarborg om elke toestel te beheer nie, en dit moet slegs gebruik word op toerusting wat jy besit of waarvoor jy gemagtig is om te toets.<sup>[[1]](#references)</sup>

Dit is genoeg om die aan/af-knoppie in die Universal Remote-modus te druk, en Flipper sal **opeenvolgend "Power Off"-opdragte** stuur vir al die TV's waarvan dit weet: Sony, Samsung, Panasonic... en so aan. Wanneer die TV sy sein ontvang, sal dit reageer en afskakel.

Sulke brute-force neem tyd. Hoe groter die woordeboek, hoe langer sal dit neem om te voltooi. Dit is onmoontlik om uit te vind watter sein presies deur die TV herken is, aangesien daar geen terugvoer vanaf die TV is nie.

### Leer nuwe afstandbeheer

Flipper Zero kan 'n **infrarooisein vaslê**. As dit die protokol en opdrag herken, stoor dit 'n gedekodeerde voorstelling; andersins kan dit die rou tydsberekeningsdata stoor vir latere herafspeel.<sup>[[1]](#references)</sup>

## References

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
