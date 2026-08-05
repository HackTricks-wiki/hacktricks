# FZ - Infrarooi

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Vir meer inligting oor hoe Infrarooi werk, kyk na:


{{#ref}}
../infrared.md
{{#endref}}

## IR-seinontvanger in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper gebruik 'n digitale IR-seinontvanger, TSOP, wat **dit moontlik maak om seine van IR-afstandbeheerders te onderskep**. Daar is sommige **slimfone** soos Xiaomi wat ook 'n IR-poort het, maar hou in gedagte dat **die meeste van hulle slegs seine kan uitstuur** en **nie in staat is om dit te ontvang nie**.<sup>[[1]](#references)</sup>

Die Flipper-infrarooi-**ontvanger is redelik sensitief**. Jy kan selfs die **sein opvang** terwyl jy **iewers tussenin** die afstandbeheer en die TV bly. Dit is onnodig om die afstandbeheer direk op Flipper se IR-poort te rig. Dit is handig wanneer iemand kanale verander terwyl hy naby die TV staan, en jy sowel as Flipper 'n ent daarvandaan is.

Aangesien die **dekodering van die infrarooi** sein aan die **sagteware**-kant plaasvind, ondersteun Flipper Zero potensieel die **ontvangs en uitstuur van enige IR-afstandbeheerkodes**. In die geval van **onbekende** protokolle wat nie herken kon word nie, **neem dit die rou sein op en speel dit weer af** presies soos dit ontvang is.<sup>[[1]](#references)</sup>

## Aksies

### Universele afstandbeheerders

Flipper Zero kan as 'n **universele afstandbeheerder gebruik word om enige TV, lugversorger of mediasentrum te beheer**. In hierdie modus **bruteforces** Flipper alle **bekende kodes** van alle ondersteunde vervaardigers **volgens die woordeboek vanaf die SD-kaart**. Jy hoef nie 'n spesifieke afstandbeheerder te kies om 'n restaurant-TV af te skakel nie.<sup>[[1]](#references)</sup>

Dit is genoeg om die kragknoppie in die Universele afstandbeheer-modus te druk, en Flipper sal die **"Power Off"-opdragte** van al die TV's wat hy ken **opeenvolgend uitstuur**: Sony, Samsung, Panasonic... en so aan. Wanneer die TV sy sein ontvang, sal dit reageer en afskakel.

Sulke brute-force-aanvalle neem tyd. Hoe groter die woordeboek, hoe langer sal dit neem om te voltooi. Dit is onmoontlik om uit te vind watter sein die TV presies herken het, aangesien daar geen terugvoer vanaf die TV is nie.

### Leer 'n nuwe afstandbeheerder

Dit is moontlik om 'n **infrarooi sein met Flipper Zero op te vang**. As dit die **sein in die databasis vind**, sal Flipper outomaties **weet watter toestel dit is** en jou toelaat om daarmee te kommunikeer.\
As dit dit nie doen nie, kan Flipper die **sein stoor** en jou toelaat om dit **weer af te speel**.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
