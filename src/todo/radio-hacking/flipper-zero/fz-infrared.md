# FZ - Infrarooi

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Vir meer inligting oor hoe Infrarooi werk, kyk:

{{#ref}}
../infrared.md
{{#endref}}

## IR Seinontvanger in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper gebruik 'n digitale IR seinontvanger TSOP, wat **toelaat om seine van IR afstandsbedienings te onderskep**. Daar is 'n paar **smartphones** soos Xiaomi, wat ook 'n IR-poort het, maar hou in gedagte dat **meeste van hulle net kan oordra** seine en **nie kan ontvang** nie.

Die Flipper infrarooi **ontvanger is redelik sensitief**. Jy kan selfs die **sein vang** terwyl jy **ergens tussen** die afstandsbediening en die TV bly. Dit is nie nodig om die afstandsbediening direk na Flipper se IR-poort te wys nie. Dit is handig wanneer iemand kanale verander terwyl hy naby die TV staan, en beide jy en Flipper is 'n afstand weg.

Aangesien die **ontleding van die infrarooi** sein aan die **programmatuur** kant gebeur, ondersteun Flipper Zero potensieel die **ontvangs en oordrag van enige IR afstandsbediening kode**. In die geval van **onbekende** protokolle wat nie herken kon word nie - dit **neem op en speel** die rou sein presies soos ontvang.

## Aksies

### Universele Afstandsbedienings

Flipper Zero kan gebruik word as 'n **universele afstandsbediening om enige TV, lugversorger of mediacentrum te beheer**. In hierdie modus, Flipper **bruteforces** al die **bekende kodes** van al die ondersteunde vervaardigers **volgens die woordeboek van die SD-kaart**. Jy hoef nie 'n spesifieke afstandsbediening te kies om 'n restaurant TV af te skakel nie.

Dit is genoeg om die aan/af-knoppie in die Universele Afstandsbediening modus te druk, en Flipper sal **volgordelik "Power Off"** opdragte van al die TV's wat hy ken, stuur: Sony, Samsung, Panasonic... ensovoorts. Wanneer die TV sy sein ontvang, sal dit reageer en afskakel.

So 'n brute-kracht neem tyd. Hoe groter die woordeboek, hoe langer sal dit neem om te voltooi. Dit is onmoontlik om uit te vind watter sein presies die TV herken het, aangesien daar geen terugvoer van die TV is nie.

### Leer Nuwe Afstandsbediening

Dit is moontlik om 'n **infrarooi sein** met Flipper Zero te **vang**. As dit **die sein in die databasis vind**, sal Flipper outomaties **weet watter toestel dit is** en jou toelaat om daarmee te interaksie.\
As dit nie, kan Flipper die **sein** **stoor** en sal dit jou toelaat om dit te **herhaal**.

## Verwysings

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
