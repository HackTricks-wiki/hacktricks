# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Eienaarskap Lêerstelsel (APFS)

**Apple Lêerstelsel (APFS)** is 'n moderne lêerstelsel wat ontwerp is om die Hiërargiese Lêerstelsel Plus (HFS+) te vervang. Die ontwikkeling daarvan is gedryf deur die behoefte aan **verbeterde prestasie, sekuriteit en doeltreffendheid**.

Sommige noemenswaardige kenmerke van APFS sluit in:

1. **Ruimte Deel**: APFS laat verskeie volumes toe om **diezelfde onderliggende vrye stoorplek** op 'n enkele fisiese toestel te deel. Dit stel meer doeltreffende ruimte benutting in staat, aangesien die volumes dinamies kan groei en krimp sonder die behoefte aan handmatige hergroting of herpartitionering.
1. Dit beteken, in vergelyking met tradisionele partities in lêer skywe, **dat in APFS verskillende partities (volumes) al die skyfspasie deel**, terwyl 'n gewone partisie gewoonlik 'n vaste grootte gehad het.
2. **Snapshots**: APFS ondersteun **die skep van snapshots**, wat **lees-slegs**, punt-in-tyd voorbeelde van die lêerstelsel is. Snapshots stel doeltreffende rugsteun en maklike stelsels terugrol in staat, aangesien hulle minimale addisionele stoorplek verbruik en vinnig geskep of teruggedraai kan word.
3. **Klone**: APFS kan **lêer of gids klone skep wat diezelfde stoorplek** as die oorspronklike deel totdat of die kloon of die oorspronklike lêer gewysig word. Hierdie kenmerk bied 'n doeltreffende manier om kopieë van lêers of gidse te skep sonder om die stoorplek te dupliceer.
4. **Enkripsie**: APFS **ondersteun van nature volle skyf enkripsie** sowel as per-lêer en per-gids enkripsie, wat datasekuriteit oor verskillende gebruiksgevalle verbeter.
5. **Crash Beskerming**: APFS gebruik 'n **kopie-op-skryf metadata skema wat lêerstelsel konsekwentheid verseker** selfs in gevalle van skielike kragverlies of stelsels wat ineenstort, wat die risiko van datakorruptie verminder.

Algeheel bied APFS 'n meer moderne, buigsame en doeltreffende lêerstelsel vir Apple-toestelle, met 'n fokus op verbeterde prestasie, betroubaarheid en sekuriteit.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Die `Data` volume is gemonteer in **`/System/Volumes/Data`** (jy kan dit nagaan met `diskutil apfs list`).

Die lys van firmlinks kan gevind word in die **`/usr/share/firmlinks`** lêer.
```bash

```
{{#include ../../banners/hacktricks-training.md}}
