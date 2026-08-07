# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple se Proprietêre Lêerstelsel (APFS)

**Apple File System (APFS)** is 'n moderne lêerstelsel wat ontwerp is om die Hierarchical File System Plus (HFS+) te vervang. Die ontwikkeling daarvan is gedryf deur die behoefte aan **verbeterde werkverrigting, sekuriteit en doeltreffendheid**.

Sommige noemenswaardige kenmerke van APFS sluit in:<sup>[[1]](#references)</sup>

1. **Ruimte-deling**: APFS laat verskeie volumes toe om **dieselfde onderliggende vrye berging** op 'n enkele fisiese toestel te **deel**. Dit maak doeltreffender ruimtebenutting moontlik, aangesien die volumes dinamies kan groei en krimp sonder dat handmatige grootteverandering of herpartisionering nodig is.
1. Dit beteken dat, vergeleke met tradisionele partisies op skywe, **verskillende partisies (volumes) in APFS al die skyfspasie deel**, terwyl 'n gewone partisie gewoonlik 'n vaste grootte gehad het.
2. **Snapshots**: APFS ondersteun die **skep van snapshots**, wat **leesalleen-**instansies van die lêerstelsel op 'n spesifieke tydstip is. Snapshots maak doeltreffende rugsteune en maklike stelselterugstellings moontlik, aangesien hulle minimale bykomende berging gebruik en vinnig geskep of teruggestel kan word.
3. **Clones**: APFS kan **lêer- of gids-clones skep wat dieselfde berging as die oorspronklike deel** totdat óf die clone óf die oorspronklike lêer gewysig word. Hierdie kenmerk bied 'n doeltreffende manier om kopieë van lêers of gidse te skep sonder om die bergingspasie te dupliseer.
4. **Enkripsie**: APFS **ondersteun oorspronklik volledige skyf-enkripsie**, sowel as enkripsie per lêer en per gids, wat datasekuriteit oor verskillende gebruiksgevalle heen verbeter.
5. **Beskerming teen ineenstortings**: APFS gebruik 'n **copy-on-write-metadataskema wat lêerstelselkonsekwentheid verseker** selfs in gevalle van skielike kragverlies of stelselongelukke, wat die risiko van datakorrupsie verminder.

Oor die algemeen bied APFS 'n meer moderne, buigsame en doeltreffende lêerstelsel vir Apple-toestelle, met 'n fokus op verbeterde werkverrigting, betroubaarheid en sekuriteit.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Die `Data`-volume word in **`/System/Volumes/Data`** gemonteer (jy kan dit met `diskutil apfs list` nagaan).

Die lys van firmlinks kan in die **`/usr/share/firmlinks`**-lêer gevind word.
```bash

```
## Verwysings

- [1] [APFS Guide - Kenmerke - Apple-ontwikkelaardokumentasie](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
