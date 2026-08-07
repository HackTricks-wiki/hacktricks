# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Propietary File System (APFS)

**Apple File System (APFS)** ni mfumo wa kisasa wa faili ulioundwa kuchukua nafasi ya Hierarchical File System Plus (HFS+). Uundaji wake ulitokana na hitaji la **kuboresha utendaji, usalama na ufanisi**.

Baadhi ya vipengele muhimu vya APFS ni pamoja na:<sup>[[1]](#references)</sup>

1. **Space Sharing**: APFS huruhusu volumes nyingi **kushiriki hifadhi ileile ya bure iliyo kwenye kifaa kimoja cha kimwili**. Hii huwezesha matumizi bora zaidi ya nafasi, kwa kuwa volumes zinaweza kukua na kupungua kwa ukubwa bila kuhitaji kubadilishwa ukubwa au kugawanywa upya kwa mikono.
1. Hii inamaanisha kuwa, ikilinganishwa na partitions za kawaida kwenye diski, **kwenye APFS partitions tofauti (volumes) hushiriki nafasi yote ya diski**, wakati partition ya kawaida kwa kawaida ilikuwa na ukubwa maalum.
2. **Snapshots**: APFS inasaidia **kuunda snapshots**, ambazo ni matukio ya mfumo wa faili ya **kusoma pekee** yanayowakilisha hali ya mfumo katika muda fulani. Snapshots huwezesha backups bora na kurejesha mfumo kwa urahisi, kwa kuwa hutumia nafasi ndogo ya ziada na zinaweza kuundwa au kurejeshwa haraka.
3. **Clones**: APFS inaweza **kuunda clones za faili au directory zinazoshiriki hifadhi ileile** na faili au directory asili hadi clone au faili asili ibadilishwe. Kipengele hiki hutoa njia bora ya kuunda nakala za faili au directories bila kunakili nafasi ya hifadhi.
4. **Encryption**: APFS **inasaidia natively full-disk encryption**, pamoja na encryption ya kila faili na kila directory, hivyo kuimarisha usalama wa data katika matumizi mbalimbali.
5. **Crash Protection**: APFS hutumia **copy-on-write metadata scheme inayohakikisha uthabiti wa mfumo wa faili** hata katika hali za kupotea kwa umeme ghafla au mfumo ku-crash, hivyo kupunguza hatari ya kuharibika kwa data.

Kwa ujumla, APFS hutoa mfumo wa kisasa, unaonyumbulika na wenye ufanisi zaidi wa faili kwa vifaa vya Apple, ukiweka mkazo katika kuboresha utendaji, kutegemewa na usalama.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

The `Data` volume imewekwa kwenye **`/System/Volumes/Data`** (unaweza kuthibitisha hili kwa kutumia `diskutil apfs list`).

Orodha ya firmlinks inaweza kupatikana kwenye faili la **`/usr/share/firmlinks`**.
```bash

```
## Marejeleo

- [1] [Mwongozo wa APFS - Vipengele - Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
