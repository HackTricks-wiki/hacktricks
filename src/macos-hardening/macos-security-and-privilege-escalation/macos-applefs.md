# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** ni mfumo wa kisasa wa faili ulioandaliwa ili kuchukua nafasi ya Hierarchical File System Plus (HFS+). Maendeleo yake yalichochewa na hitaji la **kuboresha utendaji, usalama, na ufanisi**.

Baadhi ya sifa muhimu za APFS ni pamoja na:

1. **Space Sharing**: APFS inaruhusu volumu nyingi **kushiriki hifadhi ya bure iliyo chini** kwenye kifaa kimoja cha kimwili. Hii inaruhusu matumizi bora ya nafasi kwani volumu zinaweza kukua na kupungua kwa njia ya kidijitali bila haja ya kubadilisha ukubwa au kugawanya upya.
1. Hii inamaanisha, ikilinganishwa na sehemu za jadi katika diski za faili, **kwamba katika APFS sehemu tofauti (volumu) zinashiriki nafasi yote ya diski**, wakati sehemu ya kawaida mara nyingi ilikuwa na ukubwa wa kudumu.
2. **Snapshots**: APFS inasaidia **kuunda snapshots**, ambazo ni **za kusoma tu**, matukio ya wakati wa mfumo wa faili. Snapshots zinaruhusu nakala za haraka na urahisi wa kurejesha mfumo, kwani zinatumia hifadhi ya ziada kidogo na zinaweza kuundwa au kurejeshwa haraka.
3. **Clones**: APFS inaweza **kuunda clones za faili au saraka ambazo zinashiriki hifadhi ile ile** kama ya asili hadi clone au faili ya asili ibadilishwe. Sifa hii inatoa njia bora ya kuunda nakala za faili au saraka bila kuiga nafasi ya hifadhi.
4. **Encryption**: APFS **inasaidia kwa asili encryption ya diski nzima** pamoja na encryption ya kila faili na kila saraka, ikiongeza usalama wa data katika matumizi tofauti.
5. **Crash Protection**: APFS inatumia **mpango wa metadata wa nakala-katika-k写 ambao unahakikisha uthabiti wa mfumo wa faili** hata katika matukio ya kupoteza nguvu ghafla au kuanguka kwa mfumo, ikipunguza hatari ya uharibifu wa data.

Kwa ujumla, APFS inatoa mfumo wa faili wa kisasa, rahisi, na wenye ufanisi kwa vifaa vya Apple, ukiwa na mkazo kwenye kuboresha utendaji, uaminifu, na usalama.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Hifadhi ya `Data` imewekwa katika **`/System/Volumes/Data`** (unaweza kuangalia hii kwa kutumia `diskutil apfs list`).

Orodha ya firmlinks inaweza kupatikana katika faili ya **`/usr/share/firmlinks`**.
```bash

```
{{#include ../../banners/hacktricks-training.md}}
