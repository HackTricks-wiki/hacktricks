# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** è un file system moderno progettato per sostituire l'Hierarchical File System Plus (HFS+). Il suo sviluppo è stato guidato dalla necessità di **migliorare le prestazioni, la sicurezza e l'efficienza**.

Al alcune caratteristiche notevoli di APFS includono:

1. **Condivisione dello Spazio**: APFS consente a più volumi di **condividere lo stesso spazio di archiviazione libero sottostante** su un singolo dispositivo fisico. Questo consente un utilizzo dello spazio più efficiente poiché i volumi possono crescere e ridursi dinamicamente senza la necessità di ridimensionamenti o ripartizionamenti manuali.
1. Questo significa, rispetto alle partizioni tradizionali nei dischi file, **che in APFS diverse partizioni (volumi) condividono tutto lo spazio su disco**, mentre una partizione regolare aveva solitamente una dimensione fissa.
2. **Snapshot**: APFS supporta **la creazione di snapshot**, che sono istanze **sola lettura** e puntuali del file system. Gli snapshot consentono backup efficienti e facili rollback di sistema, poiché consumano spazio di archiviazione aggiuntivo minimo e possono essere creati o ripristinati rapidamente.
3. **Cloni**: APFS può **creare cloni di file o directory che condividono lo stesso spazio di archiviazione** dell'originale fino a quando il clone o il file originale non vengono modificati. Questa funzione fornisce un modo efficiente per creare copie di file o directory senza duplicare lo spazio di archiviazione.
4. **Crittografia**: APFS **supporta nativamente la crittografia dell'intero disco** così come la crittografia per file e per directory, migliorando la sicurezza dei dati in diversi casi d'uso.
5. **Protezione da Crash**: APFS utilizza uno **schema di metadati copy-on-write che garantisce la coerenza del file system** anche in caso di improvvisi blackout o crash di sistema, riducendo il rischio di corruzione dei dati.

In generale, APFS offre un file system più moderno, flessibile ed efficiente per i dispositivi Apple, con un focus su prestazioni, affidabilità e sicurezza migliorate.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Il volume `Data` è montato in **`/System/Volumes/Data`** (puoi verificarlo con `diskutil apfs list`).

L'elenco dei firmlinks può essere trovato nel file **`/usr/share/firmlinks`**.
```bash

```
{{#include ../../banners/hacktricks-training.md}}
