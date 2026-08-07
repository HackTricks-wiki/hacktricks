# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Propietary File System (APFS)

**Apple File System (APFS)** è un file system moderno progettato per sostituire l'Hierarchical File System Plus (HFS+). Il suo sviluppo è stato motivato dalla necessità di ottenere **prestazioni, sicurezza ed efficienza migliorate**.

Alcune caratteristiche degne di nota di APFS includono:<sup>[[1]](#references)</sup>

1. **Condivisione dello spazio**: APFS consente a più volumi di **condividere lo stesso spazio di archiviazione libero sottostante** su un singolo dispositivo fisico. Ciò permette di utilizzare lo spazio in modo più efficiente, poiché i volumi possono aumentare e ridursi dinamicamente senza dover ridimensionare o ripartizionare manualmente.
1. Ciò significa che, rispetto alle partizioni tradizionali nei dischi, **in APFS partizioni diverse (volumi) condividono tutto lo spazio del disco**, mentre una partizione normale aveva solitamente una dimensione fissa.
2. **Snapshot**: APFS supporta la **creazione di snapshot**, ovvero istanze del file system **di sola lettura** relative a uno specifico momento. Gli snapshot consentono backup efficienti e semplici ripristini del sistema, poiché consumano una quantità minima di spazio aggiuntivo e possono essere creati o ripristinati rapidamente.
3. **Cloni**: APFS può **creare cloni di file o directory che condividono lo stesso spazio di archiviazione** dell'originale finché il clone o il file originale non viene modificato. Questa funzionalità offre un modo efficiente per creare copie di file o directory senza duplicare lo spazio di archiviazione.
4. **Crittografia**: APFS **supporta nativamente la crittografia dell'intero disco**, nonché la crittografia per singolo file e directory, migliorando la sicurezza dei dati in diversi casi d'uso.
5. **Protezione dagli arresti anomali**: APFS utilizza uno **schema di metadati copy-on-write che garantisce la coerenza del file system** anche in caso di improvvisa perdita di alimentazione o arresti anomali del sistema, riducendo il rischio di danneggiamento dei dati.

Nel complesso, APFS offre un file system più moderno, flessibile ed efficiente per i dispositivi Apple, con particolare attenzione a prestazioni, affidabilità e sicurezza migliorate.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Il volume **`Data`** è montato in **`/System/Volumes/Data`** (puoi verificarlo con `diskutil apfs list`).

L'elenco dei firmlinks si trova nel file **`/usr/share/firmlinks`**.
```bash

```
## Riferimenti

- [1] [Guida APFS - Funzionalità - Documentazione per sviluppatori Apple](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
