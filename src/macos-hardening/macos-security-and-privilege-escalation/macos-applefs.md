# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** एक आधुनिक file system है, जिसे Hierarchical File System Plus (HFS+) के स्थान पर लाने के लिए डिज़ाइन किया गया है। इसका विकास **बेहतर performance, security और efficiency** की आवश्यकता के कारण किया गया था।

APFS की कुछ उल्लेखनीय विशेषताओं में शामिल हैं:<sup>[[1]](#references)</sup>

1. **Space Sharing**: APFS कई volumes को एक ही physical device पर मौजूद **समान underlying free storage साझा करने** की अनुमति देता है। इससे space utilization अधिक efficient हो जाता है, क्योंकि volumes manual resizing या repartitioning की आवश्यकता के बिना dynamically बढ़ और घट सकते हैं।
1. इसका अर्थ है कि file disks में traditional partitions की तुलना में, **APFS में अलग-अलग partitions (volumes) पूरे disk space को साझा करते हैं**, जबकि एक regular partition का आकार आमतौर पर fixed होता था।
2. **Snapshots**: APFS **snapshots बनाने** का समर्थन करता है, जो file system के **read-only**, point-in-time instances होते हैं। Snapshots efficient backups और आसान system rollbacks सक्षम करते हैं, क्योंकि वे बहुत कम additional storage का उपयोग करते हैं और उन्हें जल्दी बनाया या revert किया जा सकता है।
3. **Clones**: APFS **ऐसे file या directory clones बना सकता है जो original के साथ समान storage साझा करते हैं**, जब तक कि clone या original file में बदलाव न किया जाए। यह सुविधा storage space को duplicate किए बिना files या directories की copies बनाने का efficient तरीका प्रदान करती है।
4. **Encryption**: APFS **native रूप से full-disk encryption** के साथ-साथ per-file और per-directory encryption का भी समर्थन करता है, जिससे अलग-अलग use cases में data security बेहतर होती है।
5. **Crash Protection**: APFS एक **copy-on-write metadata scheme का उपयोग करता है, जो file system consistency सुनिश्चित करती है**, भले ही अचानक power loss या system crash हो जाए। इससे data corruption का risk कम होता है।

कुल मिलाकर, APFS Apple devices के लिए एक अधिक आधुनिक, flexible और efficient file system प्रदान करता है, जिसका focus बेहतर performance, reliability और security पर है।
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` volume **`/System/Volumes/Data`** में mounted है (आप इसे `diskutil apfs list` से check कर सकते हैं)।

firmlinks की list **`/usr/share/firmlinks`** file में मिल सकती है।
```bash

```
## संदर्भ

- [1] [APFS Guide - Features - Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
