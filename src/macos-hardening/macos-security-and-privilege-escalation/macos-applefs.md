# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)**는 Hierarchical File System Plus (HFS+)를 대체하기 위해 설계된 modern file system입니다. APFS의 개발은 **향상된 성능, 보안 및 효율성**에 대한 필요성에 의해 추진되었습니다.

APFS의 주요 기능은 다음과 같습니다:<sup>[[1]](#references)</sup>

1. **Space Sharing**: APFS를 사용하면 하나의 physical device에서 여러 volume이 **동일한 underlying free storage를 공유**할 수 있습니다. 이를 통해 volume이 수동으로 크기를 조정하거나 다시 partitioning할 필요 없이 동적으로 확장 및 축소될 수 있으므로 storage를 보다 효율적으로 사용할 수 있습니다.
1. 즉, file disk의 traditional partition과 비교하면 **APFS에서는 서로 다른 partition(volume)이 disk space 전체를 공유**하는 반면, 일반적인 partition은 보통 고정된 크기를 가졌습니다.
2. **Snapshots**: APFS는 **snapshot 생성**을 지원하며, snapshot은 file system의 특정 시점 상태를 나타내는 **read-only** instance입니다. Snapshot은 추가 storage를 최소한으로 사용하고 빠르게 생성하거나 되돌릴 수 있으므로 효율적인 backup과 간편한 system rollback을 가능하게 합니다.
3. **Clones**: APFS는 clone 또는 original file이 수정될 때까지 original과 **동일한 storage를 공유하는 file 또는 directory clone을 생성**할 수 있습니다. 이 기능은 storage space를 중복으로 사용하지 않고 file 또는 directory의 복사본을 생성하는 효율적인 방법을 제공합니다.
4. **Encryption**: APFS는 **full-disk encryption**뿐만 아니라 file별 및 directory별 encryption도 native로 지원하여 다양한 사용 사례에서 data security를 향상합니다.
5. **Crash Protection**: APFS는 **file system consistency를 보장하는 copy-on-write metadata scheme**을 사용하므로 갑작스러운 전원 손실이나 system crash가 발생한 경우에도 data corruption 위험을 줄입니다.

전반적으로 APFS는 Apple device를 위한 보다 modern하고 유연하며 효율적인 file system을 제공하며, 향상된 성능, 안정성 및 보안에 중점을 둡니다.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` 볼륨은 **`/System/Volumes/Data`**에 마운트됩니다(`diskutil apfs list`를 사용하여 확인할 수 있습니다).

firmlinks 목록은 **`/usr/share/firmlinks`** 파일에서 확인할 수 있습니다.
```bash

```
## 참고 자료

- [1] [APFS Guide - Features - Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
