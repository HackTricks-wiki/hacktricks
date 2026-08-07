# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple独自のファイルシステム（APFS）

**Apple File System（APFS）**は、Hierarchical File System Plus（HFS+）に取って代わるために設計された最新のファイルシステムです。その開発は、**パフォーマンス、セキュリティ、効率性の向上**を必要としていたことが背景にあります。

APFSの主な機能には、次のようなものがあります。<sup>[[1]](#references)</sup>

1. **Space Sharing**：APFSでは、1台の物理デバイス上で複数のボリュームが**同じ基盤となる空きストレージを共有**できます。これにより、手動でサイズ変更や再パーティションを行わなくても、ボリュームを動的に拡張・縮小でき、より効率的に容量を利用できます。
1. つまり、従来のディスク上のパーティションと比較すると、**APFSでは異なるパーティション（ボリューム）がディスク容量全体を共有する**一方、通常のパーティションには固定サイズが設定されていました。
2. **Snapshots**：APFSは**スナップショットの作成**をサポートしています。スナップショットは、ファイルシステムの特定時点における**読み取り専用**の状態です。スナップショットは追加で消費するストレージが最小限で、迅速に作成・復元できるため、効率的なバックアップや容易なシステムのロールバックを可能にします。
3. **Clones**：APFSでは、元のファイルまたはディレクトリと**同じストレージを共有するファイルまたはディレクトリのクローン**を作成できます。クローンまたは元のファイルが変更されるまで、ストレージは共有されます。この機能により、ストレージ容量を重複して使用せずに、ファイルやディレクトリのコピーを効率的に作成できます。
4. **Encryption**：APFSは**ディスク全体の暗号化**に加え、ファイル単位およびディレクトリ単位の暗号化をネイティブでサポートし、さまざまな用途におけるデータセキュリティを強化します。
5. **Crash Protection**：APFSは、**copy-on-write方式のメタデータスキームを使用してファイルシステムの整合性を保証**します。これにより、突然の電源喪失やシステムクラッシュが発生した場合でも、データ破損のリスクを低減できます。

全体として、APFSはAppleデバイス向けに、パフォーマンス、信頼性、セキュリティの向上を重視した、より最新で柔軟かつ効率的なファイルシステムを提供します。
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` volumeは **`/System/Volumes/Data`** に mount されています（`diskutil apfs list` で確認できます）。

firmlinksの一覧は **`/usr/share/firmlinks`** ファイルにあります。
```bash

```
## 参照

- [1] [APFS Guide - Features - Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
