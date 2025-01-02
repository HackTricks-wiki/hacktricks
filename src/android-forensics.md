# Android Forensics

{{#include ./banners/hacktricks-training.md}}

## ロックされたデバイス

Androidデバイスからデータを抽出するには、デバイスのロックを解除する必要があります。ロックされている場合は、次のことができます：

- デバイスにUSB経由のデバッグが有効になっているか確認する。
- 可能な[スムッジ攻撃](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)を確認する。
- [ブルートフォース](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)を試みる。

## データ取得

[adbを使用してandroidバックアップを作成](mobile-pentesting/android-app-pentesting/adb-commands.md#backup)し、[Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)を使用して抽出します：`java -jar abe.jar unpack file.backup file.tar`

### ルートアクセスまたはJTAGインターフェースへの物理接続がある場合

- `cat /proc/partitions`（フラッシュメモリへのパスを検索します。一般的に最初のエントリは _mmcblk0_ で、全体のフラッシュメモリに対応します）。
- `df /data`（システムのブロックサイズを確認します）。
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096（ブロックサイズから得た情報を使用して実行します）。

### メモリ

Linux Memory Extractor (LiME)を使用してRAM情報を抽出します。これは、adb経由でロードする必要があるカーネル拡張です。

{{#include ./banners/hacktricks-training.md}}
