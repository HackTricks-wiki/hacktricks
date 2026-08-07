# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Locked Device

Androidデバイスからデータの抽出を開始するには、デバイスのロックを解除する必要があります。ロックされている場合は、以下を実行できます。

- デバイスで USB経由のデバッグが有効になっているか確認する。
- [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>の可能性を確認する。
- [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>を試す。

## Data Acquisition

[adbを使用してAndroid backupを作成し](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup)、[Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)を使用して展開します。`java -jar abe.jar unpack file.backup file.tar`

### If root access or physical connection to JTAG interface

- `cat /proc/partitions`（flash memoryへのパスを検索します。通常、最初のエントリは _mmcblk0_ で、flash memory全体に対応します）。
- `df /data`（systemのblock sizeを確認します）。
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096（block sizeから取得した情報を使用して実行します）。

### Memory

Linux Memory Extractor（LiME）を使用してRAM情報を抽出します。これはadb経由でロードする必要があるkernel extensionです。

## References

- [1] [スマートフォンのタッチスクリーンに対するSmudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [このbrute force deviceはあらゆるiPhoneのPIN codeをcrackできる](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
