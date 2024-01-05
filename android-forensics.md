# Android Forensics

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## ロックされたデバイス

Androidデバイスからデータを抽出するには、デバイスのロックを解除する必要があります。ロックされている場合は以下の方法を試すことができます:

* USB経由でのデバッグが有効になっているか確認する。
* [スマッジアタック](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)の可能性を探る。
* [ブルートフォース](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)を試す。

## データ取得

[adbを使用してandroidバックアップを作成](mobile-pentesting/android-app-pentesting/adb-commands.md#backup)し、[Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)を使用して抽出する: `java -jar abe.jar unpack file.backup file.tar`

### rootアクセスまたはJTAGインターフェースへの物理的接続がある場合

* `cat /proc/partitions` (フラッシュメモリへのパスを探す、通常最初のエントリは_mmcblk0_で、全フラッシュメモリに対応しています)。
* `df /data` (システムのブロックサイズを発見する)。
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (ブロックサイズの情報を元に実行する)。

### メモリ

Linux Memory Extractor (LiME)を使用してRAM情報を抽出する。これはadb経由でロードする必要があるカーネル拡張です。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
