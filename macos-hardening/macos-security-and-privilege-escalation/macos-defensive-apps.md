# macOS 防御アプリ

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に **参加する** か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* **HackTricks** の GitHub リポジトリ [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) に PR を提出して、あなたのハッキングのコツを共有する。

</details>

## ファイアウォール

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 各プロセスによって行われるすべての接続を監視します。モードに応じて（接続を黙って許可、接続を黙って拒否、アラート）、新しい接続が確立されるたびに **アラートを表示** します。この情報をすべて見るための非常に素敵な GUI もあります。
* [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See のファイアウォール。これは、怪しい接続について警告する基本的なファイアウォールです（GUI はありますが、Little Snitch のものほど洗練されていません）。

## 永続性検出

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): **マルウェアが永続化している可能性のある** 複数の場所を検索する Objective-See のアプリケーションです（モニタリングサービスではなくワンショットツールです）。
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): 永続性を生成するプロセスを監視することで KnockKnock と同様です。

## キーロガー検出

* [**ReiKey**](https://objective-see.org/products/reikey.html): キーボードの "イベントタップ" をインストールする **キーロガー** を見つける Objective-See のアプリケーション。

## ランサムウェア検出

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html): **ファイル暗号化** アクションを検出する Objective-See のアプリケーション。

## マイク & ウェブカメラ検出

* [**OverSight**](https://objective-see.org/products/oversight.html): ウェブカメラとマイクを使用し始める **アプリケーションを検出する** Objective-See のアプリケーション。

## プロセスインジェクション検出

* [**Shield**](https://theevilbit.github.io/shield/): 異なるプロセスインジェクション技術を **検出する** アプリケーション。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に **参加する** か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* **HackTricks** の GitHub リポジトリ [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) に PR を提出して、あなたのハッキングのコツを共有する。

</details>
