# macOS 防御アプリ

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローする**.**
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する

</details>

## ファイアウォール

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 各プロセスによって行われるすべての接続を監視します。モードに応じて（接続を許可する際のサイレント、接続を拒否する際のサイレント、アラート）新しい接続が確立されるたびに **アラートを表示** します。また、この情報をすべて見るための非常に素敵なGUIもあります。
* [**LuLu**](https://objective-see.org/products/lulu.html): Objective-Seeファイアウォール。これは疑わしい接続についてアラートを表示する基本的なファイアウォールです（GUIはLittle Snitchのものほど洗練されていません）。

## 持続性検出

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): **マルウェアが持続する可能性のある** 複数の場所を検索するObjective-Seeアプリケーション（ワンショットツールであり、監視サービスではありません）。
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): 持続性を生成するプロセスを監視することで、KnockKnockのようなもの。

## キーロガー検出

* [**ReiKey**](https://objective-see.org/products/reikey.html): キーボードの「イベントタップ」をインストールする **キーロガー** を見つけるためのObjective-Seeアプリケーション

## ランサムウェア検出

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html): **ファイルの暗号化** アクションを検出するためのObjective-Seeアプリケーション

## マイク＆ウェブカメラ検出

* [**OverSight**](https://objective-see.org/products/oversight.html): ウェブカメラとマイクを使用し始める **アプリケーション** を検出するためのObjective-Seeアプリケーション

## プロセスインジェクション検出

* [**Shield**](https://theevilbit.github.io/shield/): 異なるプロセスインジェクション **テクニックを検出** するアプリケーション
