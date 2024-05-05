# メモリーダンプ解析

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>！</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクションを入手
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するには、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの1つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## 開始

pcap内の**マルウェア**を検索してください。[**マルウェア解析**](../malware-analysis.md)で言及されている**ツール**を使用してください。

## [Volatility](volatility-cheatsheet.md)

**Volatilityはメモリーダンプ解析の主要なオープンソースフレームワーク**です。このPythonツールは、外部ソースまたはVMware VMからのダンプを分析し、ダンプのOSプロファイルに基づいてプロセスやパスワードなどのデータを識別します。プラグインで拡張可能であり、法医学調査に非常に適しています。

[**こちらでチートシートを見つける**](volatility-cheatsheet.md)

## ミニダンプクラッシュレポート

ダンプが小さい場合（数KB、おそらく数MB）、それはおそらくミニダンプクラッシュレポートであり、メモリーダンプではありません。

![](<../../../.gitbook/assets/image (532).png>)

Visual Studioがインストールされている場合、このファイルを開いてプロセス名、アーキテクチャ、例外情報、実行されているモジュールなどの基本情報をバインドできます。

![](<../../../.gitbook/assets/image (263).png>)

例外をロードして、逆コンパイルされた命令を表示することもできます

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

とにかく、Visual Studioはダンプの深い解析を行うための最適なツールではありません。

**IDA**または**Radare**を使用して、それを**詳細に**検査してください。

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの1つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>！</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクションを入手
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するには、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
