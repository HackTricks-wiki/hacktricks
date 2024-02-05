<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>


# ベースライン

ベースラインは、システムの特定の部分のスナップショットを取得して、**将来の状態と比較して変更点を強調する**ことを目的としています。

たとえば、ファイルシステムの各ファイルのハッシュを計算して保存することで、変更されたファイルを特定できます。\
これは、作成されたユーザーアカウント、実行中のプロセス、実行中のサービスなど、ほとんど変更されないか、まったく変更されないはずのものでも行うことができます。

## ファイル整合性モニタリング

ファイル整合性モニタリングは、既知および未知のさまざまな脅威に対してITインフラストラクチャとビジネスデータを保護するために使用される最も強力な技術の1つです。\
目標は、モニタリングしたいすべてのファイルの**ベースラインを生成**し、その後、定期的にこれらのファイルを可能な限り**変更**（内容、属性、メタデータなど）を**チェック**することです。

1\. **ベースライン比較**では、1つ以上のファイル属性がキャプチャまたは計算され、将来の比較のためにベースラインとして保存されます。これは、ファイルの時刻や日付など、単純なものであっても構いませんが、このデータは簡単に偽装される可能性があるため、通常はより信頼性の高いアプローチが使用されます。これには、監視されたファイルの暗号ハッシュを定期的に評価する（たとえば、MD5またはSHA-2ハッシングアルゴリズムを使用）こと、その結果を以前に計算されたチェックサムと比較することが含まれる場合があります。

2\. **リアルタイムの変更通知**は、通常、ファイルがアクセスまたは変更されたときにフラグを立てるオペレーティングシステムのカーネル内または拡張機能として実装されます。

## ツール

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# 参考文献

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
