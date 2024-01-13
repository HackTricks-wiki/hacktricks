<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**のPRを提出して、あなたのハッキングのコツを共有してください。[**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリ。

</details>


# ベースライン

ベースラインとは、システムの特定の部分のスナップショットを取り、**将来の状態と比較して変更を強調する**ためのものです。

例えば、ファイルシステムの各ファイルのハッシュを計算して保存し、どのファイルが変更されたかを把握することができます。\
これは、作成されたユーザーアカウント、実行中のプロセス、実行中のサービス、そしてあまり変わらない、または全く変わらないはずの他のものにも適用できます。

## ファイル整合性モニタリング

ファイル整合性モニタリングは、既知および未知の脅威に対してITインフラストラクチャとビジネスデータを保護するために使用される最も強力な技術の一つです。\
目的は、監視したい**すべてのファイルのベースラインを生成し**、その後**定期的に**それらのファイルを**変更**（内容、属性、メタデータなど）について**チェック**することです。

1\. **ベースライン比較**では、一つ以上のファイル属性をキャプチャまたは計算し、将来比較するためのベースラインとして保存します。これはファイルの時間と日付として単純なものかもしれませんが、このデータは簡単に偽装できるため、通常はより信頼性の高いアプローチが使用されます。これには、監視されたファイルの暗号化チェックサム（例えば、MD5またはSHA-2ハッシュアルゴリズムを使用）を定期的に評価し、以前に計算されたチェックサムと結果を比較することが含まれます。

2\. **リアルタイム変更通知**は、通常、オペレーティングシステムのカーネル内またはカーネルの拡張機能として実装され、ファイルがアクセスされたり変更されたりしたときにフラグを立てます。

## ツール

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# 参考文献

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**のPRを提出して、あなたのハッキングのコツを共有してください。[**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリ。

</details>
