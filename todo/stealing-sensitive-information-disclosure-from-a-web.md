# Stealing Sensitive Information Disclosure from a Web

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksであなたの会社を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

もし、あなたのセッションに基づいて機密情報を提示する**ウェブページ**を見つけた場合：クッキーを反映しているか、またはCCの詳細やその他の機密情報を印刷しているかもしれませんが、その情報を盗むことができるかもしれません。\
ここでは、それを達成しようとする主な方法を紹介します：

* [**CORSバイパス**](../pentesting-web/cors-bypass.md): CORSヘッダーをバイパスできる場合、悪意のあるページからAjaxリクエストを実行して情報を盗むことができます。
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): ページにXSSの脆弱性が見つかった場合、それを悪用して情報を盗むことができるかもしれません。
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): XSSタグを注入できない場合でも、他の通常のHTMLタグを使用して情報を盗むことができるかもしれません。
* [**Clickjaking**](../pentesting-web/clickjacking.md): この攻撃に対する保護がない場合、ユーザーをだまして機密データを送信させることができるかもしれません（[こちら](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)の例）。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksであなたの会社を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
