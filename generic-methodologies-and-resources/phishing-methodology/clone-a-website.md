<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**してください**。**
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **githubリポジトリに提出してください**。

</details>


フィッシングアセスメントのためには、時々完全に**ウェブサイトをクローン**することが役立つ場合があります。

クローンされたウェブサイトにBeEFフックなどのペイロードを追加することもできます。これにより、ユーザーのタブを「制御」できます。

この目的のために使用できるさまざまなツールがあります：

## wget
```text
wget -mk -nH
```
## goclone

### 概要

`goclone`は、指定されたURLからウェブサイトをクローンするためのツールです。このツールを使用すると、攻撃者は信頼されたウェブサイトの外観を模倣し、被害者を騙すためのフィッシング攻撃を実行することができます。

### 使用法

以下のコマンドを使用して、`goclone`を実行します。

```bash
goclone -url <target_url> -output <output_directory>
```

- `<target_url>`: クローンする対象のウェブサイトのURLを指定します。
- `<output_directory>`: クローンされたウェブサイトの出力先ディレクトリを指定します。

### 注意事項

- `goclone`を使用する際は、法的および倫理的な規制を遵守することを強くお勧めします。
- 他者の許可なしにウェブサイトをクローンすることは違法行為となります。
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## ソーシャルエンジニアリングツールキット
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**をフォローする。**
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>
