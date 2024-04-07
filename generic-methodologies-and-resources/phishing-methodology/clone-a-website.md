<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**し、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**してください**。**
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリに提出してください。

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}



フィッシングアセスメントのためには、時々完全に**ウェブサイトをクローン**することが役立つ場合があります。

クローンされたウェブサイトにBeEFフックなどのペイロードを追加することもできることに注意してください。これにより、ユーザーのタブを「制御」することができます。

この目的で使用できるさまざまなツールがあります：

## wget
```text
wget -mk -nH
```
## goclone

### 概要

`goclone`は、指定されたURLからウェブサイトをクローンするためのツールです。このツールは、指定されたURLからHTML、CSS、JavaScript、画像などのリソースをダウンロードし、ローカルに保存します。これにより、クローンしたウェブサイトをオフラインで閲覧したり、改ざんしたりすることが可能になります。

### 使用法

```bash
goclone -url <target_url> -output <output_directory>
```

- `-url`: クローンしたいウェブサイトのURLを指定します。
- `-output`: クローンしたファイルを保存するディレクトリを指定します。

### 例

```bash
goclone -url https://www.example.com -output /path/to/output_directory
```

このコマンドは、`https://www.example.com`からウェブサイトをクローンし、`/path/to/output_directory`に保存します。
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## ソーシャルエンジニアリングツールキット
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は**、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**をフォローする**
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出してください。

</details>
