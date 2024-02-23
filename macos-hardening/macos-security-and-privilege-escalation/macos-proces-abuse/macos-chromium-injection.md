# macOS Chromium Injection

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**する
- **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

## 基本情報

Google Chrome、Microsoft Edge、BraveなどのChromiumベースのブラウザ。これらのブラウザはChromiumオープンソースプロジェクト上に構築されており、共通のベースを共有しているため、類似の機能と開発者オプションを持っています。

#### `--load-extension` フラグ

`--load-extension` フラグは、コマンドラインやスクリプトからChromiumベースのブラウザを起動する際に使用されます。このフラグを使用すると、ブラウザの起動時に**1つ以上の拡張機能を自動的に読み込む**ことができます。

#### `--use-fake-ui-for-media-stream` フラグ

`--use-fake-ui-for-media-stream` フラグは、Chromiumベースのブラウザを起動する際に使用できる別のコマンドラインオプションです。このフラグは、通常のユーザープロンプトを**バイパスし、カメラやマイクからのメディアストリームへのアクセス許可を求める**ことなく、ブラウザが自動的にカメラやマイクへのアクセスを要求するウェブサイトやアプリケーションに許可を与えるように設計されています。

### ツール

* [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
* [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### 例
```bash
# Intercept traffic
voodoo intercept -b chrome
```
## 参考文献

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を使用して、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい場合は** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** をフォローする。**
* **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出する。 

</details>
