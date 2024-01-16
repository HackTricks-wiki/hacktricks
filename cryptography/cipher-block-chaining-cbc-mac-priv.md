<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>


# CBC

もし**cookie**が**username**だけである場合（またはcookieの最初の部分がusernameである場合）、username "**admin**"になりすましをしたい場合は、usernameに**"bdmin"**を作成し、cookieの**最初のバイト**を**ブルートフォース**することができます。

# CBC-MAC

暗号学において、**cipher block chaining message authentication code**（**CBC-MAC**）は、ブロック暗号からメッセージ認証コードを構築するための技術です。メッセージはCBCモードでブロック暗号アルゴリズムで暗号化され、**各ブロックが前のブロックの適切な暗号化に依存するブロックのチェーンを作成します**。この相互依存性により、プレーンテキストの**任意のビット**に対する**変更**が、ブロック暗号のキーを知らないと予測または対抗できない方法で**最終的な暗号化されたブロック**を**変更**することを保証します。

メッセージmのCBC-MACを計算するには、初期化ベクトルをゼロにしてmをCBCモードで暗号化し、最後のブロックを保持します。以下の図は、秘密鍵kとブロック暗号Eを使用して、ブロック![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5)で構成されるメッセージのCBC-MACの計算をスケッチしています：

![CBC-MAC structure (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_%28en%29.svg/570px-CBC-MAC_structure_%28en%29.svg.png)

# 脆弱性

通常、CBC-MACでは使用される**IVは0**です。\
これは問題です。なぜなら、2つの既知のメッセージ（`m1`と`m2`）は、独立して2つの署名（`s1`と`s2`）を生成するからです。したがって：

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

次に、m1とm2を連結したメッセージ（m3）は2つの署名（s31とs32）を生成します：

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**これは、暗号のキーを知らなくても計算することが可能です。**

例えば、名前**Administrator**を**8バイト**ブロックで暗号化しているとします：

* `Administ`
* `rator\00\00\00`

あなたは**Administ**（m1）というユーザー名を作成し、署名（s1）を取得することができます。\
次に、`rator\00\00\00 XOR s1`の結果というユーザー名を作成できます。これにより、`E(m2 XOR s1 XOR 0)`が生成され、これはs32です。\
今、あなたはs32をフルネーム**Administrator**の署名として使用することができます。

### 要約

1. ユーザー名**Administ**（m1）の署名を取得します。これはs1です。
2. ユーザー名**rator\x00\x00\x00 XOR s1 XOR 0**の署名はs32です。
3. cookieをs32に設定すると、ユーザー**Administrator**の有効なcookieになります。

# IVを制御する攻撃

使用されるIVを制御できる場合、攻撃は非常に簡単になる可能性があります。\
もしcookieが単にユーザー名を暗号化したものである場合、ユーザー"**administrator**"になりすますためには、ユーザー"**Administrator**"を作成し、そのcookieを取得します。\
今、もしあなたがIVを制御できるならば、IVの最初のバイトを変更して**IV\[0] XOR "A" == IV'\[0] XOR "a"**となるようにし、ユーザー**Administrator**のためのcookieを再生成することができます。このcookieは、初期**IV**を使用してユーザー**administrator**になりすますために有効です。

# 参考文献

より多くの情報は[https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)で入手できます。


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
