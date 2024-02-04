<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手
* 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する：[**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>


# CBC

もし**クッキー**が**ユーザー名だけ**（またはクッキーの最初の部分がユーザー名）であり、ユーザー名を "**admin**" に偽装したい場合、ユーザー名 **"bdmin"** を作成し、クッキーの**最初のバイト**を**ブルートフォース**することができます。

# CBC-MAC

暗号学において、**Cipher Block Chaining Message Authentication Code**（**CBC-MAC**）はブロック暗号からメッセージ認証コードを構築するための技術です。メッセージは、いくつかのブロック暗号アルゴリズムをCBCモードで暗号化して、**前のブロックの適切な暗号化に依存するブロックの連鎖**を作成します。この相互依存性により、**平文のビットを変更すると、最終的な暗号化されたブロックが予測できず、鍵を知らないと対抗できない方法で変更**されます。

メッセージ m の CBC-MAC を計算するには、m をゼロ初期化ベクトルで CBC モードで暗号化し、最後のブロックを保持します。次の図は、秘密鍵 k とブロック暗号 E を使用して、ブロック![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) から CBC-MAC を計算する構造を示しています：

![CBC-MAC structure (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# 脆弱性

通常、CBC-MAC では使用される**IV は 0**です。\
これは、2つの既知のメッセージ（`m1` と `m2`）が独立して2つの署名（`s1` と `s2`）を生成するという問題があります。つまり：

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

その後、m1 と m2 を連結したメッセージ（m3）は、2つの署名（s31 と s32）を生成します：

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**これは、暗号の鍵を知らなくても計算可能です。**

8 バイトのブロックで名前 **Administrator** を暗号化していると想像してください：

* `Administ`
* `rator\00\00\00`

**Administ**（m1）の署名（s1）を取得できます。\
次に、`rator\00\00\00 XOR s1` の結果となるユーザー名を作成できます。これにより `E(m2 XOR s1 XOR 0)` が生成され、s32 となります。\
これで、s32 を **Administrator** のフルネームの署名として使用できます。

### 要約

1. ユーザー名 **Administ**（m1）の署名である s1 を取得します
2. ユーザー名 **rator\x00\x00\x00 XOR s1 XOR 0** の署名である s32 を取得します**。**
3. クッキーを s32 に設定すると、ユーザー **Administrator** の有効なクッキーになります。

# IV を制御する攻撃

使用される IV を制御できる場合、攻撃は非常に簡単になります。\
クッキーが単に暗号化されたユーザー名である場合、ユーザー "**administrator**" を偽装するためにユーザー "**Administrator**" を作成し、そのクッキーを取得できます。\
そして、IV を制御できる場合、IV の最初のバイトを変更して **IV\[0] XOR "A" == IV'\[0] XOR "a"** とし、ユーザー **Administrator** のクッキーを再生成できます。このクッキーは、初期の **IV** で **administrator** ユーザーを偽装するために有効です。

# 参考文献

詳細は[https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)を参照してください。


<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手
* 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する：[**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
