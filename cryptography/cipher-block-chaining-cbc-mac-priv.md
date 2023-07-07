<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**する[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>


# CBC

もし**クッキー**が**ユーザー名**だけ（またはクッキーの最初の部分がユーザー名）であり、ユーザー名「**admin**」をなりすます場合、ユーザー名**「bdmin」**を作成し、クッキーの**最初のバイト**を**ブルートフォース**できます。

# CBC-MAC

暗号学において、**Cipher Block Chaining Message Authentication Code**（**CBC-MAC**）は、ブロック暗号からメッセージ認証コードを構築するための技術です。メッセージは、いくつかのブロック暗号アルゴリズムを使用してCBCモードで暗号化され、**各ブロックが前のブロックの適切な暗号化に依存するようにブロックのチェーンが作成**されます。この相互依存性により、平文の**任意のビットの変更が、鍵を知らない限り予測または打ち消すことができない方法で最終的な暗号化ブロックを変更**させます。

メッセージmのCBC-MACを計算するには、ゼロの初期化ベクトルでmをCBCモードで暗号化し、最後のブロックを保持します。次の図は、秘密鍵kとブロック暗号Eを使用してブロック![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5)からなるメッセージのCBC-MACの計算をスケッチしたものです。

![CBC-MAC structure (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# 脆弱性

CBC-MACでは通常、使用される**IVは0**です。\
これは、2つの既知のメッセージ（`m1`と`m2`）が独立して2つの署名（`s1`と`s2`）を生成することを意味します。したがって：

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

その後、m1とm2を連結したメッセージ（m3）は2つの署名（s31とs32）を生成します：

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**これは、暗号化の鍵を知らなくても計算可能です。**

名前**Administrator**を**8バイト**のブロックで暗号化していると想像してください：

* `Administ`
* `rator\00\00\00`

**Administ**（m1）というユーザー名を作成し、署名（s1）を取得できます。\
次に、**rator\00\00\00 XOR s1 XOR 0**の結果となるユーザー名を作成できます。これにより、`E(m2 XOR s1 XOR 0)`が生成され、それはs32です。\
これで、s32をフルネーム**Administrator**の署名として使用できます。

### 要約

1. ユーザー名**Administ**（m1）の署名であるs1を取得します。
2. ユーザー名**rator\x00\x00\x00 XOR s1 XOR 0**の署名であるs32を取得します。
3. クッキーをs32に設定し、ユーザー**Administrator**の有効なクッキーになります。

# 攻撃時のIVの制御

使用されるIVを制御できる場合、攻撃は非常に簡単になります。\
クッキーが単に暗号化されたユーザー名である場合、ユーザー**administrator**をなりすますためにユーザー**Administrator**を作成し、そのクッキーを取得できます。\
さて、IVを制御できる場合、IVの最初のバイトを変更して**IV\[0] XOR "A" == IV'\[0] XOR "a"**とすることができ、ユーザー**Administrator**のクッキーを再生成できます。このクッキーは、初期の**IV**で**ユーザーadministrator**を**なりすます**ために有効です。

# 参考文献

詳細は[https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)を参照してください。


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
- **[💬](https://emojipedia.org/speech-balloon/)ディスコードグループ**に参加するか、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>
