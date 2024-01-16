<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>


# 攻撃の概要

サーバーが**秘密**を既知のクリアテキストデータに**追加**してそのデータをハッシュ化することで、ある**データ**に**署名**していると想像してください。以下が分かっている場合：

* **秘密の長さ**（これは与えられた長さの範囲からもブルートフォースできます）
* **クリアテキストデータ**
* **アルゴリズム（そしてそれがこの攻撃に対して脆弱である）**
* **パディングが分かっている**
* 通常、デフォルトのものが使用されるので、他の3つの要件が満たされていれば、これも満たされます
* パディングは秘密+データの長さによって異なるため、秘密の長さが必要です

その場合、**攻撃者**は**データ**を**追加**して、**以前のデータ + 追加されたデータ**に対する有効な**署名**を**生成**することが可能です。

## どのように？

基本的に脆弱なアルゴリズムは、まず**データブロックをハッシュ化**し、その後、**以前に生成されたハッシュ**（状態）から、次のデータブロックを**追加**して**ハッシュ化**します。

例えば、秘密が"secret"でデータが"data"の場合、"secretdata"のMD5は6036708eba0d11f6ef52ad44e8b74d5bです。\
攻撃者が文字列"append"を追加したい場合、彼は以下のことができます：

* 64個の"A"のMD5を生成する
* 以前に初期化されたハッシュの状態を6036708eba0d11f6ef52ad44e8b74d5bに変更する
* 文字列"append"を追加する
* ハッシュを完了し、結果のハッシュは"secret" + "data" + "padding" + "append"に対して**有効なものになります**

## **ツール**

{% embed url="https://github.com/iagox86/hash_extender" %}

# 参考文献

この攻撃についてよく説明されているのは[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)で見つけることができます。


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
