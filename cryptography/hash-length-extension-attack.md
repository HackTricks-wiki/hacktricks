<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>


# 攻撃の概要

あるサーバーが、既知のクリアテキストデータに**秘密を追加**してそのデータをハッシュ化していると想像してください。以下を知っている場合：

* **秘密の長さ**（これは与えられた長さ範囲からもブルートフォースできます）
* **クリアテキストデータ**
* **アルゴリズム（およびこの攻撃に脆弱）**
* **パディングが既知**
* 通常、デフォルトのものが使用されるため、他の3つの要件が満たされている場合、これも満たされます
* パディングは秘密+データの長さに応じて異なります。そのため、秘密の長さが必要です

その後、**攻撃者**は**データを追加**し、**以前のデータ+追加されたデータ**の有効な**署名**を**生成**することが可能です。

## 方法

基本的に、脆弱なアルゴリズムは、まず**データブロックをハッシュ**し、その後、**以前に**作成された**ハッシュ**（状態）から**次のデータブロックを追加**して**ハッシュ**します。

たとえば、秘密が「secret」でデータが「data」であるとします。"secretdata"のMD5は6036708eba0d11f6ef52ad44e8b74d5bです。\
攻撃者が文字列「append」を追加したい場合：

* 64個の「A」のMD5を生成する
* 以前に初期化されたハッシュの状態を6036708eba0d11f6ef52ad44e8b74d5bに変更する
* 文字列「append」を追加する
* ハッシュを終了し、結果のハッシュは「secret」+「data」+「パディング」+「append」のための**有効なもの**になります

## **ツール**

{% embed url="https://github.com/iagox86/hash_extender" %}

# 参考文献

この攻撃について詳しく説明されている[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
