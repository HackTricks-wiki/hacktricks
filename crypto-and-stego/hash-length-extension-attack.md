# ハッシュ長延長攻撃

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでAWSハッキングを学ぶ**</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **Discordグループ**に**参加**する💬（https://discord.gg/hRep4RUj7f）または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**🐦で**フォロー**する：[**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

***

## 攻撃の概要

あるサーバーが、ある既知のクリアテキストデータに**秘密**を**追加**してそのデータをハッシュ化していると想像してください。以下を知っている場合：

- **秘密の長さ**（これは与えられた長さ範囲からもブルートフォースできます）
- **クリアテキストデータ**
- **アルゴリズム（およびこの攻撃に対して脆弱である）**
- **パディングが既知である**
- 通常、デフォルトのものが使用されるため、他の3つの要件が満たされている場合、これも満たされます
- パディングは秘密+データの長さに応じて異なります。そのため、秘密の長さが必要です

その後、**攻撃者**は**データを追加**し、**前のデータ+追加されたデータ**の有効な**署名**を**生成**することが可能です。

### 方法

基本的に、脆弱なアルゴリズムは、まず**データブロックをハッシュ化**し、その後、**以前に**作成された**ハッシュ**（状態）から、**次のデータブロックを追加**して**ハッシュ化**します。

次に、秘密が「secret」でデータが「data」であると想像してください。"secretdata"のMD5は6036708eba0d11f6ef52ad44e8b74d5bです。\
攻撃者が文字列「append」を追加したい場合は：

- 64個の「A」のMD5を生成する
- 以前に初期化されたハッシュの状態を6036708eba0d11f6ef52ad44e8b74d5bに変更する
- 文字列「append」を追加する
- ハッシュを終了し、結果のハッシュは「secret」+「data」+「パディング」+「append」のための**有効なもの**になります

### **ツール**

{% embed url="https://github.com/iagox86/hash_extender" %}

### 参考文献

この攻撃については、[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)で詳しく説明されています。

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでAWSハッキングを学ぶ**</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **Discordグループ**に**参加**する💬（https://discord.gg/hRep4RUj7f）または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**🐦で**フォロー**する：[**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
