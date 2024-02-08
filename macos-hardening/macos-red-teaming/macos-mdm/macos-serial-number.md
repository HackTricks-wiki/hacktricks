# macOSシリアル番号

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**@carlospolopm**をフォローしてください [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
- **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>


## 基本情報

2010年以降のAppleデバイスは、**12文字の英数字**で構成されるシリアル番号を持ち、各セグメントが特定の情報を伝えます：

- **最初の3文字**：**製造場所**を示す。
- **文字4と5**：**製造年および週**を示す。
- **6から8文字目**：各デバイスの**固有識別子**として機能する。
- **最後の4文字**：**モデル番号**を指定する。

たとえば、シリアル番号**C02L13ECF8J2**はこの構造に従います。

### **製造場所（最初の3文字）**
特定のコードは特定の工場を表します：
- **FC、F、XA/XB/QP/G8**：米国のさまざまな場所。
- **RN**：メキシコ。
- **CK**：アイルランドのコーク。
- **VM**：チェコ共和国のFoxconn。
- **SG/E**：シンガポール。
- **MB**：マレーシア。
- **PT/CY**：韓国。
- **EE/QT/UV**：台湾。
- **FK/F1/F2、W8、DL/DM、DN、YM/7J、1C/4H/WQ/F7**：中国のさまざまな場所。
- **C0、C3、C7**：中国の特定の都市。
- **RM**：再生品。

### **製造年（4番目の文字）**
この文字は、2010年の前半を表す 'C' から2019年の後半を表す 'Z' まで変化し、異なる文字が異なる半年ごとの期間を示します。

### **製造週（5番目の文字）**
数字1〜9は週1〜9に対応します。文字C-Y（母音と 'S' を除く）は週10〜27を表し、年の後半ではこの数値に26が追加されます。

### **固有識別子（6から8文字目）**
これらの3桁は、同じモデルやバッチのデバイスでも、固有のシリアル番号を持つようにします。

### **モデル番号（最後の4文字）**
これらの数字は、デバイスの特定のモデルを識別します。

### 参考

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**@carlospolopm**をフォローしてください [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
- **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
