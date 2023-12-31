# macOS シリアル番号

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告掲載したい場合**や **HackTricks を PDF でダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) をフォローする。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングのコツを共有する。

</details>

2010年以降に製造された Apple デバイスは一般的に **12文字の英数字** のシリアル番号を持っており、**最初の3文字は製造場所**、次の **2文字** は製造された **年** と **週**、次の **3文字** は **ユニークな識別子**、そして **最後の4文字** は **モデル番号** を表しています。

シリアル番号の例: **C02L13ECF8J2**

### **3 - 製造場所**

| コード           | 工場                                          |
| -------------- | -------------------------------------------- |
| FC             | ファウンテン コロラド, アメリカ                       |
| F              | フリーモント, カリフォルニア, アメリカ                     |
| XA, XB, QP, G8 | アメリカ                                          |
| RN             | メキシコ                                       |
| CK             | コーク, アイルランド                                |
| VM             | フォックスコン, パルドゥビツェ, チェコ共和国           |
| SG, E          | シンガポール                                    |
| MB             | マレーシア                                     |
| PT, CY         | 韓国                                        |
| EE, QT, UV     | 台湾                                       |
| FK, F1, F2     | フォックスコン – 鄭州, 中国                   |
| W8             | 上海 中国                               |
| DL, DM         | フォックスコン – 中国                              |
| DN             | フォックスコン, 成都, 中国                      |
| YM, 7J         | 鴻海/フォックスコン, 中国                       |
| 1C, 4H, WQ, F7 | 中国                                        |
| C0             | テックコム – クアンタコンピュータ子会社, 中国 |
| C3             | フォックスコン, 深セン, 中国                     |
| C7             | ペントラゴン, 上海, 中国                   |
| RM             | 改装/再製造                                   |

### 1 - 製造年

| コード | 発売                  |
| ---- | -------------------- |
| C    | 2010/2020 (前半) |
| D    | 2010/2020 (後半) |
| F    | 2011/2021 (前半) |
| G    | 2011/2021 (後半) |
| H    | 2012/... (前半)  |
| J    | 2012 (後半)      |
| K    | 2013 (前半)      |
| L    | 2013 (後半)      |
| M    | 2014 (前半)      |
| N    | 2014 (後半)      |
| P    | 2015 (前半)      |
| Q    | 2015 (後半)      |
| R    | 2016 (前半)      |
| S    | 2016 (後半)      |
| T    | 2017 (前半)      |
| V    | 2017 (後半)      |
| W    | 2018 (前半)      |
| X    | 2018 (後半)      |
| Y    | 2019 (前半)      |
| Z    | 2019 (後半)      |

### 1 - 製造週

5番目の文字はデバイスが製造された週を表します。この位置には28の可能な文字があります: **数字の1-9は最初から9週目を表すために使用され**、**CからYの文字**、母音のA, E, I, O, Uと文字Sを**除外して**、**10週目から27週目を表します**。年の**後半に製造されたデバイスの場合、シリアル番号の5番目の文字によって表される数に26を加えます**。例えば、シリアル番号の4番目と5番目の数字が「JH」の製品は、2012年の40週目に製造されました。

### 3 - ユニークコード

次の3文字は識別コードであり、**同じ年の同じ週に同じ場所で製造された同じモデルの各 Apple デバイスを区別する**ために役立ち、各デバイスが異なるシリアル番号を持つことを保証します。

### 4 - シリアル番号

シリアル番号の最後の4文字は **製品のモデル** を表します。

### 参照

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告掲載したい場合**や **HackTricks を PDF でダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) をフォローする。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングのコツを共有する。

</details>
