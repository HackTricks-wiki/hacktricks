# macOSシリアル番号

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

2010年以降に製造されたAppleデバイスは、一般的には**12文字の英数字のシリアル番号**を持っており、**最初の3桁は製造場所**を表し、次の**2桁は製造年**と**週**を示し、次の**3桁はユニークな識別子**を提供し、最後の**4桁はモデル番号**を表します。

シリアル番号の例：**C02L13ECF8J2**

### **3 - 製造場所**

| コード | 工場                                      |
| ------ | ----------------------------------------- |
| FC     | アメリカ合衆国コロラド州ファウンテン         |
| F      | アメリカ合衆国カリフォルニア州フリーモント   |
| XA, XB, QP, G8 | アメリカ合衆国                           |
| RN     | メキシコ                                   |
| CK     | アイルランドコーク                         |
| VM     | チェコ共和国フォックスコンパルドゥビツェ工場 |
| SG, E  | シンガポール                               |
| MB     | マレーシア                                 |
| PT, CY | 韓国                                      |
| EE, QT, UV | 台湾                                 |
| FK, F1, F2 | 中国郑州富士康                           |
| W8     | 中国上海                                   |
| DL, DM | 中国富士康                                 |
| DN     | 中国成都富士康                             |
| YM, 7J | 中国鴻海富士康                             |
| 1C, 4H, WQ, F7 | 中国                           |
| C0     | 中国クアンタコンピュータ子会社テックコム   |
| C3     | 中国深セン富士康                           |
| C7     | 中国チャンハイペンタゴン                   |
| RM     | 再生品/再製品                             |

### 1 - 製造年

| コード | リリース              |
| ------ | -------------------- |
| C      | 2010/2020年（前半）  |
| D      | 2010/2020年（後半）  |
| F      | 2011/2021年（前半）  |
| G      | 2011/2021年（後半）  |
| H      | 2012年/...（前半）   |
| J      | 2012年（後半）       |
| K      | 2013年（前半）       |
| L      | 2013年（後半）       |
| M      | 2014年（前半）       |
| N      | 2014年（後半）       |
| P      | 2015年（前半）       |
| Q      | 2015年（後半）       |
| R      | 2016年（前半）       |
| S      | 2016年（後半）       |
| T      | 2017年（前半）       |
| V      | 2017年（後半）       |
| W      | 2018年（前半）       |
| X      | 2018年（後半）       |
| Y      | 2019年（前半）       |
| Z      | 2019年（後半）       |

### 1 - 製造週

5番目の文字は、デバイスの製造週を表します。この場所には28の可能な文字があります：**数字1〜9は1週目から9週目を表し**、**文字CからY**、**母音A、E、I、O、U、および文字Sを除く**は、**10週目から27週目を表します**。年の**後半に製造されたデバイスの場合、シリアル番号の5番目の文字に表される数値に26を追加**します。たとえば、シリアル番号の4番目と5番目の数字が「JH」である製品は、2012年の40週目に製造されました。

### 3 - ユニークコード

次の3桁は、**同じ場所で同じ週に製造された同じモデルの各Appleデバイスを区別するための識別子コード**です。これにより、各デバイスには異なるシリアル番号が割り当てられます。

### 4 - シリアル番号

シリアル番号の最後の4桁は、**製品のモデル**を表します。
### 参考

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ会社**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
