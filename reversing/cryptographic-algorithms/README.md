# 暗号化/圧縮アルゴリズム

## 暗号化/圧縮アルゴリズム

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## アルゴリズムの特定

もし、コードが**シフト演算、XOR演算、およびいくつかの算術演算**を使用している場合、それはおそらく**暗号化アルゴリズムの実装**である可能性が高いです。ここでは、**各ステップを逆にする必要なしに使用されているアルゴリズムを特定する**いくつかの方法を紹介します。

### API関数

**CryptDeriveKey**

この関数が使用されている場合、第2パラメータの値をチェックすることで、**どのアルゴリズムが使用されているか**を特定できます。

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

可能なアルゴリズムとそれに割り当てられた値の表はこちらを参照してください：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

指定されたデータのバッファを圧縮および展開します。

**CryptAcquireContext**

**CryptAcquireContext**関数は、特定の暗号化サービスプロバイダ（CSP）内の特定のキーコンテナへのハンドルを取得するために使用されます。選択したCSPを使用するCryptoAPI関数への呼び出しで使用される返されたハンドルです。

**CryptCreateHash**

データストリームのハッシュ化を開始します。この関数が使用されている場合、第2パラメータの値をチェックすることで、**どのアルゴリズムが使用されているか**を特定できます。

![](<../../.gitbook/assets/image (376).png>)

可能なアルゴリズムとそれに割り当てられた値の表はこちらを参照してください：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### コード定数

アルゴリズムを特定するのは非常に簡単な場合があります。なぜなら、特別でユニークな値を使用する必要があるからです。

![](<../../.gitbook/assets/image (370).png>)

最初の定数をGoogleで検索すると、次のような結果が得られます。

![](<../../.gitbook/assets/image (371).png>)

したがって、逆コンパイルされた関数は**sha256の計算機**であると推定できます。他の定数のいずれかを検索しても（おそらく）同じ結果が得られます。

### データ情報

コードに有意義な定数がない場合、おそらく**.dataセクションから情報を読み込んでいる**可能性があります。そのデータにアクセスし、最初のdwordを**グループ化**し、前のセクションと同様にGoogleで検索します。

![](<../../.gitbook/assets/image (372).png>)

この場合、**0xA56363C6**を検索すると、**AESアルゴリズムのテーブル**に関連していることがわかります。

## RC4 **（対称暗号）**

### 特徴

RC4は3つの主要な部分で構成されています：

* **初期化ステージ**：0x00から0xFFまでの値のテーブル（合計256バイト、0x100）を作成します。このテーブルは一般的に**置換ボックス**（またはSBox）と呼ばれます。
* **スクランブルステージ**：以前に作成したテーブルをループします（再び0x100回のループ）。このループでは、RC4の**キーを使用して**各値を**半ランダム**バイトで変更します。この半ランダムバイトを作成するためには、通常、RC4のキーは1バイトから256バイトの長さであることが推奨されます。一般的に、RC4のキーは16バイトの長さです。
* **XORステージ**：最後に、平文または暗号文は、以前に作成した値とXOR演算されます。暗号化および復号化のための関数は同じです。そのため、作成された256バイトを必要な回数だけループします。これは通常、デコンパイルされたコードで**%256（mod 256）**として認識されます。

{% hint style="info" %}
**逆アセンブリ/デコンパイルされたコードでRC4を特定するには、2つの0x100サイズのループ（キーを使用）と、おそらく%256（mod 256）を使用して2つのループで作成された256個の値との入力データのXORをチェックできます。**
{% endhint %}
### **初期化ステージ/置換ボックス:**（256という数字がカウンターとして使用され、256文字の各桁に0が書かれていることに注意してください）

![](<../../.gitbook/assets/image (377).png>)

### **スクランブルステージ:**

![](<../../.gitbook/assets/image (378).png>)

### **XORステージ:**

![](<../../.gitbook/assets/image (379).png>)

## **AES（対称暗号）**

### **特徴**

* **置換ボックスとルックアップテーブル**の使用
* 特定のルックアップテーブルの値（定数）の使用により、AESを区別することが可能です。_注意：この定数はバイナリに**格納**されるか、**動的に作成**されることができます。_
* 暗号化キーは16で割り切れる必要があります（通常は32B）、通常は16BのIVが使用されます。

### SBoxの定数

![](<../../.gitbook/assets/image (380).png>)

## Serpent **（対称暗号）**

### 特徴

* 一部のマルウェアで使用されることは稀ですが、例があります（Ursnif）
* 非常に長い関数に基づいて、アルゴリズムがSerpentであるかどうかを簡単に判断できます。

### 識別

次の画像では、定数**0x9E3779B9**が使用されていることに注意してください（この定数は**TEA**（Tiny Encryption Algorithm）などの他の暗号アルゴリズムでも使用されます）。また、**ループのサイズ**（**132**）と**XOR操作の数**を**逆アセンブリ**の命令と**コード**の例で確認してください。

![](<../../.gitbook/assets/image (381).png>)

前述のように、このコードはジャンプがないため、デコンパイラ内で非常に長い関数として視覚化することができます。デコンパイルされたコードは次のようになります。

![](<../../.gitbook/assets/image (382).png>)

したがって、このアルゴリズムは、**マジックナンバー**と**初期のXOR**をチェックし、**非常に長い関数**を見て、その関数の**いくつかの命令**を（左に7ビットシフトし、左に22ビット回転するなど）**実装と比較する**ことで識別することができます。

## RSA **（非対称暗号）**

### 特徴

* 対称アルゴリズムよりも複雑です
* 定数はありません！（カスタム実装は判断が難しいです）
* RSAに関するヒントを表示するためには、KANAL（暗号解析ツール）は失敗します。

### 比較による識別

![](<../../.gitbook/assets/image (383).png>)

* 左側の11行目には`+7) >> 3`があり、右側の35行目には`+7) / 8`があります。
* 左側の12行目では`modulus_len < 0x040`をチェックし、右側の36行目では`inputLen+11 > modulusLen`をチェックしています。

## MD5＆SHA（ハッシュ）

### 特徴

* 初期化、更新、最終の3つの関数があります
* 類似した初期化関数

### 識別

**初期化**

両方を識別するには、定数をチェックします。MD5には存在しないsha\_initに1つの定数があることに注意してください。

![](<../../.gitbook/assets/image (385).png>)

**MD5変換**

さらに多くの定数の使用に注意してください。

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC（ハッシュ）

* データの偶発的な変更を検出するための機能として、より小さく効率的です
* ルックアップテーブルを使用します（定数を識別できます）

### 識別

**ルックアップテーブルの定数**をチェックします。

![](<../../.gitbook/assets/image (387).png>)

CRCハッシュアルゴリズムは次のようになります。

![](<../../.gitbook/assets/image (386).png>)

## APLib（圧縮）

### 特徴

* 識別可能な定数はありません
* Pythonでアルゴリズムを書いて、オンラインで類似のものを検索することができます

### 識別

グラフは非常に大きいです。

![](<../../.gitbook/assets/image (207) (2) (1).png>)

**3つの比較をチェック**してそれを認識します。

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンやHackTricksのPDFをダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をご覧ください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
