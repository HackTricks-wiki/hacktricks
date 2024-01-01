# 暗号化/圧縮アルゴリズム

## 暗号化/圧縮アルゴリズム

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## アルゴリズムの特定

もしコードが**シフト右、シフト左、XOR、複数の算術演算**を使用している場合、それは**暗号化アルゴリズム**の実装である可能性が高いです。ここでは、各ステップを逆にする必要なく使用されているアルゴリズムを**特定する方法**をいくつか紹介します。

### API関数

**CryptDeriveKey**

この関数が使用されている場合、第二引数の値をチェックすることで**使用されているアルゴリズム**を見つけることができます：

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

可能なアルゴリズムとそれらに割り当てられた値の表はこちらをチェックしてください：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

データのバッファを圧縮および解凍します。

**CryptAcquireContext**

**CryptAcquireContext**関数は、特定の暗号サービスプロバイダー（CSP）内の特定のキーコンテナへのハンドルを取得するために使用されます。**この返されたハンドルは、選択されたCSPを使用するCryptoAPI**関数の呼び出しで使用されます。

**CryptCreateHash**

データストリームのハッシュ化を開始します。この関数が使用されている場合、第二引数の値をチェックすることで**使用されているアルゴリズム**を見つけることができます：

![](<../../.gitbook/assets/image (376).png>)

\
可能なアルゴリズムとそれらに割り当てられた値の表はこちらをチェックしてください：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### コード定数

特別でユニークな値を使用する必要があるため、アルゴリズムを簡単に特定することができることがあります。

![](<../../.gitbook/assets/image (370).png>)

Googleで最初の定数を検索すると、これが得られます：

![](<../../.gitbook/assets/image (371).png>)

したがって、逆コンパイルされた関数が**sha256計算機**であると仮定することができます。\
他の定数を検索しても、おそらく同じ結果が得られます。

### データ情報

コードに特定の定数がない場合、**.dataセクションから情報を読み込んでいる**可能性があります。\
そのデータにアクセスし、**最初のdwordをグループ化**し、前のセクションで行ったようにGoogleで検索します：

![](<../../.gitbook/assets/image (372).png>)

この場合、**0xA56363C6**を検索すると、それが**AESアルゴリズムのテーブル**に関連していることがわかります。

## RC4 **(対称暗号)**

### 特徴

3つの主要な部分で構成されています：

* **初期化ステージ/**：0x00から0xFFまでの**値のテーブルを作成します**（合計256バイト、0x100）。このテーブルは一般に**置換ボックス**（またはSBox）と呼ばれます。
* **スクランブルステージ**：前に作成されたテーブルをループし（再び0x100のイテレーションのループ）、**半ランダム**バイトで各値を変更します。この半ランダムバイトを作成するために、RC4の**キーが使用されます**。RC4の**キー**は**1バイトから256バイトの長さ**であることができますが、通常は5バイト以上であることが推奨されます。一般的に、RC4のキーは16バイトの長さです。
* **XORステージ**：最後に、プレーンテキストまたは暗号テキストは**前に作成された値とXORされます**。暗号化と復号化の関数は同じです。これには、必要な回数だけ前に作成された256バイトをループします。これは通常、逆コンパイルされたコードで**%256（mod 256）**として認識されます。

{% hint style="info" %}
**逆アセンブル/逆コンパイルされたコードでRC4を特定するためには、0x100のサイズの2つのループ（キーの使用）をチェックし、その後、入力データを2つのループで前に作成された256の値とXORしていることを確認します。おそらく%256（mod 256）を使用しています。**
{% endhint %}

### **初期化ステージ/置換ボックス:** (256という数字がカウンターとして使用されていること、そして256文字の各場所に0が書かれていることに注意してください)

![](<../../.gitbook/assets/image (377).png>)

### **スクランブルステージ:**

![](<../../.gitbook/assets/image (378).png>)

### **XORステージ:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (対称暗号)**

### **特徴**

* **置換ボックスとルックアップテーブルの使用**
* 特定のルックアップテーブル値（定数）の使用により、**AESを識別することが可能です**。_定数はバイナリに**格納されているか**、_ _**動的に作成されている**ことに注意してください。_
* **暗号化キー**は**16で割り切れる**必要があります（通常は32B）で、通常は16Bの**IV**が使用されます。

### SBox定数

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(対称暗号)**

### 特徴

* それを使用しているマルウェアを見つけるのは珍しいですが、例（Ursnif）があります
* アルゴリズムがSerpentかどうかをその長さに基づいて簡単に判断できます（非常に長い関数）

### 特定

次の画像では、定数**0x9E3779B9**が使用されていることに注意してください（この定数は**TEA** -Tiny Encryption Algorithmなどの他の暗号アルゴリズムにも使用されます）。\
また、ループの**サイズ（132）**と、**逆アセンブリ**の指示と**コード**の例にある**XOR操作の数**にも注意してください：

![](<../../.gitbook/assets/image (381).png>)

前に述べたように、このコードはジャンプがないため、任意の逆コンパイラ内で**非常に長い関数**として視覚化することができます。逆コンパイルされたコードは次のように見えるかもしれません：

![](<../../.gitbook/assets/image (382).png>)

したがって、**マジックナンバー**と**初期のXOR**をチェックし、**非常に長い関数**を見て、長い関数のいくつかの**指示**を**実装と比較**することで（7による左シフトと22による左回転のように）、このアルゴリズムを特定することができます。

## RSA **(非対称暗号)**

### 特徴

* 対称アルゴリズムよりも複雑
* 定数がありません！（カスタム実装は判断が難しい）
* KANAL（暗号アナライザー）はRSAにヒントを示さず、定数に依存しています。

### 比較による特定

![](<../../.gitbook/assets/image (383).png>)

* 11行目（左）には`+7) >> 3`があり、35行目（右）には`+7) / 8`があります
* 12行目（左）は`modulus_len < 0x040`をチェックしており、36行目（右）は`inputLen+11 > modulusLen`をチェックしています

## MD5 & SHA (ハッシュ)

### 特徴

* 3つの関数：Init、Update、Final
* 類似の初期化関数

### 特定

**Init**

定数をチェックすることで、両方を特定できます。sha\_initにはMD5にはない1つの定数があります：

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

より多くの定数の使用に注意してください

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (ハッシュ)

* データの偶発的な変更を見つける機能があるため、より小さく効率的です
* ルックアップテーブルを使用する（したがって、定数を特定できます）

### 特定

**ルックアップテーブル定数**をチェックしてください：

![](<../../.gitbook/assets/image (387).png>)

CRCハッシュアルゴリズムは次のようになります：

![](<../../.gitbook/assets/image (386).png>)

## APLib (圧縮)

### 特徴

* 認識可能な定数はありません
* Pythonでアルゴリズムを書いて、オンラインで似たものを探すことができます

### 特定

グラフはかなり大きいです：

![](<../../.gitbook/assets/image (207) (2) (1).png>)

それを認識するための**3つの比較**をチェックしてください：

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
