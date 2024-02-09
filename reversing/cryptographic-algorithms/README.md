# 暗号化/圧縮アルゴリズム

## 暗号化/圧縮アルゴリズム

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または**HackTricks をPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする。
* **ハッキングテクニックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## アルゴリズムの特定

コードが**シフト右と左、XOR、およびいくつかの算術演算**を使用している場合、それが**暗号化アルゴリズム**の実装である可能性が非常に高いです。ここでは、**各ステップを逆にする必要なしに使用されているアルゴリズムを特定する方法**をいくつか紹介します。

### API 関数

**CryptDeriveKey**

この関数が使用されている場合、第2パラメータの値をチェックして、使用されている**アルゴリズムを特定**できます:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

可能なアルゴリズムとそれに割り当てられた値の表はこちらを参照: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

指定されたデータバッファを圧縮および解凍します。

**CryptAcquireContext**

[ドキュメント](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)によると、**CryptAcquireContext** 関数は、特定の暗号化サービスプロバイダ（CSP）内の特定のキーコンテナへのハンドルを取得するために使用されます。**この返されたハンドルは、選択したCSPを使用する CryptoAPI 関数の呼び出しで使用されます**。

**CryptCreateHash**

データストリームのハッシングを開始します。この関数が使用されている場合、第2パラメータの値をチェックして、使用されている**アルゴリズムを特定**できます:

![](<../../.gitbook/assets/image (376).png>)

\
可能なアルゴリズムとそれに割り当てられた値の表はこちらを参照: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### コード定数

アルゴリズムを特定するのが非常に簡単な場合があります。それは特別でユニークな値を使用する必要があるためです。

![](<../../.gitbook/assets/image (370).png>)

最初の定数をGoogleで検索すると、次のようになります:

![](<../../.gitbook/assets/image (371).png>)

したがって、逆コンパイルされた関数が**sha256 計算機**であると仮定できます。\
他の定数のいずれかを検索すると（おそらく）同じ結果が得られます。

### データ情報

コードに有意義な定数がない場合、**.data セクションから情報を読み込んでいる**可能性があります。\
そのデータにアクセスし、最初の dword をグループ化して、前述のセクションで行ったように Google で検索できます:

![](<../../.gitbook/assets/image (372).png>)

この場合、**0xA56363C6** を検索すると、**AES アルゴリズムのテーブル**に関連していることがわかります。

## RC4 **（対称暗号）**

### 特徴

* **初期化ステージ/**: 0x00 から 0xFF（合計 256 バイト、0x100）までの値の**テーブルを作成**します。このテーブルは一般的に**置換ボックス**（または SBox と呼ばれる）と呼ばれます。
* **スクランブルステージ**: 以前に作成されたテーブルを**ループ**して（再び 0x100 回のループ）、各値を**半ランダム**バイトで変更します。この半ランダムバイトを作成するために、RC4 **キーが使用**されます。RC4 **キー**は**1〜256 バイトの長さ**にすることができますが、通常は 5 バイト以上であることが推奨されています。一般的に、RC4 キーは 16 バイトの長さです。
* **XOR ステージ**: 最後に、平文または暗号文が以前に作成された値と**XOR**されます。暗号化および復号化のための関数は同じです。これにより、作成された 256 バイトを**必要な回数だけループ**します。これは通常、逆コンパイルされたコードで**%256（mod 256）**と認識されます。

{% hint style="info" %}
**逆アセンブリ/逆コンパイルされたコードで RC4 を特定するには、2 つのサイズ 0x100 のループ（キーを使用）をチェックし、おそらく %256（mod 256）を使用して 2 つのループで作成された 256 値との入力データの XOR を行うことを確認します。**
{% endhint %}

### **初期化ステージ/置換ボックス:**（256 というカウンターの使用と、256 文字の各場所に 0 が書かれていることに注目）

![](<../../.gitbook/assets/image (377).png>)

### **スクランブルステージ:**

![](<../../.gitbook/assets/image (378).png>)

### **XOR ステージ:**

![](<../../.gitbook/assets/image (379).png>)

## **AES（対称暗号）**

### **特徴**

* **置換ボックスとルックアップテーブルの使用**
* 特定のルックアップテーブル値（定数）の使用により、AES を**識別**することが可能です。_**定数**は**バイナリに格納**されるか、_**動的に作成**されることがあります。_
* **暗号化キー**は**16 で割り切れる**必要があります（通常 32B）、通常 16B の IV が使用されます。

### SBox 定数

![](<../../.gitbook/assets/image (380).png>)

## Serpent **（対称暗号）**

### 特徴

* それを使用するマルウェアを見つけるのは珍しいですが、例があります（Ursnif）
* 非常に長い関数に基づいてアルゴリズムが Serpent かどうかを簡単に判断できます。

### 特定

次の画像で、定数 **0x9E3779B9** が使用されていることに注意してください（この定数は **TEA** -Tiny Encryption Algorithm などの他の暗号アルゴリズムでも使用されています）。\
また、**ループのサイズ**（**132**）、**XOR 演算の数**（**逆アセンブリの命令**および**コード**の例で）に注目してください:

![](<../../.gitbook/assets/image (381).png>)

前述のように、このコードは**非常に長い関数**として任意の逆コンパイラ内で視覚化でき、その中に**ジャンプがない**ためです。逆コンパイルされたコードは次のように見える可能性があります:

![](<../../.gitbook/assets/image (382).png>)

したがって、このアルゴリズムを特定するには、**マジックナンバー**と**初期 XOR**をチェックし、**非常に長い関数**を見て、いくつかの**命令**を**実装**と比較することが可能です（たとえば、左に 7 ビットシフトおよび左に 22 ビット回転）。

## RSA **（非対称暗号）**

### 特徴

* 対称アルゴリズムよりも複雑
* 定数はありません！（カスタム実装は特定が難しい）
* KANAL（暗号解析ツール）は RSA についてのヒントを表示できず、定数に依存しています。

### 比較による特定

![](<../../.gitbook/assets/image (383).png>)

* 左側の 11 行目には `+7) >> 3` があり、右側の 35 行目には `+7) / 8` があります
* 左側の 12 行目は `modulus_len < 0x040` をチェックしており、右側の 36 行目は `inputLen+11 > modulusLen` をチェックしています

## MD5 & SHA（ハッシュ）

### 特徴

* 初期化、更新、最終の 3 つの関数
* 似た初期化関数

### 特定

**Init**

両方を特定するには、定数をチェックしてください。sha\_init には MD5 にはない 1 つの定数があることに注意してください:

![](<../../.gitbook/assets/image (385).png>)

**MD5 変換**

より多くの定数の使用に注意してください

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC（ハッシュ）

* データの偶発的な変更を見つけるための機能として、より小さく、効率的です
* ルックアップテーブルを使用します（定数を特定できます）

### 特定

**ルックアップテーブルの定数**をチェックしてください:

![](<../../.gitbook/assets/image (387).png>)

CRC ハッシュアルゴリズムは次のようになります:

![](<../../.gitbook/assets/image (386).png>)

## APLib（圧縮）

### 特徴

* 識別可能な定数はありません
* Python でアルゴリズムを書いて、オンラインで類似したものを検索できます

### 特定

グラフはかなり大きいです:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

認識するために**3 つの比較**をチェックしてください:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または**HackTricks をPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする。
* **ハッキングテクニックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
