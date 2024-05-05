# 暗号化/圧縮アルゴリズム

## 暗号化/圧縮アルゴリズム

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード**したい場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** をフォロー**する
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください

</details>

## アルゴリズムの特定

コードで **シフト右シフト、左シフト、XOR、およびいくつかの算術演算** を使用している場合、それが **暗号化アルゴリズム** の実装である可能性が非常に高いです。ここでは、**各ステップを逆にする必要なしに使用されているアルゴリズムを特定する方法** をいくつか紹介します。

### API 関数

**CryptDeriveKey**

この関数が使用されている場合、第2パラメータの値をチェックすることで、使用されている **アルゴリズムを特定** できます:

![](<../../.gitbook/assets/image (156).png>)

可能なアルゴリズムとそれに割り当てられた値の表はこちらを参照: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

指定されたデータバッファを圧縮および解凍します。

**CryptAcquireContext**

[ドキュメント](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta) によると、**CryptAcquireContext** 関数は、特定の暗号サービスプロバイダ（CSP）内の特定のキーコンテナへのハンドルを取得するために使用されます。**この返されたハンドルは、選択したCSPを使用する CryptoAPI 関数の呼び出しで使用されます**。

**CryptCreateHash**

データストリームのハッシュ化を開始します。この関数が使用されている場合、第2パラメータの値をチェックすることで、使用されている **アルゴリズムを特定** できます:

![](<../../.gitbook/assets/image (549).png>)

\
可能なアルゴリズムとそれに割り当てられた値の表はこちらを参照: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### コード定数

アルゴリズムを特定するのが非常に簡単な場合があります。それは特別でユニークな値を使用する必要があるためです。

![](<../../.gitbook/assets/image (833).png>)

最初の定数を Google で検索すると、次のようになります:

![](<../../.gitbook/assets/image (529).png>)

したがって、逆コンパイルされた関数が **sha256 計算機** であると仮定できます。\
他の定数のいずれかを検索すると（おそらく）同じ結果が得られます。

### データ情報

コードに有意義な定数がない場合、**.data セクションから情報を読み込んでいる** 可能性があります。\
そのデータにアクセスし、最初の dword をグループ化して、前述のセクションで行ったように Google で検索できます:

![](<../../.gitbook/assets/image (531).png>)

この場合、**0xA56363C6** を検索すると、**AES アルゴリズムのテーブル** に関連していることがわかります。

## RC4 **（対称暗号）**

### 特徴

3つの主要な部分で構成されています:

* **初期化ステージ/**: 0x00 から 0xFF（合計256バイト、0x100）までの値の **テーブルを作成** します。このテーブルは一般的に **置換ボックス**（または SBox と呼ばれる）と呼ばれます。
* **スクランブルステージ**: 以前に作成されたテーブルをループします（0x100 回のループ、再び）し、各値を **半ランダム** バイトで変更します。この半ランダムバイトを作成するために、RC4 **キーが使用** されます。RC4 **キー** は **1 〜 256 バイトの長さ** である可能性がありますが、通常は 5 バイト以上であることが推奨されています。一般的に、RC4 キーは 16 バイトの長さです。
* **XOR ステージ**: 最後に、平文または暗号文が **以前に作成された値と XOR** されます。暗号化および復号化の関数は同じです。これにより、作成された 256 バイトを **必要な回数だけループ** します。これは通常、逆コンパイルされたコードで **%256（mod 256）** として認識されます。

{% hint style="info" %}
**逆アセンブリ/逆コンパイルされたコードで RC4 を特定するには、サイズが 0x100 の 2 つのループ（キーを使用）をチェックし、次に 256 値と XOR された入力データを確認します。これらの 2 つのループで作成された値を、おそらく %256（mod 256）を使用して、入力データと XOR します。**
{% endhint %}

### **初期化ステージ/置換ボックス:**（256 というカウンターの使用と、256 文字の各場所に 0 が書かれていることに注目）

![](<../../.gitbook/assets/image (584).png>)

### **スクランブルステージ:**

![](<../../.gitbook/assets/image (835).png>)

### **XOR ステージ:**

![](<../../.gitbook/assets/image (904).png>)

## **AES（対称暗号）**

### **特徴**

* **置換ボックスとルックアップテーブルの使用**
* 特定のルックアップテーブル値（定数）の使用により、**AES を区別** することが可能です。_**定数** はバイナリに **保存** されるか、_**動的に作成**_ される可能性があります。
* **暗号化キー** は **16 で割り切れる** 必要があります（通常は 32B）、通常は 16B の IV が使用されます。

### SBox 定数

![](<../../.gitbook/assets/image (208).png>)

## Serpent **（対称暗号）**

### 特徴

* 使用例は少ないですが、マルウェアが使用している例もあります（Ursnif）
* 非常に長い関数に基づいて、アルゴリズムが Serpent であるかどうかを簡単に判断できます。

### 特定方法

次の画像で、定数 **0x9E3779B9** が使用されていることに注目してください（この定数は **TEA** -Tiny Encryption Algorithm などの他の暗号アルゴリズムでも使用されていることに注意してください）。\
また、**ループのサイズ**（**132**）、**逆アセンブリ** 命令および **コード** の例での **XOR 演算の数** に注目してください:

![](<../../.gitbook/assets/image (547).png>)

前述のように、このコードは **非常に長い関数** として任意のデコンパイラ内で視覚化できます。この長い関数の逆コンパイルされたコードは次のように見えるかもしれません:

![](<../../.gitbook/assets/image (513).png>)

したがって、**マジックナンバー** と **初期 XOR** をチェックし、**非常に長い関数** を見て、いくつかの **命令** を **実装** と比較することで、このアルゴリズムを特定することが可能です。
## RSA **(非対称暗号)**

### 特徴

* 対称アルゴリズムより複雑
* 定数が存在しない！（カスタム実装は難しい）
* KANAL（暗号解析ツール）はRSAにヒントを示さず、定数に依存しているため失敗する。

### 比較による識別

![](<../../.gitbook/assets/image (1113).png>)

* 11行目（左）には `+7) >> 3` があり、35行目（右）にも `+7) / 8` がある
* 12行目（左）は `modulus_len < 0x040` をチェックしており、36行目（右）は `inputLen+11 > modulusLen` をチェックしている

## MD5 & SHA（ハッシュ）

### 特徴

* 初期化、更新、最終の3つの関数
* 似たような初期化関数

### 識別

**初期化**

両方を識別するには定数をチェックできます。MD5にはない1つの定数が sha\_init にあることに注意してください:

![](<../../.gitbook/assets/image (406).png>)

**MD5変換**

より多くの定数の使用に注意してください

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC（ハッシュ）

* データの偶発的な変更を見つけるための関数として、より小さく効率的
* ルックアップテーブルを使用する（定数を識別できる）

### 識別

**ルックアップテーブルの定数**をチェック:

![](<../../.gitbook/assets/image (508).png>)

CRCハッシュアルゴリズムは次のように見えます:

![](<../../.gitbook/assets/image (391).png>)

## APLib（圧縮）

### 特徴

* 識別できない定数
* Pythonでアルゴリズムを書いて類似したものをオンラインで検索できます

### 識別

グラフはかなり大きいです:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

**それを認識するための3つの比較**をチェック:

![](<../../.gitbook/assets/image (430).png>)
