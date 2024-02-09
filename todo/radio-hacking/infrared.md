# 赤外線

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じて、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出してください。

</details>

## 赤外線ポートの動作方法 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**赤外線光は人間には見えません**。IR波長は**0.7から1000マイクロメートル**です。家庭用リモコンはデータ送信にIR信号を使用し、波長範囲は0.75から1.4マイクロメートルです。リモコン内のマイクロコントローラは、特定の周波数で赤外線LEDを点滅させ、デジタル信号をIR信号に変換します。

IR信号を受信するためには**フォトレシーバ**が使用されます。これはIR光を電圧パルスに変換し、すでに**デジタル信号**になります。通常、受信機内部には**望ましい波長のみを通過させ、ノイズをカットする**ダークライトフィルタがあります。

### 様々なIRプロトコル <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IRプロトコルは3つの要素で異なります：

* ビットエンコーディング
* データ構造
* キャリア周波数 — 通常は36から38 kHzの範囲内

#### ビットエンコーディング方法 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. パルス距離エンコーディング**

ビットはパルス間の間隔の長さを変調することでエンコードされます。パルス自体の幅は一定です。

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. パルス幅エンコーディング**

ビットはパルス幅の変調によってエンコードされます。パルスバーストの後のスペースの幅は一定です。

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. フェーズエンコーディング**

これはマンチェスターエンコーディングとしても知られています。論理値は、パルスバーストとスペースの間の遷移の極性によって定義されます。"スペースからパルスバースト"は論理 "0" を示し、"パルスバーストからスペース"は論理 "1" を示します。

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. 以前のものとその他のエキゾチックなものの組み合わせ**

{% hint style="info" %}
いくつかのデバイスの種類に**普遍的になろうとする**IRプロトコルがあります。最も有名なものはRC5とNECです。残念ながら、最も有名なものが**最も一般的であるとは限りません**。私の環境では、NECリモコンが2つしかなく、RC5リモコンはありませんでした。

メーカーは、同じ種類のデバイス（たとえば、TVボックス）内でも独自のユニークなIRプロトコルを使用することが好きです。したがって、異なる企業のリモコンや、時には同じ企業の異なるモデルからのリモコンは、同じ種類の他のデバイスとは動作しないことがあります。
{% endhint %}

### IR信号の探索

リモコンのIR信号がどのように見えるかを確認する最も信頼性の高い方法は、オシロスコープを使用することです。これは受信信号を復調したり反転したりしないで、受信した信号をそのまま表示します。これはテストやデバッグに役立ちます。NEC IRプロトコルの例を示します。

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

通常、エンコードされたパケットの先頭には前置きがあります。これにより、受信機はゲインと背景のレベルを判断できます。Sharpなどの前置きのないプロトコルもあります。

その後、データが送信されます。構造、前置き、およびビットエンコーディング方法は、特定のプロトコルによって決定されます。

**NEC IRプロトコル**には、ボタンが押されている間に送信される**短いコマンドとリピートコード**が含まれています。コマンドとリピートコードは、同じ前置きを持っています。

NECの**コマンド**は、前置きに加えて、アドレスバイトとコマンド番号バイトから構成され、デバイスが何を実行するかを理解します。アドレスとコマンド番号バイトは逆の値で複製され、送信の整合性を確認します。コマンドの最後には追加のストップビットがあります。

**リピートコード**には、前置きの後に「1」があり、これがストップビットです。

**論理 "0" および "1"** のために、NECはパルス距離エンコーディングを使用します：まず、パルスバーストが送信され、その後に一時停止があり、その長さがビットの値を設定します。

### エアコン

他のリモコンとは異なり、**エアコンは押されたボタンのコードだけを送信するのではありません**。**エアコン機器とリモコンが同期されていることを確認するために、ボタンが押されたときにすべての情報を送信**します。\
これにより、あるリモコンで20℃に設定された機械が21℃に増加され、その後、まだ温度が20℃の別のリモコンを使用してさらに温度を上げると、それを21℃に「増加」し、21℃にあると思って22℃にならないようにします。

### 攻撃

Flipper Zeroを使用して赤外線を攻撃することができます：

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## 参考文献

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
