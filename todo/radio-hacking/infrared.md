# 赤外線

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 赤外線の動作原理 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**赤外線は人間には見えません**。赤外線の波長は**0.7から1000マイクロメートル**です。家庭用リモコンはデータの送信に赤外線信号を使用し、波長範囲は0.75から1.4マイクロメートルです。リモコンのマイクロコントローラは、特定の周波数で赤外線LEDを点滅させ、デジタル信号を赤外線信号に変換します。

赤外線信号を受信するためには、**フォトリシーバ**が使用されます。これは赤外線を電圧パルスに変換し、すでに**デジタル信号**になります。通常、受信機内部には**ダークライトフィルタ**があり、**望ましい波長のみを通過**させ、ノイズをカットします。

### 複数の赤外線プロトコル <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

赤外線プロトコルは以下の3つの要素で異なります：

* ビットエンコーディング
* データ構造
* キャリア周波数 - 通常は36から38 kHzの範囲

#### ビットエンコーディング方法 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. パルス間隔エンコーディング**

ビットはパルス間の期間の変調によってエンコードされます。パルス自体の幅は一定です。

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. パルス幅エンコーディング**

ビットはパルス幅の変調によってエンコードされます。パルスバーストの後のスペースの幅は一定です。

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. フェーズエンコーディング**

これはマンチェスターエンコーディングとも呼ばれます。論理値はパルスバーストとスペースの間の極性によって定義されます。 "スペースからパルスバースト"は論理 "0" を示し、"パルスバーストからスペース"は論理 "1" を示します。

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. 以前の方法とその他のエキゾチックな方法の組み合わせ**

{% hint style="info" %}
いくつかのデバイスの種類に対して**普遍的になろうとしている**赤外線プロトコルがあります。最も有名なものはRC5とNECです。残念ながら、最も有名なものが最も一般的というわけではありません。私の環境では、NECリモコンは2つしか見かけず、RC5リモコンはありませんでした。

メーカーは、同じ種類のデバイス（たとえば、TVボックス）でも独自の赤外線プロトコルを使用することが好きです。したがって、異なる会社のリモコンや、同じ会社の異なるモデルからのリモコンは、同じタイプの他のデバイスとは連携できません。
{% endhint %}

### 赤外線信号の探索

リモコンの赤外線信号の見た目を確認する最も信頼性の高い方法は、オシロスコープを使用することです。これは受信信号を復調したり反転したりしないで、受信信号をそのまま表示するだけです。これはテストやデバッグに役立ちます。NECの赤外線プロトコルの例を使って、期待される信号を示します。

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

通常、エンコードされたパケットの先頭には前置詞があります。これにより、受信機は利得と背景のレベルを判断することができます。また、Sharpなどの前置詞のないプロトコルもあります。

次にデータが送信されます。構造、前置詞、ビットエンコーディング方法は、特定のプロトコルによって決まります。

**NEC赤外線プロトコル**には、ボタンが押されている間送信される短いコマンドと繰り返しコードが含まれています。コマンドと繰り返しコードは、同じ前置詞を持っています。

NECの**コマンド**は、前置詞に加えて、デバイスが実行する必要がある内容を理解するためのアドレスバイトとコマンド番号バイトで構成されています。アドレスバイトとコマンド番号バイトは、逆の値で複製され、送信の整合性をチェックします。コマンドの最後には追加のストップビットがあります。

**繰り返しコード**には、前置詞の後に「1」があり、これがストップビットです。

**論理 "0" と "1"** のためにNECはパルス間隔エンコーディングを使用します：まず、パルスバーストが送信され、その後に一時停止があり、その長さがビットの値を設定します。
### エアコン

他のリモコンとは異なり、**エアコンは押されたボタンのコードだけを送信するのではありません**。ボタンが押されたときには、**エアコンとリモコンが同期していることを保証するために、すべての情報を送信**します。\
これにより、あるリモコンで20℃に設定された機械が、21℃に増加し、その後、まだ温度が20℃のままの別のリモコンを使用してさらに温度を上げると、それは21℃に「増加」します（21℃ではなく22℃と思ってしまうことを防ぎます）。

### 攻撃

Flipper Zeroを使用して赤外線を攻撃することができます：

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## 参考文献

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出**してください。

</details>
