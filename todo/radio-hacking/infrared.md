# 赤外線

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## 赤外線の仕組み <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**赤外線は人間には見えません**。IRの波長は**0.7から1000ミクロン**です。家庭用リモコンはIR信号を使用してデータを送信し、0.75..1.4ミクロンの波長範囲で動作します。リモコンのマイクロコントローラーは特定の周波数で赤外線LEDを点滅させ、デジタル信号をIR信号に変換します。

IR信号を受信するには**フォトレシーバー**が使用されます。これは**IR光を電圧パルスに変換し**、すでに**デジタル信号**です。通常、レシーバー内には**ダークライトフィルター**があり、**望ましい波長のみを通過させ**、ノイズをカットします。

### IRプロトコルの種類 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IRプロトコルは3つの要素で異なります:

* ビットエンコーディング
* データ構造
* キャリア周波数 — しばしば36..38 kHzの範囲

#### ビットエンコーディングの方法 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. パルス距離エンコーディング**

ビットはパルス間のスペースの持続時間を変調することによってエンコードされます。パルス自体の幅は一定です。

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. パルス幅エンコーディング**

ビットはパルス幅の変調によってエンコードされます。パルスバースト後のスペースの幅は一定です。

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. フェーズエンコーディング**

マンチェスターエンコーディングとも呼ばれます。論理値はパルスバーストとスペースの間の遷移の極性によって定義されます。"スペースからパルスバースト"は論理"0"を示し、"パルスバーストからスペース"は論理"1"を示します。

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. 上記の組み合わせとその他のエキゾチックなもの**

{% hint style="info" %}
いくつかのIRプロトコルは、複数の種類のデバイスに対して**ユニバーサルになろうとしています**。最も有名なものはRC5とNECです。残念ながら、最も有名なものが最も一般的なものとは限りません。私の環境では、NECのリモコンを2つだけ見かけ、RC5のものはありませんでした。

メーカーは独自のユニークなIRプロトコルを使用することを好みます。たとえば、同じ範囲のデバイス（例えば、TVボックス）内でもそうです。そのため、異なる会社のリモコンや、同じ会社の異なるモデルのリモコンは、同じタイプの他のデバイスと互換性がありません。
{% endhint %}

### IR信号の探索

リモコンのIR信号がどのように見えるかを最も確実に知る方法は、オシロスコープを使用することです。これは受信信号を復調または反転させることなく、「そのまま」表示します。これはテストやデバッグに役立ちます。NEC IRプロトコルの例を使って、期待される信号を示します。

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

通常、エンコードされたパケットの始めにはプリアンブルがあります。これにより、レシーバーはゲインとバックグラウンドのレベルを決定できます。プリアンブルのないプロトコルもあります。例えば、Sharpなどです。

次にデータが送信されます。構造、プリアンブル、およびビットエンコーディング方法は、特定のプロトコルによって決定されます。

**NEC IRプロトコル**には、ボタンが押されている間に送信される短いコマンドとリピートコードが含まれています。コマンドとリピートコードの両方には、最初に同じプリアンブルがあります。

NECの**コマンド**は、プリアンブルに加えて、デバイスが実行する必要があることを理解するためのアドレスバイトとコマンド番号バイトで構成されています。アドレスとコマンド番号のバイトは、送信の完全性をチェックするために逆の値で複製されています。コマンドの最後には追加のストップビットがあります。

**リピートコード**には、プリアンブルの後に"1"があり、これがストップビットです。

**論理的な"0"と"1"**について、NECはパルス距離エンコーディングを使用します：まず、パルスバーストが送信され、その後に一時停止があり、その長さがビットの値を設定します。

### エアコン

他のリモコンとは異なり、**エアコンは押されたボタンのコードだけを送信するわけではありません**。ボタンが押されると、**エアコン機器とリモコンが同期していることを確認するために、すべての情報も送信されます**。\
これにより、20ºCに設定された機械が一つのリモコンで21ºCに増加し、その後、まだ温度が20ºCとして設定されている別のリモコンを使用して温度をさらに上げると、それは21ºCに"増加"されます（21ºCだと思って22ºCになるのではなく）。

### 攻撃

Flipper Zeroを使って赤外線を攻撃することができます:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## 参考文献

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
