# FZ - 125kHz RFID

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでのAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のGitHubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## イントロ

125kHzタグの動作についての詳細は以下をチェックしてください:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## アクション

これらのタグのタイプについての詳細は[**このイントロを読む**](../../../radio-hacking/pentesting-rfid.md#low-frequency-rfid-tags-125khz)。

### 読む

カード情報を**読み取り**、それを**エミュレート**します。

{% hint style="warning" %}
一部のインターコムは、読み取りの前に書き込みコマンドを送信することで鍵の複製から自身を守ろうとします。書き込みが成功した場合、そのタグは偽物と見なされます。FlipperがRFIDをエミュレートするとき、リーダーはそれをオリジナルと区別する方法がないので、そのような問題は発生しません。
{% endhint %}

### 手動で追加

手動でデータを指定して**偽のカードをFlipper Zeroで作成**し、それをエミュレートすることができます。

#### カード上のID

時々、カードを手に入れたときに、そのID（またはその一部）がカードに見える形で書かれていることがあります。

* **EM Marin**

例えば、このEM-Marinカードでは、物理カードで**最後の3バイト中の5バイトをクリアに読むことができます**。\
カードから読むことができない場合、他の2バイトはブルートフォースできます。

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

このHIDカードでも、カードに印刷されている3バイト中2バイトのみが見つかります

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### エミュレート/書き込み

カードを**コピー**した後、またはIDを**手動で入力**した後、Flipper Zeroでそれを**エミュレート**するか、実際のカードに**書き込む**ことができます。

## 参考文献

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでのAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のGitHubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
