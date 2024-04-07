# FZ - 125kHz RFID

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)でフォローする
- **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## イントロ

125kHzタグの動作についての詳細は、以下をチェックしてください：

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## アクション

これらのタイプのタグについての詳細については、[**このイントロ**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)を読んでください。

### 読み取り

カード情報を**読み取ろうと**します。その後、それらを**エミュレート**できます。

{% hint style="warning" %}
一部のインターコムは、キーの複製を防ぐために、読み取りの前に書き込みコマンドを送信しようとします。書き込みが成功すると、そのタグは偽物と見なされます。FlipperがRFIDをエミュレートすると、リーダーがオリジナルと区別する方法がないため、そのような問題は発生しません。
{% endhint %}

### 手動で追加

Flipper Zeroで**データを指定して**偽のカードを作成し、それをエミュレートできます。

#### カード上のID

カードを受け取ったときに、そのID（または一部）がカードに記載されていることがあります。

- **EM Marin**

たとえば、このEM-Marinカードでは、物理カードに**最後の5バイトのうち3バイトが明確に読み取れます**。\
カードから読み取れない場合は、ブルートフォース攻撃で残りの2つを見つけることができます。

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

- **HID**

同様に、このHIDカードでは、3つのバイトのうち2つしかカードに印刷されていません

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### エミュレート/書き込み

カードを**コピー**したり、IDを**手動で入力**した後、Flipper Zeroでそれを**エミュレート**するか、実際のカードに**書き込む**ことができます。

## 参照

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)でフォローする
- **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>
