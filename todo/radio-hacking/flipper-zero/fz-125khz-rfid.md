# FZ - 125kHz RFID

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見る
- **Discordグループ**に**参加**する💬(https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

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
一部のインターホンは、キーの複製を防ぐために、読み取りの前に書き込みコマンドを送信しようとします。書き込みが成功すると、そのタグは偽物と見なされます。FlipperがRFIDをエミュレートすると、リーダーがオリジナルと区別する方法がないため、そのような問題は発生しません。
{% endhint %}

### 手動で追加

Flipper Zeroで**データを指定して**偽のカードを作成し、それをエミュレートできます。

#### カード上のID

カードを受け取ったときに、そのID（または一部）がカードに書かれていることがあります。

- **EM Marin**

たとえば、このEM-Marinカードでは、物理カードに**最後の5バイトのうち3バイトが明確に**読み取れます。\
カードから読み取れない場合は、ブルートフォースで他の2つを見つけることができます。

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

- **HID**

同様に、このHIDカードでは、3バイトのうち2バイトだけがカードに印刷されています。

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### エミュレート/書き込み

カードを**コピー**したり、IDを**手動で入力**した後、Flipper Zeroでそれを**エミュレート**するか、実際のカードに**書き込む**ことができます。

## 参考文献

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見る
- **Discordグループ**に**参加**する💬(https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
