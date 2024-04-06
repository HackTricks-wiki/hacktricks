# FZ - 125kHz RFID

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見る
* **💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f)**に参加するか、**[**telegramグループ**](https://t.me/peass)**に参加するか、Twitter 🐦で私たちをフォローする** [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## イントロ

125kHzタグの動作に関する詳細情報については、以下をチェックしてください：

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## アクション

これらのタイプのタグに関する詳細情報については、[**このイントロ**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)を読んでください。

### 読み取り

カード情報を**読み取り**を試みます。その後、それらを**エミュレート**することができます。

{% hint style="warning" %}
一部のインターコムは、キーの複製を防ぐために、読み取りの前に書き込みコマンドを送信しようとします。書き込みが成功すると、そのタグは偽物と見なされます。FlipperがRFIDをエミュレートすると、リーダーがオリジナルと区別する方法がないため、そのような問題は発生しません。
{% endhint %}

### 手動で追加

Flipper Zeroで**データを指定して**偽のカードを作成し、それをエミュレートすることができます。

#### カード上のID

カードを取得すると、そのID（または一部）がカードに記載されていることがあります。

* **EM Marin**

たとえば、このEM-Marinカードでは、物理カードに**最後の5バイトのうち3バイトがクリアで読み取れる**可能性があります。\
カードから読み取れない場合は、ブルートフォース攻撃で残りの2つを見つけることができます。

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

同様に、このHIDカードでは、カードに印刷された3バイトのうち2バイトしか見つかりません

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### エミュレート/書き込み

カードを**コピー**したり、IDを**手動で入力**した後、Flipper Zeroでそれを**エミュレート**するか、実際のカードに**書き込む**ことができます。

## 参考文献

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見る
* **💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f)**に参加するか、**[**telegramグループ**](https://t.me/peass)**に参加するか、Twitter 🐦で私たちをフォローする** [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
