# iButton

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## イントロ

iButtonは、**コイン状の金属容器に詰め込まれた**電子識別キーの一般的な名称です。また、**Dallas Touch** Memoryまたは接触メモリとも呼ばれます。これはしばしば「磁気」キーと誤って言われることがありますが、実際には**何も磁気的なものはありません**。実際には、デジタルプロトコルで動作する完全な**マイクロチップ**が内部に隠されています。

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### iButtonとは何ですか？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常、iButtonはキーとリーダーの物理的形態を意味し、2つのコンタクトを持つ丸いコインです。それを囲むフレームには、一般的なプラスチックホルダーからリング、ペンダントなどまでさまざまなバリエーションがあります。

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

キーがリーダーに到達すると、**コンタクトが接触**し、キーは電源を入れて**IDを送信**します。時には、キーが**直ちに読み取られない**ことがあります。これは、インターコムの**コンタクトPSDが適切でない**ためです。その場合は、キーをリーダーの壁の1つに押し付ける必要があります。

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wireプロトコル** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Dallasキーは、1-Wireプロトコルを使用してデータを交換します。データ転送用のコンタクトが1つだけ (!!) で、マスターからスレーブ、およびその逆方向に向けての両方向のデータ転送が行われます。1-Wireプロトコルはマスター-スレーブモデルに従って動作します。このトポロジーでは、マスターが常に通信を開始し、スレーブがその指示に従います。

キー（スレーブ）がインターコム（マスター）に接触すると、キー内部のチップがオンになり、インターコムによって電源が供給され、キーが初期化されます。その後、インターコムはキーのIDを要求します。次に、このプロセスを詳しく見ていきます。

Flipperは、マスターモードとスレーブモードの両方で動作できます。キー読み取りモードでは、Flipperはリーダーとして機能し、つまりマスターとして機能します。そして、キーエミュレーションモードでは、Flipperはキーであるかのように振る舞い、スレーブモードになります。

### Dallas、Cyfral＆Metakomキー

これらのキーの動作に関する情報については、[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)をチェックしてください。

### 攻撃

iButtonはFlipper Zeroで攻撃される可能性があります：

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## 参考文献

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
