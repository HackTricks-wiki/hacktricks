# iButton

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## イントロ

iButtonは、**コイン形状の金属容器**に収められた電子識別キーの一般的な名前です。**Dallas Touch** Memoryや接触メモリとも呼ばれます。しばしば誤って「磁気」キーと呼ばれることがありますが、実際にはその中には**磁気は何も含まれていません**。実際には、デジタルプロトコルで動作する完全な**マイクロチップ**が内蔵されています。

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### iButtonとは何ですか？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常、iButtonはキーとリーダーの物理的な形状を意味します - 2つの接点を持つ丸いコインです。それを囲むフレームには、最も一般的なプラスチックホルダーに穴が開いているものからリング、ペンダントなど様々なバリエーションがあります。

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

キーがリーダーに到達すると、**接点が接触**し、キーはIDを**送信**するために電力を供給されます。時々、インターホンの**接点PSDが大きすぎる**ために、キーはすぐには**読み取られません**。その場合、キーとリーダーの外輪郭が接触できないのです。そのような場合は、キーをリーダーの壁の一方に押し付ける必要があります。

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wireプロトコル** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Dallasキーは1-Wireプロトコルを使用してデータを交換します。データ転送用の接点が1つだけ(!!)で、マスターからスレーブ、そしてその逆の両方向です。1-Wireプロトコルはマスター・スレーブモデルに従って動作します。このトポロジーでは、マスターが常に通信を開始し、スレーブがその指示に従います。

キー（スレーブ）がインターホン（マスター）に接触すると、インターホンによって電力を供給されたキー内のチップがオンになり、キーが初期化されます。その後、インターホンはキーIDを要求します。次に、このプロセスをより詳細に見ていきます。

Flipperはマスターモードとスレーブモードの両方で動作することができます。キー読み取りモードでは、Flipperはリーダーとして動作し、つまりマスターとして動作します。そして、キーのエミュレーションモードでは、flipperはキーであるふりをし、スレーブモードになります。

### Dallas、Cyfral、Metakomキー

これらのキーの動作についての情報は、ページ[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)をチェックしてください。

### 攻撃

iButtonはFlipper Zeroで攻撃することができます：

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## 参考文献

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
