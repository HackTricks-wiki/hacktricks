# iButton

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をご覧ください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## イントロ

iButtonは、**コイン状の金属容器**に詰められた電子識別キーの一般的な名称です。また、ダラスタッチメモリまたは接触メモリとも呼ばれます。実際には、内部にはデジタルプロトコルで動作する**完全なマイクロチップ**が隠されており、しばしば「磁気」キーと誤って言及されますが、実際には何も磁気的なものはありません。

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### iButtonとは？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常、iButtonはキーとリーダーの物理的な形態を意味し、丸いコインに2つの接点があります。それを囲むフレームには、一般的なプラスチックホルダーからリング、ペンダントなどまでさまざまなバリエーションがあります。

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

キーがリーダーに到達すると、**接点が接触**し、キーはIDを**送信**するために電力を供給されます。キーが**すぐに読み取られない**場合もあります。これは、インターコムの**接触PSDが適切なサイズよりも大きい**ためです。その場合は、キーをリーダーの壁の1つに押し付ける必要があります。

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wireプロトコル** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Dallasキーは、1-Wireプロトコルを使用してデータを交換します。データ転送用のデータのみの1つの接点を持ち、マスターからスレーブ、およびその逆方向に向かって動作します。1-Wireプロトコルはマスター-スレーブモデルに従って動作します。このトポロジでは、マスターが常に通信を開始し、スレーブがその指示に従います。

キー（スレーブ）がインターコム（マスター）に接触すると、キー内部のチップがオンになり、インターコムによって電力が供給され、キーが初期化されます。その後、インターコムはキーのIDを要求します。次に、このプロセスを詳しく見ていきます。

Flipperはマスターモードとスレーブモードの両方で動作することができます。キーの読み取りモードでは、Flipperはリーダーとして動作し、マスターとして機能します。キーのエミュレーションモードでは、Flipperはキーのふりをし、スレーブモードで動作します。

### Dallas、Cyfral、Metakomキー

これらのキーの動作方法については、次のページを参照してください：[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### 攻撃

iButtonはFlipper Zeroを使用して攻撃することができます：

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## 参考文献

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をご覧ください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
