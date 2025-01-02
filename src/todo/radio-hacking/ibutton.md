# iButton

{{#include ../../banners/hacktricks-training.md}}

## Intro

iButtonは、**コイン型の金属容器**に詰め込まれた電子識別キーの一般的な名称です。これは**Dallas Touch** Memoryまたは接触メモリとも呼ばれます。しばしば「磁気」キーと誤って呼ばれますが、実際には**磁気的なものは何もありません**。実際には、デジタルプロトコルで動作する**マイクロチップ**が内部に隠されています。

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常、iButtonはキーとリーダーの物理的な形状を指し、2つの接点を持つ丸いコインです。その周囲のフレームには、最も一般的な穴のあるプラスチックホルダーからリング、ペンダントなど、さまざまなバリエーションがあります。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

キーがリーダーに到達すると、**接点が接触し**、キーが**IDを送信するために電源が入ります**。時には、**インターホンの接触PSDが大きすぎる**ため、キーが**すぐに読み取られない**ことがあります。そのため、キーとリーダーの外形が接触できない場合があります。その場合は、リーダーの壁の1つの上にキーを押し付ける必要があります。

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallasキーは1-wireプロトコルを使用してデータを交換します。データ転送のための接点は1つだけで、両方向（マスターからスレーブ、そしてその逆）で機能します。1-wireプロトコルはマスター-スレーブモデルに従って動作します。このトポロジーでは、マスターが常に通信を開始し、スレーブがその指示に従います。

キー（スレーブ）がインターホン（マスター）に接触すると、キー内部のチップが起動し、インターホンによって電源が供給され、キーが初期化されます。その後、インターホンがキーIDを要求します。次に、このプロセスをより詳細に見ていきます。

Flipperはマスターとスレーブの両方のモードで動作できます。キー読み取りモードでは、Flipperはリーダーとして機能し、つまりマスターとして動作します。そして、キーエミュレーションモードでは、Flipperはキーのふりをし、スレーブモードにあります。

### Dallas, Cyfral & Metakom keys

これらのキーの動作についての情報は、ページ[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)を確認してください。

### Attacks

iButtonsはFlipper Zeroで攻撃できます：

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
