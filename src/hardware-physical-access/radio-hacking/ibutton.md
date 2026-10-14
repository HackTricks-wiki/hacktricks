# iButton

{{#include ../../banners/hacktricks-training.md}}

## 概要

iButtonは、**コイン型の金属容器**に収められた電子識別キーの総称です。Dallas Touch Memoryまたは接触型メモリとも呼ばれます。「磁気」キーと誤って呼ばれることもよくありますが、内部に**磁性体はありません**。実際には、デジタルプロトコルで動作する本格的な**マイクロチップ**が内蔵されています。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButtonとは？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButtonという名前は、耐久性のあるコイン型のパッケージと接点の配置を表しています。プラスチック製のフォブやリング、ペンダントなどのホルダーがあります。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

両方の接点がリーダーに触れると、デバイスに電力が供給され、データがやり取りされます。くぼんだ接点の形状によって外側のグランド接点が接触しない場合は、キーをリーダーの壁に傾けると接触を回復できます。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wireプロトコル** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maximのキーは1-Wireプロトコルを使用します。1本のデータ接点で双方向の通信を行い、寄生電力を供給する場合もあります。金属ケースはリターン接点として機能します。コントローラーがトランザクションを開始し、デバイスが応答します。<sup>[[2]](#references)</sup>

キー（Slave）がインターホン（Master）に接触すると、インターホンから電力が供給され、キー内部のチップが起動して初期化されます。その後、インターホンがキーIDを要求します。次に、このプロセスを詳しく見ていきます。

Flipperは、キーを読み取る際にはコントローラーとして、保存済みの識別子をリーダーに提示する際にはエミュレートされたデバイスとして動作できます。<sup>[[1]](#references)</sup>

### Dallas、Cyfral、Metakomのキー

これらのキーの動作については、[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)のページを参照してください。<sup>[[1]](#references)</sup>

### 攻撃

iButtonはFlipper Zeroで攻撃できます。


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Flipper ZeroでiButtonを使いこなす](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — ソフトウェアによる1-Wire通信](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
