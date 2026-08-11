# iButton

{{#include ../../banners/hacktricks-training.md}}

## Intro

iButtonは、**コイン型の金属容器**に収められた電子識別キーの一般名称です。Dallas Touch Memoryまたはcontact memoryとも呼ばれます。しばしば「磁気」キーと誤って呼ばれますが、内部に**磁気的なものは何もありません**。実際には、デジタルプロトコルで動作する本格的な**microchip**が内部に隠されています。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButtonとは？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButtonという名称は、耐久性のあるコイン型パッケージと接点の配置を表しています。ホルダーには、プラスチック製のフォブ、リング、ペンダントなどがあります。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

両方の接点がreaderに接触すると、デバイスに電力が供給され、データが交換されます。 recessed contactの形状によって外側のground接点が接触できない場合は、キーをreaderの壁に対して傾けることで接触を回復できます。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maximのキーは1-Wire protocolを使用します。1つのdata接点が双方向の通信を担い、parasitic powerを供給する場合もあります。一方、金属ケースがreturn接点になります。controllerがトランザクションを開始し、デバイスが応答します。<sup>[[2]](#references)</sup>

キー（Slave）がインターホン（Master）に接触すると、インターホンから電力が供給されてキー内部のchipが起動し、キーが初期化されます。その後、インターホンはキーIDを要求します。次に、このプロセスを詳しく見ていきます。

Flipperは、キーを読み取る際にはcontrollerとして動作し、保存された識別子をreaderに提示する際にはemulated deviceとして動作できます。<sup>[[1]](#references)</sup>

### Dallas、Cyfral、Metakom keys

これらのキーの動作については、[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)のページを確認してください。<sup>[[1]](#references)</sup>

### 攻撃

iButtonはFlipper Zeroで攻撃できます:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Flipper ZeroでiButtonを手なずける](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — softwareによる1-Wire通信](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
