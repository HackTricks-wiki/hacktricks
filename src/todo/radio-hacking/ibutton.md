# iButton

{{#include ../../banners/hacktricks-training.md}}

## 概要

iButtonは、**コイン形状の金属ケース**に収められた電子識別キーの一般的な名称です。**Dallas Touch** Memoryまたはcontact memoryとも呼ばれます。「磁気」キーと誤って呼ばれることがよくありますが、内部に**磁気的なものは一切ありません**。実際には、デジタルプロトコルで動作する本格的な**microchip**が内部に隠されています。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButtonとは？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常、iButtonとはキーとreaderの物理的な形状を指します。つまり、2つの接点を持つ丸いコインです。それを囲むフレームには、穴の開いた最も一般的なプラスチックホルダーから、リング、ペンダントなどまで、さまざまな種類があります。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

キーがreaderに到達すると、**接点が接触し**、キーに電力が供給されてIDを**送信**します。intercomの**接点PSDが本来より大きい**ため、キーがすぐに**読み取られない**ことがあります。その場合、キーとreaderの外周が接触できません。このときは、readerの壁のいずれかにキーを押し付ける必要があります。

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas keysは1-wire protocolを使用してデータを交換します。データ転送用の接点は、MasterからSlave、またはその逆方向の両方で、わずか1つだけです（!!）。1-wire protocolはMaster-Slaveモデルに従って動作します。このトポロジーでは、Masterが常に通信を開始し、Slaveがその指示に従います。

キー（Slave）がintercom（Master）に接触すると、キー内部のchipがintercomから電力を供給されて起動し、キーが初期化されます。その後、intercomがキーのIDを要求します。次に、このプロセスを詳しく見ていきます。

FlipperはMasterモードとSlaveモードの両方で動作できます。キーのreading modeでは、Flipperはreaderとして動作します。つまり、Masterとして動作します。また、キーのemulation modeでは、Flipperはキーのふりをするため、Slaveモードになります。

### Dallas、Cyfral、Metakom keys

これらのkeysの動作については、[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)のページを確認してください。<sup>[[1]](#references)</sup>

### Attacks

iButtonsはFlipper Zeroで攻撃できます:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
