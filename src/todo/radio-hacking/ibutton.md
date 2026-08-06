# iButton

{{#include ../../banners/hacktricks-training.md}}

## 概要

iButtonは、**コイン型の金属容器**に収められた電子識別キーの一般名称です。Dallas Touch Memoryまたはcontact memoryとも呼ばれます。しばしば誤って「磁気」キーと呼ばれますが、内部には**磁気的なものは何もありません**。実際には、デジタルプロトコルで動作する本格的な**マイクロチップ**が内部に隠されています。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButtonとは？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常、iButtonという名称は、キーとreaderの物理的な形状、つまり2つの接点を持つ丸いコインを指します。キーを囲むフレームには、穴の開いた最も一般的なプラスチックホルダーから、リング、ペンダントなどまで、多くのバリエーションがあります。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

キーがreaderに到達すると、**接点が接触し**、キーに電力が供給されてIDを**送信**します。intercomの**接点PSDが本来より大きい**ため、キーがすぐに**読み取られない**場合があります。その場合、キーとreaderの外縁が接触できません。この場合は、readerの壁のいずれかにキーを押し当てる必要があります。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wireプロトコル** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas keyは1-wireプロトコルを使用してデータを交換します。このプロトコルでは、MasterからSlave、またはその逆方向の両方向のデータ転送に、データ用の接点を1つだけ使用します（!!）。1-wireプロトコルはMaster-Slaveモデルに従って動作します。このトポロジーでは、Masterが常に通信を開始し、Slaveがその指示に従います。

キー（Slave）がintercom（Master）に接触すると、キー内部のchipがintercomから電力を供給されて起動し、キーが初期化されます。その後、intercomがキーのIDを要求します。次に、このプロセスをさらに詳しく見ていきます。

FlipperはMasterモードとSlaveモードの両方で動作できます。キーのreading modeでは、Flipperはreaderとして動作します。つまり、Masterとして機能します。一方、キーのemulation modeでは、Flipperはキーを装うため、Slaveモードになります。<sup>[[1]](#references)</sup>

### Dallas、Cyfral、Metakom keys

これらのkeysの動作については、[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)のページを確認してください。<sup>[[1]](#references)</sup>

### 攻撃

iButtonはFlipper Zeroで攻撃できます:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## 参考文献

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
