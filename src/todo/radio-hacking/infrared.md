# 赤外線

{{#include ../../banners/hacktricks-training.md}}

## 赤外線の仕組み <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**赤外線は人間には見えません**。IRの波長は**0.7～1000マイクロメートル**です。家庭用リモコンはデータ送信にIR信号を使用し、0.75～1.4マイクロメートルの波長範囲で動作します。リモコン内のマイクロコントローラーは赤外線LEDを特定の周波数で点滅させ、デジタル信号をIR信号に変換します。

IR信号を受信するには**フォトレシーバー**を使用します。これは**IR光を電圧パルスに変換**し、すでに**デジタル信号**になっています。通常、レシーバー内部には**暗色光フィルター**があり、**目的の波長だけを通過させ**、ノイズを除去します。<sup>[[1]](#references)</sup>

### IRプロトコルの種類 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IRプロトコルは、次の3つの要素で異なります。<sup>[[1]](#references)</sup>

- ビットエンコーディング
- データ構造
- 搬送周波数 — 多くの場合36～38 kHz

#### ビットエンコーディング方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

ビットは、パルス間のスペースの長さを変調することでエンコードされます。パルス自体の幅は一定です。

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

ビットはパルス幅を変調することでエンコードされます。パルスバースト後のスペースの幅は一定です。

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

これはManchester encodingとしても知られています。論理値は、パルスバーストとスペースの間の遷移の極性によって定義されます。「スペースからパルスバース」は論理値「0」を、「パルスバーストからスペース」は論理値「1」を表します。

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 前述の方式の組み合わせとその他の特殊な方式**

> [!TIP]
> 複数の種類のデバイスに対応する**universal化を目指している**IRプロトコルもあります。最も有名なものはRC5とNECです。ただし、最も有名であることは、**最も一般的であることを意味しません**。私の環境では、NECリモコンは2台だけ見かけ、RC5は1台も見かけませんでした。
>
> メーカーは、同じデバイス範囲内（たとえばTV-box）であっても、独自のIRプロトコルを使用することを好みます。そのため、異なる企業のリモコンや、同じ企業の異なるモデルのリモコンは、同じ種類の別のデバイスでは使用できない場合があります。

### IR信号の解析

リモコンのIR信号がどのように見えるかを確認する最も信頼できる方法は、オシロスコープを使用することです。オシロスコープは受信信号を復調も反転もせず、そのまま表示します。これはテストやデバッグに役立ちます。ここではNEC IRプロトコルを例に、予想される信号を示します。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

通常、エンコードされたパケットの先頭にはプリアンブルがあります。これにより、レシーバーはゲインのレベルと背景を判断できます。Sharpなど、プリアンブルのないプロトコルもあります。

次にデータが送信されます。構造、プリアンブル、ビットエンコーディング方式は、特定のプロトコルによって決まります。

**NEC IRプロトコル**には、短いコマンドと、ボタンが押されている間に送信されるリピートコードがあります。コマンドとリピートコードは、どちらも先頭に同じプリアンブルを持ちます。

NECの**command**は、プリアンブルに加えて、デバイスが実行内容を判断するためのアドレスバイトとコマンド番号バイトで構成されます。送信の整合性を確認するため、アドレスバイトとコマンド番号バイトは反転値とともに複製されます。コマンドの末尾には追加のストップビットがあります。

**repeat code**には、ストップビットである「1」がプリアンブルの後に続きます。

**論理値「0」と「1」**について、NECはPulse Distance Encodingを使用します。まずパルスバーストが送信され、その後に休止が続き、その長さによってビットの値が決まります。

### エアコン

他のリモコンとは異なり、**エアコンは押されたボタンのコードだけを送信するわけではありません**。ボタンが押されたときに**すべての情報も送信**し、**エアコン本体とリモコンの同期を保証**します。\
これにより、20ºCに設定されたエアコンを1台目のリモコンで21ºCに上げ、その後、温度がまだ20ºCとして認識されている別のリモコンでさらに温度を上げた際に、21ºC（22ºCではなく）に「上げる」ことを防げます。<sup>[[1]](#references)</sup>

---

## 攻撃とOffensive Research <a href="#attacks" id="attacks"></a>

Flipper Zeroを使用してInfraredを攻撃できます:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

近年の学術研究（EvilScreen、2022）では、**InfraredとBluetoothまたはWi-Fiを組み合わせたmulti-channel remoteが、最新のsmart-TVを完全にhijackするために悪用される可能性**が示されました。この攻撃では、高い権限を持つIR service codeと認証済みBluetooth packetを連鎖させ、channel-isolationを回避します。これにより、物理的なアクセスなしで任意のアプリの起動、マイクの有効化、factory-resetが可能になります。異なるベンダーの主要TV 8機種（ISO/IEC 27001準拠を主張するSamsungモデルを含む）で脆弱性が確認されました。緩和策には、ベンダーによるfirmware修正、または未使用のIR receiverの完全な無効化が必要です。<sup>[[2]](#references)</sup>

### IR LEDによるAir-Gapped Data Exfiltration（aIR-Jumper family）

Security camera、router、さらには悪意のあるUSB stickにも、**night-vision IR LED**が搭載されていることがあります。研究では、malwareがこれらのLEDを変調し、単純なOOKで毎秒10～20 kbit未満の速度で、**壁や窓越しにsecretをexfiltrate**できることが示されています。外部のcameraを数十メートル離れた場所に設置して受信できます。<sup>[[3]](#references)</sup>光が可視スペクトル外にあるため、運用担当者が気付くことはほとんどありません。対策:

* 機密エリアのIR LEDを物理的に遮蔽または取り外す
* camera LEDのduty-cycleとfirmware integrityを監視する
* 窓や監視cameraにIR-cut filterを導入する

攻撃者は、強力なIR projectorを使用して、データを安全でないcameraに点滅送信し、networkへcommandを**infiltrate**することもできます。

### Flipper Zero 1.0によるLong-Range Brute-ForceとExtended Protocols

Firmware 1.0（2024年9月）では、**数十種類の追加IR protocolと、オプションの外付けamplifier module**が追加されました。universal-remote brute-force modeと組み合わせることで、Flipperは高出力diodeを使用し、最大30 m離れた場所から、ほとんどの公共TV/ACを無効化または再設定できます。

---

## Toolingと実践例 <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning、replay、dictionary-bruteforce modeを備えたportable transceiver（上記参照）。
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – 安価なDIY analyser/transmitter。`Arduino-IRremote` libraryと組み合わせます（v4.xは40以上のprotocolをサポート）。
* **Logic analyser**（Saleae/FX2）– protocolが不明な場合にraw timingをcapture。
* **IR-blaster搭載smartphone**（例: Xiaomi）– 手早いfield testに便利ですが、rangeは限定的です。

### Software

* **`Arduino-IRremote`** – 継続的にmaintainされているC++ library:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – raw captureをimportし、protocolを自動識別してPronto/Arduino codeを生成するGUI decoder。
* **LIRC / ir-keytable (Linux)** – command lineからIRを受信・inject:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## 防御策 <a href="#defense" id="defense"></a>

* 公共スペースに設置するdeviceで不要な場合は、IR receiverを無効化または覆う。
* smart-TVとremote間の*pairing*またはcryptographic checkを強制し、権限の高い「service」codeを分離する。
* 機密エリア周辺にIR-cut filterまたはcontinuous-wave detectorを導入し、optical covert channelを遮断する。
* 制御可能なIR LEDを公開しているcamera/IoT applianceのfirmware integrityを監視する。

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
