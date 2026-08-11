# 赤外線

{{#include ../../banners/hacktricks-training.md}}

## 赤外線の仕組み <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**赤外線は人間には見えません**。IRの波長は**0.7～1000マイクロメートル**です。家庭用リモコンはデータ伝送にIR信号を使用し、0.75～1.4マイクロメートルの波長範囲で動作します。リモコン内のマイクロコントローラーは、赤外線LEDを特定の周波数で点滅させ、デジタル信号をIR信号に変換します。

IR信号を受信するには、**フォトレシーバー**を使用します。これは**IR光を電圧パルスに変換**し、すでに**デジタル信号**になっています。通常、レシーバー内部には**暗色光フィルター**があり、**目的の波長だけを通過させて**ノイズを除去します。<sup>[[1]](#references)</sup>

### IRプロトコルの種類 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IRプロトコルは、次の3つの要素で異なります。<sup>[[1]](#references)</sup>

- ビットエンコーディング
- データ構造
- キャリア周波数 — 多くの場合36～38 kHzの範囲

#### ビットエンコーディング方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

ビットは、パルス間のスペースの長さを変調することでエンコードされます。パルス自体の幅は一定です。

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

ビットは、パルス幅を変調することでエンコードされます。パルスバースト後のスペースの幅は一定です。

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

これはManchester encodingとしても知られています。論理値は、パルスバーストとスペースの間の遷移の極性によって決まります。「スペースからパルスバースト」は論理「0」を示し、「パルスバーストからスペース」は論理「1」を示します。

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 前述の方式の組み合わせとその他の特殊な方式**

> [!TIP]
> 複数の種類のデバイスに対応する**universalを目指している**IRプロトコルがあります。最も有名なのはRC5とNECです。残念ながら、**最も有名であることは最も一般的であることを意味しません**。私の環境では、NECリモコンは2台しか見たことがなく、RC5は1台もありません。
>
> メーカーは、同じデバイス範囲内（例えばTV-box）であっても、独自のIRプロトコルを使用したがります。そのため、異なる会社のリモコンや、同じ会社の異なるモデルのリモコンは、同じ種類の別のデバイスでは動作しないことがあります。

### IR信号の解析

リモコンのIR信号がどのように見えるかを確認する最も信頼できる方法は、オシロスコープを使用することです。オシロスコープは受信した信号を復調も反転もせず、単に「そのまま」表示します。これはテストやデバッグに役立ちます。ここではNEC IRプロトコルを例に、想定される信号を示します。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

通常、エンコードされたパケットの先頭にはプリアンブルがあります。これにより、レシーバーはゲインレベルと背景を判断できます。一方、Sharpのようにプリアンブルを持たないプロトコルもあります。

次にデータが送信されます。構造、プリアンブル、ビットエンコーディング方式は、特定のプロトコルによって決まります。

**NEC IRプロトコル**には、ボタンが押されている間に送信される短いコマンドとリピートコードが含まれます。コマンドとリピートコードは、どちらも先頭に同じプリアンブルを持ちます。

NECの**コマンド**は、プリアンブルに加えて、アドレスバイトとコマンド番号バイトで構成されます。これらによって、デバイスは実行すべき処理を理解します。伝送の整合性を確認するため、アドレスバイトとコマンド番号バイトは反転値とともに複製されます。コマンドの末尾には追加のストップビットがあります。

**リピートコード**には、プリアンブルの後にストップビットである「1」があります。

**論理「0」と「1」**について、NECはPulse Distance Encodingを使用します。まずパルスバーストが送信され、その後に休止が続き、その長さによってビットの値が決まります。

### エアコン

他のリモコンとは異なり、**エアコンは押されたボタンのコードだけを送信するわけではありません**。ボタンが押された際に**すべての情報も送信**し、**エアコン本体とリモコンを同期**させます。\
これにより、20ºCに設定された機器をあるリモコンで21ºCに変更した後、温度がまだ20ºCの別のリモコンを使ってさらに温度を上げた場合に、21ºCだと考えて「22ºC」ではなく「21ºC」に設定してしまうことを防げます。<sup>[[1]](#references)</sup>

---

## 攻撃とOffensive Research <a href="#attacks" id="attacks"></a>

Flipper Zeroを使用してInfraredを攻撃できます:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Boxの乗っ取り（EvilScreen）

近年のacademic research（EvilScreen、2022）では、**InfraredとBluetoothまたはWi-Fiを組み合わせたmulti-channel remoteが悪用され、最新のsmart-TVを完全にhijackできる**ことが実証されました。この攻撃では、高い権限を持つIR service codeと認証済みBluetoothパケットを組み合わせ、channel-isolationを回避して、物理的なアクセスなしに任意のアプリの起動、マイクの有効化、factory-resetを可能にします。異なるベンダーの主要なTV 8台（ISO/IEC 27001への準拠を主張するSamsungモデルを含む）で脆弱性が確認されました。対策にはベンダーによるfirmware修正、または未使用のIR receiverの完全な無効化が必要です。<sup>[[2]](#references)</sup>

### IR LEDによるAir-Gapped環境からのデータ流出（aIR-Jumper family）

Security cameraには通常、**night-vision IR LED**が搭載されています。aIR-Jumper prototypeでは、これらのLEDを制御するmalwareによって、**監視camera 1台あたり最大** **20 bit/s**、数十メートルの距離で、窓越しに外部cameraへsecretを**exfiltrate**できることが示されました。逆方向では、研究者らが数百メートルから数キロメートルの距離で、**100 bit/sを超える**速度でのinfiltrationを実証しました。<sup>[[3]](#references)</sup> 光が可視スペクトル外にあるため、operatorが気付かない可能性があります。対策には次のものがあります。

* 機密エリアのIR LEDを物理的に遮蔽または取り外す
* camera LEDのduty-cycleとfirmware integrityを監視する
* 窓とsecurity cameraにIR-cut filterを導入する

攻撃者は、強力なIR projectorを使用して、データを安全でないcameraへ点滅送信し、ネットワークにコマンドを**infiltrate**させることもできます。

### Flipper Zero 1.0によるLong-Range Brute-Forceと拡張プロトコル

Firmware 1.0（2024年9月）では、universal-remotes libraryが拡張され、microSDからinfrared asset fileをdynamic loadingする機能が追加されました。<sup>[[4]](#references)</sup> learning機能とuniversal-remote機能により、近くのTVやエアコンに対して、既知のコマンドをreplayしたり試行したりできます。到達距離はemitter、optics、ambient light、receiverに大きく依存します。外部IR hardwareによって延長できますが、固定された距離を想定してはいけません。

---

## Toolingと実践例 <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning、replay、dictionary-bruteforce modeを備えたportable transceiver（前述）。
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – 安価なDIY analyser/transmitter。`Arduino-IRremote` libraryと組み合わせます（v4.xは40以上のprotocolをサポート）。
* **Logic analyser**（Saleae/FX2）– protocolが不明な場合にraw timingをcaptureします。
* **IR-blaster搭載smartphone**（例：Xiaomi）– 手早いfield testに使えますが、rangeは限定的です。

### Software

* **`Arduino-IRremote`** – activeにmaintainされているC++ library:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – raw captureをimportし、protocolを自動識別して、Pronto/Arduino codeを生成するGUI decoder。
* **LIRC / ir-keytable (Linux)** – command lineからIRをreceiveおよびinjectします:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## 防御対策 <a href="#defense" id="defense"></a>

* 必要のない場合は、public spaceに設置されたdeviceのIR receiverを無効化または覆う。
* smart-TVとremoteの間で*pairing*またはcryptographic checkを強制し、privilegedな「service」codeを分離する。
* classified areaの周囲にIR-cut filterまたはcontinuous-wave detectorを導入し、optical covert channelを遮断する。
* 制御可能なIR LEDを公開しているcamera/IoT applianceのfirmware integrityを監視する。

## References

- [1] [Flipper Zero Infraredブログ記事](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Multi-channel Remote Control MimicryによるSmart TV Hijacking (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Security CameraとInfrared（IR）を介したCovert Air-Gap Exfiltration/Infiltration (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero Blog - Firmware 1.0 Released](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - usage and protocol documentation](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
