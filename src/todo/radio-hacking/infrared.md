# 赤外線

{{#include ../../banners/hacktricks-training.md}}

## 赤外線の仕組み <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**赤外線は人間には見えません**。IRの波長は**0.7〜1000ミクロン**です。家庭用リモコンはデータ伝送にIR信号を使用し、0.75〜1.4ミクロンの波長範囲で動作します。リモコン内のマイクロコントローラは赤外線LEDを特定の周波数で点滅させ、デジタル信号をIR信号に変換します。<sup>[[1]](#references)</sup>

IR信号の受信には**フォトレシーバー**を使用します。これは**IRの光を電圧パルスに変換**し、すでに**デジタル信号**となっています。通常、受信機内部には**暗色光フィルター**があり、**目的の波長だけを通過**させ、ノイズをカットします。

### IR Protocolsの種類 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR Protocolsは、次の3つの要素で異なります。

- bit encoding
- data structure
- carrier frequency — 多くの場合36〜38 kHzの範囲

#### bit encodingの方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bitsは、パルス間のspaceの持続時間を変調することでencodeされます。パルス自体の幅は一定です。

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bitsは、パルス幅を変調することでencodeされます。パルスburst後のspaceの幅は一定です。

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

これはManchester encodingとしても知られています。論理値は、パルスburstとspaceの間のtransitionの極性によって定義されます。「spaceからパルスburst」はlogic「0」を、「パルスburstからspace」はlogic「1」を示します。

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 前述の方式の組み合わせとその他の特殊な方式**

> [!TIP]
> 複数種類のdeviceに対して**universalになることを目指している**IR Protocolsがあります。最も有名なのはRC5とNECです。ただし、最も有名であることは、**最も一般的であることを意味しません**。私の環境では、NECリモコンは2台しか見たことがなく、RC5は1台もありません。
>
> Manufacturersは、同じdevice range内（例えばTV-box）であっても、独自のIR Protocolsを使用したがります。そのため、異なる会社のリモコンや、同じ会社の異なるmodelのリモコンは、同じ種類の他のdeviceでは動作しないことがあります。

### IR signalの調査

リモコンのIR signalがどのように見えるかを確認する最も信頼できる方法は、oscilloscopeを使用することです。oscilloscopeは受信したsignalをdemodulateしたりinvertしたりせず、単に「そのまま」表示します。これはtestingとdebuggingに役立ちます。ここではNEC IR protocolを例に、予想されるsignalを示します。

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

通常、encoded packetの先頭にはpreambleがあります。これによりreceiverはgain levelとbackgroundを判定できます。Sharpなど、preambleのないprotocolもあります。

次にdataがtransmitされます。structure、preamble、bit encoding methodは、特定のprotocolによって決まります。

**NEC IR protocol**には、短いcommandとrepeat codeが含まれます。repeat codeはbuttonが押されている間に送信されます。commandとrepeat codeは、どちらも先頭に同じpreambleを持ちます。

NECの**command**は、preambleに加えて、deviceが実行内容を理解するためのaddress byteとcommand-number byteで構成されます。transmissionのintegrityを確認するため、address byteとcommand-number byteは反転値で複製されます。commandの末尾には追加のstop bitがあります。

**repeat code**には、preambleの後に「1」があります。これはstop bitです。

**logic「0」と「1」**に対して、NECはPulse Distance Encodingを使用します。まずパルスburstがtransmitされ、その後にpauseが続き、その長さがbitのvalueを設定します。

### Air Conditioners

他のリモコンとは異なり、**air conditionersは押されたbuttonのcodeだけをtransmitするわけではありません**。buttonが押されたときに**すべてのinformationもtransmit**し、**air conditioned machineとリモコンがsynchronisedされる**ことを保証します。\
これにより、20ºCに設定されたmachineを1台目のリモコンで21ºCに上げ、その後、温度がまだ20ºCの別のリモコンを使ってさらに温度を上げたとき、21ºCの状態だと誤認して22ºCではなく21ºCに「上げる」ことを防げます。

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Flipper Zeroを使用してInfraredをattackできます:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

近年のacademic research（EvilScreen、2022）では、InfraredとBluetoothまたはWi-Fiを組み合わせた**multi-channel remotesが悪用され、現代のsmart-TVsを完全にhijackできる**ことが実証されました。このattackは、高いprivilegeを持つIR service codesとauthenticated Bluetooth packetsをchainし、channel-isolationをbypassして、physical accessなしに任意のapp launch、microphone activation、factory-resetを可能にします。異なるvendorのmainstream TV 8台（ISO/IEC 27001 complianceを主張するSamsung modelを含む）でvulnerableであることが確認されました。Mitigationにはvendor firmwareのfix、または未使用のIR receiversの完全なdisableが必要です。<sup>[[2]](#references)</sup>

### IR LEDsを介したAir-Gapped Data Exfiltration（aIR-Jumper family）

Security cameras、routers、さらにはmalicious USB sticksにも、**night-vision IR LEDs**が搭載されていることがあります。researchでは、malwareがこれらのLEDをmodulateし（単純なOOKで<10〜20 kbit/s）、**壁や窓越しにsecretsを、数十メートル離れた外部cameraへexfiltrateできる**ことが示されています。光がvisible spectrumの外側にあるため、operatorsが気づくことはほとんどありません。Counter-measures:

* Sensitive area内のIR LEDsを物理的にshieldするかremoveする
* Camera LEDのduty-cycleとfirmware integrityをmonitorする
* Windowsとsurveillance camerasにIR-cut filtersをdeployする

Attackerは、強力なIR projectorsを使用し、dataを安全でないcamerasへflash backすることで、networkにcommandsを**infiltrate**することもできます。

### Flipper Zero 1.0によるLong-Range Brute-ForceとExtended Protocols

Firmware 1.0（2024年9月）では、**数十種類の追加IR Protocolsとoptional external amplifier modules**が追加されました。universal-remote brute-force modeと組み合わせることで、Flipperはhigh-power diodeを使用し、最大30 m離れた場所から、ほとんどのpublic TVs/ACsをdisableまたはreconfigureできます。

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning、replay、dictionary-bruteforce modeを備えたportable transceiver（上記参照）。
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – 安価なDIY analyser/transmitter。`Arduino-IRremote` library（v4.xは40以上のprotocolsをsupport）と組み合わせます。
* **Logic analysers**（Saleae/FX2）– protocolがunknownの場合にraw timingsをcaptureします。
* **IR-blaster搭載のSmartphones**（例：Xiaomi）– field testをすぐに実行できますが、rangeは限定的です。

### Software

* **`Arduino-IRremote`** – actively-maintained C++ library:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – raw capturesをimportし、protocolを自動identifyしてPronto/Arduino codeをgenerateするGUI decoders。
* **LIRC / ir-keytable (Linux)** – command lineからIRをreceiveおよびinjectします:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* 必要がない場合は、public spacesにdeployされたdeviceのIR receiversをdisableするかcoverする。
* Smart-TVsとremotes間の*pairing*またはcryptographic checksをenforceし、privilegedな「service」codesをisolateする。
* Classified areas周辺にIR-cut filtersまたはcontinuous-wave detectorsをdeployし、optical covert channelsを遮断する。
* Control可能なIR LEDsを公開しているcameras/IoT appliancesのfirmware integrityをmonitorする。

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: Smart TV hijacking via remote control mimicry](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
