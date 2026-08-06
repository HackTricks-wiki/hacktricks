# 红外线

{{#include ../../banners/hacktricks-training.md}}

## 红外线的工作原理 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**红外光对人类不可见**。红外线波长范围为 **0.7 至 1000 微米**。家用遥控器使用红外信号传输数据，工作波长范围为 0.75..1.4 微米。遥控器中的微控制器使红外 LED 以特定频率闪烁，将数字信号转换为红外信号。

接收红外信号需要使用**光接收器**。它会**将红外光转换为电压脉冲**，这些脉冲已经是**数字信号**。通常，接收器内部有一个**深色滤光片**，只允许**目标波长通过**，并滤除噪声。<sup>[[1]](#references)</sup>

### 红外协议的多样性 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

红外协议在 3 个因素上存在差异：<sup>[[1]](#references)</sup>

- 比特编码
- 数据结构
- 载波频率 —— 通常在 36..38 kHz 范围内

#### 比特编码方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

通过调制脉冲之间空闲部分的持续时间来编码比特。脉冲本身的宽度保持不变。

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

通过调制脉冲宽度来编码比特。脉冲突发之后的空闲部分宽度保持不变。

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

它也称为 Manchester encoding。逻辑值由脉冲突发与空闲部分之间转换的极性决定。“空闲到脉冲突发”表示逻辑“0”，“脉冲突发到空闲”表示逻辑“1”。

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 前述方式的组合及其他特殊方式**

> [!TIP]
> 有些红外协议**试图成为多种设备通用的协议**。其中最著名的是 RC5 和 NEC。遗憾的是，**最著名并不意味着最常见**。在我的使用环境中，我只遇到过两个 NEC 遥控器，没有遇到 RC5 遥控器。
>
> 制造商喜欢使用自己独有的红外协议，即使是同一设备类别中的设备也如此（例如电视盒）。因此，不同公司的遥控器，有时甚至同一公司不同型号的遥控器，也无法与同类型的其他设备配合使用。

### 探索红外信号

了解遥控器红外信号形态的最可靠方法是使用示波器。示波器不会对接收信号进行解调或反相，只会将其“原样”显示出来。这对于测试和调试很有用。下面将以 NEC 红外协议为例展示预期信号。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

通常，编码数据包的开头会有一个前导码。这使接收器能够确定增益水平和背景情况。有些协议没有前导码，例如 Sharp。

随后会传输数据。数据结构、前导码和比特编码方式由具体协议决定。

**NEC 红外协议**包含一个短命令和一个重复代码，按钮按下期间会发送重复代码。命令和重复代码开头具有相同的前导码。

NEC **命令**除前导码外，还由一个地址字节和一个命令编号字节组成，设备根据它们确定要执行的操作。地址字节和命令编号字节会以反向值重复发送，用于检查传输完整性。命令末尾还有一个额外的停止位。

**重复代码**在前导码之后包含一个“1”，该位就是停止位。

对于**逻辑“0”和“1”**，NEC 使用 Pulse Distance Encoding：首先传输一个脉冲突发，之后是暂停，暂停的长度决定比特值。

### 空调

与其他遥控器不同，**空调不会只传输被按下按钮的代码**。按下按钮时，它们还会**传输所有信息**，以确保**空调设备与遥控器保持同步**。\
这样可以避免以下情况：一台设定为 20ºC 的空调先用一个遥控器调高到 21ºC，随后使用另一个仍显示 20ºC 的遥控器继续调高温度时，它会将温度“调高”到 21ºC，而不是误以为当前是 21ºC 后调到 22ºC。<sup>[[1]](#references)</sup>

---

## 攻击与 Offensive Research <a href="#attacks" id="attacks"></a>

你可以使用 Flipper Zero 攻击 Infrared：


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / 机顶盒接管（EvilScreen）

近期的学术研究（EvilScreen，2022 年）表明，**将 Infrared 与 Bluetooth 或 Wi-Fi 结合的多通道遥控器，可能被滥用于完全劫持现代智能电视**。该攻击将高权限 IR 服务代码与经过身份验证的 Bluetooth 数据包结合起来，绕过通道隔离，从而允许在无需物理访问的情况下启动任意应用、激活麦克风或执行恢复出厂设置。研究确认，不同厂商的 8 款主流电视存在漏洞，其中包括一款声称符合 ISO/IEC 27001 的 Samsung 型号。缓解措施需要厂商修复固件，或完全禁用未使用的 IR 接收器。<sup>[[2]](#references)</sup>

### 通过 IR LED 进行 Air-Gapped 数据外泄（aIR-Jumper family）

安全摄像头、路由器，甚至恶意 USB 设备通常都包含**夜视 IR LED**。研究表明，恶意软件可以调制这些 LED（使用简单的 OOK 时速率低于 10–20 kbit/s），将**机密信息通过墙壁和窗户外泄**到数十米外的外部摄像头。<sup>[[3]](#references)</sup>由于这种光线位于可见光谱之外，操作人员很少会察觉。对策包括：

* 在敏感区域物理遮挡或移除 IR LED
* 监控摄像头 LED 的占空比和固件完整性
* 在窗户和监控摄像头上部署 IR-cut filters

攻击者还可以使用高功率 IR 投影器，通过向不安全的摄像头闪烁数据，将命令**注入**网络。

### 使用 Flipper Zero 1.0 进行远距离暴力破解与扩展协议攻击

Firmware 1.0（2024 年 9 月）新增了**数十种额外的 IR 协议和可选的外部放大器模块**。结合 universal-remote brute-force mode，Flipper 配合高功率二极管，可以在最远 30 m 的距离禁用或重新配置大多数公共场所的电视和空调。

---

## 工具与实践示例 <a href="#tooling" id="tooling"></a>

### 硬件

* **Flipper Zero** —— 支持学习、重放和 dictionary-bruteforce modes 的便携式收发器（见上文）。
* **Arduino / ESP32** + IR LED / TSOP38xx receiver —— 廉价的 DIY 分析器/发射器。可结合 `Arduino-IRremote` library 使用（v4.x 支持超过 40 种协议）。
* **Logic analysers**（Saleae/FX2）——在协议未知时捕获原始时序。
* **带 IR-blaster 的智能手机**（例如 Xiaomi）——可用于快速现场测试，但范围有限。

### 软件

* **`Arduino-IRremote`** —— actively-maintained C++ library：
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** —— GUI decoders，可导入原始捕获数据并自动识别协议，还能生成 Pronto/Arduino code。
* **LIRC / ir-keytable (Linux)** —— 从命令行接收和注入 IR：
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## 防御措施 <a href="#defense" id="defense"></a>

* 对于部署在公共场所且不需要使用 IR 的设备，禁用或遮盖其 IR 接收器。
* 在智能电视与遥控器之间强制执行 *pairing* 或加密检查；隔离具有高权限的“service”代码。
* 在涉密区域周围部署 IR-cut filters 或 continuous-wave detectors，以阻断光学 covert channels。
* 监控暴露可控 IR LED 的摄像头和 IoT 设备的固件完整性。

## 参考资料

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
