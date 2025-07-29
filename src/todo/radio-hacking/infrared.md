# Infrared

{{#include ../../banners/hacktricks-training.md}}

## How the Infrared Works <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**红外光对人类是不可见的**。红外波长范围为**0.7到1000微米**。家用遥控器使用红外信号进行数据传输，工作波长范围为0.75..1.4微米。遥控器中的微控制器使红外LED以特定频率闪烁，将数字信号转换为红外信号。

接收红外信号使用**光接收器**。它**将红外光转换为电压脉冲**，这些脉冲已经是**数字信号**。通常，接收器内部有一个**暗光滤波器**，只允许**所需波长通过**，并切除噪声。

### Variety of IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

红外协议在三个因素上有所不同：

- 位编码
- 数据结构
- 载波频率——通常在36..38 kHz范围内

#### Bit encoding ways <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 脉冲间距编码**

通过调制脉冲之间的间隔持续时间来编码位。脉冲本身的宽度是恒定的。

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. 脉冲宽度编码**

通过调制脉冲宽度来编码位。脉冲爆发后的间隔宽度是恒定的。

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. 相位编码**

也称为曼彻斯特编码。逻辑值由脉冲爆发与间隔之间的过渡极性定义。“间隔到脉冲爆发”表示逻辑“0”，“脉冲爆发到间隔”表示逻辑“1”。

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 之前编码方式和其他特殊方式的组合**

> [!TIP]
> 有些红外协议**试图成为多种设备的通用协议**。最著名的有RC5和NEC。不幸的是，最著名**并不意味着最常见**。在我的环境中，我只遇到过两个NEC遥控器，而没有RC5的。
>
> 制造商喜欢使用自己独特的红外协议，即使在同一类设备（例如，电视盒）中也是如此。因此，不同公司的遥控器，有时甚至是同一公司的不同型号，无法与同类设备配合使用。

### Exploring an IR signal

查看遥控器红外信号的最可靠方法是使用示波器。它不会解调或反转接收到的信号，而是“原样”显示。这对于测试和调试非常有用。我将以NEC红外协议为例展示预期信号。

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

通常，编码数据包的开头有一个前导码。这使接收器能够确定增益和背景水平。也有没有前导码的协议，例如Sharp。

然后传输数据。结构、前导码和位编码方法由特定协议确定。

**NEC红外协议**包含一个短命令和一个重复代码，在按下按钮时发送。命令和重复代码在开头都有相同的前导码。

NEC **命令**除了前导码外，还由一个地址字节和一个命令编号字节组成，设备通过这些字节理解需要执行的操作。地址和命令编号字节用反向值进行重复，以检查传输的完整性。命令末尾有一个额外的停止位。

**重复代码**在前导码后有一个“1”，这是一个停止位。

对于**逻辑“0”和“1”**，NEC使用脉冲间距编码：首先传输一个脉冲爆发，然后是一个暂停，其长度设置位的值。

### Air Conditioners

与其他遥控器不同，**空调不仅仅传输按下按钮的代码**。它们还**在按下按钮时传输所有信息**，以确保**空调和遥控器同步**。\
这将避免将设置为20ºC的机器用一个遥控器增加到21ºC，然后当使用另一个仍将温度保持在20ºC的遥控器进一步增加温度时，它会“增加”到21ºC（而不是22ºC，认为它在21ºC）。

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

您可以使用Flipper Zero攻击红外：

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

最近的学术研究（EvilScreen，2022）表明，**结合红外与蓝牙或Wi-Fi的多通道遥控器可以被滥用以完全劫持现代智能电视**。该攻击链将高权限的红外服务代码与经过身份验证的蓝牙数据包结合在一起，绕过通道隔离，允许任意应用程序启动、麦克风激活或在没有物理访问的情况下恢复出厂设置。来自不同供应商的八款主流电视——包括声称符合ISO/IEC 27001标准的三星型号——被确认存在漏洞。缓解措施需要供应商的固件修复或完全禁用未使用的红外接收器。

### Air-Gapped Data Exfiltration via IR LEDs (aIR-Jumper family)

安全摄像头、路由器甚至恶意USB闪存驱动器通常包括**夜视红外LED**。研究表明，恶意软件可以调制这些LED（<10–20 kbit/s，使用简单的OOK）以**通过墙壁和窗户泄露秘密**到放置在数十米外的外部摄像头。由于光线在可见光谱之外，操作员很少注意到。对策：

* 在敏感区域物理屏蔽或移除红外LED
* 监控摄像头LED的占空比和固件完整性
* 在窗户和监控摄像头上部署红外切割滤光片

攻击者还可以使用强大的红外投影仪通过闪烁数据向不安全的摄像头**渗透**命令。

### Long-Range Brute-Force & Extended Protocols with Flipper Zero 1.0

固件1.0（2024年9月）增加了**数十种额外的红外协议和可选的外部放大模块**。结合通用遥控器的暴力破解模式，Flipper可以在高功率二极管的帮助下，从最多30米的距离禁用或重新配置大多数公共电视/空调。

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – 便携式收发器，具有学习、重放和字典暴力破解模式（见上文）。
* **Arduino / ESP32** + 红外LED / TSOP38xx接收器 – 便宜的DIY分析仪/发射器。与`Arduino-IRremote`库结合使用（v4.x支持>40种协议）。
* **逻辑分析仪**（Saleae/FX2） – 在协议未知时捕获原始时序。
* **带红外发射器的智能手机**（例如，小米） – 快速现场测试，但范围有限。

### Software

* **`Arduino-IRremote`** – 积极维护的C++库：
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI解码器，导入原始捕获并自动识别协议 + 生成Pronto/Arduino代码。
* **LIRC / ir-keytable (Linux)** – 从命令行接收和注入红外：
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* 在不需要时禁用或覆盖公共场所部署的设备上的红外接收器。
* 强制智能电视和遥控器之间的*配对*或加密检查；隔离特权“服务”代码。
* 在机密区域周围部署红外切割滤光片或连续波探测器，以打破光学隐蔽通道。
* 监控暴露可控红外LED的摄像头/物联网设备的固件完整性。

## References

- [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- EvilScreen: Smart TV hijacking via remote control mimicry (arXiv 2210.03014)

{{#include ../../banners/hacktricks-training.md}}
