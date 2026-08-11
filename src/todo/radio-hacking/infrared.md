# 红外

{{#include ../../banners/hacktricks-training.md}}

## 红外的工作原理 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**红外光对人类不可见**。IR 波长范围为 **0.7 至 1000 微米**。家用遥控器使用 IR 信号传输数据，工作波长范围为 0.75..1.4 微米。遥控器中的微控制器使红外 LED 以特定频率闪烁，将数字信号转换为 IR 信号。

接收 IR 信号需要使用**光电接收器**。它会**将 IR 光转换为电压脉冲**，而这些已经是**数字信号**。通常，接收器内部有一个**暗光滤光器**，只允许**所需波长通过**并滤除噪声。<sup>[[1]](#references)</sup>

### IR 协议的多样性 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR 协议在 3 个因素上有所不同：<sup>[[1]](#references)</sup>

- 比特编码
- 数据结构
- 载波频率 — 通常范围为 36..38 kHz

#### 比特编码方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 脉冲距离编码**

通过调制脉冲之间空闲间隔的持续时间来编码比特。脉冲本身的宽度保持不变。

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. 脉冲宽度编码**

通过调制脉冲宽度来编码比特。脉冲串之后的空闲间隔宽度保持不变。

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. 相位编码**

它也称为 Manchester 编码。逻辑值由脉冲串与空闲间隔之间转换的极性决定。“空闲间隔到脉冲串”表示逻辑“0”，“脉冲串到空闲间隔”表示逻辑“1”。

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 前述方式的组合及其他特殊方式**

> [!TIP]
> 有些 IR 协议**试图在多种设备类型之间实现通用**。其中最著名的是 RC5 和 NEC。遗憾的是，**最著名并不意味着最常见**。在我的使用环境中，我只遇到过两个 NEC 遥控器，没有遇到 RC5 遥控器。
>
> 制造商喜欢使用自有的独特 IR 协议，即使是在同一类设备中也是如此（例如电视盒）。因此，不同公司的遥控器，有时甚至同一公司不同型号的遥控器，也无法控制其他同类型设备。

### 探索 IR 信号

观察遥控器 IR 信号形态最可靠的方法是使用示波器。它不会对接收到的信号进行解调或反相，而是将信号“原样”显示出来。这对于测试和调试很有用。下面将以 NEC IR 协议为例展示预期信号。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

通常，编码数据包的开头会有一个前导码。这使接收器能够确定增益水平和背景。也有不带前导码的协议，例如 Sharp。

随后会传输数据。数据结构、前导码和比特编码方式由具体协议决定。

**NEC IR 协议**包含一个短命令和一个重复码，按钮按住期间会发送重复码。命令和重复码的开头具有相同的前导码。

NEC **命令**除前导码外，还由一个地址字节和一个命令编号字节组成，设备通过它们了解需要执行的操作。地址字节和命令编号字节会以反相值重复发送，用于检查传输完整性。命令末尾还有一个额外的停止位。

**重复码**在前导码之后包含一个“1”，该位就是停止位。

对于**逻辑“0”和“1”**，NEC 使用脉冲距离编码：首先传输一个脉冲串，之后是一个暂停，其长度决定比特的值。

### 空调

与其他遥控器不同，**空调不会只传输被按下按钮的代码**。它们还会在按钮按下时**传输全部信息**，以确保**空调设备与遥控器保持同步**。\
这样可以避免以下情况：一台设置为 20ºC 的空调通过一个遥控器被调高到 21ºC，随后使用另一个仍显示 20ºC 的遥控器继续调高温度时，它会将温度“调高”到 21ºC（而不是认为当前为 21ºC 并调高到 22ºC）。<sup>[[1]](#references)</sup>

---

## 攻击与 Offensive Research <a href="#attacks" id="attacks"></a>

你可以使用 Flipper Zero 攻击红外：


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / 机顶盒接管（EvilScreen）

近期的学术研究（EvilScreen，2022）表明，**将红外与 Bluetooth 或 Wi-Fi 结合的多通道遥控器可能被滥用，从而完全劫持现代 Smart-TV**。该攻击将高权限 IR 服务代码与经过身份验证的 Bluetooth 数据包串联起来，绕过通道隔离，并允许在无物理访问的情况下任意启动应用、激活麦克风或执行恢复出厂设置。研究确认，来自不同厂商的八款主流电视存在漏洞，其中包括一款声称符合 ISO/IEC 27001 的 Samsung 型号。缓解措施需要厂商修复固件，或完全禁用未使用的 IR 接收器。<sup>[[2]](#references)</sup>

### 通过 IR LED 对 Air-Gapped 网络进行数据外泄（aIR-Jumper family）

安全摄像头通常包含**夜视 IR LED**。aIR-Jumper 原型表明，控制这些 LED 的 malware 可以通过窗户向外部摄像头**外泄机密信息**，在数十米距离上达到**每台监控摄像头最高 20 bit/s**。在反向方向上，研究人员展示了超过 **100 bit/s** 的 infiltration，距离从数百米到数公里不等。<sup>[[3]](#references)</sup>由于这种光线处于可见光谱之外，操作人员可能不会注意到。对策包括：

* 在敏感区域对 IR LED 进行物理遮蔽或拆除
* 监控摄像头 LED 的占空比和固件完整性
* 在窗户和监控摄像头上部署 IR-cut 滤光片

攻击者还可以使用高功率 IR 投影器，通过向不安全的摄像头闪烁数据，将命令 **infiltrate** 到网络中。

### 使用 Flipper Zero 1.0 进行远距离 Brute-Force 与扩展协议操作

Firmware 1.0（2024 年 9 月）扩展了 universal-remotes 库，并增加了从 microSD 动态加载红外 asset 文件的功能。<sup>[[4]](#references)</sup>它的学习和 universal-remote 功能可以针对附近的电视和空调重放或尝试已知命令。传输距离高度取决于发射器、光学器件、环境光和接收器；外部 IR 硬件可以扩大范围，但不应假设存在固定距离。

---

## 工具与实践示例 <a href="#tooling" id="tooling"></a>

### 硬件

* **Flipper Zero** – 支持学习、重放和 dictionary-bruteforce 模式的便携式收发器（见上文）。
* **Arduino / ESP32** + IR LED / TSOP38xx 接收器 – 廉价的 DIY 分析器/发射器。可与 `Arduino-IRremote` 库结合使用（v4.x 支持超过 40 种协议）。
* **Logic analysers**（Saleae/FX2）– 在协议未知时捕获原始时序。
* **带 IR-blaster 的智能手机**（例如 Xiaomi）– 可用于快速现场测试，但范围有限。

### 软件

* **`Arduino-IRremote`** – actively maintained 的 C++ 库：<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI 解码器，可导入原始捕获数据并自动识别协议，同时生成 Pronto/Arduino 代码。
* **LIRC / ir-keytable (Linux)** – 从命令行接收和注入 IR：
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## 防御措施 <a href="#defense" id="defense"></a>

* 不需要时，禁用或遮盖部署在公共场所设备上的 IR 接收器。
* 在 Smart-TV 与遥控器之间强制执行 *pairing* 或加密检查；隔离具有特权的“service”代码。
* 在机密区域周围部署 IR-cut 滤光片或连续波检测器，以阻断光学 covert channel。
* 监控暴露可控 IR LED 的摄像头/IoT 设备的固件完整性。

## References

- [1] [Flipper Zero 红外博客文章](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen 攻击：通过多通道遥控器仿冒劫持 Smart TV（arXiv:2210.03014）](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper：通过安全摄像头与红外进行 Covert Air-Gap 数据外泄/渗透（IR）（arXiv:1709.05742）](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero 博客 - Firmware 1.0 发布](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - 用法与协议文档](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
