# 红外

{{#include ../../banners/hacktricks-training.md}}

## 红外的工作原理 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**红外光对人眼不可见**。红外波长范围为 **0.7 到 1000 微米**。家用遥控器使用红外信号传输数据，工作波长范围为 0.75..1.4 微米。遥控器中的微控制器会让红外 LED 按特定频率闪烁，将数字信号转换为红外信号。

接收红外信号时会使用**光接收器**。它会**将红外光转换为电压脉冲**，而这些脉冲已经是**数字信号**。接收器内部通常有一个**暗色滤光片**，可让**只有所需波长的光通过**，并滤除噪声。<sup>[[1]](#references)</sup>

### 红外协议的种类 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

红外协议在以下 3 个方面存在差异：<sup>[[1]](#references)</sup>

- 位编码
- 数据结构
- 载波频率 — 通常在 36..38 kHz 范围内

#### 位编码方式 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 脉冲间隔编码**

通过调制脉冲之间间隔的时长来编码比特。脉冲本身的宽度保持不变。

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. 脉冲宽度编码**

通过调制脉冲宽度来编码比特。脉冲串之后的间隔宽度保持不变。

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. 相位编码**

这种编码也称为 Manchester 编码。逻辑值由脉冲串与间隔之间跃迁的极性决定。“间隔到脉冲串”表示逻辑“0”，“脉冲串到间隔”表示逻辑“1”。

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 上述方式的组合以及其他特殊方式**

> [!TIP]
> 有些红外协议**试图适用于多种设备**。其中最著名的是 RC5 和 NEC。遗憾的是，**最著名并不意味着最常见**。在我的使用环境中，我只遇到过两个 NEC 遥控器，没有遇到过 RC5 遥控器。
>
> 制造商喜欢使用自己独有的红外协议，即使是同一类设备（例如电视盒）也不例外。因此，不同公司的遥控器，有时甚至同一家公司不同型号的遥控器，都无法控制其他同类设备。

### 探测红外信号

要观察遥控器红外信号的波形，最可靠的方法是使用示波器。示波器不会对接收到的信号进行解调或反相，而是直接显示信号的“原始”样子。这对于测试和调试很有用。下面以 NEC 红外协议为例，展示预期信号。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

编码数据包的开头通常有一个前导码。这让接收器能够确定增益和背景信号电平。有些协议没有前导码，例如 Sharp。

随后会传输数据。数据结构、前导码和位编码方式由具体协议决定。

**NEC 红外协议**包含一条短命令和一个重复码；按住按钮时会发送重复码。命令和重复码开头都有相同的前导码。

除了前导码之外，NEC **命令**还包含一个地址字节和一个命令编号字节，设备据此确定要执行的操作。地址字节和命令编号字节都会以反码重复发送，以检查传输完整性。命令末尾还有一个额外的停止位。

**重复码**在前导码后包含一个“1”，它就是停止位。

对于**逻辑“0”和“1”**，NEC 使用脉冲间隔编码：先发送一个脉冲串，然后是一个暂停，其长度决定比特值。

### 空调

与其他遥控器不同，**空调遥控器传输的不只是被按下按钮的代码**。按下按钮时，它还会**传输所有信息**，以确保**空调和遥控器保持同步**。\
这样可以避免空调设定为 20ºC 时，用一个遥控器将温度调高到 21ºC 后，再使用一个温度仍设为 20ºC 的遥控器继续调高温度时，空调将温度“调高”到 21ºC（而不是误以为当前是 21ºC，再调到 22ºC）。<sup>[[1]](#references)</sup>

---

## 攻击与攻防研究 <a href="#attacks" id="attacks"></a>

可以使用 Flipper Zero 攻击红外设备：


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / 机顶盒接管（EvilScreen）

近期的一项学术研究（EvilScreen，2022）表明，**结合红外与 Bluetooth 或 Wi-Fi 的多通道遥控器可被滥用，从而完全劫持现代 smart-TV**。该攻击将高权限红外服务代码与经过身份验证的 Bluetooth 数据包串联起来，绕过通道隔离，并允许攻击者在无需物理接触设备的情况下启动任意应用、激活麦克风或恢复出厂设置。研究确认，来自不同厂商的八款主流电视存在漏洞，其中包括一款声称符合 ISO/IEC 27001 标准的 Samsung 机型。缓解措施包括由厂商修复固件，或彻底禁用未使用的红外接收器。<sup>[[2]](#references)</sup>

### 通过红外 LED 实现隔离网络数据外传（aIR-Jumper 系列）

监控摄像头通常配有**夜视红外 LED**。aIR-Jumper 原型表明，控制这些 LED 的恶意软件可以通过窗户将秘密**外传**至外部摄像头，在数十米范围内实现每台监控摄像头最高 **20 bit/s** 的传输速率。反向来看，研究人员还演示了以超过 **100 bit/s** 的速率，在数百米至数千米的距离内向内渗透。<sup>[[3]](#references)</sup>由于这种光不在可见光谱内，操作人员可能不会察觉。防护措施包括：

* 在敏感区域物理遮挡或移除红外 LED
* 监控摄像头 LED 的占空比和固件完整性
* 在窗户和监控摄像头上安装红外截止滤光片

攻击者也可以使用高功率红外投影器，通过向不安全的摄像头闪烁数据，将命令**注入**网络。 

### 使用 Flipper Zero 1.0 进行远距离暴力破解与扩展协议攻击

固件 1.0（2024 年 9 月）扩展了通用遥控器库，并增加了从 microSD 动态加载红外资源文件的功能。<sup>[[4]](#references)</sup>它的学习和通用遥控功能可以重放或尝试对附近电视和空调发送已知命令。作用距离很大程度上取决于发射器、光学器件、环境光和接收器；外接红外硬件可以延长作用距离，但不应假定固定距离。

---

## 工具与实用示例 <a href="#tooling" id="tooling"></a>

### 硬件

* **Flipper Zero** – 便携式收发器，支持学习、重放和字典暴力破解模式（见上文）。
* **Arduino / ESP32** + 红外 LED / TSOP38xx 接收器 – 价格低廉的 DIY 分析器/发射器。可搭配 `Arduino-IRremote` 库使用（v4.x 支持超过 40 种协议）。
* **逻辑分析仪**（Saleae/FX2）– 协议未知时，用于捕获原始时序。
* **带红外发射器的智能手机**（例如 Xiaomi）– 可快速进行现场测试，但作用距离有限。

### 软件

* **`Arduino-IRremote`** – 持续维护的 C++ 库：<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – GUI 解码器，可导入原始捕获数据、自动识别协议并生成 Pronto/Arduino 代码。
* **LIRC / ir-keytable (Linux)** – 从命令行接收和注入 IR：
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## 防御措施 <a href="#defense" id="defense"></a>

* 在公共区域部署的设备上，如果不需要使用红外接收器，请将其禁用或遮盖。
* 在智能电视和遥控器之间强制执行*配对*或加密检查；隔离特权“服务”代码。
* 在机密区域周围部署红外截止滤光片或连续波探测器，以阻断光学隐蔽信道。
* 监控摄像头/IoT 设备的固件完整性，尤其是那些暴露可控红外 LED 的设备。

## References

- [1] [Flipper Zero 红外博客文章](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen 攻击：通过多频道遥控器仿冒劫持智能电视 (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper：通过安全摄像头和红外线 (IR) 进行隐蔽的气隙数据窃取/渗入 (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero 博客 - 固件 1.0 发布](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - 用法和协议文档](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
