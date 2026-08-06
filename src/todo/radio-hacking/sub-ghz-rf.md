# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## 车库门

车库门开启器通常工作在 300-190 MHz 频段，最常见的频率为 300 MHz、310 MHz、315 MHz 和 390 MHz。车库门开启器通常使用这一频段，是因为该频段相比其他频段更加空闲，也不太容易受到其他设备的干扰。

## 车门

大多数汽车钥匙遥控器工作在 **315 MHz 或 433 MHz**。这两者都是无线电频率，并用于各种不同的应用。两种频率之间的主要区别是，433 MHz 的传输距离比 315 MHz 更远。这意味着 433 MHz 更适合需要较远传输距离的应用，例如远程无钥匙进入。\
在欧洲通常使用 433.92MHz，而在美国和日本则使用 315MHz。<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

如果不再将每个 code 发送 5 次（之所以这样发送，是为了确保接收器能够收到），而是只发送一次，时间就会缩短至 6 分钟：

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

如果**移除信号之间 2 ms 的等待**时间，还可以**将时间缩短至 3 分钟。**

此外，通过使用 De Bruijn Sequence（一种减少发送所有潜在二进制数所需位数的方法，以执行 burteforce），这一**时间可以进一步缩短至仅 8 秒**：<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

该攻击的一个示例已在 [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) 中实现。

要求存在 **preamble 将避免 De Bruijn Sequence** 优化，而 **rolling codes 将阻止该攻击**（假设 code 足够长，不可能被 bruteforce）。

## Sub-GHz Attack

要使用 Flipper Zero 攻击这些信号，请查看：


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

自动车库门开启器通常使用无线遥控器打开和关闭车库门。遥控器向车库门开启器**发送无线电频率（RF）信号**，从而激活电机打开或关闭车库门。

攻击者可以使用一种称为 code grabber 的设备拦截 RF 信号，并将其记录下来以供之后使用。这称为 **replay attack**。为了防止此类攻击，许多现代车库门开启器使用一种更安全的加密方法，称为 **rolling code** 系统。

**RF 信号通常使用 rolling code 进行传输**，这意味着 code 会在每次使用时发生变化。这使攻击者很难**拦截**信号并利用它获得车库的**未授权**访问权限。

在 rolling code 系统中，遥控器和车库门开启器具有一个**共享算法**，每次使用遥控器时都会**生成一个新的 code**。车库门开启器只会响应**正确的 code**，因此攻击者仅通过捕获 code 来获得车库的未授权访问权限会困难得多。

### **Missing Link Attack**

基本上，你需要监听按钮操作，并在遥控器位于设备（例如汽车或车库）**信号范围之外时捕获信号**。然后移动到设备附近，**使用捕获的 code 将其打开**。<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

攻击者可以在车辆或接收**器**附近**干扰信号**，使**接收器实际上无法“听到”code**；一旦发生这种情况，你只需在停止干扰后**捕获并重放**该 code。<sup>[[2]](#references)</sup>

受害者最终会使用**钥匙锁车**，但此时攻击者已经**记录了足够多的“关闭车门”code**，之后可能可以重新发送这些 code 来打开车门（可能需要**更换频率**，因为有些汽车使用相同的 code 执行开门和关门操作，但会在不同频率上监听这两个命令）。

> [!WARNING]
> **Jamming 有效**，但很容易被察觉：如果锁车的人只是测试车门以确认车门已锁，他们就会发现车门仍处于解锁状态。此外，如果他们了解这类攻击，甚至可能注意到按下“锁定”按钮时车门始终没有发出上锁**声音**，或者汽车的**灯光**没有闪烁。

### **Code Grabbing Attack ( aka ‘RollJam’ )**

这是一种更加**隐蔽的 Jamming 技术**。攻击者会干扰信号，因此受害者尝试锁门时不会成功，但攻击者会**记录该 code**。随后，受害者会再次按下按钮**尝试锁车**，汽车会**记录第二个 code**。<sup>[[2]](#references)[[4]](#references)</sup>\
紧接着，**攻击者可以发送第一个 code**，汽车便会**锁上**（受害者会认为是第二次按键将车锁上）。然后，攻击者可以**发送第二个被窃取的 code 来打开**汽车（假设**“关闭汽车”code 也可用于打开汽车**）。可能需要更换频率（因为有些汽车使用相同的 code 执行开门和关门操作，但会在不同频率上监听这两个命令）。

攻击者可以**干扰汽车接收器而不干扰自己的接收器**，因为如果汽车接收器正在监听例如 1MHz 的宽带，攻击者就不会**干扰**遥控器使用的精确频率，而是干扰该频谱中**相邻的频率**；与此同时，**攻击者的接收器会在更小的范围内监听**，从而能够在没有干扰信号的情况下监听遥控器信号。

> [!WARNING]
> 规范中出现的其他实现表明，**rolling code 只是所发送完整 code 的一部分**。例如，发送的 code 是一个 **24 位 key**，其中前 **12 位是 rolling code**，接下来 **8 位是 command**（例如锁定或解锁），最后 4 位是 **checksum**。实现了这种机制的车辆也天然容易受到攻击，因为攻击者只需要替换 rolling code 部分，就能够在**两个频率上使用任意 rolling code**。

> [!CAUTION]
> 注意，如果受害者在攻击者发送第一个 code 时发送了第三个 code，那么第一个和第二个 code 都会失效。

### Alarm Sounding Jamming Attack

在对安装于汽车上的 aftermarket rolling code 系统进行测试时，**连续发送两次相同的 code** 会立即**激活 alarm 和 immobiliser**，从而提供一个独特的**拒绝服务**机会。具有讽刺意味的是，**禁用 alarm** 和 immobiliser 的方法是**按下**遥控器，这使攻击者能够**持续执行 DoS attack**。也可以将此攻击与**前一种攻击**结合，以获取更多 code，因为受害者会希望尽快停止攻击。<sup>[[2]](#references)</sup>

## References

- [1] [汽车钥匙遥控器使用什么无线电频率？](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [绕过 Rolling Code 系统 - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23：像被你 Hacked 的那样驾驶（OpenSesame）](https://samy.pl/defcon2015/)
- [4] [如何 Hack 汽车 - 使用 YARD Stick One / RTL-SDR 重现 RollJam](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
