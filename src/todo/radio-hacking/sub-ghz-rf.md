# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## 车库门

车库门遥控器使用多个因地区和产品而异的 Sub-GHz 频段分配。常见频率包括 300、310、315、390 和 433.92 MHz，但并不存在通用的“300–190 MHz”车库门频段。在发射信号前，应确认目标设备的标签、监管区域以及观测到的信号。<sup>[[1]](#references)</sup>

## 车门

许多汽车钥匙遥控器使用 **315 MHz 或 433.92 MHz**，具体选择取决于地区规定和车辆设计。频率本身并不意味着 433 MHz 的传输距离比 315 MHz 更远：发射功率、天线效率、调制方式、接收器灵敏度、传播条件以及当地法规都会产生影响。欧洲通常使用 433.92 MHz，而北美和日本通常使用 315 MHz。<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

在演示的 fixed-code 系统中，每个 code 只发送一次而不是五次，可将预计时间缩短至六分钟：

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

移除信号之间 2 ms 的等待时间后，该演示所需时间可缩短至约三分钟。

使用 De Bruijn sequence 重叠候选 bit string，并且接收器能够接受连续 sequence、无需 preamble 或 frame reset 时，可将演示中的攻击缩短至约八秒。<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame 针对兼容的 fixed-code 系统实现了此攻击。<sup>[[5]](#references)</sup>

要求 **preamble 将避免 De Bruijn Sequence** 优化，而 **rolling codes 将阻止此攻击**（前提是 code 足够长，无法通过 bruteforce 破解）。

## Sub-GHz Attack

要使用 Flipper Zero 攻击这些信号，请检查：


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

自动车库门开启器通常使用 wireless remote control 来打开和关闭车库门。remote control 会向车库门开启器**发送 radio frequency (RF) signal**，后者会启动电机来打开或关闭车门。

攻击者可以使用一种称为 code grabber 的设备拦截 RF signal，并将其记录下来以供之后使用。这称为 **replay attack**。为了防止此类攻击，许多现代车库门开启器使用一种更安全的 encryption method，即 **rolling code** 系统。

**RF signal 通常使用 rolling code 进行传输**，这意味着 code 会在每次使用时发生变化。这使攻击者很难**拦截** signal 并利用它获得车库的**未授权**访问权限。

在 rolling code 系统中，remote control 和车库门开启器拥有一个**共享算法**，每次使用 remote 时都会**生成新的 code**。车库门开启器只会响应**正确的 code**，因此攻击者仅通过捕获 code 来获得车库的未授权访问会困难得多。

### **Missing Link Attack**

基本上，你需要监听按钮操作，并在 remote 超出设备（例如汽车或车库）的范围时**捕获 signal**。然后移动到设备附近，并**使用捕获的 code 将其打开**。<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> 在许多司法管辖区，故意制造 RF interference 都是违法行为，并且可能干扰与安全相关的系统。只能在具有屏蔽条件并获得授权的实验室中，依据适用的 radio regulations 执行 jamming 测试。<sup>[[6]](#references)</sup>

攻击者可以**在车辆或接收器附近对 signal 进行 jam**，使接收器无法 decode code，同时单独捕获被阻断的 transmission；然后停止 jamming，并 replay 捕获的 code。<sup>[[2]](#references)</sup>

受害者最终会使用**钥匙锁车**，但此时攻击者已经**记录了足够多的“close door” codes**，希望能够重新发送这些 code 来打开车门（可能需要**更改 frequency**，因为有些车辆使用相同的 codes 来开门和关门，但会在不同 frequency 上监听这两个命令）。

> [!WARNING]
> **Jamming 有效**，但很容易被察觉：如果锁车的人只是**测试车门**以确认车门已锁，他们就会发现车门仍处于解锁状态。此外，如果他们了解这类攻击，甚至可能注意到按下“lock”按钮后，车门从未发出锁定**声音**，或者车辆的**灯光**从未闪烁。

### **Code Grabbing Attack ( aka ‘RollJam’ )**

这是一种更**隐蔽的 Jamming technique**。攻击者会对 signal 进行 jam，因此受害者尝试锁门时不会成功，但攻击者会**记录该 code**。随后，受害者会再次按下按钮**尝试锁车**，而车辆会**记录第二个 code**。<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
紧接着，**攻击者可以发送第一个 code**，车辆就会**锁定**（受害者会以为是第二次按键使车辆锁定）。之后，攻击者便能够**发送第二个被窃取的 code 来打开**车辆（前提是**“close car” code 也能用于开车门**）。可能需要更改 frequency（因为有些车辆使用相同的 codes 来开门和关门，但会在不同 frequency 上监听这两个命令）。

一种 RollJam 实现利用了接收器带宽：jammer 在距离 remote carrier 足够近的位置进行 transmission，使车辆带宽更宽的接收器失去灵敏度；与此同时，攻击者带宽更窄的接收器仍保持在 remote 的中心 frequency 上，因此仍然可以记录 signal。具体的 offset 和 bandwidth 取决于目标硬件。<sup>[[2]](#references)</sup>

> [!WARNING]
> 规范中还出现过其他实现方式，其中 **rolling code 只是所发送完整 code 的一部分**。例如，发送的 code 是一个 **24 bit key**，其中前 **12 bit 是 rolling code**，接下来的 **8 bit 是 command**（例如 lock 或 unlock），最后 4 bit 是 **checksum**。实现此类机制的车辆同样容易受到攻击，因为攻击者只需替换 rolling code 部分，就能在两个 frequency 上**使用任意 rolling code**。

> [!CAUTION]
> 请注意，如果受害者在攻击者发送第一个 code 时发送了第三个 code，则第一个和第二个 code 都会失效。

### Alarm Sounding Jamming Attack

针对安装在汽车上的 aftermarket rolling code 系统进行测试时，**连续两次发送相同的 code** 会立即**触发 alarm** 和 immobiliser，从而提供一个独特的 **denial of service** 机会。具有讽刺意味的是，**禁用 alarm** 和 immobiliser 的方式是**按下** remote，这使攻击者能够**持续执行 DoS attack**。也可以将此攻击与**前一种攻击**结合，以获取更多 codes，因为受害者会希望尽快停止攻击。<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero documentation - regional Sub-GHz frequencies](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [绕过 Rolling Code 系统 - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23：像破解过一样驾驶（OpenSesame）](https://samy.pl/defcon2015/)
- [4] [如何 Hack 汽车 - 使用 YARD Stick One / RTL-SDR 重现 RollJam](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame 源代码](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - Jammer Enforcement](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
