# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## 车库门

车库门遥控器使用因地区和产品而异的 Sub-GHz 频段。常见频率包括 300、310、315、390 和 433.92 MHz，但不存在通用的“300–190 MHz”车库门频段。在发射信号前，请先确认目标设备的标签、监管区域和观测到的信号。<sup>[[1]](#references)</sup>

## 车门

许多汽车钥匙遥控器使用 **315 MHz 或 433.92 MHz**，具体频率取决于地区法规和车辆设计。仅凭频率，不能断定 433 MHz 的通信距离比 315 MHz 更远：发射功率、天线效率、调制方式、接收器灵敏度、传播条件和当地法规都会产生影响。欧洲常用 433.92 MHz，而北美和日本常用 315 MHz。<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

在演示的固定码系统中，每个代码只发送一次而不是五次，可将预计耗时缩短至六分钟：

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

移除信号之间 2 ms 的等待时间，可将该演示耗时缩短至约三分钟。

使用 De Bruijn 序列重叠候选位串，在接收器能够接受连续序列且不要求前导码或帧重置的情况下，可将演示中的攻击耗时缩短至约八秒。<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame 可针对兼容的固定码系统实施此攻击。<sup>[[5]](#references)</sup>

要求使用**前导码可避免 De Bruijn Sequence** 优化，而 **rolling codes 会阻止此攻击**（前提是代码足够长，无法通过暴力破解获得）。

## Sub-GHz Attack

要使用 Flipper Zero 攻击这些信号，请查看：


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

自动车库门开启器通常使用无线遥控器来打开和关闭车库门。遥控器会向车库门开启器**发送射频 (RF) 信号**，从而启动电机打开或关闭车库门。

攻击者可以使用一种称为 code grabber 的设备拦截 RF 信号并录制下来，以供之后使用。这称为 **replay attack**。为了防止此类攻击，许多现代车库门开启器采用更安全的加密方式，即 **rolling code** 系统。

**RF 信号通常使用 rolling code 进行传输**，也就是说，代码每次使用都会变化。这使攻击者难以**拦截**信号并**利用**它来获得对车库的**未授权**访问。

在 rolling code 系统中，遥控器和车库门开启器使用**共享算法**，每次使用遥控器时都会**生成新代码**。车库门开启器只会响应**正确的代码**，因此攻击者仅靠捕获代码来获得对车库的未授权访问会困难得多。

### **Missing Link Attack**

基本做法是监听按钮操作，并在遥控器不在设备（例如汽车或车库）通信范围内时**捕获信号**。然后移动到设备附近，**使用捕获的代码将其打开**。<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> 在许多司法辖区，故意干扰 RF 信号属于违法行为，并可能影响与安全相关的系统。只能在屏蔽且经过授权的实验室内，并遵守适用的无线电法规进行干扰测试。<sup>[[6]](#references)</sup>

攻击者可以在车辆或接收器附近**干扰信号**，使接收器无法解码代码，同时单独捕获被阻断的传输；随后停止干扰，并重放捕获的代码。<sup>[[2]](#references)</sup>

受害者之后某个时刻会使用**钥匙锁车**，但攻击已经**记录了足够多的“关门”代码**，这些代码或许可以重新发送以开门（可能需要**切换频率**，因为有些汽车使用相同的代码开锁和闭锁，但会在不同频率上监听这两种指令）。

> [!WARNING]
> **干扰确实有效**，但很容易被发现：如果**锁车的人只是拉一下车门确认是否锁好**，就会发现车门没锁。此外，如果他们了解这类攻击，甚至可能会留意到按下“lock”按钮时，车门没有发出锁车**声音**，或者车灯没有闪烁。

### **Code Grabbing Attack ( aka ‘RollJam’ )**

这是一种更**隐蔽的 jamming 技术**。攻击者会干扰信号，因此受害者尝试锁车时不会成功，但攻击者会**录下这个代码**。随后，受害者会再次按下按钮尝试**锁车**，汽车则会**记录第二个代码**。<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
紧接着，**攻击者可以发送第一个代码**，汽车便会**上锁**（受害者会以为是第二次按键锁上了车）。然后，攻击者就能**发送第二个被盗代码来打开汽车**（前提是**“锁车”代码也能用于开锁**）。可能需要切换频率（因为有些汽车使用相同的代码开锁和闭锁，但会在不同频率上监听这两种指令）。

一种 RollJam 实现利用了接收器带宽的差异：干扰器在足够靠近遥控器载波频率的位置发射信号，使车辆较宽带的接收器失敏；与此同时，攻击者较窄带的接收器仍对准遥控器信号，因此仍能将其录下。具体的频偏和带宽取决于目标硬件。<sup>[[2]](#references)</sup>

> [!WARNING]
> 规范中提到的其他实现表明，**rolling code 只是所发送完整代码的一部分**。例如，发送的代码是一个 **24 位密钥**，其中前 **12 位是 rolling code**，接下来的 **8 位是指令**（例如锁车或开锁），最后 4 位是**校验和**。采用这种设计的车辆也容易受到攻击，因为攻击者只需替换 rolling code 部分，就能在**两个频率上使用任意 rolling code**。

> [!CAUTION]
> 请注意，如果攻击者发送第一个代码时，受害者又发送了第三个代码，那么第一个和第二个代码都会失效。

### Alarm Sounding Jamming Attack

在一辆安装了售后 rolling code 系统的汽车上进行测试时，**立即将同一个代码发送两次**会触发警报和防盗锁止系统，从而造成一种独特的**拒绝服务**机会。讽刺的是，**解除警报**和防盗锁止系统的方法是按下遥控器，这使攻击者能够**持续发动 DoS attack**。也可以将此攻击与**前一种攻击结合起来以获取更多代码**，因为受害者会想尽快停止攻击。<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero 文档 - 各地区的 Sub-GHz 频率](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [绕过 Rolling Code 系统 - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23：像你刚入侵过一样驾驶（OpenSesame）](https://samy.pl/defcon2015/)
- [4] [如何黑入汽车 - 使用 YARD Stick One / RTL-SDR 重现 RollJam](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame 源代码](https://github.com/samyk/opensesame)
- [6] [FCC 执法公告 - 对干扰器的执法](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
