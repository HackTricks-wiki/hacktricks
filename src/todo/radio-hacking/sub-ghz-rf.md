# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## 车库门

车库门开启器通常工作在 300-190 MHz 频段，最常见的频率为 300 MHz、310 MHz、315 MHz 和 390 MHz。车库门开启器普遍使用这一频段，是因为它相比其他频段更加空闲，也不太容易受到其他设备的干扰。

## 车门

大多数汽车钥匙遥控器工作在 **315 MHz 或 433 MHz**。这两者都是无线电频率，可用于各种不同的应用。两种频率之间的主要区别是，433 MHz 的传输距离比 315 MHz 更远。这意味着 433 MHz 更适合需要较远传输距离的应用，例如 remote keyless entry。\
在欧洲通常使用 433.92MHz，而在美国和日本则使用 315MHz。<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

如果不再将每个 code 发送 5 次（之所以这样发送，是为了确保 receiver 能够收到），而是只发送一次，时间就会缩短到 6 分钟：

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

如果**移除信号之间 2 ms 的等待**时间，还可以**将时间缩短到 3 分钟。**

此外，通过使用 De Bruijn Sequence（一种减少发送所有潜在二进制数进行 burteforce 所需 bit 数量的方法），这个**时间可以缩短到仅 8 秒**：

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

该攻击的示例已在 [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)<sup>[[3]](#references)</sup> 中实现。

要求提供 **preamble 将避免 De Bruijn Sequence** 优化，而 **rolling codes 将阻止此攻击**（假设 code 足够长，无法被 bruteforce）。

## Sub-GHz Attack

要使用 Flipper Zero 攻击这些信号，请查看：


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

自动车库门开启器通常使用无线 remote control 来打开和关闭车库门。remote control 向车库门开启器**发送 radio frequency (RF) signal**，从而激活电机以打开或关闭车门。

攻击者可以使用一种称为 code grabber 的设备拦截 RF signal 并将其记录下来，以便稍后使用。这称为 **replay attack**。为了防止此类攻击，许多现代车库门开启器使用一种更安全的加密方式，即 **rolling code** 系统。

**RF signal 通常使用 rolling code 传输**，这意味着 code 会在每次使用时发生变化。这使得攻击者很难**拦截** signal 并**利用**它获得车库的**未授权**访问权限。

在 rolling code 系统中，remote control 和车库门开启器拥有一个**共享 algorithm**，每次使用 remote 时都会**生成新的 code**。车库门开启器只会响应**正确的 code**，因此攻击者仅通过捕获 code 来获得车库的未授权访问会困难得多。

### **Missing Link Attack**

基本上，你需要监听按钮，并在 remote 位于设备（例如汽车或车库）**范围之外时捕获 signal**。然后移动到设备附近，**使用捕获的 code 将其打开**。<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

攻击者可以在车辆或 receiver 附近**jam signal**，使 **receiver 实际上无法“听到”code**；在此期间，你只需在停止 jamming 后**捕获并 replay**该 code。

受害者之后某个时刻会使用**keys 锁车**，但攻击者已经**记录了足够多的“close door” codes**，希望可以重新发送这些 code 来打开车门（可能需要**更改 frequency**，因为有些汽车使用相同的 codes 来开门和关门，但会在不同的 frequency 上监听这两个 command）。

> [!WARNING]
> **Jamming 有效**，但很容易被察觉：如果**锁车的人简单地测试车门**以确认车门已锁，就会发现汽车仍处于解锁状态。此外，如果他们了解此类攻击，甚至可能注意到按下“lock”按钮时车门从未发出锁定**声音**，或者汽车的**灯光**从未闪烁。

### **Code Grabbing Attack ( aka ‘RollJam’ )**

这是一种更**隐蔽的 Jamming technique**。攻击者会 jam signal，因此受害者尝试锁门时不会成功，但攻击者会**记录该 code**。随后，受害者会再次按下按钮**尝试锁车**，汽车会**记录第二个 code**。\
紧接着，**攻击者可以发送第一个 code**，汽车将会锁上（受害者会以为是第二次按键将车锁上）。之后，攻击者可以**发送第二个被盗 code 来打开**汽车（假设 **“close car” code 也可以用于打开汽车**）。可能需要更改 frequency（因为有些汽车使用相同的 codes 来开门和关门，但会在不同的 frequency 上监听这两个 command）。<sup>[[3]](#references)[[2]](#references)</sup>

攻击者可以 **jam 汽车 receiver，而不 jam 自己的 receiver**：如果汽车 receiver 例如正在监听 1MHz broadband，攻击者就不会 **jam** remote 使用的精确 frequency，而是 jam 该 spectrum 中的**相近 frequency**；与此同时，**攻击者的 receiver 会监听更小的范围**，从而可以在没有 jam signal 的情况下监听 remote signal。

> [!WARNING]
> 规范中还可以看到其他实现方式，其中 **rolling code 只是完整 code 的一部分**。例如，发送的 code 是一个 **24 bit key**，其中前 **12 bit 是 rolling code**，接下来的 **8 bit 是 command**（例如 lock 或 unlock），最后 4 bit 是 **checksum**。实现这种方式的车辆也天然容易受到攻击，因为攻击者只需替换 rolling code 部分，就能在两个 frequency 上**使用任意 rolling code**。

> [!CAUTION]
> 注意，如果受害者在攻击者发送第一个 code 时发送了第三个 code，那么第一个和第二个 code 都会失效。

### Alarm Sounding Jamming Attack

在对安装于汽车上的 aftermarket rolling code 系统进行测试时，**连续两次发送相同的 code** 会立即**激活 alarm** 和 immobiliser，从而提供一个独特的 **denial of service** 机会。具有讽刺意味的是，**禁用 alarm** 和 immobiliser 的方式是**按下** remote，这使攻击者能够**持续执行 DoS attack**。或者，也可以将此攻击与**前一种攻击结合，以获取更多 codes**，因为受害者会希望尽快停止攻击。<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
