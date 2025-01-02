# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

车库门开启器通常在300-190 MHz范围内工作，最常见的频率为300 MHz、310 MHz、315 MHz和390 MHz。这个频率范围通常用于车库门开启器，因为它比其他频段更不拥挤，并且不太可能受到其他设备的干扰。

## Car Doors

大多数汽车钥匙遥控器在**315 MHz或433 MHz**上工作。这两者都是无线电频率，应用于多种不同的场合。这两种频率之间的主要区别是433 MHz的范围比315 MHz更长。这意味着433 MHz更适合需要更长范围的应用，例如远程无钥匙进入。\
在欧洲，433.92MHz是常用的，而在美国和日本则是315MHz。

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

如果不将每个代码发送5次（这样发送是为了确保接收器接收到），而只发送一次，时间将减少到6分钟：

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

如果**去掉信号之间的2毫秒等待**时间，你可以**将时间减少到3分钟。**

此外，通过使用De Bruijn序列（减少发送所有潜在二进制数字所需的位数的方法），这个**时间仅减少到8秒**：

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

此攻击的示例已在[https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)中实现。

要求**前导码将避免De Bruijn序列**优化，而**滚动代码将防止此攻击**（假设代码足够长，不易被暴力破解）。

## Sub-GHz Attack

要攻击这些信号，请检查Flipper Zero：

{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

自动车库门开启器通常使用无线遥控器来打开和关闭车库门。遥控器**发送无线电频率（RF）信号**到车库门开启器，激活电机以打开或关闭门。

有人可以使用称为代码抓取器的设备来拦截RF信号并记录以备后用。这被称为**重放攻击**。为了防止这种攻击，许多现代车库门开启器使用一种更安全的加密方法，称为**滚动代码**系统。

**RF信号通常使用滚动代码传输**，这意味着每次使用时代码都会变化。这使得**拦截**信号并**利用**它获得**未授权**访问车库变得**困难**。

在滚动代码系统中，遥控器和车库门开启器有一个**共享算法**，每次使用遥控器时**生成一个新代码**。车库门开启器只会对**正确代码**做出响应，这使得仅通过捕获代码就获得未授权访问车库变得更加困难。

### **Missing Link Attack**

基本上，你监听按钮并**在遥控器超出设备范围时捕获信号**（比如汽车或车库）。然后你移动到设备并**使用捕获的代码打开它**。

### Full Link Jamming Attack

攻击者可以**在车辆或接收器附近干扰信号**，使得**接收器无法真正“听到”代码**，一旦发生这种情况，你可以简单地**捕获并重放**代码，当你停止干扰时。

受害者在某个时刻会使用**钥匙锁定汽车**，但攻击者将**记录足够的“关门”代码**，希望能够重新发送以打开门（可能需要**更改频率**，因为有些汽车使用相同的代码来打开和关闭，但在不同频率下监听两个命令）。

> [!WARNING]
> **干扰有效**，但很明显，如果**锁车的人只是测试车门**以确保它们被锁上，他们会注意到汽车未锁。此外，如果他们意识到这种攻击，他们甚至可以听到车门在按下“锁定”按钮时从未发出锁定**声音**或汽车**灯光**在按下时从未闪烁。

### **Code Grabbing Attack ( aka ‘RollJam’ )**

这是一种更**隐蔽的干扰技术**。攻击者将干扰信号，因此当受害者尝试锁门时将无法工作，但攻击者会**记录此代码**。然后，受害者将**再次尝试锁定汽车**，按下按钮，汽车将**记录第二个代码**。\
紧接着，**攻击者可以发送第一个代码**，汽车将**锁定**（受害者会认为第二次按下锁定了）。然后，攻击者将能够**发送第二个被盗代码以打开**汽车（假设**“关车”代码也可以用于打开它**）。可能需要更改频率（因为有些汽车使用相同的代码来打开和关闭，但在不同频率下监听两个命令）。

攻击者可以**干扰汽车接收器而不是他的接收器**，因为如果汽车接收器在例如1MHz宽带中监听，攻击者不会**干扰**遥控器使用的确切频率，而是**在该频谱中的一个接近频率**，而**攻击者的接收器将监听一个更小的范围**，在没有干扰信号的情况下监听遥控器信号。

> [!WARNING]
> 其他实施方案在规格中显示，**滚动代码是发送的总代码的一部分**。即发送的代码是一个**24位密钥**，其中前**12位是滚动代码**，**第二个8位是命令**（如锁定或解锁），最后4位是**校验和**。实施这种类型的车辆也自然容易受到攻击，因为攻击者只需替换滚动代码段即可在两个频率上**使用任何滚动代码**。

> [!CAUTION]
> 请注意，如果受害者在攻击者发送第一个代码时发送第三个代码，则第一个和第二个代码将失效。

### Alarm Sounding Jamming Attack

在对安装在汽车上的后市场滚动代码系统进行测试时，**立即发送相同的代码两次**会**激活警报**和防盗装置，提供了一个独特的**拒绝服务**机会。具有讽刺意味的是，**禁用警报**和防盗装置的方法是**按下**遥控器，这使得攻击者能够**持续执行DoS攻击**。或者将此攻击与**前一个攻击结合以获取更多代码**，因为受害者希望尽快停止攻击。

## References

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
