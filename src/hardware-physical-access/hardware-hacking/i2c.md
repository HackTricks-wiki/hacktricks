# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> 连接 Bus Pirate 前，请确认目标电压、引脚排列、上拉配置和共地情况。仅为嗅探总线时，不要在目标设备已供电的总线上启用 Bus Pirate 电源；两个电源可能相互冲突并损坏硬件。以下记录是针对特定设备的 Bus Pirate v3/社区固件示例，并非通用接线指南。<sup>[[1]](#references)[[2]](#references)</sup>

要测试 Bus Pirate 是否正常工作，请将 +5V 接到 VPU，将 3.3V 接到 ADC，然后访问 Bus Pirate（例如使用 Tera Term），并使用命令 `~`：

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

如你在上一条命令行中所见，它显示发现了 0 个错误。购买后或刷入固件后，这对确认设备能否正常工作非常有用。

要连接 Bus Pirate，可以参考文档：

![使用命令 - 按空格键：要连接 Bus Pirate，可以参考文档](<../../images/image (484).png>)

在本例中，目标是一款 24C256 系列 I²C EEPROM。请确认确切的后缀型号及其数据手册，因为不同型号支持的电源电压可能不同。<sup>[[3]](#references)</sup>

![使用命令 - 按空格键：在本例中，我要连接一款 EPROM：ATMEL901 24C256 PU27](<../../images/image (964).png>)

为了与 Bus Pirate 通信，我使用 Tera Term 连接到 Bus Pirate 的 COM 端口，并通过 Setup --> Serial Port --> Speed 将速度设为 115200。\
在以下通信记录中，你可以看到如何将 Bus Pirate 配置为使用 I2C 通信，以及如何从存储器中读写数据（注释以“#”开头，实际通信中不会包含这些注释）：

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

在此场景中，我们将嗅探 arduino 与前述 EPROM 之间的 I2C 通信。你只需让两个设备相互通信，然后将 bus pirate 连接到 SCL、SDA 和 GND 引脚：

![Read 20B from address 0x69 configured before - Sniffer: 在此场景中，我们将嗅探 arduino 与前述 EPROM 之间的 I2C 通信。你只需……](<../../images/image (166).png>)

```bash
I2C>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## 黑盒 I2C 协议重建

### 根据实时引脚识别总线

如果外设没有引脚定义或数据手册，可先在原主机运行时使用高阻抗逻辑分析仪进行被动分析。建立共地并确认逻辑电平安全后，将恒定电平的引脚归类为可能的电源轨、地线或上拉信号，再将活动线路与常见总线进行比较：UART 使用异步、方向独立的 TX/RX；传统 SPI 通常有时钟、片选和方向分离的数据线；I2C 则有规则时钟和一条双向数据线。随后，I2C 解码应能显示 7 位目标地址、读/写方向、ACK/NACK 以及重复出现的载荷。<sup>[[2]](#references)[[4]](#references)</sup>

捕获多次合法通信，并同时保留解码后的字节和原始时序。重复帧可作为后续序列化器的已知答案测试；请求之间的差异则可能揭示操作码、索引、偏移、长度、序列号或校验和字段。<sup>[[4]](#references)</sup>

### 从主机固件还原帧格式

如果无法访问外设固件，可提取**主机**固件，并找到打开 I2C 设备的组件。搜索字符串和符号，包括外设名称、`/dev/i2c-`、命令构造器、响应解析器、重置/初始化例程以及校验和函数。对于每个构造器，应记录确切的字段偏移、常量、接受的参数大小、载荷长度、校验和覆盖范围、校验和字节序和返回帧长度，而不要根据函数名推断格式。<sup>[[4]](#references)</sup>

名为 `crc16_ccitt` 的校验和函数并不足以确定应选用哪个预设。应确认移位方向、表索引字节、表所用的多项式、初始寄存器值、输入/输出反射、最终异或/取反以及序列化器在线路上的字节序。例如，使用反转多项式 `0x8408` 的右移低字节查找表，初始值为 `0xFFFF` 且末尾取反，说明它是 **CRC-16/X-25 (IBM-SDLC)**。正确的校验和通常是让测试用例通过完整性验证并进入命令解析器的必要条件。<sup>[[4]](#references)</sup>

还原格式后，可在公开代码中搜索独特的符号名称和常量。在 MJA1 案例中，独立找到的 SDK 封装验证了命令 ID、参数校验、响应定义和镜像 CRC 实现；应将此类源码用作验证依据，而不能用它替代对目标二进制和线路字节序的检查。<sup>[[4]](#references)[[5]](#references)</sup>

### 从已获取 root 权限的 Linux 主机发送帧

被攻陷的嵌入式 Linux 主机可以直接操作外设，无需添加另一台总线控制器。打开相应适配器，使用 `I2C_SLAVE` 选择 7 位地址，并发送由专用序列化器生成的帧；同时保留原始帧模式，以便进行变异和 fuzzing。<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

针对与目标 CPU 和 libc 兼容的工具链进行交叉编译，并将测试客户端的分析器跟踪结果与合法流量进行比较。即使可见字节相同，事务边界、读写顺序、延迟和外设状态也可能很重要。<sup>[[4]](#references)</sup>

### 基于响应的 opcode 枚举

确定最短有效帧和校验和后，枚举完整的 opcode 宽度，并将协议明确返回的**不支持的命令**响应作为负基线。不同的结果（例如参数无效、状态无效或未记录的状态）表明解码已到达已实现或部分实现的处理程序。这**并不能**证明该处理程序可被利用；应优先对候选项进行结构化的长度、参数、状态和命令序列 fuzzing。<sup>[[4]](#references)</sup>

如果测试导致外设卡死，请通过外部控制器自动化测试：每次启动只运行一个独立用例，通过 SSH 连接、执行用例、保存原始请求/响应及时间信息，然后重启或断电重启，等待健康检查恢复后继续。之后可将组件移至由微控制器控制的测试夹具，以实现确定性重置、直接电源控制和更快速的 fuzzing。<sup>[[4]](#references)</sup>

## References

- [1] [Bus Pirate 文档 — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C 总线规范和用户手册](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C 串行 EEPROM 数据手册](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — 黑盒探测：对小米 MJA1 安全芯片的安全分析](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1 密码学封装](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
