# Modbus 协议

{{#include ../../banners/hacktricks-training.md}}

## Modbus 协议简介

Modbus 协议是工业自动化与控制系统中广泛使用的一种协议。Modbus 支持可编程逻辑控制器（PLCs）、传感器、执行器及其他工业设备之间的通信。理解 Modbus 协议非常重要，因为它是 ICS 中使用最广泛的通信协议，并且具有很大的攻击面，可用于 sniffing，甚至向 PLCs 注入命令。

下面将以要点形式介绍相关概念，为理解该协议及其运行方式提供背景。ICS 系统安全面临的最大挑战是实施和升级的成本。这些协议和标准是在 80 年代和 90 年代初设计的，至今仍被广泛使用。由于一个工业系统通常包含大量设备和连接，升级设备非常困难，这使 hackers 能够利用过时协议进行攻击。由于 Modbus 将在工业运行关键的环境中持续使用且难以升级，因此针对 Modbus 的攻击实际上几乎不可避免。

## Client-Server 架构

Modbus 协议通常采用 Client-Server 架构，其中主设备（client）向一个或多个从设备（servers）发起通信。这也被称为 Master-Slave 架构，广泛应用于电子设备和 IoT 中的 SPI、I2C 等技术。

## Serial 和 Ethernet 版本

Modbus 协议既支持 Serial Communication，也支持 Ethernet Communication。Serial Communication 广泛用于 legacy systems，而现代设备支持 Ethernet，后者能够提供更高的数据速率，也更适合现代工业网络。

## 数据表示

在 Modbus 协议中，数据可以通过 ASCII 或 Binary 进行传输，但由于 Binary 格式与旧设备的兼容性更好且更加紧凑，因此得到了广泛使用。

## Function Codes

Modbus 协议通过传输特定的 Function Codes 来操作 PLCs 和各种控制设备。理解这一部分非常重要，因为攻击者可以通过重新传输 Function Codes 来实施 replay attacks。Legacy devices 不支持数据传输加密，并且通常通过较长的线缆进行连接，这可能导致线缆被篡改，以及数据被捕获或注入。

## Modbus 的寻址

网络中的每个设备都有一个唯一地址，这是设备之间进行通信的必要条件。Modbus RTU、Modbus TCP 等协议用于实现寻址，并在数据传输中充当类似传输层的角色。传输的数据采用包含消息的 Modbus 协议格式。

此外，Modbus 还实现了错误检查，以确保传输数据的完整性。但最重要的是，Modbus 是一种 Open Standard，任何人都可以在自己的设备中实现它。这使该协议成为全球标准，并在工业自动化行业中得到广泛应用。

由于 Modbus 使用规模庞大且缺乏升级，攻击 Modbus 能够利用其攻击面带来显著优势。ICS 高度依赖设备之间的通信，针对这些设备的任何攻击都可能危及工业系统的运行。如果攻击者识别出数据传输媒介，就可以实施 replay、data injection、data sniffing 和 leak、Denial of Service、data forgery 等攻击。

{{#include ../../banners/hacktricks-training.md}}
