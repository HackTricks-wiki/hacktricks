# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)是一个可以与Raspberry PI或Arduino一起使用的工具，用于尝试从未知芯片中找到JTAG引脚。\
在**Arduino**中，将**引脚2到11连接到10个可能属于JTAG的引脚**。在Arduino中加载程序，它将尝试暴力破解所有引脚，以找出是否有引脚属于JTAG以及每个引脚的具体情况。\
在**Raspberry PI**中，您只能使用**引脚1到6**（6个引脚，因此测试每个潜在JTAG引脚的速度会更慢）。

### Arduino

在Arduino中，连接电缆后（引脚2到11连接到JTAG引脚，Arduino GND连接到主板GND），**在Arduino中加载JTAGenum程序**，并在串口监视器中发送**`h`**（帮助命令），您应该会看到帮助信息：

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

配置**“无行结束符”和115200波特率**。\
发送命令s以开始扫描：

![](<../../images/image (774).png>)

如果您正在连接JTAG，您将找到一行或多行以FOUND!开头的**行，指示JTAG的引脚**。

{{#include ../../banners/hacktricks-training.md}}
