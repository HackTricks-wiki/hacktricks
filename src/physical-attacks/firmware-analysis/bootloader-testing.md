{{#include ../../banners/hacktricks-training.md}}

以下步骤建议用于修改设备启动配置和引导加载程序，如 U-boot：

1. **访问引导加载程序的解释器 Shell**：

- 在启动期间，按 "0"、空格或其他识别的 "魔法代码" 以访问引导加载程序的解释器 Shell。

2. **修改引导参数**：

- 执行以下命令将 '`init=/bin/sh`' 附加到引导参数中，以允许执行 Shell 命令：
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **设置 TFTP 服务器**：

- 配置 TFTP 服务器以通过本地网络加载映像：
%%%
#setenv ipaddr 192.168.2.2 #设备的本地 IP
#setenv serverip 192.168.2.1 #TFTP 服务器 IP
#saveenv
#reset
#ping 192.168.2.1 #检查网络访问
#tftp ${loadaddr} uImage-3.6.35 #loadaddr 是加载文件的地址，uImage-3.6.35 是 TFTP 服务器上的映像文件名
%%%

4. **利用 `ubootwrite.py`**：

- 使用 `ubootwrite.py` 写入 U-boot 映像并推送修改后的固件以获得 root 访问权限。

5. **检查调试功能**：

- 验证是否启用了调试功能，如详细日志记录、加载任意内核或从不受信任的来源启动。

6. **谨慎的硬件干扰**：

- 在设备启动序列期间，特别是在内核解压缩之前，连接一个引脚到地并与 SPI 或 NAND 闪存芯片交互时要小心。在短接引脚之前，请查阅 NAND 闪存芯片的数据手册。

7. **配置恶意 DHCP 服务器**：
- 设置一个恶意 DHCP 服务器，使用恶意参数供设备在 PXE 启动期间获取。利用 Metasploit 的 (MSF) DHCP 辅助服务器等工具。修改 'FILENAME' 参数，使用命令注入命令，如 `'a";/bin/sh;#'` 来测试设备启动程序的输入验证。

**注意**：涉及与设备引脚物理交互的步骤（\*用星号标记）应极其谨慎，以避免损坏设备。

## 参考文献

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
