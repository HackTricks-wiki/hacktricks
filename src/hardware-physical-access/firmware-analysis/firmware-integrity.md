{{#include ../../banners/hacktricks-training.md}}

## 固件完整性

**自定义固件和/或编译的二进制文件可以被上传以利用完整性或签名验证漏洞**。可以按照以下步骤进行后门绑定 shell 编译：

1. 可以使用 firmware-mod-kit (FMK) 提取固件。
2. 应识别目标固件的架构和字节序。
3. 可以使用 Buildroot 或其他适合环境的方法构建交叉编译器。
4. 可以使用交叉编译器构建后门。
5. 可以将后门复制到提取的固件 /usr/bin 目录。
6. 可以将适当的 QEMU 二进制文件复制到提取的固件 rootfs。
7. 可以使用 chroot 和 QEMU 模拟后门。
8. 可以通过 netcat 访问后门。
9. 应从提取的固件 rootfs 中删除 QEMU 二进制文件。
10. 可以使用 FMK 重新打包修改后的固件。
11. 可以通过固件分析工具包 (FAT) 模拟后门固件，并使用 netcat 连接到目标后门 IP 和端口进行测试。

如果已经通过动态分析、引导加载程序操作或硬件安全测试获得了 root shell，可以执行预编译的恶意二进制文件，如植入物或反向 shell。可以使用以下步骤利用自动化有效载荷/植入工具，如 Metasploit 框架和 'msfvenom'：

1. 应识别目标固件的架构和字节序。
2. 可以使用 msfvenom 指定目标有效载荷、攻击者主机 IP、监听端口号、文件类型、架构、平台和输出文件。
3. 可以将有效载荷传输到被攻陷的设备，并确保其具有执行权限。
4. 可以通过启动 msfconsole 并根据有效载荷配置设置来准备 Metasploit 处理传入请求。
5. 可以在被攻陷的设备上执行 meterpreter 反向 shell。

{{#include ../../banners/hacktricks-training.md}}
