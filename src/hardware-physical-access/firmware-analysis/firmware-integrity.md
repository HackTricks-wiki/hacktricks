# 固件完整性

{{#include ../../banners/hacktricks-training.md}}

在经授权的评估中，如果发现固件签名验证薄弱或缺失，可以通过修改固件映像来展示其完整性影响。以下实验室工作流会在保留原有提取、仿真和重新打包步骤的基础上添加 bind shell。<sup>[[2]](#references)[[3]](#references)</sup>

1. 可以使用 firmware-mod-kit (FMK) 提取固件。
2. 应识别目标固件的架构和字节序。
3. 可以使用 Buildroot 或其他适合该环境的方法构建交叉编译器。
4. 可以使用交叉编译器构建 backdoor。
5. 可以将 backdoor 复制到提取出的固件 `/usr/bin` 目录中。
6. 可以将相应的 QEMU 二进制文件复制到提取出的固件 rootfs 中。
7. 可以使用 chroot 和 QEMU 仿真 backdoor。
8. 可以通过 netcat 访问 backdoor。
9. 应从提取出的固件 rootfs 中移除 QEMU 二进制文件。
10. 可以使用 FMK 重新打包修改后的固件。
11. 可以使用 firmware analysis toolkit (FAT) 仿真植入 backdoor 的固件，并通过 netcat 连接目标 backdoor 的 IP 和端口，以进行测试。

如果已通过动态分析、bootloader 操纵或硬件安全测试获得 root shell，则可以执行预编译的测试二进制文件，例如 implants 或 reverse shells。Metasploit 的 `msfvenom` 可以为此验证工作流生成特定架构的 payload：<sup>[[4]](#references)</sup>

1. 应识别目标固件的架构和字节序。
2. 可以使用 Msfvenom 指定目标 payload、攻击者主机 IP、监听端口号、文件类型、架构、平台和输出文件。
3. 可以将 payload 传输到已攻陷设备，并确保其具有执行权限。
4. 可以启动 msfconsole 并根据 payload 配置设置，让 Metasploit 准备好处理传入请求。
5. 可以在已攻陷设备上执行 meterpreter reverse shell。

## 未经身份验证的传输桥接到特权更新协议

一种常见的嵌入式设备设计错误是通过多种传输方式暴露**相同的内部命令协议**，但只在其中一种方式上实施身份验证。例如，USB 可能要求 challenge-response，而 BLE 却会将未经身份验证的 **GATT writes** 直接转发到相同的特权固件更新处理程序。<sup>[[1]](#references)</sup>

典型的攻击工作流：

1. 枚举 BLE GATT 数据库，并识别官方移动应用使用的可写特征。
2. 嗅探应用流量，并查找与有线协议匹配的 **magic bytes / opcodes**。
3. **无需配对**，通过 BLE 重放特权命令，并验证敏感操作是否仍可执行。
4. 如果可以访问固件升级、配置写入、调试或工厂测试 opcodes，则应将 BLE 视为**可通过无线电访问的管理端口**。

快速检查：

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

逆向分析时需要验证：

- BLE 是否需要 **配对/绑定**，还是只需建立普通连接？
- 所有传输方式是否都路由到同一个内部 dispatcher table？
- USB / BLE / UART / Wi-Fi 上的特权 opcode 是否采用不同的过滤方式？
- 移动应用能否远程触发固件更新、恢复或诊断处理程序？

## 仅使用校验和保护的固件容器仍由攻击者控制

仅受**无密钥校验和**（CRC32、SHA-256、MD5 等）保护的固件容器只能检测损坏，**不能验证真实性**。如果攻击者能访问更新例程，就可以修改镜像、重新计算校验和，并刷入任意代码。<sup>[[1]](#references)</sup>

RE 过程中的危险信号：

- 更新代码只验证尾随的校验和数据块，例如 `CHK2`、`CRC` 或 `SHA256`。
- 不存在签名验证或 secure-boot 信任根。
- 未使用绑定设备的 MAC / HMAC / authenticated encryption。
- 恢复模式接受相同的未认证镜像格式。

实用验证流程：

1. 提取固件容器，并识别 bootloader、主固件和完整性元数据。
2. 修改镜像中的无害字符串或横幅。
3. 按更新程序的预期方式准确重新计算校验和。
4. 通过正常更新路径重新刷写镜像。
5. 确认启动后改动生效，以证明可以替换为任意固件。

如果通过 BLE/Wi-Fi 等可远程访问的传输方式也能做到这一点，那么该漏洞实际上就是**未认证的 OTA 固件替换**。

## 分片更新状态和可写的完整性元数据

更新程序可能在安装时验证已签名的固件头，但启动镜像时仍只使用存储的完整性哈希。在 Cypherock X1 上，Bootloader 会调用独立的 Firewall 任务来验证头部并将版本/大小写入 RAM、将固件签名存入 RAM、验证写入的镜像，最后将镜像哈希写入持久化的 Primary Bootloader Data。签名本身不会持久化。这些任务可以独立调用，而非强制执行一次经过认证的升级事务。<sup>[[5]](#references)</sup>

在获得 MCU 代码执行能力和 Flash 写入权限后，报告中的攻击会重写应用镜像，修改 Bootloader 与 Firewall 共享的 RAM 中的版本/大小值，然后调用最后的元数据任务，存储恶意镜像的哈希并恢复正常启动状态。正常的启动完整性检查会接受该哈希，而不会重新验证签名。分析类似更新程序时，应追踪**哪些组件可以调用各任务**、已验证的值存放在哪里，以及启动时的判断是否对存储哈希的*同一镜像*进行身份认证。这比仅使用校验和的镜像格式更隐蔽：虽然存在签名验证，但状态转换并未与之绑定。<sup>[[5]](#references)</sup>

## 安全元件对不可信固件测量值进行签名

安全元件仅仅对代码提供的哈希进行签名，并不能证明正在运行的代码。在同一款钱包中，安全元件会对设备序列号以及云端 nonce 与 MCU 提供的固件哈希的 XOR 值进行签名。受损固件可以在运行不同字节的同时，提供预期哈希供签名。配套客户端还会向云端提交固件版本，因此验证方对预期哈希的比对仍依赖 MCU 提供的测量值，而非独立读取 Flash。<sup>[[5]](#references)</sup>

设备端结果构成了另一条独立的信任边界：云端会检查设备，但设备不会验证云端的判定。被修改的客户端可以向被篡改的设备报告本地成功。应分别测试测量值的来源和响应认证；有效的安全元件签名和成功界面本身并不能证明已安装的应用是真实的。<sup>[[5]](#references)</sup>

关于促成该更新程序分析的受保护代码披露，请参阅 [Firewall copy-task firmware acquisition](index.html#disclosing-protected-code-through-a-firewall-copy-task)。<sup>[[5]](#references)</sup>

## 通过重新刷写固件，将可信 USB 外设变成 BadUSB

当主机已经信任目标 USB 设备时，恶意固件可能无需实现一套完整的新 USB 协议栈。更简单的切入方式通常是**复用现有 HID 支持**。<sup>[[1]](#references)</sup>

实用思路：

1. 检查设备是否已枚举为 **HID Consumer Control** / media / vendor HID 接口。
2. 在固件中定位现有的 **HID report descriptor**。
3. 追加或替换 descriptor 条目，使设备同时声明 **keyboard** 功能。
4. 复用现有固件中已发送 HID reports 的例程，而不是编写新的传输实现。
5. 注入按键按下和按键释放 reports，在主机上输入命令。

这样就能将固件失陷转变为**主机失陷**，因为 PC 会将重新刷写后的外设视为合法键盘并信任它。

### 最简评估清单

- `dmesg`、Device Manager 或 USB descriptors 是否显示已有 HID 接口？
- report descriptor 附近是否有空余空间，或是否存在可重定位的 descriptor table？
- 能否复用现有的 media-control 发送例程来发送键盘 reports？
- 重新刷写后，主机是否会自动接受新的键盘接口？

## 在 RTOS 固件中可靠执行 payload

与其在随机代码路径中插入脆弱的 trampoline，不如寻找**现有的 RTOS task**，尤其是正常运行时未使用或影响较小的 task。<sup>[[1]](#references)</sup>

这样做的好处：

- 调度器会在启动时自然运行你的 payload。
- 无需破坏关键控制流。
- 与在对延迟敏感的 USB/网络处理程序中运行相比，延迟执行的 payload 不太可能触发 watchdog reset。

合适的目标包括正常使用时似乎处于休眠状态的诊断、工厂测试、遥测或协处理器服务任务。

## 快速迭代 exploit：改用无害的协议处理程序

固件补丁可行后，加快 RE 的一种简便方法是覆盖无害的命令处理程序（例如 **echo/debug opcode**），将其替换为自定义的 **memory read / write / execute** 原语。这样无需每次实验都完整重新刷写；尤其适用于设备支持通过高速有线传输调用修改后的处理程序的情况。<sup>[[1]](#references)</sup>

可用来：

- 验证 scatter-loaded memory maps
- 实时检查 heap/task 状态
- 在将小型 payload 写入 flash 前进行测试
- 安全地恢复函数指针、字符串和 descriptor tables

## References

- [1] [Pwnd Blaster：无需触碰电脑，仅用扬声器入侵电脑](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [固件分析工具包](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - 如何使用 `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [我们如何以及为何入侵 Cypherock 硬件钱包：完整经过](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
