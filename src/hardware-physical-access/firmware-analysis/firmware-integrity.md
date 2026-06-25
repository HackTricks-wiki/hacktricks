# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**自定义 firmware 和/或编译后的 binaries 可以被上传，以利用完整性或签名验证缺陷**。以下步骤可用于编译 backdoor bind shell：

1. 可以使用 firmware-mod-kit (FMK) 提取 firmware。
2. 应识别目标 firmware 的架构和大小端序。
3. 可以使用 Buildroot 或其他适合该环境的方法构建 cross compiler。
4. 可以使用 cross compiler 构建 backdoor。
5. 可以将 backdoor 复制到提取出的 firmware 的 /usr/bin 目录。
6. 可以将合适的 QEMU binary 复制到提取出的 firmware rootfs。
7. 可以使用 chroot 和 QEMU 对 backdoor 进行模拟。
8. 可以通过 netcat 访问 backdoor。
9. 应从提取出的 firmware rootfs 中移除 QEMU binary。
10. 可以使用 FMK 重新打包修改后的 firmware。
11. 可以使用 firmware analysis toolkit (FAT) 对带 backdoor 的 firmware 进行模拟测试，并通过 netcat 连接到目标 backdoor IP 和端口。

如果已经通过 dynamic analysis、bootloader manipulation 或 hardware security testing 获得 root shell，则可以执行预编译的恶意 binaries，例如 implants 或 reverse shells。可使用 Metasploit framework 和 'msfvenom' 等自动化 payload/implant 工具，步骤如下：

1. 应识别目标 firmware 的架构和大小端序。
2. 可以使用 Msfvenom 指定目标 payload、攻击者主机 IP、监听端口号、filetype、architecture、platform 和输出文件。
3. 可以将 payload 传输到已被入侵的设备，并确保其具有执行权限。
4. 可以通过启动 msfconsole 并根据 payload 配置设置来准备 Metasploit 以处理传入请求。
5. 可以在已被入侵的设备上执行 meterpreter reverse shell。

## 未经认证的 transport bridges 到特权 update protocols

一个常见的 embedded 设计错误是：**将同一个内部命令协议暴露在多个 transport 上**，但只在其中一个 transport 上强制认证。例如，USB 可能需要 challenge-response，而 BLE 却只是把未经认证的 **GATT writes** 直接转发到同一个特权 firmware-update handler。

典型的 offensive 工作流程：

1. 枚举 BLE GATT database，并识别官方 mobile app 使用的可写 characteristics。
2. 抓取 app traffic，查找与有线协议匹配的 **magic bytes / opcodes**。
3. 通过 BLE **在不配对的情况下** 重放特权命令，并验证敏感操作是否仍然有效。
4. 如果可以访问 firmware upgrade、config write、debug 或 factory-test opcodes，则应将 BLE 视为一个 **radio-reachable admin port**。

快速检查：
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
反向工程时需要验证的事项：

- BLE 需要 **pairing/bonding** 还是只需要普通连接？
- 所有 transports 是否都路由到同一个内部 dispatcher table？
- 特权 opcodes 在 USB / BLE / UART / Wi-Fi 上是否有不同过滤？
- mobile app 能否远程触发 firmware update、recovery 或 diagnostic handlers？

## 仅有 checksum 的 firmware 容器仍然是攻击者可控的 firmware

一个仅由 **未加密 key 的 checksum**（CRC32、SHA-256、MD5 等）保护的 firmware 容器，只提供完整性损坏检测，**不提供真实性**。如果攻击者能够访问更新流程，就可以修改镜像、重新计算 checksum，并刷入任意代码。

RE 期间的红旗：

- 更新代码只验证末尾的 checksum blob，例如 `CHK2`、`CRC` 或 `SHA256`。
- 没有 signature verification 或 secure-boot root of trust。
- 没有使用 device-bound MAC / HMAC / authenticated encryption。
- recovery mode 接受相同的未认证镜像格式。

实际验证流程：

1. 提取 firmware 容器，并识别 bootloader、主 firmware 和完整性元数据。
2. 修改镜像中的一个无害字符串或 banner。
3. 按 updater 期望的方式精确重新计算 checksum。
4. 通过正常 update 路径重新刷写镜像。
5. 在启动时确认修改已生效，以证明可以替换任意 firmware。

如果这能通过 BLE/Wi-Fi 这类可远程访问的 transport 完成，那么这个 bug 实际上就是 **unauthenticated OTA firmware replacement**。

## 通过 firmware 重新刷写把受信任的 USB peripheral 变成 BadUSB

当目标设备已经通过 USB 被 host 视为受信任设备时，恶意 firmware 往往不需要实现完整的新 USB stack。一个更容易的切入点通常是 **复用现有 HID 支持**。

有用的模式：

1. 检查设备是否已经枚举为 **HID Consumer Control** / media / vendor HID interface。
2. 在 firmware 中定位现有的 **HID report descriptor**。
3. 追加或替换 descriptor 条目，让设备同时声明 **keyboard** 能力。
4. 复用现有 firmware 例程，直接发送 HID reports，而不是编写新的 transport 实现。
5. 注入 key press + key release reports，在 host 上输入命令。

这会把 firmware compromise 变成 **host compromise**，因为 PC 会把重新刷写后的 peripheral 当作合法 keyboard 信任。

### 最小评估清单

- `dmesg`、Device Manager 或 USB descriptors 是否显示已有 HID interface？
- report descriptor 附近是否有剩余空间，或者是否有可重定位的 descriptor table？
- 现有的 media-control 发送例程能否复用于 keyboard reports？
- host 在重新刷写后是否会自动接受新的 keyboard interface？

## 在 RTOS firmware 中可靠执行 payload

不要把脆弱的 trampoline 插入到随机代码路径中，而应寻找在正常运行中未使用或影响较小的 **现有 RTOS tasks**。

这样做的好处：

- scheduler 会在启动时自然地启动你的 payload。
- 你不会破坏关键控制流。
- 相比在对延迟敏感的 USB/network handler 中运行，延迟执行的 payload 更不容易触发 watchdog resets。

好的目标包括在正常使用中看起来处于 dormant 状态的 diagnostic、factory-test、telemetry 或 coprocessor service tasks。

## 快速 exploit 迭代：复用 benign protocol handlers

一旦可以修改 firmware，一个加速 RE 的紧凑方法是覆盖一个无害的 command handler（例如 **echo/debug opcode**），将其替换为自定义的 **memory read / write / execute** primitives。这样可以避免每次实验都完整重新刷写，尤其适用于设备通过快速有线 transport 支持被修改后的 handler 的情况。

可用它来：

- 验证 scatter-loaded memory maps
- 实时检查 heap/task 状态
- 在写入 flash 前测试小 payload
- 安全地恢复 function pointers、strings 和 descriptor tables

## References

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
