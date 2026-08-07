# 固件完整性

{{#include ../../banners/hacktricks-training.md}}

**自定义固件和/或编译后的 binaries 可被上传，以利用完整性或签名验证缺陷**。以下步骤可用于编译 backdoor bind shell：

1. 可以使用 firmware-mod-kit（FMK）提取固件。
2. 应识别目标固件的架构和字节序。
3. 可以使用 Buildroot 或其他适用于该环境的方法构建 cross compiler。
4. 可以使用 cross compiler 构建 backdoor。
5. 可以将 backdoor 复制到提取出的固件 `/usr/bin` 目录。
6. 可以将适当的 QEMU binary 复制到提取出的固件 rootfs。
7. 可以使用 chroot 和 QEMU 对 backdoor 进行 emulation。
8. 可以通过 netcat 访问 backdoor。
9. 应从提取出的固件 rootfs 中移除 QEMU binary。
10. 可以使用 FMK 重新打包修改后的固件。
11. 可以使用 firmware analysis toolkit（FAT）对修改后的固件进行 emulation，并通过 netcat 连接目标 backdoor 的 IP 和端口，从而测试 backdoored 固件。

如果已经通过 dynamic analysis、bootloader manipulation 或 hardware security testing 获得 root shell，则可以执行预编译的恶意 binaries，例如 implants 或 reverse shells。可以按照以下步骤使用 Metasploit framework 和 `msfvenom` 等自动化 payload/implant 工具：

1. 应识别目标固件的架构和字节序。
2. 可以使用 Msfvenom 指定目标 payload、attacker 主机 IP、监听端口号、文件类型、架构、平台和输出文件。
3. 可以将 payload 传输到已被 compromise 的设备，并确保其具有执行权限。
4. 可以通过启动 msfconsole 并根据 payload 配置设置，使 Metasploit 准备好处理传入请求。
5. 可以在已被 compromise 的设备上执行 meterpreter reverse shell。

## 未经身份验证的传输桥接到特权更新协议

一种常见的 embedded 设计错误是通过多个传输方式暴露**同一内部 command protocol**，但只在其中一种传输方式上强制执行身份验证。例如，USB 可能需要 challenge-response，而 BLE 只需将未经身份验证的 **GATT writes** 转发到同一个特权 firmware-update handler。<sup>[[1]](#references)</sup>

典型的 offensive workflow：

1. 枚举 BLE GATT database，并识别官方 mobile app 使用的可写 characteristics。
2. sniff app traffic，并查找与 wired protocol 匹配的 **magic bytes / opcodes**。
3. 在**无需 pairing** 的情况下通过 BLE replay 特权 commands，并验证敏感操作是否仍然有效。
4. 如果 firmware upgrade、config write、debug 或 factory-test opcodes 可访问，则应将 BLE 视为一个**可通过 radio 访问的 admin port**。

快速检查：
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
逆向时需要验证：

- BLE 是否要求 **pairing/bonding**，还是只需建立普通连接？
- 所有传输是否都路由到同一个内部 dispatcher table？
- 在 USB / BLE / UART / Wi-Fi 上，特权 opcode 的过滤方式是否不同？
- 移动应用是否可以远程触发 firmware update、recovery 或 diagnostic handlers？

## 仅使用 checksum 保护的 firmware containers 仍由攻击者控制

仅由 **unkeyed checksum**（CRC32、SHA-256、MD5 等）保护的 firmware container 只能检测损坏，**不能验证真实性**。如果攻击者可以访问 update routine，就能修改 image、重新计算 checksum，并刷入任意代码。<sup>[[1]](#references)</sup>

RE 期间的危险信号：

- Update code 只验证末尾的 checksum blob，例如 `CHK2`、`CRC` 或 `SHA256`。
- 不存在 signature verification 或 secure-boot root of trust。
- 未使用 device-bound MAC / HMAC / authenticated encryption。
- Recovery mode 接受相同的 unauthenticated image format。

实际验证流程：

1. 提取 firmware container，并识别 bootloader、main firmware 和 integrity metadata。
2. 修改 image 中的无害字符串或 banner。
3. 按 updater 的要求准确重新计算 checksum。
4. 通过正常的 update path 重新刷入 image。
5. 在启动时确认修改，以证明可以替换任意 firmware。

如果可以通过 BLE/Wi-Fi 等可远程访问的 transport 实现这一点，则该漏洞实际上属于 **unauthenticated OTA firmware replacement**。

## 通过 firmware reflashing 将受信任的 USB peripheral 转变为 BadUSB

当目标设备已经被 host 通过 USB 信任时，恶意 firmware 可能不需要实现完整的新 USB stack。通常更简单的 pivot 是 **复用现有的 HID support**。<sup>[[1]](#references)</sup>

实用模式：

1. 检查设备是否已经枚举为 **HID Consumer Control** / media / vendor HID interface。
2. 在 firmware 中定位现有的 **HID report descriptor**。
3. 添加或替换 descriptor entries，使设备同时声明具备 **keyboard** capability。
4. 复用现有 firmware routines，它们已经能够发送 HID reports，无需编写新的 transport implementation。
5. 注入 key press + key release reports，在 host 上输入 commands。

这样可以将 firmware compromise 变成 **host compromise**，因为 PC 会将重新刷写后的 peripheral 信任为合法 keyboard。

### 最小评估清单

- `dmesg`、Device Manager 或 USB descriptors 是否显示已有的 HID interface？
- report descriptor 附近是否有剩余空间，或是否存在可重定位的 descriptor table？
- 是否可以复用已有的 media-control send routines 来发送 keyboard reports？
- 重新刷写后，host 是否会自动接受新的 keyboard interface？

## 在 RTOS firmware 中可靠地执行 payload

不要将脆弱的 trampolines 插入随机的 code paths，而应寻找正常运行时未使用或影响较小的 **现有 RTOS tasks**。<sup>[[1]](#references)</sup>

这样做的好处：

- scheduler 会在启动期间自然地启动你的 payload。
- 可以避免破坏关键的 control flow。
- 与在对延迟敏感的 USB/network handler 中运行相比，延迟执行的 payload 不太可能触发 watchdog resets。

较好的目标包括 diagnostic、factory-test、telemetry 或 coprocessor service tasks，它们在正常使用中通常处于 dormant 状态。

## 快速迭代 exploit：重新利用无害的 protocol handlers

一旦可以 patch firmware，加速 RE 的一种紧凑方法是：将无害的 command handler（例如 **echo/debug opcode**）覆盖为自定义的 **memory read / write / execute** primitives。这样可以避免每次实验都进行完整 reflashing；当设备支持通过高速 wired transport 访问被修改的 handler 时，这种方法尤其有用。<sup>[[1]](#references)</sup>

可用于：

- 验证 scatter-loaded memory maps
- 实时检查 heap/task state
- 在将小型 payload 写入 flash 前进行测试
- 安全地恢复 function pointers、strings 和 descriptor tables

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
