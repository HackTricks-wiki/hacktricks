# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

当授权评估发现 firmware-signature verification 存在薄弱环节或缺失时，可以通过修改 firmware image 来展示其完整性影响。以下 lab workflow 在保留原始提取、emulation 和 repacking 步骤的同时添加 bind shell。<sup>[[2]](#references)[[3]](#references)</sup>

1. 可以使用 firmware-mod-kit (FMK) 提取 firmware。
2. 应识别目标 firmware 的 architecture 和 endianness。
3. 可以使用 Buildroot 或其他适用于该环境的方法构建 cross compiler。
4. 可以使用 cross compiler 构建 backdoor。
5. 可以将 backdoor 复制到提取出的 firmware 的 /usr/bin 目录。
6. 可以将适当的 QEMU binary 复制到提取出的 firmware rootfs。
7. 可以使用 chroot 和 QEMU 对 backdoor 进行 emulation。
8. 可以通过 netcat 访问 backdoor。
9. 应从提取出的 firmware rootfs 中删除 QEMU binary。
10. 可以使用 FMK 重新打包修改后的 firmware。
11. 可以通过使用 firmware analysis toolkit (FAT) 对其进行 emulation，并使用 netcat 连接目标 backdoor IP 和 port，来测试植入 backdoor 的 firmware。

如果已经通过 dynamic analysis、bootloader manipulation 或 hardware security testing 获得 root shell，则可以执行预编译的 test binaries，例如 implants 或 reverse shells。Metasploit 的 `msfvenom` 可以为此 validation workflow 生成特定 architecture 的 payload：<sup>[[4]](#references)</sup>

1. 应识别目标 firmware 的 architecture 和 endianness。
2. 可以使用 Msfvenom 指定目标 payload、attacker host IP、listening port number、filetype、architecture、platform 以及 output file。
3. 可以将 payload 传输到已遭 compromise 的设备，并确保其具有 execution permissions。
4. 可以通过启动 msfconsole 并根据 payload 配置设置，使 Metasploit 准备好处理 incoming requests。
5. 可以在已遭 compromise 的设备上执行 meterpreter reverse shell。

## Unauthenticated transport bridges to privileged update protocols

一种常见的 embedded design mistake，是通过多个 transport 暴露**同一个 internal command protocol**，但只在其中一个 transport 上强制执行 authentication。例如，USB 可能需要 challenge-response，而 BLE 只需将未经 authentication 的 **GATT writes** 转发到同一个 privileged firmware-update handler。<sup>[[1]](#references)</sup>

Typical offensive workflow：

1. 枚举 BLE GATT database，并识别 official mobile app 使用的可写 characteristics。
2. Sniff app traffic，并查找与 wired protocol 匹配的 **magic bytes / opcodes**。
3. **without pairing** 通过 BLE replay privileged commands，并验证敏感操作是否仍然有效。
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
逆向时需要验证的事项：

- BLE 是否需要 **pairing/bonding**，还是只需建立普通连接？
- 所有传输方式是否都路由到同一个内部 dispatcher table？
- 在 USB / BLE / UART / Wi-Fi 上，特权 opcode 是否采用不同的过滤方式？
- 移动应用是否可以远程触发 firmware update、recovery 或 diagnostic handlers？

## 仅使用 checksum 的 firmware containers 仍然是由攻击者控制的 firmware

仅由**无密钥 checksum**（CRC32、SHA-256、MD5 等）保护的 firmware container 只能检测损坏，**不能验证真实性**。如果攻击者能够访问 update routine，就可以修改 image、重新计算 checksum，并刷写任意代码。<sup>[[1]](#references)</sup>

RE 期间的危险信号：

- Update code 只验证末尾的 checksum blob，例如 `CHK2`、`CRC` 或 `SHA256`。
- 不存在 signature verification 或 secure-boot root of trust。
- 未使用 device-bound MAC / HMAC / authenticated encryption。
- Recovery mode 接受相同的未经身份验证的 image format。

实际验证流程：

1. 提取 firmware container，并识别 bootloader、main firmware 和 integrity metadata。
2. 修改 image 中的无害字符串或 banner。
3. 按 updater 的预期方式准确重新计算 checksum。
4. 通过正常 update path 重新刷写 image。
5. 在启动时确认修改结果，以证明可以替换任意 firmware。

如果可以通过 BLE/Wi-Fi 等可远程访问的传输方式实现，这个漏洞实际上就是**未经身份验证的 OTA firmware replacement**。

## 通过重新刷写 firmware 将受信任的 USB peripheral 变成 BadUSB

当目标设备已经受到主机通过 USB 的信任时，恶意 firmware 可能不需要实现完整的新 USB stack。更容易的切入点通常是**复用现有的 HID support**。<sup>[[1]](#references)</sup>

有用的模式：

1. 检查设备是否已经枚举为 **HID Consumer Control** / media / vendor HID interface。
2. 在 firmware 中定位现有的 **HID report descriptor**。
3. 添加或替换 descriptor entries，使设备同时声明 **keyboard** capability。
4. 复用现有 firmware routines，这些 routines 已经能够发送 HID reports，而不必编写新的 transport implementation。
5. 注入 key press + key release reports，以便在主机上输入命令。

这样，firmware compromise 就会变成**主机 compromise**，因为 PC 会将重新刷写的 peripheral 信任为合法 keyboard。

### 最小评估清单

- `dmesg`、Device Manager 或 USB descriptors 是否显示现有的 HID interface？
- report descriptor 附近是否有剩余空间，或者是否存在可重定位的 descriptor table？
- 是否可以复用现有的 media-control send routines 来发送 keyboard reports？
- 重新刷写后，主机是否会自动接受新的 keyboard interface？

## 在 RTOS firmware 内可靠地执行 payload

与其将脆弱的 trampolines 插入随机 code paths，不如寻找正常运行中未使用或影响较小的**现有 RTOS tasks**。<sup>[[1]](#references)</sup>

这样做的好处：

- scheduler 会在启动期间自然地启动你的 payload。
- 可以避免破坏关键 control flow。
- 与在对延迟敏感的 USB/network handler 内执行相比，延迟执行的 payload 不太可能触发 watchdog resets。

良好的目标包括 diagnostic、factory-test、telemetry 或 coprocessor service tasks；这些 tasks 在正常使用时通常处于 dormant 状态。

## 快速迭代 exploit：重新利用无害的 protocol handlers

一旦可以 patch firmware，加速 RE 的一种简便方法是：将无害的 command handler（例如 **echo/debug opcode**）覆盖为自定义的 **memory read / write / execute** primitives。这样可以避免每次实验都进行完整的 reflashing；当设备支持通过快速 wired transport 使用修改后的 handler 时，这种方法尤其有用。<sup>[[1]](#references)</sup>

可用于：

- 验证 scatter-loaded memory maps
- 实时检查 heap/task state
- 在将小型 payload 写入 flash 之前进行测试
- 安全地恢复 function pointers、strings 和 descriptor tables

## References

- [1] [Pwnd Blaster：无需接触电脑即可利用 speaker 入侵 PC](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - 如何使用 `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
