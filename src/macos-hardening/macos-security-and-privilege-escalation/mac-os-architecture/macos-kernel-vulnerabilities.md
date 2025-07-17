# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**在本报告中**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) 解释了几个漏洞，这些漏洞允许通过软件更新程序破坏内核。\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722)。

---

## 2024: 在野外的内核0天漏洞 (CVE-2024-23225 & CVE-2024-23296)

苹果在2024年3月修复了两个内存损坏漏洞，这些漏洞在iOS和macOS中被积极利用（在macOS 14.4/13.6.5/12.7.4中修复）。

* **CVE-2024-23225 – 内核**
• XNU虚拟内存子系统中的越界写入允许一个无特权进程在内核地址空间中获得任意的读/写权限，绕过PAC/KTRR。
• 通过一个精心制作的XPC消息从用户空间触发，该消息溢出`libxpc`中的缓冲区，然后在解析消息时转入内核。
* **CVE-2024-23296 – RTKit**
• 苹果硅RTKit（实时协处理器）中的内存损坏。
• 观察到的利用链使用CVE-2024-23225进行内核读/写，并使用CVE-2024-23296逃离安全协处理器沙箱并禁用PAC。

补丁级别检测：
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
如果无法升级，请通过禁用易受攻击的服务来减轻风险：
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG 类型混淆 – CVE-2023-41075

`mach_msg()` 请求发送到一个没有特权的 IOKit 用户客户端，导致 MIG 生成的粘合代码中的 **类型混淆**。当回复消息被重新解释为一个比最初分配的更大的离线描述符时，攻击者可以实现对内核堆区域的受控 **OOB 写入**，并最终提升到 `root`。

原始概述（Sonoma 14.0-14.1，Ventura 13.5-13.6）：
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
公共漏洞利用该漏洞的方法包括：
1. 用活动端口指针喷洒 `ipc_kmsg` 缓冲区。
2. 覆盖悬挂端口的 `ip_kobject`。
3. 使用 `mprotect()` 跳转到映射在 PAC 伪造地址的 shellcode。

---

## 2024-2025: 通过第三方 Kext 绕过 SIP – CVE-2024-44243（又名“Sigma”）

来自微软的安全研究人员显示，高权限守护进程 `storagekitd` 可以被迫加载一个 **未签名的内核扩展**，从而完全禁用完全修补的 macOS 上的 **系统完整性保护 (SIP)**（在 15.2 之前）。攻击流程如下：

1. 滥用私有权限 `com.apple.storagekitd.kernel-management` 在攻击者控制下生成一个助手。
2. 助手调用 `IOService::AddPersonalitiesFromKernelModule`，并使用指向恶意 kext 包的精心制作的信息字典。
3. 因为 SIP 信任检查是在 `storagekitd` 阶段后执行的，所以代码在验证之前以 ring-0 执行，并且可以通过 `csr_set_allow_all(1)` 关闭 SIP。

检测提示：
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
立即修复的方法是更新到 macOS Sequoia 15.2 或更高版本。

---

### 快速枚举备忘单
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Mach 消息模糊测试器，针对 MIG 子系统 (`github.com/preshing/luftrauser`)。
* **oob-executor** – 用于 CVE-2024-23225 研究的 IPC 越界原语生成器。
* **kmutil inspect** – 内置的 Apple 工具（macOS 11+），用于在加载前静态分析 kext：`kmutil inspect -b io.kext.bundleID`。



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
