# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows Accessibility 功能会将用户配置持久化到 HKCU，并将其传播到每个会话的 HKLM 位置。在 **Secure Desktop** 切换期间（锁屏或 UAC 提示），**SYSTEM** 组件会重新复制这些值。如果**每个会话的 HKLM 键可由用户写入**，它就会成为一个特权写入 choke point，可通过 **registry symbolic links** 进行重定向，从而实现**任意 SYSTEM 注册表写入**。<sup>[[1]](#references)</sup>

RegPwn technique 利用该传播链，并通过对 `osk.exe` 使用的文件设置 **opportunistic lock (oplock)** 来稳定一个小型 race window。<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

示例功能：**On-Screen Keyboard** (`osk`)。相关位置如下：

- **System-wide feature list**：
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**：
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**：
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**：
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Secure desktop 切换期间的传播过程（简化版）：

1. **User `atbroker.exe`** 将 `HKCU\...\ATConfig\osk` 复制到 `HKLM\...\Session<session id>\ATConfig\osk`。
2. **SYSTEM `atbroker.exe`** 将 `HKLM\...\Session<session id>\ATConfig\osk` 复制到 `HKU\.DEFAULT\...\ATConfig\osk`。
3. **SYSTEM `osk.exe`** 将 `HKU\.DEFAULT\...\ATConfig\osk` 复制回 `HKLM\...\Session<session id>\ATConfig\osk`。

如果 session HKLM subtree 可由用户写入，则第 2/3 步会通过一个用户可以替换的位置提供 SYSTEM 写入能力。<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

将用户可写的 per-session key 替换为指向攻击者所选目标的 **registry symbolic link**。SYSTEM copy 发生时，会跟随该 link，并将攻击者控制的值写入任意目标 key。

核心思路：

- Victim write target (user-writable)：
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker 将该 key 替换为指向任意其他 key 的 **registry link**。
- SYSTEM 执行 copy，并以 SYSTEM permissions 将内容写入攻击者所选的 key。

这将产生一个**任意 SYSTEM 注册表写入** primitive。<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

在 **SYSTEM `osk.exe`** 启动并写入 per-session key 之间存在一个短暂的 timing window。为使其可靠，exploit 会在以下对象上设置 **oplock**：
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
当 oplock 触发时，攻击者将每会话 HKLM 键替换为 registry link，让 SYSTEM 写入生效，然后移除该 link。<sup>[[1]](#references)</sup>

## 示例 Exploitation 流程（高级概述）

1. 从访问令牌中获取当前**会话 ID**。
2. 启动一个隐藏的 `osk.exe` 实例并短暂休眠（确保 oplock 会触发）。
3. 将攻击者控制的值写入：
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. 在 `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` 上设置 **oplock**。
5. 触发 **Secure Desktop**（`LockWorkstation()`），使 SYSTEM 启动 `atbroker.exe` / `osk.exe`。
6. 在 oplock 触发时，将 `HKLM\...\Session<session id>\ATConfig\osk` 替换为指向任意目标的 **registry link**。
7. 短暂等待 SYSTEM 完成复制，然后移除该 link。<sup>[[1]](#references)</sup>

## 将该 Primitive 转换为 SYSTEM 执行

一种直接的链是覆盖**服务配置**值（例如 `ImagePath`），然后启动该服务。RegPwn PoC 会覆盖 **`msiserver`** 的 `ImagePath`，并通过实例化 **MSI COM object** 触发该服务，最终实现 **SYSTEM** 代码执行。<sup>[[1]](#references)[[2]](#references)</sup>

## 相关内容

有关其他 Secure Desktop / UIAccess 行为，请参阅：

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## 参考资料

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
