# 安全桌面 可访问性 注册表传播 LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## 概述

Windows 可访问性功能将用户配置保存在 HKCU 下，并将其传播到每个会话的 HKLM 位置。在 **安全桌面** 切换（锁屏或 UAC 提示）期间，**SYSTEM** 组件会重新复制这些值。如果 **每会话 HKLM 键对用户可写**，它就成为一个可被重定向的特权写入 chokepoint，可以通过 **注册表符号链接** 重定向，从而产生 **任意 SYSTEM 注册表写入**。

RegPwn 技术滥用了该传播链，并通过在 `osk.exe` 使用的文件上设置 **机会锁 (oplock)** 来稳定一个小的竞态窗口。

## 注册表传播链（可访问性 -> 安全桌面）

示例功能：**屏幕键盘** (`osk`)。相关位置是：

- **系统范围的功能列表**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **每用户配置（用户可写）**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **每会话 HKLM 配置（由 `winlogon.exe` 创建，用户可写）**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **安全桌面/默认用户 hive（SYSTEM 上下文）**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

在安全桌面切换期间的传播（简化）：

1. **用户 `atbroker.exe`** 将 `HKCU\...\ATConfig\osk` 复制到 `HKLM\...\Session<session id>\ATConfig\osk`。
2. **SYSTEM `atbroker.exe`** 将 `HKLM\...\Session<session id>\ATConfig\osk` 复制到 `HKU\.DEFAULT\...\ATConfig\osk`。
3. **SYSTEM `osk.exe`** 将 `HKU\.DEFAULT\...\ATConfig\osk` 再次复制回 `HKLM\...\Session<session id>\ATConfig\osk`。

如果会话 HKLM 子树对用户可写，步骤 2/3 会通过用户可替换的位置提供一次 SYSTEM 写入。

## 原语：通过注册表链接实现任意 SYSTEM 注册表写入

将用户可写的每会话键替换为指向攻击者选定目标的 **注册表符号链接**。当 SYSTEM 执行复制时，它会跟随该链接并将攻击者控制的值写入任意目标键。

关键思路：

- 受害者写入目标（用户可写）:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- 攻击者将该键替换为指向任意其它键的 **注册表链接**。
- 当 SYSTEM 执行复制时，它会以 SYSTEM 权限将数据写入攻击者选择的键。

这就产生了一个 **任意 SYSTEM 注册表写入** 的原语。

## 使用机会锁 (oplock) 赢得竞态窗口

在 **SYSTEM `osk.exe`** 启动并写入每会话键之间存在一个短暂的时间窗口。为使其可靠，利用程序在以下对象上设置一个 **oplock**：
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
当 oplock 触发时，攻击者将每个会话的 HKLM 键替换为一个 registry link，允许 SYSTEM 写入，然后移除该链接。

## 示例利用流程（高层）

1. 从访问令牌获取当前 **session ID**。
2. 启动一个隐藏的 `osk.exe` 实例并短暂休眠（确保 oplock 会触发）。
3. 将攻击者控制的值写入：
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. 在 `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` 上设置一个 **oplock**。
5. 触发 **Secure Desktop** (`LockWorkstation()`)，导致 SYSTEM 的 `atbroker.exe` / `osk.exe` 启动。
6. 在 oplock 触发时，用指向任意目标的 **registry link** 替换 `HKLM\...\Session<session id>\ATConfig\osk`。
7. 等待 SYSTEM 完成复制，然后移除该链接。

## 将该原语转换为 SYSTEM 执行

一个直接的方法是覆盖一个 **服务配置** 值（例如 `ImagePath`），然后启动该服务。RegPwn PoC 覆盖了 `msiserver` 的 `ImagePath`，并通过实例化 **MSI COM object** 来触发它，从而导致 **SYSTEM** 代码执行。

## 相关

有关其他 Secure Desktop / UIAccess 行为，请参见：

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
