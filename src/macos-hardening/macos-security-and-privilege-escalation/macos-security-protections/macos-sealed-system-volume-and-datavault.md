# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 基本信息

从 **macOS Big Sur (11.0)** 开始，系统卷使用 **APFS snapshot hash tree** 进行加密密封。这被称为 **Sealed System Volume (SSV)**。系统分区以 **read-only** 模式挂载，任何修改都会破坏该密封，并会在启动期间进行验证。<sup>[[11]](#references)</sup>

SSV 提供：
- **篡改检测** — 通过检测损坏的加密密封，可以发现对系统二进制文件或 frameworks 的任何修改
- **回滚保护** — 启动过程会验证系统 snapshot 的完整性
- **Rootkit 防护** — 即使是 root，也无法持久修改系统卷上的文件（除非破坏该密封）

### 检查 SSV 状态
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### SSV Writer 权限

某些 Apple 系统二进制文件具有允许其修改或管理密封系统卷的权限：

| 权限 | 用途 |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | 将系统卷还原到之前的快照 |
| `com.apple.private.apfs.create-sealed-snapshot` | 系统更新后创建新的密封快照 |
| `com.apple.rootless.install.heritable` | 写入受 SIP 保护的路径（由子进程继承） |
| `com.apple.rootless.install` | 写入受 SIP 保护的路径 |

### 查找 SSV Writers
```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```
### Snapshot Rollback Attack

如果攻击者入侵了具有 `com.apple.private.apfs.revert-to-snapshot` 权限的二进制文件，他们可以**将系统卷回滚到更新前的状态**，从而恢复已知漏洞：
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback effectively **撤销安全更新**，恢复之前已修补的 kernel 和系统漏洞。这是现代 macOS 上可能执行的最危险操作之一。

#### 系统二进制替换

借助 SIP bypass + SSV 写入能力，攻击者可以：

1. 将系统卷以读写模式挂载
2. 将系统 daemon 或 framework library 替换为植入木马的版本
3. 重新封装 snapshot（如果 SIP 已经降级，也可以接受损坏的 seal）
4. rootkit 会在重启后持续存在，并且对 userland 检测工具不可见

### 现实世界中的 CVE

| CVE | 描述 |
|---|---|
| CVE-2021-30892 | **Shrootless** —— 利用 `system_installd` 的 `com.apple.rootless.install.heritable` entitlement 执行任意 post-install scripts，从而绕过 SIP（[Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass：`system_installd` 将 post-install script 暂存于 `/tmp` 下受 SIP 保护的文件夹中，但 `/tmp` 本身不受 SIP 保护，因此可以通过在其上挂载 image 来替换该文件夹（[Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** —— XNU 中的 copy-on-write race，允许向只读的 root-owned 文件写入内容（[Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)<sup>[[3]](#references)</sup> |

---

## DataVault

### 基本信息

**DataVault** 是 Apple 为敏感系统数据库提供的保护层。即使是 **root 也无法访问 DataVault 保护的文件** —— 只有具有特定 entitlements 的进程才能读取或修改这些文件。<sup>[[4]](#references)</sup> 受保护的存储包括：

| 受保护的数据库 | 路径 | 内容 |
|---|---|---|
| TCC（系统） | `/Library/Application Support/com.apple.TCC/TCC.db` | 全系统范围的 TCC 隐私决策 |
| TCC（用户） | `~/Library/Application Support/com.apple.TCC/TCC.db` | 每个用户的 TCC 隐私决策 |
| Keychain（系统） | `/Library/Keychains/System.keychain` | 系统 Keychain |
| Keychain（用户） | `~/Library/Keychains/login.keychain-db` | 用户 Keychain |

DataVault protection 在**文件系统层面**强制执行，使用 extended attributes 和 volume protection flags，并由 kernel 验证。

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### 查找 DataVault 控制器
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### 攻击场景

#### 直接修改 TCC 数据库

如果攻击者 compromise 了 DataVault controller binary（例如，通过向具有 `com.apple.private.tcc.manager` 的进程中进行 code injection），他们可以**直接修改 TCC 数据库**，向任意 application 授予任意 TCC 权限：<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC 数据库修改是**终极隐私 bypass**——它可以静默授予任何权限，不会显示任何用户提示或可见指示。历史上，多条 macOS privilege escalation 链最终都以写入 TCC 数据库作为 payload。

#### Keychain 数据库访问

DataVault 还保护着 keychain 的后端文件。被攻陷的 DataVault controller 可以：

1. 读取原始 keychain 数据库文件
2. 提取加密的 keychain 项目
3. 尝试使用用户密码或恢复的密钥进行 offline 解密

### 涉及 DataVault/TCC bypass 的 Real-World CVE

| CVE | 描述 |
|---|---|
| CVE-2024-44131 | FileProvider symlink race 使 privileged helper 能够访问 TCC 保护的数据（[Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | 以 root 身份，**创建一个 `NFSHomeDirectory` 指向攻击者控制的 `TCC.db` 的新用户**；登录时 `tccd` 会读取该文件并应用其中的授权，从而访问其他用户的数据（[Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir"：更改用户的 home dir，以植入攻击者控制的 TCC.db（[Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bundle-conclusion flaw 使 app 能够**继承 donor bundle 的 TCC grants**，且无需提示；该漏洞曾被 **XCSSET** 在野外利用，用于截取桌面屏幕截图（[Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` 根据 `$HOME` 构建数据库路径，因此 `launchctl setenv HOME` 可将其重定向到攻击者控制的 `TCC.db`（[Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` 持有 `com.apple.private.tcc.manager`，**并且**禁用了 library validation，因此放置在 `/Library/Audio/Plug-Ins/HAL` 中的 HAL plug-in 可以授予任意 TCC 权限（[Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## References

- [1] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Uncovering macOS Malware: Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
