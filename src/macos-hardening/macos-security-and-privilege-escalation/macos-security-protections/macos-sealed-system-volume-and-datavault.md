# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 基本信息

从 **macOS Big Sur (11.0)** 开始，系统卷通过 **APFS snapshot hash tree** 进行加密密封。这称为 **Sealed System Volume (SSV)**。系统分区以 **只读** 方式挂载，任何修改都会破坏该密封，并会在启动期间进行验证。

SSV 提供：
- **Tamper detection** — 可通过损坏的 cryptographic seal 检测对系统二进制文件和 frameworks 的任何修改
- **Rollback protection** — 启动过程会验证 system snapshot 的完整性
- **Rootkit prevention** — 即使是 root，也无法持久修改系统卷上的文件（除非破坏该密封）

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
### SSV Writer Entitlements

某些 Apple 系统二进制文件具有允许其修改或管理 sealed system volume 的 entitlements：

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | 将系统卷恢复到之前的 snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | 系统更新后创建新的 sealed snapshot |
| `com.apple.rootless.install.heritable` | 写入受 SIP 保护的路径（由子进程继承） |
| `com.apple.rootless.install` | 写入受 SIP 保护的路径 |

### Finding SSV Writers
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
### 攻击场景

#### 快照回滚攻击

如果攻击者攻陷了具有 `com.apple.private.apfs.revert-to-snapshot` 权限的 binary，他们可以**将系统卷回滚到更新前的状态**，从而恢复已知漏洞：
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback effectively **undoes security updates**, restoring previously-patched kernel and system vulnerabilities. This is one of the most dangerous operations possible on modern macOS.

#### System Binary Replacement

With SIP bypass + SSV write capability, an attacker can:

1. Mount the system volume read-write
2. Replace a system daemon or framework library with a trojaned version
3. Re-seal the snapshot (or accept the broken seal if SIP is already degraded)
4. The rootkit persists across reboots and is invisible to userland detection tools

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — 通过滥用 `system_installd` 的 `com.apple.rootless.install.heritable` entitlement 绕过 SIP，从而运行任意 post-install scripts ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass：`system_installd` 将 post-install script 暂存于 `/tmp` 下受 SIP 保护的文件夹中，但 `/tmp` 本身不受 SIP 保护，因此可以通过在其上挂载镜像来替换该文件夹 ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — XNU 中的 copy-on-write 竞态条件，允许写入只读的 root-owned 文件 ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault** 是 Apple 为敏感系统数据库提供的保护层。即使是 **root 也无法访问 DataVault 保护的文件** —— 只有具有特定 entitlements 的进程才能读取或修改这些文件。受保护的存储包括：

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | 系统范围的 TCC 隐私决策 |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | 每个用户的 TCC 隐私决策 |
| Keychain (system) | `/Library/Keychains/System.keychain` | 系统 Keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | 用户 Keychain |

DataVault 保护在**文件系统级别**通过 extended attributes 和 volume protection flags 强制执行，并由 kernel 验证。

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

如果攻击者攻陷 DataVault controller 二进制文件（例如，通过向具有 `com.apple.private.tcc.manager` 的进程注入代码），就可以**直接修改 TCC 数据库**，向任意应用授予任意 TCC 权限：
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> 修改 TCC 数据库是**终极隐私绕过手段**——它可以静默授予任何权限，不会显示任何用户提示或可见指示器。从历史上看，多条 macOS 权限提升链最终都以写入 TCC 数据库作为 payload。

#### Keychain 数据库访问

DataVault 还保护着 keychain 的后端文件。被攻陷的 DataVault 控制器可以：

1. 读取原始 keychain 数据库文件
2. 提取加密的 keychain 项
3. 尝试使用用户密码或恢复的密钥进行离线解密

### 涉及 DataVault/TCC 绕过的真实 CVE

| CVE | 描述 |
|---|---|
| CVE-2024-44131 | FileProvider symlink race 使特权 helper 能够访问受 TCC 保护的数据（[Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)） |
| CVE-2023-40424 | 以 root 身份，**创建一个 `NFSHomeDirectory` 指向攻击者控制的 `TCC.db` 的新用户**；登录时 `tccd` 会读取该文件并应用其中的授权，从而访问其他用户的数据（[Kandji](https://blog.kandji.io/malware-bypass-tcc)） |
| CVE-2021-30970 | “powerdir”：更改用户的 home 目录，以植入攻击者控制的 TCC.db（[Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)） |
| CVE-2021-30713 | Bundle-conclusion 缺陷使应用能够**继承 donor bundle 的 TCC 授权**而无需提示；该漏洞曾被 **XCSSET** 在野外利用，以截取桌面截图（[Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)） |
| CVE-2020-9934 | `tccd` 根据 `$HOME` 构建数据库路径，因此 `launchctl setenv HOME` 可以将其重定向到攻击者控制的 `TCC.db`（[Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)） |
| CVE-2020-29621 | `coreaudiod` 持有 `com.apple.private.tcc.manager` **且禁用了 library validation**，因此放置在 `/Library/Audio/Plug-Ins/HAL` 中的 HAL plug-in 可以授予任意 TCC 权限（[Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)） |

## 参考资料

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [Apple OTA 更新的噩梦（APFS Snapshots）](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
