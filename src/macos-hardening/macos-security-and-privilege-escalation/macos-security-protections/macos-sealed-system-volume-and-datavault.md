# macOS 封存系统卷（SSV）与 DataVault

{{#include ../../../banners/hacktricks-training.md}}

## 封存系统卷（SSV）

### 基本信息

从 **macOS Big Sur (11.0)** 开始，系统卷使用 **APFS snapshot hash tree** 进行加密封存。这称为 **Sealed System Volume (SSV)**。系统分区以 **只读** 模式挂载，任何修改都会破坏封存，该封存会在启动时被验证。

SSV 提供：
- **篡改检测** — 任何对系统二进制/frameworks 的修改都会通过被破坏的加密封存被检测到
- **回滚保护** — 启动过程会验证系统快照的完整性
- **Rootkit prevention** — 即使 root 也无法在系统卷上持久修改文件（除非破坏封存）

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
### SSV 写入权限

某些 Apple 系统二进制文件具有允许它们修改或管理密封系统卷（SSV）的权限：

| Entitlement | 用途 |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | 将系统卷还原到先前的快照 |
| `com.apple.private.apfs.create-sealed-snapshot` | 在系统更新后创建新的密封快照 |
| `com.apple.rootless.install.heritable` | 写入受 SIP 保护的路径（可被子进程继承） |
| `com.apple.rootless.install` | 写入受 SIP 保护的路径 |

### 查找 SSV 写入者
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

如果攻击者妥协了具有 `com.apple.private.apfs.revert-to-snapshot` 权限的二进制，他们可以 **将系统卷回滚到更新前的状态**，重新引入已知漏洞：
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> 快照回滚实际上会 **撤销安全更新**，恢复先前已修补的内核和系统漏洞。这是在现代 macOS 上最危险的操作之一。

#### 系统二进制替换

在具备 SIP bypass + SSV 写入能力的情况下，攻击者可以：

1. 将系统卷以读写方式挂载
2. 用木马化的版本替换系统守护进程或框架库
3. 重新封印快照（如果 SIP 已被降级，则接受已损坏的 seal）
4. rootkit 能在重启后持续存在，并对 userland 检测工具不可见

### Real-World CVEs

| CVE | 描述 |
|---|---|
| CVE-2021-30892 | **Shrootless** — 通过 `system_installd` 的 SIP 绕过，允许修改 SSV |
| CVE-2022-22583 | 通过 PackageKit 的 snapshot 处理导致 SSV 绕过 |
| CVE-2022-46689 | 竞态条件允许对 SIP 保护的文件进行写入 |

---

## DataVault

### 基本信息

**DataVault** 是 Apple 为敏感系统数据库提供的保护层。即使 **root 也无法访问受 DataVault 保护的文件** —— 只有具有特定 entitlements 的进程才能读取或修改它们。受保护的存储包括：

| 受保护的数据库 | 路径 | 内容 |
|---|---|---|
| TCC（系统） | `/Library/Application Support/com.apple.TCC/TCC.db` | 系统范围的 TCC 隐私决策 |
| TCC（用户） | `~/Library/Application Support/com.apple.TCC/TCC.db` | 用户级别的 TCC 隐私决策 |
| Keychain（系统） | `/Library/Keychains/System.keychain` | 系统 Keychain |
| Keychain（用户） | `~/Library/Keychains/login.keychain-db` | 用户 Keychain |

DataVault 保护在 **文件系统级别** 强制实施，使用扩展属性和卷保护标志，并由内核验证。

### DataVault 控制器 Entitlements
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

如果攻击者攻陷了 DataVault 控制器二进制文件（例如，通过 code injection 注入到具有 `com.apple.private.tcc.manager` 的进程中），他们可以 **直接修改 TCC 数据库** 来授予任何应用程序任何 TCC 权限：
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC 数据库修改是 **终极隐私绕过** — 它会静默地授予任意权限，不会弹出任何用户提示或可见指示。历史上，多起 macOS 提权链最终都以对 TCC 数据库的写入作为最终载荷结束。

#### Keychain Database Access

DataVault 还保护 keychain 的后备文件。受损的 DataVault 控制器可能会：

1. 读取原始 keychain 数据库文件
2. 提取加密的 keychain 条目
3. 使用用户密码或恢复的密钥尝试离线解密

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | 描述 |
|---|---|
| CVE-2023-40424 | 通过 symlink 指向受 DataVault 保护的文件进行 TCC 绕过 |
| CVE-2023-32364 | 通过 sandbox 绕过导致对 TCC 数据库的修改 |
| CVE-2021-30713 | 通过 XCSSET 恶意软件修改 TCC.db 实现的 TCC 绕过 |
| CVE-2020-9934 | 通过操纵 environment variable 实现的 TCC 绕过 |
| CVE-2020-29621 | Music 应用的 TCC 绕过触及 DataVault |

## References

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
