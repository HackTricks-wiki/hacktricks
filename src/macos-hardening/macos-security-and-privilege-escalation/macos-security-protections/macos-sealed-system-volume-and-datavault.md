# macOS Sealed System Volume 与 DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 基本信息

从 **macOS Big Sur (11.0)** 开始，系统卷使用 **APFS 快照哈希树**进行加密密封。这称为 **Sealed System Volume (SSV)**。系统分区以**只读**方式挂载，任何修改都会破坏密封状态，并在启动时进行验证。<sup>[[11]](#references)</sup>

SSV 提供：
- **篡改检测** — 对系统二进制文件/框架的任何修改都会改变 Merkle 树根，并使 Apple 签名的密封失效
- **启动时身份验证** — 启动链会在选定的系统快照成为根文件系统之前对其进行验证
- **抵御 rootkit** — 即使是 root，也无法在不禁用 authenticated root 或破坏授权更新路径的情况下，持久替换经身份验证的系统快照中的文件

SSV 保护的是 **System** 卷，而不是与其配对的可写 **Data** 卷。Firmlinks 会将两个卷合并到 `/` 下可见的命名空间中，因此，看起来可写的路径并不能证明底层对象属于密封快照。FileVault 和 Data Protection 用于保护静态数据的机密性；它们与 SSV 完整性保护相互独立。<sup>[[11]](#references)</sup>

### 检查 SSV 状态

```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / " 

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```

### 有效系统视图：SSV + Cryptex grafts

在较新的 macOS 版本中，`/System` 下可见的可执行文件不一定都来自已启动的 SSV 快照。**Cryptexes** 是经过单独认证的 APFS 磁盘映像，其内容会 graft 到选定目录上；因此，快速安全响应（Rapid Security Responses）可以替换与安全相关的组件，而无需重建基础 SSV。在排查 persistence 或对系统代码进行 diff 时，应盘点当前挂载项和 Preboot Cryptex 存储区，而不要只对基础快照计算哈希：

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

启动链和 Rapid Security Response 的细节请参阅 [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses)；本节聚焦于 SSV 本身的边界。

### SSV 写入者权限

某些 Apple 系统二进制文件具有允许其修改或管理密封系统卷的权限：

| 权限 | 用途 |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | 将系统卷还原到先前的快照 |
| `com.apple.private.apfs.create-sealed-snapshot` | 系统更新后创建新的密封快照 |
| `com.apple.rootless.install.heritable` | 写入受 SIP 保护的路径（由子进程继承） |
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

如果攻击者攻陷了一个拥有 `com.apple.private.apfs.revert-to-snapshot` 权限的二进制文件，就可以**将系统卷回滚到更新前的状态**，从而恢复已知漏洞：

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> 快照回滚实际上会**撤销安全更新**，恢复此前已修补的内核和系统漏洞。这是现代 macOS 上可能执行的最危险操作之一。

#### 系统二进制文件替换

通过绕过 SIP + 获得 SSV 写入能力，攻击者可以：

1. 将系统卷以读写方式挂载
2. 将系统守护进程或框架库替换为植入木马的版本
3. 重新密封快照（或者在 SIP 已经降级时接受密封失效）
4. rootkit 可在重启后继续存在，并躲过用户态检测工具

### 现实世界中的 CVE

| CVE | 描述 |
|---|---|
| CVE-2021-30892 | **Shrootless** — 通过滥用 `system_installd` 的 `com.apple.rootless.install.heritable` entitlement 绕过 SIP，从而运行任意安装后脚本 ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | 绕过 SIP：`system_installd` 将安装后脚本暂存到 `/tmp` 下受 SIP 保护的文件夹中，但 `/tmp` 本身不受 SIP 保护，因此可以通过在该文件夹上挂载磁盘映像来替换它 ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — XNU 中的写时复制竞态条件，允许写入只读的 root 所有文件 ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### 基本信息

**DataVault** 是一种由 entitlement 控制的文件系统保护机制，用于保护敏感文件和目录。BSD 标志 `UF_DATAVAULT`（`0x00000080`）用于标记需要 entitlement 才能读取和写入的对象；与普通 DAC 不同，在保护机制生效时，仅仅成为 **root** 或获得 Full Disk Access 并不能通过检查。<sup>[[4]](#references)[[13]](#references)</sup>

不要将“DataVault”当作所有受保护数据库的统称。TCC 数据库受 TCC/FDA 和 SIP 特定策略约束（参见 [macOS TCC](macos-tcc/README.md)），而 Keychain 项目的访问还取决于 Keychain ACL 和加密保护（参见 [macOS Keychain](../../macos-red-teaming/macos-keychain.md)）。实际的 DataVault 示例通常是 `/private/var/folders/.../0/` 下由服务所有的存储，例如 Screen Time 存储；如果能对其父目录执行 stat，BSD 文件标志中会显示 `datavault`。

### DataVault 控制器 Entitlement

| Entitlement | 边界 |
|---|---|
| `com.apple.rootless.datavault.controller` | 访问/管理 `UF_DATAVAULT` 对象<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | 管理 TCC 决策；这是相关但独立的隐私边界 |
| `com.apple.private.tcc.allow` | 绕过 entitlement 值中指定的特定 TCC 服务 |
| `com.apple.rootless.storage.TCC` | 写入受 SIP 保护的 TCC 存储 |

同时具备 DataVault 控制器 entitlement 和 FDA、备份、索引或 IPC 功能的进程尤其值得关注：应寻找一种 confused-deputy 原语，使其将受保护对象复制到普通路径，而不是尝试直接打开 vault。<sup>[[14]](#references)</sup>

### 查找 DataVault 控制器

```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
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

#### 直接修改 TCC 数据库（独立的 TCC 边界）

如果攻击者攻陷 TCC 管理器进程（例如，通过向携带 `com.apple.private.tcc.manager` 的进程注入代码），他们就可以**直接修改 TCC 数据库**，向任意应用授予任意 TCC 权限：<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> TCC 数据库修改是**终极隐私绕过**——它能静默授予任何权限，不会触发用户提示或显示任何可见标记。从历史上看，多个 macOS 权限提升链最终都以写入 TCC 数据库作为 payload。

#### Keychain 数据库访问

直接访问 Keychain 后端数据库，并不等同于获取明文机密。即使攻击者通过其他权限边界复制了数据库，仍然需要攻破密钥材料和项目 ACL；请参阅专门的 [macOS Keychain](../../macos-red-teaming/macos-keychain.md) 页面，而不要假设仅有 DataVault-controller entitlement 就足够。

#### 备份副本边界：Time Machine

2026 年的一项分析展示了一种有用的通用模式：`backupd` 同时拥有 `com.apple.rootless.datavault.controller` 和 Full Disk Access，因此能够复制受保护的存储。在测试配置中，`/private/var/folders` 被纳入 Time Machine 备份，而挂载后的备份副本不受实时 DataVault 边界保护。研究人员利用这一点定位了 Screen Time SQLite 存储，并读取其中的明文限制 PIN，全程无需打开实时 vault。应将其视为一种**副本边界攻击**：枚举那些能在权限较弱的挂载或路径下生成 vault 数据副本的备份、导出、迁移、索引和诊断代理。<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

此行为取决于系统版本和备份布局。请在目标系统版本上验证，并记住：加密的 Time Machine 目标只有在锁定时才能保护副本；挂载后，其访问控制也会成为攻击面的一部分。

### 涉及 DataVault/TCC 绕过的真实 CVE

| CVE | 描述 |
|---|---|
| CVE-2024-44131 | FileProvider 符号链接竞态使特权 helper 能够访问受 TCC 保护的数据（[Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)）<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | 以 root 身份，**创建一个 `NFSHomeDirectory` 指向攻击者控制的 `TCC.db` 的新用户**；用户登录时，`tccd` 会读取该数据库并应用其中的授权，从而访问其他用户的数据（[Kandji](https://blog.kandji.io/malware-bypass-tcc)）<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | “powerdir”：更改用户的主目录，以植入攻击者控制的 TCC.db（[Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)）<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bundle 归属判定缺陷使应用无需提示即可**继承捐赠 bundle 的 TCC 授权**；**XCSSET** 曾在野外利用此漏洞对桌面进行截图（[Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)）<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` 根据 `$HOME` 构造数据库路径，因此 `launchctl setenv HOME` 可将其重定向到攻击者控制的 `TCC.db`（[Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)）<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` 持有 `com.apple.private.tcc.manager` **权限**，且禁用了库验证，因此放入 `/Library/Audio/Plug-Ins/HAL` 的 HAL 插件可以授予任意 TCC 权限（[Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)）<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft 发现可绕过系统完整性保护的 macOS 新漏洞 Shrootless](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [技术分析：CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - 值得费力做差事](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple 平台安全 — 数据保护](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131：TCC 绕过窃取 iCloud 数据](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - 揭秘 macOS 恶意软件：绕过 TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [macOS 新漏洞“powerdir”可能导致未经授权访问用户数据](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [在 XCSSET 恶意软件中发现 TCC 零日绕过漏洞](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934：绕过 macOS 透明度、同意与控制（TCC）框架](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [播放音乐并绕过 TCC，即 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Apple OTA 更新的噩梦（APFS 快照）](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC 利用](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [如何绕过自己的屏幕使用时间密码 — 源代码及 Time Machine/DataVault 分析](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
