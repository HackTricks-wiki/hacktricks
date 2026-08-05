# macOS 防御应用

{{#include ../../banners/hacktricks-training.md}}

## 防火墙

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html)：它会监控每个进程建立的所有连接。根据模式（静默允许连接、静默拒绝连接和发出警报），每次建立新连接时都会**向你显示警报**。它还提供了非常好用的 GUI，用于查看所有这些信息。
- [**LuLu**](https://objective-see.org/products/lulu.html)：Objective-See firewall。这是一个基础 firewall，会针对可疑连接向你发出警报（它有 GUI，但没有 Little Snitch 的 GUI 那么精致）。

## 持久化检测

- [**KnockKnock**](https://objective-see.org/products/knockknock.html)：Objective-See 应用，会搜索多个**malware 可能实现持久化**的位置（这是一个单次运行的工具，不是 monitoring service）。
- [**BlockBlock**](https://objective-see.org/products/blockblock.html)：类似于 KnockKnock，但会监控生成持久化的进程。

## Keyloggers 检测

- [**ReiKey**](https://objective-see.org/products/reikey.html)：Objective-See 应用，用于查找安装 keyboard "event taps" 的 **keyloggers**。

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/)：macOS 的二进制授权和 monitoring system。它使用 **Endpoint Security** client 在代码运行前授权 **`exec`** events，因此它常见于专注于 **allowlisting/denylisting** 而非仅进行 post-execution detection 的企业 fleet 中。
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor)：类似 Procmon 的 macOS dynamic analysis tool。它接收 **Endpoint Security telemetry**（process、file、interprocess、login 以及与 XProtect 相关的 events），有助于了解成熟的基于 ES 的 sensor 实际可以观测到什么。<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html)：Objective-See 提供的轻量级 **process**、**file** 和 **DNS** telemetry 工具。在现代 macOS 上，它们还有额外的前置要求，例如 **root**、**Terminal Full Disk Access** 或 **System/Network Extension approval**。有关更多 instrumentation 思路，请查看[这个关于 macOS app inspection/debugging 的其他页面](macos-apps-inspecting-debugging-and-fuzzing/README.md)。

## 防御工具快速分诊

大多数现代 macOS security products 以 **System Extensions / Endpoint Security clients**、**launchd agents/daemons** 以及拥有 **Full Disk Access** 的 applications 的某种组合形式运行。快速 operator checklist：
```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
[ -f "$db" ] || continue
echo "== $db =="
sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```
如果 `systemextensionsctl list` 显示某个 sensor 为 **`[activated enabled]`**，通常这是确认该 extension 实际处于 live 状态的最快指标。在 **macOS 15 Sequoia 及更高版本**中，MDM 还可以将特定 security extensions 标记为**无法从 UI 移除**，因此“从 System Settings 中禁用它”不再是安全假设。有关内部机制，请参阅 [macOS System Extensions](mac-os-architecture/macos-system-extensions.md)。

## defenders 可以使用的近期原生 telemetry

近期的 macOS 版本使一些此前难以检测、由用户驱动的 bypass 对 blue teams 来说更加 noisy：

- **macOS 15+**：Endpoint Security clients 可以接收 **`gatekeeper_user_override`** events，因此可以集中记录手动 Gatekeeper bypass。
- **当前的 macOS Endpoint Security tooling** 还可以 ingest **XProtect malware detection** events，从而更容易确认 Apple 已在 endpoint 上检测到的内容。
- **macOS 15.4+**：Endpoint Security 新增 **`tcc_modify`**，终于为 defenders 提供了受支持的方式来监控 **TCC grants/revokes**，而不是抓取 TCC debug logs。<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
这对 defenders 和进行 self-assessment 的 red teamers 都很有用：如果目标拥有成熟的 ES-based stack，**user-approved Gatekeeper / TCC bypass chains 可能比过去更容易被发现**。有关这些保护机制的背景信息，请参阅 [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) 和 [TCC](macos-security-protections/macos-tcc/README.md)。

## References

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
