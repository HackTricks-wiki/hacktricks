# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 它会监控每个进程发起的每一次连接。根据模式（静默允许连接、静默拒绝连接并告警），每次建立新连接时它都会**向你显示告警**。它还有一个非常好用的 GUI 来查看这些信息。
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall。这是一个基础 firewall，会对可疑连接向你发出告警（它有 GUI，但没有 Little Snitch 那么炫）。

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See 应用，用于在多个位置搜索 **malware could be persisting** 的痕迹（它是一次性工具，不是监控服务）。
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): 类似 KnockKnock，通过监控生成 persistence 的进程来工作。

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See 应用，用于查找安装了键盘 "event taps" 的 **keyloggers**

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS 的二进制授权与监控系统。它使用 **Endpoint Security** client 在代码运行前授权 **`exec`** 事件，因此它常见于专注于 **allowlisting/denylisting** 而不仅仅是事后检测的企业 fleet。
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): 类似 Procmon 的 macOS 动态分析工具。它摄取 **Endpoint Security telemetry**（进程、文件、进程间、登录以及与 XProtect 相关的事件），可用于理解成熟的 ES-based sensor 实际能够观察到什么。
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): 轻量级 Objective-See 工具，用于 **process**、**file** 和 **DNS** telemetry。在现代 macOS 上，它们还有额外前提条件，例如 **root**、**Terminal Full Disk Access** 或 **System/Network Extension approval**。更多检测思路请查看[这另一页关于 macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md)。

## Quick triage of defensive tooling

大多数现代 macOS security products 都作为 **System Extensions / Endpoint Security clients**、**launchd agents/daemons** 以及拥有 **Full Disk Access** 的应用的某种组合运行。一个快速 operator checklist：
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
如果 `systemextensionsctl list` 将某个 sensor 显示为 **`[activated enabled]`**，这通常是该 extension  वास्तव live 的最快指标。对于 **macOS 15 Sequoia 及更新版本**，MDM 还可以将特定 security extensions 标记为在 UI 中 **non-removable**，因此“从 System Settings 里把它 disable 掉”不再是一个安全的假设。内部细节见 [macOS System Extensions](mac-os-architecture/macos-system-extensions.md)。

## Recent native telemetry defenders can consume

最近的 macOS releases 让一些以前很难检测的、由用户触发的 bypasses 对 blue teams 来说变得更明显了：

- **macOS 15+**：Endpoint Security clients 可以接收 **`gatekeeper_user_override`** 事件，因此手动 Gatekeeper bypasses 可以被集中记录。
- **Current macOS Endpoint Security tooling** 也可以接收 **XProtect malware detection** 事件，从而更容易确认 Apple 已经在 endpoint 上检测到了什么。
- **macOS 15.4+**：Endpoint Security 新增 **`tcc_modify`**，这终于为 defenders 提供了一种受支持的方式来监控 **TCC grants/revokes**，而不是去抓取 TCC debug logs。
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
这对防御者和进行自我评估的 red teamers 都很有用：如果目标有成熟的基于 ES 的技术栈，**用户批准的 Gatekeeper / TCC bypass 链可能比过去更容易被看到**。关于这些保护机制的背景，请参见 [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) 和 [TCC](macos-security-protections/macos-tcc/README.md)。

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
