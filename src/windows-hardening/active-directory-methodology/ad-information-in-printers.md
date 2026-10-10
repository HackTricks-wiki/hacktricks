# 打印机中的信息

{{#include ../../banners/hacktricks-training.md}}

Internet 上有几篇博客**指出，将打印机配置为使用 LDAP，却保留默认/弱**登录凭据的危险。  \
这是因为攻击者可以**诱使打印机向恶意 LDAP 服务器进行身份验证**（通常使用 `nc -vv -l -p 389` 或 `slapd -d 2` 就足够了），并以**明文**捕获打印机的凭据。

此外，一些打印机还会保存**包含用户名的日志**，甚至能够从 Domain Controller **下载所有用户名**。

这些**敏感信息**以及普遍存在的**安全性不足**，使打印机成为攻击者非常感兴趣的目标。

以下是一些关于此主题的入门博客：

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## 打印机配置

- **位置**：LDAP 服务器列表通常位于 Web 界面中（例如 *Network ➜ LDAP Setting ➜ Setting Up LDAP*）。
- **行为**：许多嵌入式 Web 服务器允许在**无需重新输入凭据**的情况下修改 LDAP 服务器（易用性功能 → 安全风险）。
- **利用方式**：将 LDAP 服务器地址重定向到攻击者控制的主机，然后使用 *Test Connection* / *Address Book Sync* 按钮，强制打印机向你发起绑定。

---

## 捕获凭据

### 方法 1 – Netcat 监听器

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

小型/老旧的 MFP 可能会发送一个简单的 *simple-bind*，其 bind DN 和密码在原始 BER 流中可见。现代设备通常会先执行匿名查询，然后再尝试 bind，因此结果各不相同。<sup>[[1]](#references)</sup>

在 636/3269 端口上运行普通的 `nc` listener 只能接收到 TLS 密文；测试 LDAPS 需要支持 TLS 的 LDAP endpoint，并且设备正确验证服务器证书时，重定向应该会失败。

### Method 2 – 完整的 Rogue LDAP server（推荐）

由于许多设备会在身份验证前先执行匿名搜索，搭建一个真正的 LDAP daemon 能得到可靠得多的结果：<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

当打印机执行查找时，你会在调试输出中看到明文凭据。

> 💡  Responder 包含 rogue LDAP 和 SMB 身份验证服务。简单的 LDAP bind 可以暴露已配置的密码，而 NTLM 身份验证会生成 challenge-response 数据；不要将这两种结果都描述为明文密码。

---

## 近期 Pass-Back 漏洞（2024-2025）

Pass-back *并非理论上的问题*——厂商在 2024/2025 年持续发布公告，描述的正是这类攻击。

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFP 的固件版本 ≤ 57.69.91 存在漏洞，经过身份验证的管理员（或仍使用默认凭据时的任何人）可以：

* **CVE-2024-12510 – LDAP pass-back**：更改 LDAP 服务器地址并触发查找，导致设备将已配置的 Windows 凭据 leak 到攻击者控制的主机。
* **CVE-2024-12511 – SMB/FTP pass-back**：通过 *scan-to-folder* 目标触发相同问题，泄露 NetNTLMv2 或 FTP 明文凭据。<sup>[[2]](#references)</sup>

例如，可以使用简单的监听器：

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

或 rogue SMB server（`impacket-smbserver`）就足以窃取凭据。  

### Canon imageRUNNER / imageCLASS – 2025 年 5 月 20 日公告

Canon 确认，数十条 Laser 和 MFP 产品线存在 **SMTP/LDAP pass-back** 漏洞。拥有管理员访问权限的攻击者可以修改服务器配置，并获取存储的 LDAP **或** SMTP 凭据（许多组织会使用特权账户来实现扫描到邮件）。<sup>[[3]](#references)</sup>

厂商明确建议：

1. 尽快更新到已修复的固件。
2. 使用强且唯一的管理员密码。
3. 避免在打印机集成中使用特权 AD 账户。

---

### Brother 设备和 OEM 变体 – 基于序列号的管理员访问及服务凭据泄露

2025 年的一次协同披露展示了受影响 Brother 设备上的一条特别有用的攻击链；该漏洞集中的部分问题也影响 OEM 型号，因此请根据厂商公告核实具体型号。在易受攻击的固件上，未经身份验证的攻击者可以通过 HTTP/HTTPS/IPP 获取设备序列号，而序列号也可能通过 SNMP 或 PJL 等管理协议获得。如果从未更改出厂密码，序列号便能确定性地推导出管理员密码。完成身份验证后，另一个独立的 pass-back 漏洞 CVE-2024-51984 会以明文形式暴露已配置的外部服务密码，例如 LDAP 或 FTP，从而将打印机管理权限转化为可重复使用的网络凭据。固件更新可修复服务密码泄露问题，但对于此前生产的设备，操作员仍需更换由序列号推导出的初始管理员密码。<sup>[[6]](#references)</sup>

当前 Metasploit 包含一个辅助模块，可通过 HTTP、SNMP 或 PJL 发现序列号、生成可能的初始密码，并可选择对照 Web 控制台验证该密码。`DiscoverSerialVia=AUTO` 会尝试支持的发现途径；如果资产清单中已有序列号，则改为提供 `TargetSerial`。<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

使用结果仅用于验证已获授权的资产。密码是否有效取决于确切的型号，尤其取决于出厂管理员密码是否已更改。<sup>[[6]](#references)[[7]](#references)</sup>

---

## 自动化枚举 / 利用工具

| 工具 | 用途 | 示例 |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | 滥用 PostScript/PJL/PCL、访问文件系统、检查默认凭据、*SNMP 发现* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | 通过 HTTP/HTTPS 收集配置（包括通讯录和 LDAP 凭据） | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | 运行恶意身份验证服务，并从 SMB 回连中捕获/中继 NetNTLM | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | 发现序列号、推导可能的出厂管理员密码，并验证 Web 控制台访问权限 | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## 加固与检测

1. **及时修补 / 更新固件** MFP（查看厂商 PSIRT 公告）。
2. **更换出厂管理员密码**——仅更新固件并不会移除已生产的受影响 Brother/OEM 设备中由序列号推导出的初始密码。<sup>[[6]](#references)</sup>
3. **服务帐户遵循最小权限原则**——切勿将 Domain Admin 用于 LDAP/SMB/SMTP；将权限限制在*只读* OU 范围内。
4. **限制管理访问**——将打印机的 Web/IPP/SNMP 接口放在管理 VLAN 中，或置于 ACL/VPN 之后。
5. **限制打印机出站流量**——允许每台设备仅连接预期的 DC/LDAP、邮件、DNS/NTP、打印和扫描文件目标。Pass-back 需要回连攻击者指定的端点。
6. **禁用未使用的协议**——FTP、Telnet、raw-9100、较旧的 SSL 密码套件。
7. **启用审计日志**——部分设备可以通过 syslog 记录 LDAP/SMTP 失败；关联分析异常绑定。
8. **监控身份验证目标**——当打印机向许可列表之外的主机发起 LDAP、SMB、SMTP 或 FTP 连接时发出警报，尤其是在管理登录或配置更改后立即发生的连接。
9. **使用 SNMPv3 或禁用 SNMP**——community `public` 经常会泄露设备和序列号信息。

---



---

## References

- [1] [只是一台打印机……最坏会发生什么？](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 多功能打印机：Pass-Back 攻击漏洞（已修复）](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004：生产型打印机、办公室/小型办公室多功能打印机和激光打印机的漏洞缓解/修复](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [使用 Netcat 通过打印机获取域凭据](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [在渗透测试项目中利用多功能打印机](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [多款 Brother 设备：多个漏洞（已修复）](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit：Brother 默认管理员身份验证绕过模块](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
