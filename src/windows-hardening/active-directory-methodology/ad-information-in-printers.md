# 打印机中的信息

{{#include ../../banners/hacktricks-training.md}}

Internet 上有一些博客**强调了将打印机配置为使用 LDAP，并保留默认/弱**登录凭据的危险性。  \
这是因为攻击者可以**诱骗打印机向恶意 LDAP 服务器进行身份验证**（通常使用 `nc -vv -l -p 389` 或 `slapd -d 2` 就足够了），从而捕获打印机的**明文凭据**。

此外，许多打印机会包含带有**用户名的日志**，甚至可能能够从 Domain Controller **下载所有用户名**。

所有这些**敏感信息**以及普遍存在的**安全性不足**，使打印机成为攻击者非常感兴趣的目标。

关于该主题的一些入门博客：

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## 打印机配置

- **位置**：LDAP 服务器列表通常位于 Web 界面中（例如 *Network ➜ LDAP Setting ➜ Setting Up LDAP*）。
- **行为**：许多嵌入式 Web 服务器允许在**无需重新输入凭据**的情况下修改 LDAP 服务器（易用性功能 → 安全风险）。
- **利用**：将 LDAP 服务器地址重定向到攻击者控制的主机，然后使用 *Test Connection* / *Address Book Sync* 按钮，强制打印机向攻击者发起 bind。

---

## 捕获凭据

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
小型/老旧的 MFP 可能会以明文发送简单的 *simple-bind*，netcat 可以捕获这些内容。现代设备通常会先执行匿名查询，然后尝试 bind，因此结果可能有所不同。<sup>[[1]](#references)</sup>

### 方法 2 – Full Rogue LDAP server（推荐）

由于许多设备会在认证*之前*执行匿名搜索，启动一个真正的 LDAP daemon 可以获得更加可靠的结果：<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
当打印机执行查找时，你将在 debug 输出中看到明文凭据。

> 💡  你也可以使用 `impacket/examples/ldapd.py`（Python rogue LDAP）或 `Responder -w -r -f`，通过 LDAP/SMB 收集 NTLMv2 hashes。

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back *并非*理论问题——vendors 持续在 2024/2025 年发布 advisories，明确描述了此类攻击。

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFPs 的固件 ≤ 57.69.91 允许 authenticated admin（或在默认 creds 仍存在时的任何人）：

* **CVE-2024-12510 – LDAP pass-back**：更改 LDAP server address 并触发 lookup，使设备将配置的 Windows credentials 泄露给 attacker-controlled host。
* **CVE-2024-12511 – SMB/FTP pass-back**：通过 *scan-to-folder* destinations 存在相同问题，会泄露 NetNTLMv2 或 FTP 明文 creds。<sup>[[2]](#references)</sup>

一个简单的 listener，例如：
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
或 rogue SMB server（`impacket-smbserver`）就足以窃取凭据。

### Canon imageRUNNER / imageCLASS – 2025 年 5 月 20 日公告

Canon 确认了数十条 Laser & MFP 产品线中存在 **SMTP/LDAP pass-back** 弱点。拥有管理员访问权限的攻击者可以修改服务器配置，并获取 LDAP **或** SMTP 中存储的凭据（许多组织会使用特权账户来实现扫描到邮件）。<sup>[[3]](#references)</sup>

厂商指南明确建议：

1. 尽快更新至已修复的 firmware。
2. 使用强且唯一的管理员密码。
3. 避免将特权 AD 账户用于打印机集成。

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL abuse、文件系统访问、默认凭据检查、*SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | 通过 HTTP/HTTPS 窃取配置（包括地址簿和 LDAP 凭据） | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | 从 SMB/FTP pass-back 捕获并 relay NetNTLM hashes | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | 用于接收明文 binds 的轻量级 rogue LDAP service | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFPs promptly（检查厂商 PSIRT 公告）。
2. **Least-Privilege Service Accounts** – 不要将 Domain Admin 用于 LDAP/SMB/SMTP；将权限限制在*只读* OU 范围内。
3. **Restrict Management Access** – 将打印机 web/IPP/SNMP interfaces 放置在 management VLAN 中，或置于 ACL/VPN 之后。
4. **Disable Unused Protocols** – FTP、Telnet、raw-9100 以及较旧的 SSL ciphers。
5. **Enable Audit Logging** – 某些设备可以通过 syslog 记录 LDAP/SMTP failures；关联分析异常 binds。
6. **Monitor for Clear-Text LDAP binds** on unusual sources（打印机通常只应与 DCs 通信）。
7. **SNMPv3 or disable SNMP** – community `public` 经常会泄露设备和 LDAP 配置。

---

## References

- [1] [这只是一台打印机……最坏的情况会是什么？](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
