# 打印机中的信息

{{#include ../../banners/hacktricks-training.md}}

保存了 LDAP 凭据的打印机可能会在服务器设置被更改后向恶意端点进行身份验证，从而暴露这些凭据。<sup>[[2]](#references)</sup>结果取决于绑定方式：未受保护的 simple bind 会暴露密码，而 SASL challenge-response bind 不会以明文形式暴露密码。<sup>[[8]](#references)</sup>请参阅 [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks)。

此外，许多打印机都包含**带有用户名的日志**，甚至可能能够从 Domain Controller **下载所有用户名**。

所有这些**敏感信息**以及普遍存在的**安全性不足**，使打印机成为攻击者非常感兴趣的目标。

以下是一些介绍该主题的博客：

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## 打印机配置

- **位置**：LDAP 服务器列表通常位于 Web 界面中（例如 *Network ➜ LDAP Setting ➜ Setting Up LDAP*）。
- **行为**：许多嵌入式 Web 服务器允许在**无需重新输入凭据**的情况下修改 LDAP 服务器（这是为了方便用户的功能 → 也是安全风险）。
- **利用**：将 LDAP 服务器地址重定向到攻击者控制的主机，然后使用 *Test Connection* / *Address Book Sync* 按钮，强制打印机向你进行绑定。

---

## 捕获凭据

### 方法 1 – Netcat 监听器

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

简单的 BindRequest 即使服务器随后拒绝登录，也可能在 BER 流中暴露 bind DN 和密码。仅进行匿名查询或 SASL 协商不会暴露存储的密码。<sup>[[8]](#references)</sup>

在 636/3269 端口上运行的普通 `nc` 监听器看到的是 TLS 握手，而不是 LDAP bind。LDAPS 需要支持 TLS 的端点。仅验证证书并不能阻止 pass-back：如果打印机接受更改后的主机名，且新端点具有适用于该主机名的有效证书，仍可能发生 pass-back；客户端还必须限制哪些服务器有权接收存储的凭据。<sup>[[8]](#references)</sup>

### 方法 2 – 完整的 Rogue LDAP 服务器（推荐）

打印机可能要求收到有效的 LDAP 响应后才会尝试 bind。<sup>[[10]](#references)</sup> 完整的 LDAP 服务器可以处理这次前置交互，但无法让使用强 SASL 机制或绑定到预期 TLS 服务器的客户端泄露密码。<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

将一次查询视为存在连接的证据，而非密码泄露的证明。只有客户端发送了包含明文密码的 bind 请求时，密码才会暴露；请检查实际使用的 bind 机制和 TLS 状态。<sup>[[8]](#references)</sup>

> 💡  Responder 包含 rogue LDAP 和 SMB authentication 服务。简单的 LDAP bind 可能会暴露已配置的密码，而 NTLM authentication 会产生 challenge-response 数据；不要将这两种结果都描述为明文密码。

### SASL 机制选择

某些打印机 LDAP 客户端会从 LDAP 服务器通告的机制中进行选择。<sup>[[8]](#references)[[10]](#references)</sup> 研究表明，如果客户端愿意接受通告的明文 SASL 机制，它就可能发送密码；而在通常的 NTLM 协商中，只会产生 challenge-response 数据。<sup>[[9]](#references)[[10]](#references)</sup> 这是**客户端策略失效**，并非所有 SASL bind 都具有的特性：要求使用更强机制或固定预期 TLS 服务器的客户端则应安全失败。<sup>[[8]](#references)</sup> OpenLDAP 默认会禁用支持明文的 SASL 机制，因此标准守护进程并不能证明打印机上存在此行为。<sup>[[11]](#references)</sup>

---

## 近期 Pass-Back 漏洞（2024-2025）

Pass-back *并非*理论问题——厂商在 2024/2025 年持续发布公告，描述的正是这类攻击。

### Xerox VersaLink – CVE-2024-12510 和 CVE-2024-12511

Xerox VersaLink C70xx MFP 的固件版本 ≤ 57.69.91 存在问题，已认证的管理员（或默认凭据仍未更改时的任何人）可以：

* **CVE-2024-12510 – LDAP pass-back**：更改 LDAP 服务器地址并触发查询，导致设备将已配置的 Windows 凭据泄露到攻击者控制的主机。
* **CVE-2024-12511 – SMB/FTP pass-back**：通过 *scan-to-folder* 目标触发相同问题，泄露 NetNTLMv2 或 FTP 明文凭据。<sup>[[2]](#references)</sup>

一个简单的监听器，例如：

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

或者使用 rogue SMB server（`impacket-smbserver`）就足以收集凭据。  

### Canon imageRUNNER / imageCLASS – 2025 年 5 月 20 日公告

Canon 确认，数十个 Laser & MFP 产品系列存在 **SMTP/LDAP pass-back** 弱点。拥有管理员访问权限的攻击者可以修改服务器配置，并获取存储的 LDAP **或** SMTP 凭据（许多组织会使用特权账户来启用扫描到邮件功能）。<sup>[[3]](#references)</sup>

厂商的指导明确建议：

1. 尽快更新到已修复的固件。
2. 使用强且唯一的管理员密码。
3. 避免使用特权 AD 账户进行打印机集成。

---

### Brother 设备及 OEM 变体 – 通过序列号获取服务凭据的管理员访问权限

2025 年的一次协调披露展示了受影响 Brother 设备上一条特别实用的攻击链；部分漏洞也影响 OEM 型号，因此请根据厂商公告核实具体型号。在存在漏洞的固件上，未经身份验证的攻击者可以通过 HTTP/HTTPS/IPP 获取设备序列号；序列号也可能通过 SNMP 或 PJL 等管理协议获取。如果从未更改过出厂密码，攻击者便可根据序列号确定管理员密码。完成身份验证后，另一个独立的 pass-back 漏洞 CVE-2024-51984 会以明文形式泄露已配置的外部服务密码，例如 LDAP 或 FTP，从而将打印机管理权限转化为可重复使用的网络凭据。固件更新可以修复服务密码泄露问题，但对于此前生产的设备，操作人员仍需更换由序列号生成的初始管理员密码。<sup>[[6]](#references)</sup>

当前的 Metasploit 包含一个辅助模块，可通过 HTTP、SNMP 或 PJL 发现序列号，生成可能的初始密码，并可选择通过 Web 控制台验证该密码。`DiscoverSerialVia=AUTO` 会尝试受支持的发现方式；如果资产清单中已有序列号，则改为提供 `TargetSerial`。<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

仅将结果用于验证已获授权的资产。密码是否有效取决于具体型号，关键在于出厂管理员密码是否已更改。<sup>[[6]](#references)[[7]](#references)</sup>

---

## 自动化枚举 / Exploitation 工具

| 工具 | 用途 | 示例 |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | 滥用 PostScript/PJL/PCL、访问文件系统、检查默认凭据、*SNMP 发现*；参见 [PJL assessment](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | 通过 HTTP/HTTPS 收集配置（包括通讯录和 LDAP 凭据） | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | 运行 rogue authentication 服务，并从 SMB 回调中捕获 / relay NetNTLM | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | 发现序列号、推导候选出厂管理员密码，并验证 Web 控制台访问权限 | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## 加固与检测

1. **及时修补 / 更新固件** MFP（检查供应商 PSIRT 公告）。
2. **更换出厂管理员密码** – 单靠固件无法移除此前生产的受影响 Brother/OEM 设备上由序列号推导出的初始密码。<sup>[[6]](#references)</sup>
3. **最小权限服务帐户** – LDAP/SMB/SMTP 绝不要使用 Domain Admin；将权限限制在*只读* OU 范围内。
4. **限制管理访问** – 将打印机的 Web/IPP/SNMP 接口置于管理 VLAN 中，或通过 ACL/VPN 进行限制。
5. **限制打印机的出站流量** – 仅允许每台设备连接预期的 DC/LDAP、邮件、DNS/NTP、打印及扫描文件目标。Pass-back 需要回连攻击者指定的端点。
6. **禁用未使用的协议** – FTP、Telnet、raw-9100、较旧的 SSL 密码套件。
7. **启用审计日志** – 部分设备可以通过 syslog 记录 LDAP/SMTP 失败；关联分析异常的绑定请求。
8. **监控身份验证目标** – 当打印机向允许列表之外的主机发起 LDAP、SMB、SMTP 或 FTP 连接时发出警报，尤其是在管理登录或配置更改后立即发生的情况。
9. **使用 SNMPv3 或禁用 SNMP** – community `public` 经常会 leak 设备和序列号信息。

---



---



## References

- [1] [这只是一台打印机……最坏会发生什么？](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 多功能打印机：Pass-Back Attack 漏洞（已修复）](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004：生产型打印机、办公 / 小型办公室多功能打印机和激光打印机的漏洞缓解 / 修复](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [使用 Netcat 通过打印机获取域凭据](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [在渗透测试过程中利用多功能打印机](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [多款 Brother 设备：多个漏洞（已修复）](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit：Brother 默认管理员身份验证绕过模块](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – LDAP 身份验证方法和安全机制](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [LDAP passback Docker 服务器](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [LDAP pass back attack – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – SASL 安全属性](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
