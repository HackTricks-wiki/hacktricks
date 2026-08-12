# SeManageVolumePrivilege: Missbrauch der Volume-Wartung und Validierung des Raw-Zugriffs

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Windows-Benutzerrecht: Volume-Wartungsaufgaben ausführen (Konstante: SeManageVolumePrivilege).

Dieses Recht autorisiert Volume-Wartungsvorgänge wie Defragmentierung sowie das Erstellen oder Entfernen von Volumes. Microsoft warnt, dass ein Inhaber möglicherweise Dateien in Speicher erweitern kann, der andere Daten enthält, und anschließend die erlangten Bytes lesen oder ändern kann.<sup>[[1]](#references)</sup>

Setze den Besitz von `SeManageVolumePrivilege` nicht mit garantiertem Raw-Disk-Zugriff gleich. Microsoft dokumentiert, dass das Öffnen eines physischen Datenträgers oder Volumes über `CreateFile` für direkten Zugriff administrative Berechtigungen erfordert und dass weiterhin normale Objekt-/Gerätezugriffsprüfungen gelten. Teste bei einem bestimmten Build oder Produkt, ob Token, Geräte-ACL, angeforderter Zugriff, Share-Flags und Volume-Status einen Raw-Handle erlauben, bevor du beliebigen Dateizugriff zum Lesen behauptest.<sup>[[3]](#references)</sup>

Standard: Administrators auf Servern und Domain Controllern.<sup>[[1]](#references)</sup>

## Missbrauchsszenarien

- Wenn das Konto tatsächlich einen lesbaren Raw-Volume-Handle erhalten kann, kann ein NTFS-fähiger Parser dateibezogene ACLs umgehen und geschützte oder gesperrte Dateien aus belegten Clustern wiederherstellen.
- Mögliche Ziele umfassen gesperrte oder durch ACLs geschützte Inhalte unter `C:\Windows\System32`, Registry-Hives, DPAPI-Master-Keys, die SAM und – sofern separat über einen Snapshot oder ein Offline-Volume zugänglich – `ntds.dit`.
- Auf Hosts mit Certificate Services befinden sich nützliche Speicherorte für Software-Schlüssel unter `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` und `%ProgramData%\Microsoft\Crypto\Keys`; das Wiederherstellen einer Datei ist nur dann hilfreich, wenn das darin enthaltene Schlüsselmaterial exportierbar ist und zusätzlich entschlüsselt werden kann.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Auf einem AD-CS-Host kann ein erfolgreich wiederhergestellter **exportierbarer, softwarebasierter** privater CA-Schlüssel den Missbrauch von Golden Certificates ermöglichen. Hardwarebasierte oder nicht exportierbare Schlüsselkonzepte ändern diesen Pfad.<sup>[[2]](#references)</sup>

Hinweis: Du benötigst weiterhin einen Parser für NTFS-Strukturen, sofern du dich nicht auf Hilfsprogramme verlässt. Viele handelsübliche Tools abstrahieren den Raw-Zugriff.

## Praktische Techniken

- Einen Raw-Volume-Handle öffnen und Cluster lesen:

<details>
<summary>Zum Erweitern klicken</summary>
```powershell
# Validation attempt: current Windows versions normally require an administrative token
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
static void Main(string[] a){
using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
fs.Position = 0x100000; // seek
var buf = new byte[4096];
fs.Read(buf,0,buf.Length);
File.WriteAllBytes("C:\\temp\\blk.bin", buf);
}
}
}
```
</details>

- Verwende ein NTFS-fähiges Tool, um bestimmte Dateien aus dem Raw-Volume wiederherzustellen:
- RawCopy/RawCopy64 (sektorbasierte Kopie verwendeter Dateien)
- FTK Imager oder The Sleuth Kit (schreibgeschütztes Imaging, anschließend Dateien carven)
- vssadmin/diskshadow + Shadow Copy und anschließend die Zieldatei aus dem Snapshot kopieren (wenn du VSS erstellen kannst; erfordert häufig Administratorrechte, ist aber für dieselben Operatoren, die SeManageVolumePrivilege besitzen, oft verfügbar)

Typische sensible Pfade als Ziel:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokale Secrets)
- C:\Windows\NTDS\ntds.dit (Domain Controller – über Shadow Copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA-Zertifikate/CRLs; private Schlüssel befinden sich im oben genannten Machine Key Store)

## AD CS: Forging a Golden Certificate

Wenn du den privaten Schlüssel der Enterprise CA aus dem Machine Key Store lesen kannst, kannst du Client-Auth-Zertifikate für beliebige Principals fälschen und dich über PKINIT/Schannel authentifizieren. Dies wird häufig als Golden Certificate bezeichnet.<sup>[[2]](#references)</sup> Siehe:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Abschnitt: „Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1“).

## Erkennung und Hardening

- Beschränke die Zuweisung von SeManageVolumePrivilege (Perform volume maintenance tasks) strikt auf vertrauenswürdige Administratoren.
- Überwache die Verwendung sensibler Berechtigungen und das Öffnen von Prozess-Handles für Geräteobjekte wie \\.\C:, \\.\PhysicalDrive0.
- Bevorzuge ordnungsgemäß konfigurierte, durch HSM oder TPM geschützte und nicht exportierbare CA-Schlüssel, damit das Kopieren einer Schlüsselcontainerdatei nicht ausreicht, um verwendbares privates Schlüsselmaterial wiederherzustellen.
- Bei Application-Secrets außerhalb des CA-Schlüsselpfads können DPAPI oder DPAPI-NG eine kopierte Datendatei unzureichend machen, indem sie diese an einen Benutzer, eine Maschine, eine Gruppe oder einen anderen autorisierten Principal binden. Dies schützt keinen Klartext, auf den der kompromittierte Principal bereits zugreifen kann.<sup>[[4]](#references)</sup>
- Halte Upload-, Temp- und Extraktionspfade nicht ausführbar und voneinander getrennt (eine Web-Context-Abwehr, die häufig mit dieser post-exploitation chain kombiniert wird).

## References

- [1] [Microsoft – Aufgaben zur Volume-Wartung durchführen (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege zum Lesen des CA-Schlüssels verwendet → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft – `CreateFile` für physische Datenträger und Volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft – Cryptography API: Next Generation und DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
