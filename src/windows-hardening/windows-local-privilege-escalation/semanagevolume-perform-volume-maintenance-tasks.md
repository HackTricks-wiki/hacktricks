# SeManageVolumePrivilege: Rohzugriff auf Volumes für beliebiges Dateilesen

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Windows user right: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Inhaber können Low-Level-Volume-Operationen durchführen, wie Defragmentierung, Erstellen/Entfernen von Volumes und Wartungs-IO. Für Angreifer kritisch: Dieses Recht erlaubt das Öffnen roher Volume-Geräte-Handles (z. B. \\.\C:) und das Ausführen direkter Disk-I/O-Operationen, die NTFS-Datei-ACLs umgehen. Mit rohem Zugriff kann man Bytes jeder Datei auf dem Volume kopieren, selbst wenn der Zugriff durch DACL verweigert wird, indem man die Dateisystemstrukturen offline parst oder Tools verwendet, die auf Block-/Cluster-Ebene lesen.

Default: Administrators on servers and domain controllers.

## Missbrauchsszenarien

- Beliebiges Dateilesen unter Umgehung von ACLs durch Lesen des Disk-Geräts (z. B. Exfiltrieren sensibler systemgeschützter Daten wie lokale Maschinenprivatschlüssel unter %ProgramData%\Microsoft\Crypto\RSA\MachineKeys und %ProgramData%\Microsoft\Crypto\Keys, Registry-Hives, DPAPI-Masterkeys, SAM, ntds.dit via VSS usw.).
- Umgehen gesperrter/privilegierter Pfade (C:\Windows\System32\…) durch direktes Kopieren von Bytes vom raw device.
- In AD CS-Umgebungen: Exfiltrieren des CA-Key-Materials (machine key store), um “Golden Certificates” zu erstellen und beliebige Domain-Prinzipale via PKINIT zu impersonifizieren. Siehe Link unten.

Hinweis: Sie benötigen weiterhin einen Parser für NTFS-Strukturen, es sei denn, Sie verlassen sich auf Hilfswerkzeuge. Viele handelsübliche Tools abstrahieren den rohen Zugriff.

## Praktische Techniken

- Open a raw volume handle and read clusters:

<details>
<summary>Click to expand</summary>
```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
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

- Verwende ein NTFS-fähiges Tool, um bestimmte Dateien von einem rohen Volume wiederherzustellen:
- RawCopy/RawCopy64 (sektorweises Kopieren von in Benutzung befindlichen Dateien)
- FTK Imager or The Sleuth Kit (schreibgeschützte Image-Erstellung, dann Datei-Carving)
- vssadmin/diskshadow + shadow copy, dann die Ziel-Datei aus dem Snapshot kopieren (wenn du VSS erstellen kannst; erfordert oft Admin, ist aber häufig für dieselben Operatoren verfügbar, die das SeManageVolumePrivilege halten)

Typische sensible Pfade als Ziel:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokale Geheimnisse)
- C:\Windows\NTDS\ntds.dit (Domain Controller – via Schattenkopie)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys befinden sich im oben genannten Machine Key Store)

## AD CS tie‑in: Forging a Golden Certificate

Wenn du den Private Key der Enterprise CA aus dem Machine Key Store auslesen kannst, kannst du client‑auth Zertifikate für beliebige Principals fälschen und dich via PKINIT/Schannel authentifizieren. Dies wird häufig als Golden Certificate bezeichnet. Siehe:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Abschnitt: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Erkennung und Härtung

- Beschränke die Zuweisung von SeManageVolumePrivilege (Perform volume maintenance tasks) strikt auf vertrauenswürdige Admins.
- Überwache Sensitive Privilege Use und Prozesshandle-Öffnungen zu Device-Objekten wie \\.\C:, \\.\PhysicalDrive0.
- Bevorzuge HSM/TPM-geschützte CA-Keys oder DPAPI-NG, damit Rohdatenlesezugriffe Schlüsselmaterial nicht in nutzbarer Form rekonstruieren können.
- Halte Upload-, Temp- und Extraktionspfade nicht-ausführbar und getrennt (Web-Kontext-Defense, die oft mit dieser Chain post‑exploitation kombiniert wird).

## Referenzen

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
