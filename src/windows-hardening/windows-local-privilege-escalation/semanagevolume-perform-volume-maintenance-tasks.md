# SeManageVolumePrivilege: Rohzugriff auf Volumes für beliebiges Dateilesen

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Windows-Benutzerrecht: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Inhaber können Low-Level-Volume-Operationen durchführen, wie Defragmentierung, Erstellen/Entfernen von Volumes und Wartungs-IO. Für Angreifer besonders wichtig: Dieses Recht erlaubt das Öffnen von Roh-Volume-Gerätehandles (z. B. \\.\C:) und das Ausführen direkter Festplatten-I/O-Operationen, die NTFS-Datei-ACLs umgehen. Mit Rohzugriff können Sie die Bytes beliebiger Dateien auf dem Volume kopieren, selbst wenn der Zugriff durch DACL verweigert wird, indem Sie die Dateisystemstrukturen offline parsen oder Hilfsprogramme verwenden, die auf Block-/Cluster-Ebene lesen.

Standardmäßig: Administratoren auf Servern und Domänencontrollern.

## Missbrauchsszenarien

- Beliebiges Datei-Lesen zur Umgehung von ACLs durch Lesen des Datenträgers (z. B. Exfiltration sensibler systemgeschützter Daten wie Maschinen-Private-Keys unter %ProgramData%\Microsoft\Crypto\RSA\MachineKeys und %ProgramData%\Microsoft\Crypto\Keys, Registry-Hives, DPAPI-Masterkeys, SAM, ntds.dit via VSS, etc.).
- Gesperrte/privilegierte Pfade (C:\Windows\System32\…) umgehen, indem Bytes direkt vom Rohgerät kopiert werden.
- In AD CS-Umgebungen das CA-Schlüsselsmaterial (machine key store) exfiltrieren, um “Golden Certificates” zu erstellen und sich mittels PKINIT als beliebigen Domänenprinzipal auszugeben. Siehe Link unten.

Hinweis: Sie benötigen weiterhin einen Parser für NTFS-Strukturen, sofern Sie nicht auf Hilfsprogramme zurückgreifen. Viele Standardtools abstrahieren den Rohzugriff.

## Praktische Techniken

- Roh-Volume-Handle öffnen und Cluster lesen:

<details>
<summary>Klicken zum Erweitern</summary>
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

- Verwende ein NTFS-kompatibles Tool, um bestimmte Dateien von einem rohen Volume wiederherzustellen:
- RawCopy/RawCopy64 (sektorweise Kopie von in Benutzung befindlichen Dateien)
- FTK Imager or The Sleuth Kit (schreibgeschütztes Imaging, dann Dateien carven)
- vssadmin/diskshadow + shadow copy, dann die Zieldatei aus dem Snapshot kopieren (falls du VSS erstellen kannst; erfordert oft Admin-Rechte, ist aber häufig für dieselben Operatoren verfügbar, die SeManageVolumePrivilege haben)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS-Bezug: Forging a Golden Certificate

Wenn du den Private Key der Enterprise CA aus dem machine key store auslesen kannst, kannst du client‑auth-Zertifikate für beliebige Principals fälschen und dich via PKINIT/Schannel authentifizieren. Das wird oft als Golden Certificate bezeichnet. Siehe:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Abschnitt: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Erkennung und Härtung

- Beschränke die Zuweisung von SeManageVolumePrivilege (Perform volume maintenance tasks) strikt auf vertrauenswürdige Admins.
- Überwache Sensitive Privilege Use und das Öffnen von Prozess-Handles zu Device-Objekten wie \\.\C:, \\.\PhysicalDrive0.
- Bevorzuge HSM/TPM-geschützte CA-Keys oder DPAPI-NG, sodass rohe Dateilesungen kein Schlüsselmaterial in brauchbarer Form wiederherstellen können.
- Halte Upload-, Temp- und Extraction-Pfade nicht ausführbar und getrennt (Web-Kontext-Verteidigung, die oft mit dieser Kette post‑exploitation kombiniert wird).

## Referenzen

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
