# SeManageVolumePrivilege: Raw volume access zum Lesen beliebiger Dateien

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Windows-Benutzerrecht: Volume-Wartungsaufgaben durchführen (Konstante: SeManageVolumePrivilege).

Inhaber können Low-Level-Volume-Operationen wie Defragmentierung, das Erstellen/Entfernen von Volumes und Wartungs-I/O durchführen. Für Angreifer besonders relevant ist, dass dieses Recht das Öffnen von Raw-Volume-Device-Handles (z. B. \\.\C:) und das Ausführen direkter Festplatten-I/O ermöglicht, wodurch NTFS-Datei-ACLs umgangen werden. Mit Raw-Zugriff können die Bytes jeder Datei auf dem Volume kopiert werden, selbst wenn der Zugriff durch die DACL verweigert wird, indem die Dateisystemstrukturen offline analysiert oder Tools verwendet werden, die auf Block-/Cluster-Ebene lesen.

Standard: Administrators auf Servern und Domain Controllern.<sup>[[1]](#references)</sup>

## Missbrauchsszenarien

- Beliebiges Lesen von Dateien unter Umgehung von ACLs durch das Lesen des Festplattengeräts (z. B. das Exfiltrieren von vertraulichem, systemgeschütztem Material wie privaten Maschinenschlüsseln unter %ProgramData%\Microsoft\Crypto\RSA\MachineKeys und %ProgramData%\Microsoft\Crypto\Keys, Registry-Hives, DPAPI-Masterkeys, SAM, ntds.dit über VSS usw.).
- Umgehen gesperrter/privilegierter Pfade (C:\Windows\System32\…) durch direktes Kopieren von Bytes vom Raw-Gerät.
- In AD CS-Umgebungen das Exfiltrieren des Schlüsselmaterials der CA (Maschinenschlüsselspeicher), um „Golden Certificates“ auszustellen und sich über PKINIT als beliebiger Domain Principal auszugeben. Siehe den untenstehenden Link.<sup>[[2]](#references)</sup>

Hinweis: Du benötigst weiterhin einen Parser für NTFS-Strukturen, sofern du nicht auf Hilfstools zurückgreifst. Viele frei verfügbare Tools abstrahieren den Raw-Zugriff.

## Praktische Techniken

- Einen Raw-Volume-Handle öffnen und Cluster lesen:

<details>
<summary>Zum Erweitern anklicken</summary>
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

- Verwende ein NTFS-aware tool, um bestimmte Dateien aus dem raw volume wiederherzustellen:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager oder The Sleuth Kit (read-only imaging, anschließend Dateien carven)
- vssadmin/diskshadow + shadow copy, anschließend die Zieldatei aus dem Snapshot kopieren (falls du VSS erstellen kannst; erfordert häufig Administratorrechte, ist aber für dieselben Operatoren, die SeManageVolumePrivilege besitzen, üblicherweise verfügbar)

Typische sensitive Pfade als Ziel:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokale Secrets)
- C:\Windows\NTDS\ntds.dit (Domain Controller – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA-Zertifikate/CRLs; private keys befinden sich im oben genannten machine key store)

## AD CS: Forging a Golden Certificate

Wenn du den private key der Enterprise CA aus dem machine key store lesen kannst, kannst du client-auth certificates für beliebige Principals fälschen und dich via PKINIT/Schannel authentifizieren. Dies wird häufig als Golden Certificate bezeichnet.<sup>[[2]](#references)</sup> Siehe:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Abschnitt: „Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1“).

## Erkennung und Hardening

- Beschränke die Zuweisung von SeManageVolumePrivilege (Perform volume maintenance tasks) strikt auf vertrauenswürdige Administratoren.
- Überwache Sensitive Privilege Use sowie das Öffnen von process handles zu device objects wie \\.\C:, \\.\PhysicalDrive0.
- Bevorzuge HSM/TPM-backed CA keys oder DPAPI-NG, damit raw file reads kein verwendbares key material wiederherstellen können.
- Halte Upload-, Temp- und Extraction-Pfade non-executable und getrennt (web context defense, die häufig mit dieser post-exploitation chain kombiniert wird).

## Referenzen

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
