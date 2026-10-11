# SeManageVolumePrivilege: Missbrauch der Volume-Wartung und Validierung des Raw-Zugriffs

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Windows-Benutzerrecht: Wartungsaufgaben für Volumes durchführen (Konstante: SeManageVolumePrivilege).

Dieses Recht erlaubt Wartungsvorgänge für Volumes, etwa die Defragmentierung sowie das Erstellen oder Entfernen von Volumes. Microsoft warnt, dass ein Inhaber möglicherweise Dateien in Speicherbereiche mit anderen Daten erweitern und anschließend die dort befindlichen Bytes lesen oder ändern kann.<sup>[[1]](#references)</sup>

Setze den Besitz von `SeManageVolumePrivilege` nicht mit garantiertem Raw-Disk-Zugriff gleich. Microsoft dokumentiert, dass zum direkten Öffnen einer physischen Festplatte oder eines Volumes über `CreateFile` administrative Berechtigungen erforderlich sind und weiterhin die normalen Zugriffsprüfungen für Objekte und Geräte gelten. Prüfe für den jeweiligen Build oder das jeweilige Produkt, ob Token, Geräte-ACL, angeforderte Zugriffsrechte, Freigabeflags und Volume-Status einen Raw-Handle erlauben, bevor du beliebiges Lesen von Dateien behauptest.<sup>[[3]](#references)</sup>

Standard: Administratoren auf Servern und Domänencontrollern.<sup>[[1]](#references)</sup>

## Missbrauchsszenarien

- Wenn das Konto tatsächlich einen lesbaren Raw-Volume-Handle erhalten kann, kann ein NTFS-fähiger Parser dateibasierte ACLs umgehen und geschützte oder gesperrte Dateien aus belegten Clustern wiederherstellen.
- Mögliche Ziele sind gesperrte oder durch ACLs geschützte Inhalte unter `C:\Windows\System32`, Registry-Hives, DPAPI-Masterschlüssel, die SAM und – sofern separat über einen Snapshot oder ein Offline-Volume zugänglich – `ntds.dit`.
- Auf Hosts mit Zertifikatdiensten befinden sich nützliche Speicherorte für Softwareschlüssel unter `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` und `%ProgramData%\Microsoft\Crypto\Keys`. Das Wiederherstellen einer Datei ist nur dann hilfreich, wenn sich ihr Schlüsselmaterial exportieren und außerdem entschlüsseln lässt.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Auf einem AD-CS-Host kann ein erfolgreich wiederhergestellter **exportierbarer, softwarebasierter** privater CA-Schlüssel den Missbrauch von Golden Certificates ermöglichen. Hardwarebasierte oder nicht exportierbare Schlüsselkonfigurationen verändern diesen Angriffsweg.<sup>[[2]](#references)</sup>
- Manche Tools zur Volume-Wartung verwenden `FSCTL_SD_GLOBAL_CHANGE`, um Dateisystem-ACL-Einträge zu ersetzen, sofern dieser Vorgang zulässig ist. Dadurch werden Zugriffskontrollen geändert, statt Raw-Blöcke passiv zu lesen. Das kann große Teile eines Volumes betreffen und muss anhand des tatsächlichen Token- und Geräteverhaltens überprüft werden. Der [Quellcode des Tools](https://github.com/CsEnox/SeManageVolumeExploit) zeigt diesen konkreten Mechanismus; der Besitz des Privilegs allein beweist nicht, dass er erfolgreich sein wird.
- Durch ACL-Änderungen erlangter Dateizugriff entschlüsselt keine EFS-verschlüsselte Datei. Für den Klartext wird weiterhin ein passender privater Benutzer- oder Wiederherstellungsschlüssel benötigt. Ebenso setzt der Export eines softwarebasierten CA-Schlüssels mit [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) voraus, dass der Schlüssel lokal verfügbar, exportierbar und zugänglich ist.

Hinweis: Du benötigst weiterhin einen Parser für NTFS-Strukturen, sofern du nicht auf Hilfsprogramme zurückgreifst. Viele handelsübliche Tools abstrahieren den Raw-Zugriff.

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

- Verwende ein NTFS-fähiges Tool, um bestimmte Dateien aus einem Raw Volume wiederherzustellen:
  - RawCopy/RawCopy64 (Sektorkopie aktuell verwendeter Dateien)
  - FTK Imager oder The Sleuth Kit (schreibgeschütztes Imaging, danach Dateien extrahieren)
  - vssadmin/diskshadow + Shadow Copy, dann die Zieldatei aus dem Snapshot kopieren (wenn du VSS erstellen kannst; erfordert oft Adminrechte, ist aber häufig für dieselben Operatoren verfügbar, die SeManageVolumePrivilege besitzen)

Typische sensible Pfade:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokale Secrets)
- C:\Windows\NTDS\ntds.dit (Domain Controller – über Shadow Copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA-Zertifikate/CRLs; private Schlüssel befinden sich im oben genannten Machine Key Store)

## AD CS-Bezug: Ein Golden Certificate fälschen

Wenn du den privaten Schlüssel der Enterprise CA aus dem Machine Key Store lesen kannst, kannst du Client-Auth-Zertifikate für beliebige Principals fälschen und dich über PKINIT/Schannel authentifizieren. Dies wird oft als Golden Certificate bezeichnet.<sup>[[2]](#references)</sup> Siehe:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Abschnitt: „Zertifikate mit gestohlenen CA-Zertifikaten fälschen (Golden Certificate) – DPERSIST1“).

## Erkennung und Härtung

- Beschränke die Zuweisung von SeManageVolumePrivilege (Perform volume maintenance tasks) strikt auf vertrauenswürdige Admins.
- Überwache Sensitive Privilege Use und das Öffnen von Prozess-Handles für Geräteobjekte wie \\.\C:, \\.\PhysicalDrive0.
- Bevorzuge korrekt konfigurierte, durch HSM oder TPM geschützte, nicht exportierbare CA-Schlüssel, damit eine kopierte Schlüsselcontainerdatei nicht ausreicht, um verwendbares privates Schlüsselmaterial wiederherzustellen.
- Für Anwendungs-Secrets außerhalb des CA-Schlüsselpfads können DPAPI oder DPAPI-NG dafür sorgen, dass eine kopierte Datendatei nicht ausreicht, indem sie an einen Benutzer, einen Computer, eine Gruppe oder einen anderen autorisierten Principal gebunden wird. Das schützt keine Klartextdaten, auf die der kompromittierte Principal bereits zugreifen kann.<sup>[[4]](#references)</sup>
- Halte Upload-, Temp- und Extraktionspfade nicht ausführbar und getrennt (eine Web-Kontext-Abwehrmaßnahme, die häufig mit dieser Post-Exploitation-Kette kombiniert wird).

## References

- [1] [Microsoft – Aufgaben zur Volume-Wartung ausführen (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege zum Lesen des CA-Schlüssels verwendet → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` für physische Datenträger und Volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation und DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
