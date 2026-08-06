# SeManageVolumePrivilege : accès au volume brut pour la lecture arbitraire de fichiers

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

Droit utilisateur Windows : effectuer des tâches de maintenance des volumes (constante : SeManageVolumePrivilege).

Les détenteurs de ce droit peuvent effectuer des opérations de bas niveau sur les volumes, comme la défragmentation, la création ou la suppression de volumes et les opérations d’E/S de maintenance. Pour les attackers, ce droit permet notamment d’ouvrir des handles de périphériques de volume brut (par exemple, \\.\C:) et d’émettre des opérations d’E/S directes sur le disque, en contournant les ACL de fichiers NTFS. Avec un accès brut, il est possible de copier les octets de n’importe quel fichier du volume, même si l’accès est refusé par la DACL, en analysant les structures du système de fichiers offline ou en utilisant des outils qui lisent les données au niveau des blocs ou des clusters.

Par défaut : Administrators sur les serveurs et les domain controllers.<sup>[[1]](#references)</sup>

## Scénarios d’abus

- Lecture arbitraire de fichiers contournant les ACL en lisant le périphérique disque (par exemple, exfiltrer des éléments sensibles protégés par le système, comme les clés privées de la machine dans %ProgramData%\Microsoft\Crypto\RSA\MachineKeys et %ProgramData%\Microsoft\Crypto\Keys, les registry hives, les DPAPI masterkeys, SAM, ntds.dit via VSS, etc.).
- Contournement des chemins verrouillés ou privilégiés (C:\Windows\System32\…) en copiant directement les octets depuis le périphérique brut.
- Dans les environnements AD CS, exfiltration du matériel de clé de la CA (machine key store) afin de créer des « Golden Certificates » et d’usurper l’identité de n’importe quel principal du domaine via PKINIT. Voir le lien ci-dessous.<sup>[[2]](#references)</sup>

Remarque : vous avez toujours besoin d’un parser pour les structures NTFS, sauf si vous utilisez des outils auxiliaires. De nombreux outils disponibles sur le marché abstraient l’accès brut.

## Techniques pratiques

- Ouvrir un handle de volume brut et lire les clusters :

<details>
<summary>Cliquez pour développer</summary>
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

- Utilisez un outil compatible NTFS pour récupérer des fichiers spécifiques depuis le volume brut :
- RawCopy/RawCopy64 (copie au niveau des secteurs de fichiers utilisés)
- FTK Imager ou The Sleuth Kit (imagerie en lecture seule, puis carving des fichiers)
- vssadmin/diskshadow + shadow copy, puis copiez le fichier cible depuis le snapshot (si vous pouvez créer un VSS ; cela nécessite souvent des privilèges d’administrateur, mais est généralement accessible aux mêmes opérateurs qui détiennent SeManageVolumePrivilege)

Chemins sensibles typiques à cibler :
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (secrets locaux)
- C:\Windows\NTDS\ntds.dit (contrôleurs de domaine – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificats/CRL de l’AC ; les clés privées se trouvent dans le magasin de clés machine ci-dessus)

## AD CS tie‑in : Forging a Golden Certificate

Si vous pouvez lire la clé privée de l’Enterprise CA depuis le magasin de clés machine, vous pouvez forger des certificats d’authentification client pour des principaux arbitraires et vous authentifier via PKINIT/Schannel. Cela est souvent appelé un Golden Certificate.<sup>[[2]](#references)</sup> Voir :

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section : « Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1 »).

## Detection and hardening

- Limitez strictement l’attribution de SeManageVolumePrivilege (Perform volume maintenance tasks) aux seuls administrateurs de confiance.
- Surveillez Sensitive Privilege Use et les ouvertures de handles de processus vers des objets de périphérique tels que \\.\C:, \\.\PhysicalDrive0.
- Préférez des clés d’AC protégées par HSM/TPM ou DPAPI-NG afin que la lecture brute des fichiers ne permette pas de récupérer le matériel cryptographique sous une forme exploitable.
- Conservez les chemins d’upload, temporaires et d’extraction comme non exécutables et séparés (défense du contexte web qui accompagne souvent cette chaîne post‑exploitation).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
