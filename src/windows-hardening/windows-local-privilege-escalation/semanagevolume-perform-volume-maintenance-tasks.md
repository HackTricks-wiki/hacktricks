# SeManageVolumePrivilege: Accès brut au volume pour lecture arbitraire de fichiers

{{#include ../../banners/hacktricks-training.md}}

## Aperçu

Droit utilisateur Windows : Effectuer des tâches de maintenance de volume (constante : SeManageVolumePrivilege).

Les titulaires peuvent effectuer des opérations de volume bas niveau telles que la défragmentation, la création/suppression de volumes, et des E/S de maintenance. De façon critique pour les attaquants, ce droit permet d'ouvrir des handles de périphérique de volume brut (par ex., \\.\C:) et d'émettre des opérations d'E/S directes sur le disque qui contournent les ACL de fichiers NTFS. Avec un accès brut, vous pouvez copier les octets de n'importe quel fichier sur le volume même si l'accès est refusé par la DACL, en analysant hors ligne les structures du système de fichiers ou en utilisant des outils qui lisent au niveau des blocs/clusters.

Par défaut : Administrators sur les serveurs et les contrôleurs de domaine.

## Scénarios d'abus

- Lecture arbitraire de fichiers en contournant les ACL en lisant le périphérique disque (par ex., exfiltrer du matériel sensible protégé par le système tel que les clés privées de la machine sous %ProgramData%\Microsoft\Crypto\RSA\MachineKeys et %ProgramData%\Microsoft\Crypto\Keys, les ruchettes du Registre, les masterkeys DPAPI, le SAM, ntds.dit via VSS, etc.).
- Contourner les chemins verrouillés/privilégiés (C:\Windows\System32\…) en copiant les octets directement depuis le périphérique brut.
- Dans les environnements AD CS, exfiltrer le matériel de clé de la CA (magasin de clés machine) pour forger des “Golden Certificates” et usurper n'importe quel principal de domaine via PKINIT. Voir le lien ci-dessous.

Remarque : Vous avez toujours besoin d'un parseur des structures NTFS à moins de vous appuyer sur des outils d'assistance. De nombreux outils prêts à l'emploi abstraient l'accès brut.

## Techniques pratiques

- Ouvrir un handle de volume brut et lire des clusters :

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

- Utiliser un outil compatible NTFS pour récupérer des fichiers spécifiques à partir du volume brut :
- RawCopy/RawCopy64 (copie au niveau secteur des fichiers en cours d'utilisation)
- FTK Imager ou The Sleuth Kit (imagerie en lecture seule, puis carve des fichiers)
- vssadmin/diskshadow + shadow copy, puis copier le fichier cible depuis le snapshot (si vous pouvez créer VSS ; nécessite souvent des privilèges admin mais est fréquemment accessible aux mêmes opérateurs qui détiennent SeManageVolumePrivilege)

Chemins sensibles typiques à cibler :
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (secrets locaux)
- C:\Windows\NTDS\ntds.dit (contrôleurs de domaine – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificats/CRL de la CA ; les clés privées se trouvent dans le magasin de clés machine ci‑dessus)

## AD CS — lien : Forger un Golden Certificate

Si vous pouvez lire la clé privée de la CA d’entreprise dans le magasin de clés machine, vous pouvez forger des certificats client‑auth pour des principals arbitraires et vous authentifier via PKINIT/Schannel. Cela est souvent appelé Golden Certificate. Voir :

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Détection et durcissement

- Limiter strictement l'attribution de SeManageVolumePrivilege (Perform volume maintenance tasks) aux seuls administrateurs de confiance.
- Surveiller l'utilisation des privilèges sensibles et les ouvertures de handles de processus vers des objets de périphérique comme \\.\C:, \\.\PhysicalDrive0.
- Préférer des clés CA protégées par HSM/TPM ou DPAPI-NG afin que des lectures brutes de fichiers ne permettent pas de récupérer du matériel clé exploitable.
- Garder les chemins d'upload, temporaires et d'extraction non exécutables et séparés (défense en contexte web qui est souvent couplée à cette chaîne post‑exploitation).

## Références

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
