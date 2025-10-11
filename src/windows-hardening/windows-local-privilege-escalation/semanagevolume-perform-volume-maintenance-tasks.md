# SeManageVolumePrivilege: Accès brut au volume pour la lecture arbitraire de fichiers

{{#include ../../banners/hacktricks-training.md}}

## Aperçu

Droit utilisateur Windows : Perform volume maintenance tasks (constante : SeManageVolumePrivilege).

Les titulaires peuvent effectuer des opérations de volume bas niveau telles que la défragmentation, la création/suppression de volumes et les E/S de maintenance. De façon critique pour les attaquants, ce droit permet d'ouvrir des handles de périphérique de volume brut (par ex., \\.\C:) et d'émettre des E/S disque directes qui contournent les ACLs de fichiers NTFS. Avec un accès brut, vous pouvez copier les octets de n'importe quel fichier sur le volume même si l'accès est refusé par la DACL, en analysant hors ligne les structures du système de fichiers ou en utilisant des outils qui lisent au niveau bloc/cluster.

Par défaut : Administrators sur les serveurs et les contrôleurs de domaine.

## Scénarios d'abus

- Lecture arbitraire de fichiers en contournant les ACLs en lisant le périphérique disque (par ex., exfiltrer des éléments sensibles protégés par le système tels que les clés privées machine sous %ProgramData%\Microsoft\Crypto\RSA\MachineKeys et %ProgramData%\Microsoft\Crypto\Keys, les ruche du registre, les DPAPI masterkeys, SAM, ntds.dit via VSS, etc.).
- Contourner des chemins verrouillés/privilegiés (C:\Windows\System32\…) en copiant directement les octets depuis le périphérique brut.
- Dans des environnements AD CS, exfiltrer le matériel clé de la CA (machine key store) pour forger des “Golden Certificates” et usurper n'importe quel principal de domaine via PKINIT. Voir le lien ci-dessous.

Remarque : Vous aurez toujours besoin d'un parseur pour les structures NTFS sauf si vous comptez sur des outils d'assistance. Beaucoup d'outils prêts à l'emploi abstraient l'accès brut.

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

- Utiliser un outil compatible NTFS pour récupérer des fichiers spécifiques depuis un volume brut :
- RawCopy/RawCopy64 (copie au niveau des secteurs des fichiers en cours d'utilisation)
- FTK Imager or The Sleuth Kit (imagerie en lecture seule, puis extraction des fichiers)
- vssadmin/diskshadow + shadow copy, puis copier le fichier cible depuis le snapshot (si vous pouvez créer VSS ; requiert souvent des droits admin mais est couramment disponible aux mêmes opérateurs qui détiennent SeManageVolumePrivilege)

Chemins sensibles typiques à cibler :
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

Si vous pouvez lire la clé privée de l'Enterprise CA depuis le magasin de clés machine, vous pouvez forger des certificats d'authentification client pour des principaux arbitraires et vous authentifier via PKINIT/Schannel. This is often referred to as a Golden Certificate. Voir :

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section : “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Détection et durcissement

- Limiter fortement l'attribution de SeManageVolumePrivilege (Perform volume maintenance tasks) aux seuls administrateurs de confiance.
- Surveiller l'utilisation de privilèges sensibles et les ouvertures de handles de processus vers des objets de périphérique comme \\.\C:, \\.\PhysicalDrive0.
- Préférer des clés CA protégées par HSM/TPM ou DPAPI-NG afin que les lectures de fichiers bruts ne puissent pas récupérer le matériel clé sous une forme exploitable.
- Garder les répertoires d'uploads, temporaires et d'extraction non exécutables et séparés (mesure de défense en contexte web qui accompagne souvent cette chaîne post‑exploitation).

## Références

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
