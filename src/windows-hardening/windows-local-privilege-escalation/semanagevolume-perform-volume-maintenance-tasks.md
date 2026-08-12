# SeManageVolumePrivilege : abus de la maintenance des volumes et validation de l’accès brut

{{#include ../../banners/hacktricks-training.md}}

## Présentation

Droit utilisateur Windows : effectuer des tâches de maintenance des volumes (constante : SeManageVolumePrivilege).

Ce droit autorise les opérations de maintenance des volumes, telles que la défragmentation et la création ou la suppression de volumes. Microsoft avertit qu’un détenteur peut être en mesure d’étendre des fichiers dans un espace de stockage contenant d’autres données, puis de lire ou de modifier les octets ainsi acquis.<sup>[[1]](#references)</sup>

Ne considérez pas la possession de `SeManageVolumePrivilege` comme un accès garanti au disque brut. Microsoft précise que l’ouverture d’un disque physique ou d’un volume via `CreateFile` pour un accès direct nécessite des privilèges administratifs, et que les contrôles d’accès normaux aux objets et aux périphériques s’appliquent toujours. Sur une version ou un produit donné, vérifiez si le token, l’ACL du périphérique, l’accès demandé, les indicateurs de partage et l’état du volume permettent d’obtenir un handle brut avant d’affirmer qu’une lecture arbitraire de fichiers est possible.<sup>[[3]](#references)</sup>

Par défaut : Administrators sur les serveurs et les contrôleurs de domaine.<sup>[[1]](#references)</sup>

## Scénarios d’abus

- Si le compte peut effectivement obtenir un handle lisible vers le volume brut, un parseur compatible avec NTFS peut contourner les ACL appliquées aux fichiers et récupérer des fichiers protégés ou verrouillés depuis les clusters alloués.
- Les cibles possibles incluent le contenu verrouillé ou protégé par une ACL sous `C:\Windows\System32`, les ruches du registre, les clés principales DPAPI, la SAM et — lorsqu’il est accessible séparément via un snapshot ou un volume hors ligne — `ntds.dit`.
- Sur les hôtes de services de certificats, les emplacements utiles des clés logicielles incluent `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` et `%ProgramData%\Microsoft\Crypto\Keys` ; la récupération d’un fichier n’est utile que si son matériel de clé est exportable et peut également être déchiffré.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Sur un hôte AD CS, une clé privée d’AC **exportable et stockée dans un logiciel** récupérée avec succès peut permettre un abus de type Golden Certificate. Les conceptions utilisant des clés protégées par matériel ou non exportables modifient cette voie d’exploitation.<sup>[[2]](#references)</sup>

Remarque : vous avez toujours besoin d’un parseur pour les structures NTFS, sauf si vous utilisez des outils auxiliaires. De nombreux outils disponibles dans le commerce abstraient l’accès brut.

## Techniques pratiques

- Ouvrir un handle vers un volume brut et lire les clusters :

<details>
<summary>Cliquez pour développer</summary>
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

- Utiliser un outil compatible avec NTFS pour récupérer des fichiers spécifiques depuis le volume brut :
- RawCopy/RawCopy64 (copie au niveau des secteurs de fichiers en cours d’utilisation)
- FTK Imager ou The Sleuth Kit (création d’une image en lecture seule, puis récupération des fichiers)
- vssadmin/diskshadow + shadow copy, puis copier le fichier cible depuis le snapshot (si vous pouvez créer un VSS ; cela nécessite souvent des privilèges d’administrateur, mais ceux-ci sont généralement disponibles pour les mêmes opérateurs qui détiennent SeManageVolumePrivilege)

Chemins sensibles typiques à cibler :
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (secrets locaux)
- C:\Windows\NTDS\ntds.dit (contrôleurs de domaine – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificats/CRL de l’AC ; les clés privées se trouvent dans le magasin de clés de l’ordinateur indiqué ci-dessus)

## Intégration AD CS : Forging a Golden Certificate

Si vous pouvez lire la clé privée de l’Enterprise CA dans le magasin de clés de l’ordinateur, vous pouvez forger des certificats d’authentification client pour des principals arbitraires et vous authentifier via PKINIT/Schannel. Cette technique est souvent appelée Golden Certificate.<sup>[[2]](#references)</sup> Voir :

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section : « Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1 »).

## Détection et hardening

- Limiter strictement l’attribution de SeManageVolumePrivilege (Perform volume maintenance tasks) aux administrateurs de confiance uniquement.
- Surveiller l’utilisation des privilèges sensibles et les ouvertures de handles de processus vers des objets device tels que \\.\C:, \\.\PhysicalDrive0.
- Privilégier des clés d’AC correctement configurées, protégées par HSM ou TPM et non exportables, afin que la copie d’un fichier de conteneur de clé ne suffise pas à récupérer du matériel de clé privée utilisable.
- Pour les secrets applicatifs situés en dehors du chemin des clés d’AC, DPAPI ou DPAPI-NG peut rendre un fichier de données copié insuffisant en le protégeant pour un utilisateur, une machine, un groupe ou un autre principal autorisé. Cela ne protège pas le texte en clair déjà accessible au principal compromis.<sup>[[4]](#references)</sup>
- Conserver les chemins d’upload, temporaires et d’extraction comme non exécutables et séparés (défense du contexte web qui accompagne souvent cette chaîne post‑exploitation).

## References

- [1] [Microsoft – Effectuer les tâches de maintenance des volumes (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege utilisé pour lire la clé d’AC → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` disques physiques et volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - API de cryptographie : Next Generation et DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
