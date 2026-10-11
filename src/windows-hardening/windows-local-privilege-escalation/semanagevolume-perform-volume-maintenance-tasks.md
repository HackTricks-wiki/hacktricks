# SeManageVolumePrivilege : abus de la maintenance des volumes et validation de l’accès brut

{{#include ../../banners/hacktricks-training.md}}

## Présentation

Droit utilisateur Windows : Effectuer des tâches de maintenance des volumes (constante : SeManageVolumePrivilege).

Ce droit autorise des opérations de maintenance des volumes, comme la défragmentation et la création ou la suppression de volumes. Microsoft avertit qu’un détenteur peut être en mesure d’étendre des fichiers vers un espace de stockage contenant d’autres données, puis de lire ou de modifier les octets ainsi obtenus.<sup>[[1]](#references)</sup>

Ne confondez pas la possession de `SeManageVolumePrivilege` avec un accès garanti au disque brut. Microsoft indique que l’ouverture d’un disque physique ou d’un volume via `CreateFile` pour un accès direct nécessite des privilèges d’administrateur, et que les contrôles d’accès normaux aux objets et aux périphériques restent applicables. Sur une build ou un produit donné, vérifiez si le jeton, l’ACL du périphérique, l’accès demandé, les indicateurs de partage et l’état du volume permettent d’obtenir un handle brut avant d’affirmer qu’il est possible de lire arbitrairement des fichiers.<sup>[[3]](#references)</sup>

Valeur par défaut : Administrateurs sur les serveurs et les contrôleurs de domaine.<sup>[[1]](#references)</sup>

## Scénarios d’abus

- Si le compte peut réellement obtenir un handle lisible vers un volume brut, un parseur compatible avec NTFS peut contourner les ACL par fichier et récupérer des fichiers protégés ou verrouillés à partir des clusters alloués.
- Les cibles possibles comprennent les contenus verrouillés ou protégés par ACL dans `C:\Windows\System32`, les ruches du registre, les clés principales DPAPI, le SAM et — lorsqu’il est accessible séparément via un instantané ou un volume hors ligne — `ntds.dit`.
- Sur les hôtes des services de certificats, les emplacements utiles des clés logicielles comprennent `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` et `%ProgramData%\Microsoft\Crypto\Keys` ; la récupération d’un fichier n’est utile que si le matériel de clé peut être exporté et déchiffré.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- Sur un hôte AD CS, la récupération réussie d’une clé privée d’AC **exportable et reposant sur un logiciel** peut permettre un abus de type Golden Certificate. Les conceptions reposant sur du matériel ou utilisant des clés non exportables modifient cette possibilité.<sup>[[2]](#references)</sup>
- Certains outils de maintenance des volumes utilisent `FSCTL_SD_GLOBAL_CHANGE` pour remplacer des entrées d’ACL du système de fichiers lorsque cette opération est autorisée. Cela modifie les contrôles d’accès au lieu de lire passivement les blocs bruts, peut affecter une grande partie d’un volume et doit être validé en fonction du jeton réel et du comportement du périphérique. Le [code source de l’outil](https://github.com/CsEnox/SeManageVolumeExploit) présente ce mécanisme précis ; la possession du privilège ne suffit pas à prouver qu’il fonctionnera.
- L’accès à un fichier obtenu par la modification des ACL ne déchiffre pas un fichier chiffré avec EFS. Le texte en clair nécessite toujours la clé privée correspondante de l’utilisateur ou de récupération. De même, l’exportation d’une clé d’AC reposant sur un logiciel avec [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) dépend du fait que la clé soit disponible localement, exportable et accessible.

Remarque : vous avez toujours besoin d’un parseur des structures NTFS, sauf si vous utilisez des outils auxiliaires. De nombreux outils prêts à l’emploi abstraient l’accès brut.

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

- Utilisez un outil compatible avec NTFS pour récupérer des fichiers spécifiques depuis un volume brut :
  - RawCopy/RawCopy64 (copie au niveau des secteurs de fichiers en cours d’utilisation)
  - FTK Imager ou The Sleuth Kit (création d’une image en lecture seule, puis récupération de fichiers)
  - vssadmin/diskshadow + copie instantanée, puis copiez le fichier cible depuis l’instantané (si vous pouvez créer une VSS ; cela nécessite souvent des privilèges d’administrateur, mais est généralement possible pour les mêmes opérateurs qui détiennent SeManageVolumePrivilege)

Chemins sensibles typiques à cibler :
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (secrets locaux)
- C:\Windows\NTDS\ntds.dit (contrôleurs de domaine – via une copie instantanée)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificats/CRL de l’AC ; les clés privées se trouvent dans le magasin de clés machine ci-dessus)

## Lien avec AD CS : forger un Golden Certificate

Si vous pouvez lire la clé privée de l’AC d’entreprise depuis le magasin de clés machine, vous pouvez forger des certificats d’authentification client pour des principals arbitraires et vous authentifier via PKINIT/Schannel. On parle souvent de Golden Certificate.<sup>[[2]](#references)</sup> Voir :

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section : « Forger des certificats à partir de certificats d’AC volés (Golden Certificate) – DPERSIST1 »).

## Détection et renforcement de la sécurité

- Limitez strictement l’attribution de SeManageVolumePrivilege (Effectuer des tâches de maintenance des volumes) aux seuls administrateurs de confiance.
- Surveillez l’utilisation des privilèges sensibles et l’ouverture de handles de processus vers des objets périphériques tels que \\.\C:, \\.\PhysicalDrive0.
- Privilégiez des clés d’AC non exportables, protégées par un HSM ou un TPM et correctement configurées, afin que la copie d’un fichier conteneur de clé ne suffise pas à récupérer du matériel de clé privée utilisable.
- Pour les secrets d’application situés hors du chemin de la clé d’AC, DPAPI ou DPAPI-NG peuvent rendre insuffisante la copie d’un fichier de données en le protégeant pour un utilisateur, une machine, un groupe ou un autre principal autorisé. Cela ne protège pas le texte en clair déjà accessible au principal compromis.<sup>[[4]](#references)</sup>
- Gardez les chemins de téléversement, temporaires et d’extraction non exécutables et séparés (défense du contexte web souvent associée à cette chaîne après exploitation).

## References

- [1] [Microsoft – Effectuer des tâches de maintenance des volumes (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB : Certificate (SeManageVolumePrivilege utilisé pour lire la clé d’AC → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` : disques physiques et volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - API de cryptographie : Next Generation et DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
