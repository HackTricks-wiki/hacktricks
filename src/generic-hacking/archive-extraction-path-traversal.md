# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Aperçu

De nombreux formats d'archive (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée de contenir son propre **chemin interne**. Lorsqu'un utilitaire d'extraction respecte aveuglément ce chemin, un nom de fichier forgé contenant `..` ou un **chemin absolu** (par exemple `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l'utilisateur.
Cette classe de vulnérabilité est généralement appelée *Zip-Slip* ou **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Les conséquences vont de l'écrasement de fichiers arbitraires à l'obtention directe d'une **exécution de code à distance (RCE)** en déposant un payload dans un emplacement **auto-run**, tel que le dossier *Startup* de Windows.

## Cause racine

1. L'attaquant crée une archive dont un ou plusieurs en-têtes de fichiers contiennent :
* Des séquences de traversal relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Des chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou des **symlinks** forgés qui pointent en dehors du répertoire cible (fréquent avec ZIP/TAR sur *nix*).
2. La victime extrait l'archive avec un outil vulnérable qui fait confiance au chemin intégré (ou suit les symlinks) au lieu de le nettoyer ou de forcer l'extraction sous le répertoire choisi.
3. Le fichier est écrit à l'emplacement contrôlé par l'attaquant, puis exécuté/chargé la prochaine fois que le système ou l'utilisateur déclenche ce chemin.

### Traversal `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern .NET courant consiste à combiner la destination prévue avec le `ZipArchiveEntry.FullName` **contrôlé par l'utilisateur** et à effectuer l'extraction sans normalisation du chemin :<sup>[[4]](#references)[[8]](#references)</sup>
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- Si `entry.FullName` commence par `..\\`, il effectue une traversal ; s’il s’agit d’un **absolute path**, le composant de gauche est entièrement ignoré, ce qui permet une **arbitrary file write** en tant qu’identité d’extraction.
- Archive proof-of-concept pour écrire dans un répertoire `app` frère surveillé par un scanner planifié :
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Le dépôt de ce ZIP dans la boîte de réception surveillée produit `C:\samples\app\0xdf.txt`, prouvant une traversal en dehors de `C:\samples\queue\` et permettant des primitives de suivi (par exemple, des DLL hijacks).

## Exemple concret – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows et ses composants Windows RAR/UnRAR ne validaient pas les noms de fichiers lors de l’extraction. La faille utilisait les NTFS alternate data streams (ADS) pour contourner le chemin d’extraction sélectionné et écrire des fichiers à des emplacements non prévus.<sup>[[5]](#references)</sup>
Une archive RAR malveillante contenant une entrée telle que :
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
finirait **en dehors** du répertoire de sortie sélectionné et dans le dossier *Startup* de l’utilisateur. ESET a observé que des fichiers LNK malveillants y étaient décompressés puis exécutés lors de la connexion de l’utilisateur, assurant ainsi la persistence et fournissant un chemin vers la RCE.<sup>[[5]](#references)</sup>

### Création d’une archive PoC (Linux/Mac)

Comme CVE-2025-8088 utilise un chemin de traversal dans un nom ADS, utilisez un générateur dédié pour créer le RAR, puis testez l’extraction uniquement dans un lab isolé avec une build vulnérable de WinRAR.<sup>[[5]](#references)</sup>

### Exploitation observée dans la nature

ESET a signalé des campagnes de spear-phishing de RomCom (Storm-0978/UNC2596) dans lesquelles des archives RAR exploitant CVE-2025-8088 étaient jointes afin de déployer des backdoors personnalisées et de faciliter des opérations de ransomware.<sup>[[5]](#references)</sup>

## Cas plus récents (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug** : les entrées ZIP qui étaient des **symbolic links** étaient déréférencées lors de l’extraction, ce qui permettait aux attaquants de sortir du répertoire de destination et d’écraser des chemins arbitraires. L’interaction de l’utilisateur se limite à *ouvrir/extraire* l’archive.<sup>[[1]](#references)</sup>
* **Versions affectées** : builds de 7-Zip antérieures à **25.00**. La faille de traitement des symbolic links a été corrigée dans **25.00** (juillet 2025) et les versions ultérieures.<sup>[[1]](#references)[[10]](#references)</sup>
* **Chemin d’impact** : écraser `Start Menu/Programs/Startup` ou des emplacements d’exécution de services → le code s’exécute à la prochaine connexion ou au redémarrage du service.
* **Fixture minimale pour le traitement des symlinks (Linux)** :
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Cette archive contient une entrée symlink pointant en dehors du répertoire d’extraction ; utilisez une cible jetable et vérifiez que l’extracteur ne le suit pas. Un test d’écriture au travers du symlink nécessite également une entrée regular-file située sous celui-ci.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug** : `archiver.Unarchive()` suit les entrées ZIP contenant `../` et les symlinks, et écrit en dehors de `outputDir`.<sup>[[2]](#references)</sup>
* **Versions affectées** : `github.com/mholt/archiver` ≤ 3.5.1 (projet désormais déprécié).
* **Correctif** : passez à `mholt/archives` ≥ 0.1.0 ou implémentez des vérifications de chemins canoniques avant l’écriture.
* **Reproduction minimale** :
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Conseils de détection

* **Inspection statique** – Listez les entrées de l’archive et signalez tout nom contenant `../`, `..\\`, des *absolute paths* (`/`, `C:`) ou des entrées de type *symlink* dont la cible se trouve en dehors du répertoire d’extraction.
* **Canonicalisation** – Vérifiez que `realpath(join(dest, name))` reste à l’intérieur de `realpath(dest)` (comparez les composants du chemin, et pas uniquement un préfixe de chaîne brut). Rejetez le cas contraire.<sup>[[3]](#references)</sup>
* **Extraction en sandbox** – Décompressez dans un répertoire jetable à l’aide d’un extracteur intégrant des vérifications de chemins/symlinks (par exemple les vérifications sécurisées par défaut de bsdtar ou 7-Zip ≥ 25.00), puis vérifiez que les chemins résultants restent à l’intérieur du répertoire.<sup>[[1]](#references)[[9]](#references)</sup>
* **Surveillance des endpoints** – Déclenchez une alerte lorsque de nouveaux exécutables sont écrits dans des emplacements `Startup`/`Run`/`cron` peu après l’ouverture d’une archive par WinRAR/7-Zip/etc.

## Mesures d’atténuation et durcissement

1. **Mettez à jour l’extracteur** – WinRAR 7.13+ et 7-Zip 25.00+ contiennent des correctifs pour les problèmes de chemins/symlinks cités.<sup>[[1]](#references)[[5]](#references)</sup>
2. Lorsque cela est possible, extrayez les archives avec “**Do not extract paths**” / “**Ignore paths**”.
3. Sous Unix, réduisez les privilèges et montez un **chroot/namespace** avant l’extraction ; sous Windows, utilisez **AppContainer** ou une sandbox.
4. Si vous écrivez du code personnalisé, normalisez avec `realpath()`/`PathCanonicalize()` **avant** la création/l’écriture, et rejetez toute entrée qui sort de la destination.

## Autres cas affectés / historiques

* 2018 – Advisory *Zip-Slip* majeur de Snyk affectant de nombreuses bibliothèques Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377), traversal lors de l’extraction TAR dans les slugs (corrigé dans v0.16.3).<sup>[[7]](#references)</sup>
* Toute logique d’extraction personnalisée qui n’appelle pas `PathCanonicalize` / `realpath` avant l’écriture.

## References

- [1] [Trend Micro ZDI-25-949 – traversal de symlink ZIP dans 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Recherche JFrog – Zip-Slip de mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prévenir Zip Slip dans .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – chaîne HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Recherche ESET – Mettez à jour les outils WinRAR maintenant : RomCom et d’autres exploitent une zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgation publique d’une vulnérabilité critique d’écrasement arbitraire de fichiers : Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01 : go-slug de HashiCorp vulnérable à une attaque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Méthode Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flags d’extraction sécurisée de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit Proof-of-Concept signalé pour CVE-2025-11001 dans 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
