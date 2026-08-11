# Traversal de chemin lors de l’extraction d’archives ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Vue d’ensemble

De nombreux formats d’archives (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée de contenir son propre **chemin interne**. Lorsqu’un utilitaire d’extraction respecte aveuglément ce chemin, un nom de fichier conçu avec `..` ou un **chemin absolu** (par ex. `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l’utilisateur.
Cette classe de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Les conséquences vont de l’écrasement de fichiers arbitraires à l’obtention directe d’une **remote code execution (RCE)** en déposant une charge utile dans un emplacement **auto-run**, comme le dossier *Startup* de Windows.

## Cause première

1. L’attaquant crée une archive dont un ou plusieurs en-têtes de fichiers contiennent :
* Des séquences de traversal relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Des chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou des **symlinks** conçus pour se résoudre en dehors du répertoire cible (cas courant dans les ZIP/TAR sur *nix*).
2. La victime extrait l’archive avec un outil vulnérable qui fait confiance au chemin intégré (ou suit les symlinks) au lieu de l’assainir ou de forcer l’extraction sous le répertoire choisi.
3. Le fichier est écrit à l’emplacement contrôlé par l’attaquant, puis exécuté/chargé la prochaine fois que le système ou l’utilisateur déclenche ce chemin.

### Traversal `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern courant en .NET consiste à combiner la destination prévue avec le `ZipArchiveEntry.FullName` **contrôlé par l’utilisateur** et à extraire sans normalisation du chemin :<sup>[[4]](#references)[[8]](#references)</sup>
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
- Si `entry.FullName` commence par `..\\`, il effectue une traversée ; s’il s’agit d’un **chemin absolu**, le composant de gauche est entièrement supprimé, ce qui permet une **écriture arbitraire de fichier** lors de l’extraction.
- Archive de preuve de concept permettant d’écrire dans un répertoire `app` voisin surveillé par un scanner planifié :
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Déposer ce ZIP dans la boîte de réception surveillée crée `C:\samples\app\0xdf.txt`, ce qui prouve une traversal en dehors de `C:\samples\queue\` et permet des primitives de suivi (par ex. des DLL hijacks).

## Exemple réel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows ainsi que ses composants Windows RAR/UnRAR ne validaient pas les noms de fichiers lors de l’extraction. La faille utilisait les alternate data streams (ADS) de NTFS pour contourner le chemin d’extraction sélectionné et écrire des fichiers à des emplacements non prévus.<sup>[[5]](#references)</sup>
Une archive RAR malveillante contenant une entrée telle que :
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **à l’extérieur** du répertoire de sortie sélectionné et à l’intérieur du dossier *Startup* de l’utilisateur. ESET a observé des fichiers LNK malveillants y être décompressés et exécutés lors de la connexion de l’utilisateur, assurant la persistence et fournissant un chemin vers la RCE.<sup>[[5]](#references)</sup>

### Création d’une archive PoC (Linux/Mac)

Comme CVE-2025-8088 utilise un chemin de traversal dans un nom ADS, utilisez un générateur dédié pour créer le RAR, puis testez l’extraction uniquement dans un lab isolé avec une version vulnérable de WinRAR.<sup>[[5]](#references)</sup>

### Exploitation observée dans la nature

ESET a signalé des campagnes de spear-phishing de RomCom (Storm-0978/UNC2596) qui joignaient des archives RAR exploitant CVE-2025-8088 afin de déployer des backdoors personnalisées et de faciliter des opérations de ransomware.<sup>[[5]](#references)</sup>

## Cas plus récents (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug** : les entrées ZIP qui sont des **liens symboliques** étaient déréférencées lors de l’extraction, permettant aux attaquants de sortir du répertoire de destination et d’écraser des chemins arbitraires. L’interaction de l’utilisateur consiste simplement à *ouvrir/extraire* l’archive.<sup>[[1]](#references)</sup>
* **Affecté** : versions de 7-Zip antérieures à **25.00**. La faille de traitement des liens symboliques a été corrigée dans la version **25.00** (juillet 2025) et les versions ultérieures.<sup>[[1]](#references)[[10]](#references)</sup>
* **Chemin d’impact** : écraser `Start Menu/Programs/Startup` ou des emplacements d’exécution de services → le code s’exécute à la prochaine connexion ou au redémarrage du service.
* **Fixture minimale pour la gestion des symlinks (Linux)** :
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Cette archive contient une entrée symlink pointant à l’extérieur du répertoire d’extraction ; utilisez une cible jetable et vérifiez que l’extracteur ne le suit pas. Un test d’écriture indirecte nécessite également une entrée de fichier standard sous le symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug** : `archiver.Unarchive()` suit les chemins `../` et les entrées ZIP symlinkées, écrivant en dehors de `outputDir`.<sup>[[2]](#references)</sup>
* **Affecté** : `github.com/mholt/archiver` ≤ 3.5.1 (projet désormais déprécié).
* **Correctif** : passez à `mholt/archives` ≥ 0.1.0 ou implémentez des vérifications de chemins canoniques avant l’écriture.
* **Reproduction minimale** :
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Conseils de détection

* **Inspection statique** – Listez les entrées de l’archive et signalez tout nom contenant `../`, `..\\`, des *chemins absolus* (`/`, `C:`) ou des entrées de type *symlink* dont la cible se trouve à l’extérieur du répertoire d’extraction.
* **Canonicalisation** – Vérifiez que `realpath(join(dest, name))` reste à l’intérieur de `realpath(dest)` (comparez les composants du chemin, pas uniquement un préfixe de chaîne brut). Rejetez l’entrée dans le cas contraire.<sup>[[3]](#references)</sup>
* **Extraction en sandbox** – Décompressez dans un répertoire jetable à l’aide d’un extracteur doté de vérifications des chemins/symlinks (par exemple, les vérifications sécurisées par défaut de bsdtar ou 7-Zip ≥ 25.00), puis vérifiez que les chemins résultants restent à l’intérieur du répertoire.<sup>[[1]](#references)[[9]](#references)</sup>
* **Surveillance des endpoints** – Déclenchez une alerte lorsque de nouveaux exécutables sont écrits dans les emplacements `Startup`/`Run`/`cron` peu après l’ouverture d’une archive par WinRAR/7-Zip/etc.

## Mitigation et durcissement

1. **Mettez à jour l’extracteur** – WinRAR 7.13+ et 7-Zip 25.00+ contiennent des correctifs pour les problèmes liés aux chemins d et aux symlinks.<sup>[[1]](#references)[[5]](#references)</sup>
2. Lorsque c’est possible, extrayez les archives avec “**Do not extract paths**” / “**Ignore paths**”.
3. Sous Unix, réduisez les privilèges et montez un **chroot/namespace** avant l’extraction ; sous Windows, utilisez **AppContainer** ou une sandbox.
4. Si vous écrivez du code personnalisé, normalisez avec `realpath()`/`PathCanonicalize()` **avant** la création/l’écriture, et rejetez toute entrée qui sort de la destination.

## Autres cas affectés / historiques

* 2018 – Advisory massif *Zip-Slip* de Snyk affectant de nombreuses bibliothèques Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377) : traversal lors de l’extraction TAR dans les slugs (corrigé dans la v0.16.3).<sup>[[7]](#references)</sup>
* Toute logique d’extraction personnalisée qui n’appelle pas `PathCanonicalize` / `realpath` avant l’écriture.

## References

- [1] [Trend Micro ZDI-25-949 – traversal ZIP par symlink dans 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip de mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Empêcher Zip Slip dans .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Chaîne HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Mettez à jour vos outils WinRAR maintenant : RomCom et d’autres exploitent une vulnérabilité zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgation publique d’une vulnérabilité critique d’écrasement arbitraire de fichiers : Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01 : go-slug vulnérable à une attaque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Méthode Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – indicateurs d’extraction sécurisée de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit Proof-of-Concept signalé pour CVE-2025-11001 dans 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
