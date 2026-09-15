# Traversal de chemin lors de l'extraction d'archives ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Vue d'ensemble

De nombreux formats d'archives (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée de contenir son propre **chemin interne**. Lorsqu'un utilitaire d'extraction respecte aveuglément ce chemin, un nom de fichier forgé contenant `..` ou un **chemin absolu** (par ex. `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l'utilisateur.
Cette classe de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **traversal de chemin lors de l'extraction d'archives**.<sup>[[6]](#references)</sup>

Les conséquences vont de l'écrasement de fichiers arbitraires à l'obtention directe d'une **remote code execution (RCE)** en déposant une charge utile dans un emplacement **auto-run**, comme le dossier Windows *Startup*.

## Cause racine

1. L'attaquant crée une archive dans laquelle un ou plusieurs en-têtes de fichiers contiennent :
* Des séquences de traversal relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Des chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou des **symlinks** forgés qui pointent en dehors du répertoire cible (fréquent dans les ZIP/TAR sur *nix*).
2. La victime extrait l'archive avec un outil vulnérable qui fait confiance au chemin intégré (ou suit les symlinks) au lieu de le nettoyer ou de forcer l'extraction sous le répertoire choisi.
3. Le fichier est écrit à l'emplacement contrôlé par l'attaquant, puis exécuté/chargé lors de la prochaine activation de ce chemin par le système ou l'utilisateur.

### Traversal `.NET` avec `Path.Combine` + `ZipArchive`

Un anti-pattern .NET courant consiste à combiner la destination prévue avec `ZipArchiveEntry.FullName` **contrôlé par l'utilisateur** et à effectuer l'extraction sans normalisation du chemin :<sup>[[4]](#references)[[8]](#references)</sup>
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
- Si `entry.FullName` commence par `..\\`, il effectue une traversal ; s’il s’agit d’un **absolute path**, le composant de gauche est entièrement ignoré, ce qui permet une **arbitrary file write** utilisée comme identité d’extraction.
- Archive proof-of-concept permettant d’écrire dans un répertoire `app` voisin surveillé par un scanner planifié :
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Déposer ce ZIP dans la boîte de réception surveillée produit `C:\samples\app\0xdf.txt`, ce qui prouve une traversal en dehors de `C:\samples\queue\` et permet des primitives de suivi (par exemple, des DLL hijacks).

## Primitives avancées de breakout d’archives

Traitez l’extraction comme une séquence de mutations du système de fichiers, et non comme une série de vérifications indépendantes des noms de fichiers. Une entrée sûre lors de son analyse peut devenir dangereuse après qu’un membre précédent a créé ou remplacé un lien ; le même problème survient lorsqu’un extracteur met en cache un répertoire comme étant sûr, puis modifie son type.<sup>[[11]](#references)</sup>

### Pivots via des liens et collisions d’entrées

* **Symlink write-through** : créez `pivot -> /tmp`, puis extrayez un membre ordinaire sous la forme `pivot/PWNED.txt`. Si l’extracteur suit le premier membre lors de la matérialisation du second, l’écriture sort du chemin prévu sans que `..` apparaisse dans le deuxième nom.
* **Collision directory-cache/TOCTOU** : émettez le répertoire `d/sub/`, remplacez `d/sub` par un symlink vers `/tmp`, puis émettez `d/sub/PWNED.txt`. Cela cible les extracteurs qui valident ou mettent en cache le répertoire une seule fois et ne le revérifient pas avant l’écriture finale.
* **Hardlink read/overwrite** : TAR et RAR peuvent représenter des hardlinks. Un hardlink vers un fichier hôte existant peut exposer son contenu si un composant ultérieur sert le nom extrait ; une entrée ordinaire en collision peut au contraire écraser l’inode lié. Cela est limité par les règles relatives au même système de fichiers et aux permissions de hardlink du système d’exploitation.
* **Pre-existing or cross-archive pivot** : réessayez avec une destination non vide. Une archive peut installer un lien, puis une extraction ultérieure peut écrire à travers celui-ci, même si chaque archive réussit une vérification sans état du nom dans l’en-tête.<sup>[[11]](#references)</sup>

### Collisions d’équivalence du système de fichiers

Comparez les noms en utilisant la sémantique du système de fichiers qui les recevra. Les cas différentiels utiles comprennent `LINK` contre `link` sur les systèmes de fichiers insensibles à la casse, les écritures Unicode NFC contre NFD, les noms équivalents par compatibilité tels que `ﬁle` contre `file`, les membres en double qui transforment un chemin de répertoire en symlink, ainsi que les antislashs interprétés comme des séparateurs uniquement sous Windows. Testez également les noms contenant des ADS sur NTFS. Ces cas peuvent faire voir deux chemins au validateur alors que le système de fichiers n’en résout qu’un seul.<sup>[[5]](#references)[[11]](#references)</sup>

Un corpus compact devrait donc tester des combinaisons ordonnées de **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, des mélanges de `/` et `\`, des noms absolus/enracinés, ainsi que des wrappers compressés tels que `.tar.gz`. Exécutez ces tests uniquement dans une VM ou un container jetable et surveillez à la fois la destination et le chemin canari externe prévu.<sup>[[11]](#references)</sup>

L’ambiguïté structurelle propre aux ZIP peut faire observer au pre-scan et à l’extracteur réel des noms d’entrées ou des arborescences différents. Consultez [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) plutôt que de faire confiance à la sortie d’une seule bibliothèque ZIP.

## Exemple réel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows ainsi que ses composants Windows RAR/UnRAR ne validaient pas les noms de fichiers lors de l’extraction. La vulnérabilité exploitait les alternate data streams (ADS) de NTFS pour contourner le chemin d’extraction sélectionné et écrire des fichiers à des emplacements non prévus.<sup>[[5]](#references)</sup>
Une archive RAR malveillante contenant une entrée telle que :
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
finirait **en dehors** du répertoire de sortie sélectionné et à l’intérieur du dossier *Startup* de l’utilisateur. ESET a observé des fichiers LNK malveillants y être décompressés puis exécutés lors de la connexion de l’utilisateur, assurant la persistance et offrant un chemin vers la RCE.<sup>[[5]](#references)</sup>

### Création d’une archive PoC (Linux/Mac)

Comme CVE-2025-8088 utilise un chemin de traversal dans un nom ADS, utilisez un générateur dédié pour créer le RAR, puis testez l’extraction uniquement dans un lab isolé avec une version vulnérable de WinRAR.<sup>[[5]](#references)</sup>

### Exploitation observée dans la nature

ESET a signalé des campagnes de spear-phishing de RomCom (Storm-0978/UNC2596) qui joignaient des archives RAR exploitant CVE-2025-8088 afin de déployer des backdoors personnalisées et de faciliter des opérations de ransomware.<sup>[[5]](#references)</sup>

## Cas plus récents (2024–2026)

### Traversal de symlink ZIP de 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug** : les entrées ZIP qui étaient des **liens symboliques** étaient déréférencées lors de l’extraction, permettant aux attaquants de sortir du répertoire de destination et d’écraser des chemins arbitraires. L’interaction utilisateur se limite à *ouvrir/extraire* l’archive.<sup>[[1]](#references)</sup>
* **Affecté** : les builds de 7-Zip antérieurs à **25.00**. La faille de traitement des liens symboliques a été corrigée dans la version **25.00** (juillet 2025) et les versions ultérieures.<sup>[[1]](#references)[[10]](#references)</sup>
* **Chemin d’impact** : écraser `Start Menu/Programs/Startup` ou des emplacements exécutés par des services → le code s’exécute à la prochaine connexion ou au redémarrage du service.
* **Fixture rapide pour la gestion des symlinks (Linux)** :
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Cette archive contient une entrée symlink pointant en dehors du répertoire d’extraction ; utilisez une cible jetable et vérifiez que l’extracteur ne le suit pas. Un test d’écriture effective nécessite également une entrée de fichier ordinaire sous le symlink.

### Collision de symlink dans `Unarchive()` de Go mholt/archiver (CVE-2025-3445)
* **Bug** : `archiver.Unarchive()` peut extraire un symlink ZIP puis le déréférencer lorsqu’un membre ordinaire ultérieur porte le même nom, transformant une écriture apparemment interne à la racine en écriture externe à la racine.<sup>[[2]](#references)</sup>
* **Affecté** : `github.com/mholt/archiver` ≤ 3.5.1 (le projet est désormais déprécié).<sup>[[2]](#references)</sup>
* **Correction** : passer à `mholt/archives` ≥ 0.1.0 ou refuser les liens et recalculer immédiatement chaque destination avant de l’ouvrir.<sup>[[2]](#references)</sup>
* **Générateur minimal de collision** (puis appeler `archiver.Unarchive("exploit.zip", "/tmp/safe")`) :<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
 link = zipfile.ZipInfo("./x")
 link.create_system = 3
 link.external_attr = 0o120777 << 16
 z.writestr(link, "../../../tmp/PWNED")
 z.writestr("./x", b"owned\n")
```

### Contournement de l’extraction TAR filtrée de CPython (CVE-2026-11940)

Même `tarfile.extractall(filter="data")` et `filter="tar"` ont connu des contournements liés à l’ordre des liens. Dans ce cas, un hardlink faisait référence à un symlink archivé à un chemin plus profond ; l’extraction de secours validait le symlink relatif à cet emplacement profond, mais le recréait à l’emplacement moins profond du hardlink, où la même cible relative sortait de la racine. Il s’agit d’un test général utile : faire en sorte que la validation et la matérialisation ne soient pas d’accord sur le répertoire de base ou le type final du membre.<sup>[[12]](#references)</sup>

### Évasion de la cible d’un hardlink de Node `tar` via une chaîne de symlinks (GHSA-83g3-92jg-28cx)

Le package Node.js `tar` acceptait un hardlink dont la cible semblait contenue d’un point de vue lexical, mais qui se résolvait en dehors de la racine d’extraction via deux symlinks antérieurs. L’attaque fonctionne avec les options d’extraction par défaut : les vérifications du parent de destination couvraient le nom du hardlink situé dans la racine, tandis que la cible du hardlink était transmise au système de fichiers sans résoudre la chaîne complète pour vérifier son confinement. `tar` ≤ 7.5.7 est affecté ; la version 7.5.8 corrige le problème.<sup>[[13]](#references)</sup>

L’élément essentiel de la fixture de test est la **relation ordonnée** entre les membres, et non ces noms littéraux :<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
Si l’extraction réussit, `exfil` reste visiblement présent dans l’arborescence de sortie, mais partage un inode avec le fichier externe choisi ; sa lecture exfiltre ce fichier et son écriture modifie l’original. Ce bypass montre pourquoi il est insuffisant de vérifier uniquement le pathname final, de supprimer les préfixes absolus ou de bloquer `..` dans l’en-tête du hardlink : il faut valider les cibles des liens après avoir appliqué tout l’état du système de fichiers précédemment extrait.<sup>[[13]](#references)</sup>

## Conseils de détection

* **Inspection statique** – Listez les noms des membres et les cibles des liens. Signalez `../`, `..\\`, les chemins absolus/racinés, les symlinks, les hardlinks, les fichiers spéciaux, les noms dupliqués, les changements de type et les collisions entre formes équivalentes en termes de casse/Unicode. Préservez l’ordre des entrées pendant l’examen, car l’exploit peut dépendre de membres précédents.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
7z l -slt suspect.7z          # technical metadata, one field per line
zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
```

* **Canonicalisation** – Assurez-vous que le parent résolu ainsi que le basename final restent sous le répertoire de destination résolu (comparez les composants du chemin, et non un simple préfixe de chaîne). Effectuez une nouvelle vérification après chaque membre précédent ; un test ponctuel avec `realpath(join(dest, name))` est vulnérable au remplacement d’un lien et peut échouer pour une feuille qui n’a pas encore été créée.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extraction en sandbox** – Décompressez dans un répertoire neuf et jetable à l’aide d’un extracteur qui vérifie les chemins/symlinks (par exemple, les contrôles de sécurité par défaut de bsdtar ou 7-Zip ≥ 25.00), puis vérifiez que l’arborescence résultante ne contient aucun lien sortant. L’isolation doit empêcher une escape déjà déclenchée d’atteindre les chemins de l’hôte.<sup>[[1]](#references)[[9]](#references)</sup>
* **Les lectures en aval sont importantes** – Un symlink ou un hardlink persistant peut devenir une primitive de lecture de fichiers arbitraires lorsqu’un prévisualiseur, un CDN, un navigateur de fichiers ou un pipeline de packages ouvre ou sert ensuite le nom extrait, même si l’extraction elle-même n’a créé aucun fichier externe.<sup>[[11]](#references)</sup>
* **Surveillance des endpoints** – Déclenchez une alerte lorsqu’un nouvel exécutable est écrit dans des emplacements `Startup`/`Run`/`cron` peu après l’ouverture d’une archive par WinRAR/7-Zip/etc.

## Correctifs et durcissement

1. **Mettez à jour l’extracteur** – WinRAR 7.13+, 7-Zip 25.00+ et Node `tar` 7.5.8+ contiennent des correctifs pour les problèmes de path/symlink/link-target cités.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Extrayez les archives avec « **Do not extract paths** » / « **Ignore paths** » lorsque cela est possible. Pour les entrées non fiables, rejetez les liens symboliques, les hardlinks, les devices et les FIFO, sauf si l’application en a explicitement besoin.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extrayez dans un **nouveau répertoire vide**. Ne fusionnez pas des membres non fiables dans une arborescence contenant des chemins remplaçables par l’attaquant et ne réutilisez pas un répertoire préparé par une archive précédente.<sup>[[11]](#references)</sup>
4. Sous Unix, abandonnez les privilèges et isolez la destination dans un **chroot/mount namespace** ; sous Windows, utilisez **AppContainer** ou une sandbox. Une analyse post-extraction seule est insuffisante, car une écriture échappée se produit avant l’analyse.<sup>[[11]](#references)</sup>
5. Dans le code personnalisé, appliquez les règles de séparateur, de casse et d’Unicode du système cible et validez à la fois le membre et la cible du lien. Résolvez et ouvrez la destination sans suivre les liens ; ne séparez pas une vérification de confinement d’une opération ultérieure de création/remplacement. Le validateur doit utiliser exactement la même base et la même sémantique d’émulation des liens que le chemin d’écriture.<sup>[[11]](#references)[[12]](#references)</sup>

## Cas supplémentaires / historiques affectés

* 2018 – Avis *Zip-Slip* massif de Snyk affectant de nombreuses bibliothèques Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377) : traversal lors de l’extraction TAR dans les slugs (corrigé dans v0.16.3).<sup>[[7]](#references)</sup>
* Toute logique d’extraction personnalisée qui valide les chaînes des en-têtes, mais pas les cibles des liens ni le chemin final du système de fichiers utilisé pour chaque écriture.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – traversal ZIP de symlink dans 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip de mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prévenir Zip Slip dans .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Chaîne HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Mettez à jour les outils WinRAR maintenant : RomCom et d’autres exploitent une vulnérabilité zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgation publique d’une vulnérabilité critique d’écrasement arbitraire de fichiers : Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01 : go-slug de HashiCorp vulnérable à une attaque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Méthode Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – indicateurs d’extraction sécurisée de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit Proof-of-Concept signalé pour CVE-2025-11001 dans 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – S’amuser avec les zip-slips, tar-slips, symlinks, hardlinks, collisions et bien plus](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – bypass du filtre d’extraction tarfile CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – escape de cible de hardlink de node-tar via une chaîne de symlinks](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
