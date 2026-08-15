# Traversal de chemin lors de l'extraction d'archives ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Vue d'ensemble

De nombreux formats d'archives (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée de contenir son propre **chemin interne**. Lorsqu'un utilitaire d'extraction respecte aveuglément ce chemin, un nom de fichier conçu avec `..` ou un **chemin absolu** (par exemple `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l'utilisateur.
Cette classe de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **traversal de chemin lors de l'extraction d'archives**.<sup>[[6]](#references)</sup>

Les conséquences vont de l'écrasement de fichiers arbitraires à l'obtention directe d'une **exécution de code à distance (RCE)** en déposant une payload dans un emplacement à **exécution automatique**, tel que le dossier *Startup* de Windows.

## Cause fondamentale

1. L'attaquant crée une archive dont un ou plusieurs en-têtes de fichiers contiennent :
* Des séquences de traversal relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Des chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou des **symlinks** conçus pour pointer en dehors du répertoire cible (fréquent dans les ZIP/TAR sur *nix*).
2. La victime extrait l'archive avec un outil vulnérable qui fait confiance au chemin intégré (ou suit les symlinks) au lieu de le nettoyer ou de forcer l'extraction sous le répertoire choisi.
3. Le fichier est écrit à l'emplacement contrôlé par l'attaquant, puis exécuté/chargé la prochaine fois que le système ou l'utilisateur déclenche ce chemin.

### Traversal via `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern courant en .NET consiste à combiner la destination prévue avec le `ZipArchiveEntry.FullName` **contrôlé par l'utilisateur** et à effectuer l'extraction sans normalisation du chemin :<sup>[[4]](#references)[[8]](#references)</sup>
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
- Archive de proof-of-concept permettant d’écrire dans un répertoire `app` voisin surveillé par un scanner planifié :
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Le dépôt de ce ZIP dans l'inbox surveillée produit `C:\samples\app\0xdf.txt`, prouvant une traversal en dehors de `C:\samples\queue\` et permettant des primitives de suivi (par exemple, des DLL hijacks).

## Advanced Archive-Breakout Primitives

Considérez l'extraction comme une séquence de mutations du système de fichiers, et non comme une série de vérifications indépendantes des noms de fichiers. Une entrée sûre lors de son analyse peut devenir dangereuse après qu'un membre précédent a créé ou remplacé un lien ; le même problème apparaît lorsqu'un extractor met en cache un répertoire comme étant sûr, puis que son type change ultérieurement.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through** : créez `pivot -> /tmp`, puis extrayez un membre régulier sous la forme `pivot/PWNED.txt`. Si l'extractor suit le premier membre lors de la matérialisation du second, l'écriture s'échappe sans présence de `..` dans le second nom.
* **Directory-cache/TOCTOU collision** : émettez le répertoire `d/sub/`, remplacez `d/sub` par un symlink vers `/tmp`, puis émettez `d/sub/PWNED.txt`. Cela cible les extractors qui valident ou mettent en cache le répertoire une seule fois et ne le vérifient pas à nouveau avant l'écriture finale.
* **Hardlink read/overwrite** : TAR et RAR peuvent représenter des hardlinks. Un hardlink vers un fichier hôte existant peut exposer son contenu si un composant ultérieur fournit le nom extrait ; une entrée régulière en collision peut au contraire écraser l'inode lié. Cela est limité par les règles relatives au même système de fichiers et aux permissions de hardlink du système d'exploitation.
* **Pre-existing or cross-archive pivot** : réessayez avec une destination non vide. Une archive peut déposer un lien, puis une extraction ultérieure peut écrire à travers celui-ci, même si chaque archive réussit une vérification sans état du nom présent dans l'en-tête.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Comparez les noms en utilisant la sémantique du système de fichiers qui les recevra. Les cas différentiels utiles incluent `LINK` et `link` sur les systèmes de fichiers insensibles à la casse, les représentations Unicode NFC et NFD, les noms équivalents par compatibilité tels que `ﬁle` et `file`, les membres en double qui changent un chemin de répertoire en symlink, ainsi que les backslashes interprétés comme séparateurs uniquement sous Windows. Testez également les noms contenant des ADS sur NTFS. Ces cas peuvent amener le validateur à voir deux chemins alors que le système de fichiers n'en résout qu'un.<sup>[[5]](#references)[[11]](#references)</sup>

Un corpus compact devrait donc tester des combinaisons ordonnées de **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, des mélanges de `/` et `\`, des noms absolus/racinés, ainsi que des wrappers compressés tels que `.tar.gz`. Exécutez-le uniquement dans une VM ou un container jetable et surveillez à la fois la destination et le chemin canary externe prévu.<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows ainsi que ses composants Windows RAR/UnRAR ne validaient pas les noms de fichiers lors de l'extraction. La faille utilisait les alternate data streams (ADS) de NTFS pour contourner le chemin d'extraction sélectionné et écrire des fichiers à des emplacements non prévus.<sup>[[5]](#references)</sup>
Une archive RAR malveillante contenant une entrée telle que :
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
finirait **en dehors** du répertoire de sortie sélectionné et à l’intérieur du dossier *Startup* de l’utilisateur. ESET a observé des fichiers LNK malveillants y être décompressés puis exécutés à la connexion de l’utilisateur, assurant une persistance et un chemin vers la RCE.<sup>[[5]](#references)</sup>

### Création d’une archive PoC (Linux/Mac)

Comme CVE-2025-8088 utilise un chemin de traversal dans un nom ADS, utilisez un générateur dédié pour créer le RAR, puis testez l’extraction uniquement dans un lab isolé avec une version vulnérable de WinRAR.<sup>[[5]](#references)</sup>

### Exploitation observée dans la nature

ESET a signalé des campagnes de spear-phishing de RomCom (Storm-0978/UNC2596) qui joignaient des archives RAR exploitant CVE-2025-8088 afin de déployer des backdoors personnalisées et de faciliter des opérations de ransomware.<sup>[[5]](#references)</sup>

## Cas plus récents (2024–2026)

### Traversal de symlink ZIP dans 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug** : les entrées ZIP qui sont des **liens symboliques** étaient déréférencées lors de l’extraction, permettant aux attaquants de sortir du répertoire de destination et d’écraser des chemins arbitraires. L’interaction utilisateur consiste simplement à *ouvrir/extraire* l’archive.<sup>[[1]](#references)</sup>
* **Versions affectées** : builds de 7-Zip antérieures à **25.00**. La faille de traitement des liens symboliques a été corrigée dans la version **25.00** (juillet 2025) et les versions ultérieures.<sup>[[1]](#references)[[10]](#references)</sup>
* **Chemin d’impact** : écraser `Start Menu/Programs/Startup` ou des emplacements d’exécution de services → le code s’exécute à la prochaine connexion ou au redémarrage du service.
* **Fixture rapide pour la gestion des symlinks (Linux)** :
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Cette archive contient une entrée symlink pointant en dehors du répertoire d’extraction ; utilisez une cible jetable et vérifiez que l’extracteur ne le suit pas. Un test d’écriture à travers le lien nécessite également une entrée de fichier ordinaire sous le symlink.

### Collision de symlink dans `Unarchive()` de Go mholt/archiver (CVE-2025-3445)
* **Bug** : `archiver.Unarchive()` peut extraire un symlink ZIP, puis le déréférencer lorsqu’un membre ordinaire ultérieur porte le même nom, transformant une écriture apparemment située dans la racine en écriture hors de celle-ci.<sup>[[2]](#references)</sup>
* **Versions affectées** : `github.com/mholt/archiver` ≤ 3.5.1 (projet désormais déprécié).<sup>[[2]](#references)</sup>
* **Correctif** : passez à `mholt/archives` ≥ 0.1.0 ou refusez les liens et résolvez à nouveau chaque destination immédiatement avant de l’ouvrir.<sup>[[2]](#references)</sup>
* **Générateur minimal de collision** (puis appelez `archiver.Unarchive("exploit.zip", "/tmp/safe")`) :<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### Contournement du filtrage d’extraction TAR de CPython (CVE-2026-11940)

Même `tarfile.extractall(filter="data")` et `filter="tar"` ont fait l’objet de contournements liés à l’ordre des liens. Dans ce cas, un hardlink référençait un symlink archivé à un chemin plus profond ; l’extraction de secours validait le symlink relatif à cet emplacement profond, mais le recréait à l’emplacement moins profond du hardlink, où la même cible relative sortait du répertoire. Il s’agit d’un test général utile : faites en sorte que la validation et la matérialisation ne soient pas d’accord sur le répertoire de base ou le type final du membre.<sup>[[12]](#references)</sup>

## Conseils de détection

* **Inspection statique** – Listez à la fois les noms des membres et les cibles des liens. Signalez `../`, `..\\`, les chemins absolus/racinés, les symlinks, les hardlinks, les fichiers spéciaux, les noms dupliqués, les changements de type et les collisions équivalentes en matière de casse/Unicode. Préservez l’ordre des entrées lors de l’analyse, car l’exploit peut dépendre de membres précédents.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Vérifiez que le parent résolu ainsi que le nom de fichier final restent sous la destination résolue (comparez les composants du chemin, pas un simple préfixe de chaîne). Effectuez une nouvelle vérification après chaque membre précédent ; un test unique `realpath(join(dest, name))` est vulnérable au remplacement par un lien et peut échouer pour une feuille qui n’a pas encore été créée.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extraction en sandbox** – Décompressez dans un répertoire neuf et jetable à l’aide d’un extracteur qui vérifie les chemins/symlinks (par exemple les contrôles sécurisés par défaut de bsdtar ou 7-Zip ≥ 25.00), puis vérifiez que l’arborescence résultante ne contient aucun lien vers l’extérieur. L’isolation doit empêcher une sortie déjà déclenchée d’atteindre les chemins de l’hôte.<sup>[[1]](#references)[[9]](#references)</sup>
* **Les lectures en aval sont importantes** – Un symlink ou un hardlink survivant peut devenir une primitive de lecture de fichiers arbitraires lorsqu’un previewer, un CDN, un navigateur de fichiers ou un pipeline de packages ouvre ou sert ultérieurement le nom extrait, même si l’extraction elle-même n’a créé aucun fichier externe.<sup>[[11]](#references)</sup>
* **Surveillance des endpoints** – Déclenchez une alerte lorsqu’un nouvel exécutable est écrit dans des emplacements `Startup`/`Run`/`cron` peu après l’ouverture d’une archive par WinRAR/7-Zip/etc.

## Mitigation et hardening

1. **Mettez à jour l’extracteur** – WinRAR 7.13+ et 7-Zip 25.00+ contiennent des correctifs pour les problèmes de chemin/symlink cités.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extrayez les archives avec “**Do not extract paths**” / “**Ignore paths**” lorsque cela est possible. Pour les entrées non fiables, refusez les liens symboliques, hardlinks, devices et FIFOs, sauf si l’application en a explicitement besoin.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extrayez dans un **nouveau répertoire vide**. Ne fusionnez pas des membres non fiables dans une arborescence contenant des chemins remplaçables par l’attaquant et ne réutilisez pas un répertoire préparé par une archive précédente.<sup>[[11]](#references)</sup>
4. Sous Unix, abandonnez les privilèges et isolez la destination dans un **chroot/namespace de montage** ; sous Windows, utilisez **AppContainer** ou une sandbox. Une analyse post-extraction seule est insuffisante, car une écriture hors répertoire se produit avant l’analyse.<sup>[[11]](#references)</sup>
5. Dans le code personnalisé, appliquez les règles de séparateurs, de casse et d’Unicode du système d’exploitation cible, puis validez à la fois le membre et la cible du lien. Résolvez et ouvrez la destination sans suivre les liens ; ne séparez pas un contrôle de confinement d’une opération ultérieure de création/remplacement. Le validateur doit utiliser exactement la même base et les mêmes semantics d’émulation des liens que le chemin d’écriture.<sup>[[11]](#references)[[12]](#references)</sup>

## Autres cas affectés / historiques

* 2018 – Avis *Zip-Slip* massif de Snyk affectant de nombreuses bibliothèques Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377) : traversal lors de l’extraction TAR dans les slugs (corrigé dans v0.16.3).<sup>[[7]](#references)</sup>
* Toute logique d’extraction personnalisée qui valide les chaînes des headers, mais pas les cibles des liens ni le chemin final du système de fichiers utilisé pour chaque écriture.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – Traversal de symlink ZIP dans 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip de mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prévenir Zip Slip dans .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Chaîne ZipSlip → DLL hijack de HTB Bruno](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Mettez à jour WinRAR maintenant : RomCom et d’autres exploitent une vulnérabilité zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgation publique d’une vulnérabilité critique d’écrasement arbitraire de fichiers : Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01 : go-slug de HashiCorp vulnérable à une attaque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Méthode Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Flags d’extraction sécurisée de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit Proof-of-Concept signalé pour CVE-2025-11001 dans 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – S’amuser avec les zip-slips, tar-slips, symlinks, hardlinks, collisions et plus encore](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Contournement du filtre d’extraction tarfile CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
