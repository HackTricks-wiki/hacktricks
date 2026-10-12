# Traversal de chemin lors de l’extraction d’archives (« Zip-Slip »)

{{#include ../banners/hacktricks-training.md}}

## Aperçu

De nombreux formats d’archive (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée de contenir son propre **chemin interne**. Lorsqu’un utilitaire d’extraction respecte aveuglément ce chemin, un nom de fichier conçu avec `..` ou un **chemin absolu** (par ex. `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l’utilisateur.  
Cette catégorie de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **traversée de chemin lors de l’extraction d’archives**.<sup>[[6]](#references)</sup>

Les conséquences vont de l’écrasement arbitraire de fichiers à l’obtention directe d’une **exécution de code à distance (RCE)** en déposant un payload dans un emplacement à **exécution automatique**, comme le dossier *Startup* de Windows.

## Cause racine

1. L’attaquant crée une archive dont un ou plusieurs en-têtes de fichier contiennent :
   * Des séquences de traversal relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Des chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Ou des **liens symboliques** conçus pour pointer en dehors du répertoire cible (courants dans les ZIP/TAR sous *nix*). 
2. La victime extrait l’archive avec un outil vulnérable qui fait confiance au chemin intégré (ou suit les liens symboliques), au lieu de l’assainir ou de forcer l’extraction dans le répertoire choisi.
3. Le fichier est écrit à l’emplacement contrôlé par l’attaquant, puis exécuté/chargé la prochaine fois que le système ou l’utilisateur déclenche ce chemin.

### Traversal .NET avec `Path.Combine` + `ZipArchive`

Un anti-pattern courant en .NET consiste à combiner la destination prévue avec `ZipArchiveEntry.FullName`, contrôlé par l’utilisateur, puis à extraire les fichiers sans normaliser les chemins :<sup>[[4]](#references)[[8]](#references)</sup>

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

- Si `entry.FullName` commence par `..\\`, le chemin sort du répertoire ; s’il s’agit d’un **chemin absolu**, le composant de gauche est entièrement supprimé, ce qui permet une **écriture arbitraire de fichiers** lors de l’extraction.
- Archive de preuve de concept permettant d’écrire dans un répertoire `app` voisin surveillé par un scanner planifié :

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Déposer ce ZIP dans la boîte de réception surveillée crée `C:\samples\app\0xdf.txt`, prouvant qu’il est possible de sortir de `C:\samples\queue\` par traversée de répertoires et d’exploiter des primitives en aval (p. ex., des DLL hijacks).

### Racine d’extraction contrôlée par l’utilisateur

Testez également le **répertoire transmis à l’extracteur**, et pas seulement les noms des membres de l’archive. Une application peut déduire ce répertoire d’un titre, d’un nom de projet ou d’un autre champ de la requête. Une valeur telle que `../../../../app/module` peut déplacer la racine d’extraction hors du répertoire de téléversement avant que l’extracteur ne traite les membres. Dans ce cas, même une archive contenant uniquement le nom de fichier sûr `api.py` peut écraser du code de l’application.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Il s’agit d’une frontière de confinement distincte du Zip-Slip classique. Validez à la fois la racine d’extraction résolue et chaque chemin de membre résolu. Une vérification de la racine peut utiliser les composants du chemin plutôt qu’un préfixe de chaîne :<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Pour un test sûr, téléversez une archive valide contenant un fichier canary et placez des séquences de traversal dans chaque champ susceptible de sélectionner son répertoire d’extraction. Surveillez à la fois le répertoire prévu et un chemin externe jetable. Si la destination peut atteindre un module importé, l’écraser peut entraîner une exécution de code lorsque les workers se rechargent ; une erreur HTTP 500 ou une réinitialisation de la connexion pendant ce rechargement ne prouve pas que l’écriture a échoué.<sup>[[14]](#references)[[15]](#references)</sup> Voir aussi la [méthodologie de file upload](../pentesting-web/file-upload/).

## Primitives avancées de sortie d’archive

Considérez l’extraction comme une séquence de mutations du système de fichiers, et non comme des vérifications indépendantes de noms de fichiers. Une entrée sûre lors de son analyse peut devenir dangereuse après qu’un membre précédent a créé ou remplacé un lien ; le même problème se produit lorsqu’un extracteur met en cache un répertoire comme sûr, puis en change le type.<sup>[[11]](#references)</sup>

### Pivots par lien et collisions d’entrées

* **Écriture via symlink** : créez `pivot -> /tmp`, puis extrayez un membre ordinaire sous le nom `pivot/PWNED.txt`. Si l’extracteur suit le premier membre lors de la matérialisation du second, l’écriture sort du répertoire sans que le second nom contienne `..`.
* **Collision de cache de répertoire/TOCTOU** : ajoutez le répertoire `d/sub/`, remplacez `d/sub` par un symlink vers `/tmp`, puis ajoutez `d/sub/PWNED.txt`. Cette attaque vise les extracteurs qui valident ou mettent en cache le répertoire une seule fois et ne le revérifient pas avant l’écriture finale.
* **Lecture/écrasement par hardlink** : TAR et RAR peuvent représenter des hardlinks. Un hardlink vers un fichier existant de l’hôte peut exposer son contenu si un composant sert ensuite le nom extrait ; une entrée ordinaire en collision peut au contraire écraser l’inode lié. Cela dépend des règles de même système de fichiers et des autorisations du système d’exploitation concernant les hardlinks.
* **Pivot préexistant ou entre archives** : réessayez avec une destination non vide. Une archive peut créer un lien, puis une extraction ultérieure peut écrire à travers celui-ci, même si chaque archive passe une vérification sans état du nom dans l’en-tête.<sup>[[11]](#references)</sup>

### Collisions dues aux équivalences du système de fichiers

Comparez les noms selon la sémantique du système de fichiers qui les recevra. Parmi les cas différentiels utiles : `LINK` et `link` sur les systèmes de fichiers insensibles à la casse, les graphies Unicode NFC et NFD, les noms équivalents par compatibilité comme `ﬁle` et `file`, les membres en double qui changent un chemin de répertoire en symlink, et les barres obliques inverses interprétées comme séparateurs uniquement sous Windows. Testez également les noms contenant des ADS sur NTFS. Ces cas peuvent amener le validateur à voir deux chemins alors que le système de fichiers n’en résout qu’un.<sup>[[5]](#references)[[11]](#references)</sup>

Un corpus compact devrait donc tester des combinaisons ordonnées de **répertoire → symlink → enfant**, **symlink → fichier ordinaire en collision**, **hardlink → fichier ordinaire en collision**, des mélanges de `/` et `\`, des noms absolus/enracinés et des enveloppes compressées comme `.tar.gz`. Exécutez ces tests uniquement dans une VM ou un conteneur jetable, et surveillez à la fois la destination et le chemin canary externe prévu.<sup>[[11]](#references)</sup>

Une ambiguïté structurelle propre aux ZIP peut amener une préanalyse et l’extracteur réel à observer des noms d’entrées ou des arborescences différents. Consultez [Confusion entre l’analyseur d’en-tête local et celui du répertoire central](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) plutôt que de vous fier à la sortie d’une seule bibliothèque ZIP.

## Exemple concret – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows et ses composants Windows RAR/UnRAR ne validaient pas les noms de fichiers pendant l’extraction. La faille exploitait les flux de données alternatifs NTFS (ADS) pour contourner le chemin d’extraction sélectionné et écrire des fichiers à des emplacements non prévus.<sup>[[5]](#references)</sup>
Une archive RAR malveillante contenant une entrée telle que :

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

aboutirait **en dehors** du répertoire de sortie sélectionné et dans le dossier *Startup* de l’utilisateur. ESET a observé des fichiers LNK malveillants décompressés à cet emplacement et exécutés à l’ouverture de session de l’utilisateur, assurant ainsi la persistance et une voie vers le RCE.<sup>[[5]](#references)</sup>

### Création d’une archive PoC (Linux/Mac)

Comme CVE-2025-8088 utilise un chemin de traversal dans un nom ADS, utilisez un générateur spécialement conçu pour créer le RAR, puis testez l’extraction uniquement dans un laboratoire isolé avec une version vulnérable de WinRAR.<sup>[[5]](#references)</sup>

### Exploitation observée dans la nature

ESET a signalé des campagnes de spear-phishing de RomCom (Storm-0978/UNC2596) qui joignaient des archives RAR exploitant CVE-2025-8088 pour déployer des backdoors personnalisées et faciliter des opérations de ransomware.<sup>[[5]](#references)</sup>

## Cas plus récents (2024–2026)

### Traversal de liens symboliques dans les ZIP de 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug** : les entrées ZIP qui étaient des **liens symboliques** étaient déréférencées lors de l’extraction, permettant aux attaquants de sortir du répertoire de destination et d’écraser des chemins arbitraires. L’interaction utilisateur se limite à *ouvrir ou extraire* l’archive.<sup>[[1]](#references)</sup>
* **Versions concernées** : versions de 7-Zip antérieures à **25.00**. La faille de traitement des liens symboliques a été corrigée dans la version **25.00** (juillet 2025) et les versions ultérieures.<sup>[[1]](#references)[[10]](#references)</sup>
* **Voie d’impact** : écraser `Start Menu/Programs/Startup` ou des emplacements utilisés par les services → le code s’exécute à la prochaine ouverture de session ou au redémarrage du service.
* **Exemple rapide de gestion des liens symboliques (Linux)** :
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Cette archive contient une entrée symlink pointant à l’extérieur du répertoire d’extraction ; utilisez une cible jetable et vérifiez que l’extracteur ne la suit pas. Un test d’écriture à travers le symlink nécessite également une entrée de fichier ordinaire située sous le symlink.

### Go mholt/archiver `Unarchive()` : collision de symlink (CVE-2025-3445)
* **Bug** : `archiver.Unarchive()` peut extraire un symlink ZIP, puis le déréférencer lorsqu’un membre ordinaire ultérieur porte le même nom, transformant une écriture apparemment limitée au répertoire racine en écriture hors de celui-ci.<sup>[[2]](#references)</sup>
* **Affecté** : `github.com/mholt/archiver` ≤ 3.5.1 (projet désormais obsolète).<sup>[[2]](#references)</sup>
* **Correctif** : Passez à `mholt/archives` ≥ 0.1.0, ou rejetez les liens et résolvez à nouveau chaque destination juste avant de l’ouvrir.<sup>[[2]](#references)</sup>
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

### Bypass du filtrage de l’extraction TAR de CPython (CVE-2026-11940)

Même `tarfile.extractall(filter="data")` et `filter="tar"` ont été contournés par l’ordre des liens. Dans ce cas, un hardlink référençait un symlink archivé à un chemin plus profond ; l’extraction de repli validait le symlink relatif à cet emplacement profond, mais le recréait à l’emplacement moins profond du hardlink, où la même cible relative sortait du répertoire. Il s’agit d’un test général utile : faire en sorte que la validation et la matérialisation ne s’accordent pas sur le répertoire de base ou le type final du membre.<sup>[[12]](#references)</sup>

### Évasion de la cible d’un hardlink dans `tar` pour Node à travers une chaîne de symlinks (GHSA-83g3-92jg-28cx)

Le package `tar` de Node.js acceptait, dans `tar.extract()`, un hardlink dont la cible semblait lexicalement incluse, mais qui était résolue hors du répertoire d’extraction via deux symlinks antérieurs. L’attaque fonctionne avec les options d’extraction par défaut : les vérifications du répertoire parent de destination couvraient le nom du hardlink dans le répertoire, tandis que la cible du hardlink était transmise au système de fichiers sans résoudre la chaîne complète pour vérifier qu’elle restait dans le répertoire. Les versions de `tar` ≤ 7.5.7 sont concernées ; la version 7.5.8 corrige le problème.<sup>[[13]](#references)</sup>

L’élément important du jeu de test est la **relation d’ordre** entre les membres, pas ces noms littéraux :<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Si l’extraction réussit, `exfil` reste visiblement dans l’arborescence de sortie, mais partage un inode avec le fichier extérieur choisi ; sa lecture divulgue ce fichier et son écriture modifie l’original. Ce contournement montre pourquoi vérifier uniquement le chemin final, supprimer les préfixes absolus ou bloquer `..` dans l’en-tête hardlink ne suffit pas : validez les cibles des liens après avoir appliqué tout l’état du système de fichiers créé par les extractions précédentes.<sup>[[13]](#references)</sup>

## Conseils de détection

* **Inspection statique** – Répertoriez les noms des entrées et les cibles des liens. Signalez `../`, `..\\`, les chemins absolus ou ancrés à la racine, les symlinks, les hardlinks, les fichiers spéciaux, les noms en double, les changements de type et les collisions entre formes équivalentes en casse ou en Unicode. Conservez l’ordre des entrées pendant l’examen, car l’exploit peut dépendre d’entrées précédentes.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Canonicalisation** – Vérifiez que le parent résolu et le nom de base final restent sous le répertoire de destination résolu (comparez les composants du chemin, pas un préfixe de chaîne brut). Revérifiez après chaque membre précédent ; un test ponctuel de `realpath(join(dest, name))` est vulnérable au remplacement de liens et peut échouer si la feuille n’a pas encore été créée.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extraction en sandbox** – Décompressez dans un répertoire neuf et jetable à l’aide d’un extracteur qui vérifie les chemins et les liens symboliques (par exemple, les vérifications sécurisées par défaut de bsdtar ou 7-Zip ≥ 25.00), puis vérifiez que l’arborescence obtenue ne contient aucun lien vers l’extérieur. L’isolation doit empêcher une évasion déjà déclenchée d’atteindre les chemins de l’hôte.<sup>[[1]](#references)[[9]](#references)</sup>
* **Les lectures en aval comptent** – Un lien symbolique ou matériel qui subsiste peut permettre la lecture arbitraire de fichiers lorsqu’un aperçu, un CDN, un navigateur de fichiers ou un pipeline de paquets ouvre ou sert ensuite le nom extrait, même si l’extraction elle-même n’a créé aucun fichier à l’extérieur.<sup>[[11]](#references)</sup>
* **Surveillance des endpoints** – Déclenchez une alerte lorsque de nouveaux exécutables sont écrits dans des emplacements `Startup`/`Run`/`cron` peu après l’ouverture d’une archive par WinRAR/7-Zip/etc.

## Atténuation et renforcement

1. **Mettez l’extracteur à jour** – WinRAR 7.13+, 7-Zip 25.00+ et Node `tar` 7.5.8+ corrigent les problèmes cités liés aux chemins, aux liens symboliques et aux cibles des liens.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Extrayez les archives avec les options « **Do not extract paths** » / « **Ignore paths** » lorsque c’est possible. Pour les entrées non fiables, rejetez les liens symboliques, liens matériels, périphériques et FIFOs, sauf si l’application en a explicitement besoin.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extrayez dans un **nouveau répertoire vide**. Ne fusionnez pas des membres non fiables dans une arborescence contenant des chemins que l’attaquant peut remplacer, et ne réutilisez pas un répertoire créé par une archive précédente.<sup>[[11]](#references)</sup>
4. Sous Unix, abandonnez les privilèges et isolez la destination dans un **chroot/espace de noms de montage** ; sous Windows, utilisez **AppContainer** ou un sandbox. Une analyse après extraction ne suffit pas, car une écriture ayant échappé au répertoire se produit avant l’analyse.<sup>[[11]](#references)</sup>
5. Dans le code personnalisé, appliquez les règles de séparation, de casse et d’Unicode du système d’exploitation cible, et validez à la fois le membre et la cible du lien. Résolvez et ouvrez la destination sans suivre les liens ; ne séparez pas la vérification du confinement de l’opération ultérieure de création/remplacement. Le validateur doit utiliser exactement la même base et la même sémantique d’émulation des liens que le chemin d’écriture.<sup>[[11]](#references)[[12]](#references)</sup>

## Autres cas concernés / historiques

* 2018 – Avis massif de Snyk sur *Zip-Slip*, concernant de nombreuses bibliothèques Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377) : traversal lors de l’extraction TAR de slugs (corrigé dans v0.16.3).<sup>[[7]](#references)</sup>
* Toute logique d’extraction personnalisée qui valide les chaînes des en-têtes, mais pas les cibles des liens ni le chemin final du système de fichiers utilisé pour chaque écriture.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – traversal ZIP par lien symbolique dans 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Recherche JFrog – Zip-Slip dans mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prévenir Zip Slip dans .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Chaîne HTB Bruno ZipSlip → détournement de DLL](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Recherche ESET – Mettez à jour WinRAR maintenant : RomCom et d’autres exploitent une vulnérabilité zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgation publique d’une vulnérabilité critique d’écrasement arbitraire de fichiers : Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01 : go-slug vulnérable à une attaque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Méthode Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Options d’extraction sécurisée de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit de preuve de concept signalé pour CVE-2025-11001 dans 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – S’amuser avec zip-slips, tar-slips, liens symboliques, liens matériels, collisions et plus encore](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Annonce de sécurité Python – Contournement du filtre d’extraction tarfile CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [Avis de sécurité GitHub – Évasion de la cible d’un lien matériel dans node-tar via une chaîne de liens symboliques](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [PoC CVE de Rhino Security Labs – racine d’extraction SCORM contrôlée par l’utilisateur](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Vulnérabilités multiples dans Frappe LMS menant à l’exécution de code à distance](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
