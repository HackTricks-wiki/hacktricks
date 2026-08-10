# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Aperçu

De nombreux formats d’archive (ZIP, RAR, TAR, 7-ZIP, etc.) permettent à chaque entrée de contenir son propre **chemin interne**. Lorsqu’un utilitaire d’extraction respecte aveuglément ce chemin, un nom de fichier conçu avec `..` ou un **chemin absolu** (par ex. `C:\Windows\System32\`) sera écrit en dehors du répertoire choisi par l’utilisateur.
Cette classe de vulnérabilité est largement connue sous le nom de *Zip-Slip* ou **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Les conséquences vont de l’écrasement de fichiers arbitraires à l’obtention directe d’une **remote code execution (RCE)** en déposant un payload dans un emplacement **auto-run**, tel que le dossier *Startup* de Windows.

## Cause racine

1. L’attaquant crée une archive dont un ou plusieurs en-têtes de fichier contiennent :
* Des séquences de traversal relatives (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Des chemins absolus (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou des **symlinks** conçus pour se résoudre en dehors du répertoire cible (fréquent dans les ZIP/TAR sur *nix*).
2. La victime extrait l’archive avec un outil vulnérable qui fait confiance au chemin intégré (ou qui suit les symlinks) au lieu de le nettoyer ou de forcer l’extraction sous le répertoire choisi.
3. Le fichier est écrit à l’emplacement contrôlé par l’attaquant, puis exécuté/chargé la prochaine fois que le système ou l’utilisateur déclenche ce chemin.

### .NET `Path.Combine` + `ZipArchive` path traversal

Un anti-pattern .NET courant consiste à combiner la destination prévue avec le `ZipArchiveEntry.FullName` **contrôlé par l’utilisateur** et à extraire sans normalisation du chemin :<sup>[[4]](#references)[[8]](#references)</sup>
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
- Si `entry.FullName` commence par `..\\`, il effectue une traversée ; s’il s’agit d’un **absolute path**, le composant de gauche est entièrement ignoré, ce qui permet une **arbitrary file write** comme identité d’extraction.
- Archive de proof-of-concept permettant d’écrire dans un répertoire `app` frère surveillé par un scanner planifié :
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Déposer ce fichier ZIP dans la boîte de réception surveillée crée `C:\samples\app\0xdf.txt`, ce qui prouve une traversal en dehors de `C:\samples\queue\` et permet des primitives ultérieures (par exemple, des DLL hijacks).

## Exemple réel – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR pour Windows ainsi que ses composants Windows RAR/UnRAR ne validaient pas les noms de fichiers lors de l'extraction. La faille utilisait les alternate data streams (ADS) de NTFS pour contourner le chemin d'extraction sélectionné et écrire des fichiers à des emplacements non prévus.<sup>[[5]](#references)</sup>
Une archive RAR malveillante contenant une entrée telle que :
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **outside** the selected output directory and inside the user’s *Startup* folder. ESET observed malicious LNK files being unpacked there and executed at user logon, providing persistence and a path to RCE.<sup>[[5]](#references)</sup>

### Création d’une archive PoC (Linux/Mac)

Because CVE-2025-8088 uses a traversal path in an ADS name, use a purpose-built generator to create the RAR, then test extraction only in an isolated lab with a vulnerable WinRAR build.<sup>[[5]](#references)</sup>

### Exploitation observée dans la nature

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.<sup>[[5]](#references)</sup>

## Cas plus récents (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds before **25.00**. The symbolic-link processing flaw was fixed in **25.00** (July 2025) and later.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
This archive contains a symlink entry pointing outside the extraction directory; use a disposable target and verify that the extractor does not follow it. A write-through test also needs a regular-file entry beneath the symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Conseils de détection

* **Inspection statique** – List archive entries and flag any name containing `../`, `..\\`, *absolute paths* (`/`, `C:`) or entries of type *symlink* whose target is outside the extraction dir.
* **Canonicalisation** – Ensure `realpath(join(dest, name))` stays inside `realpath(dest)` (compare path components, not only a raw string prefix). Reject otherwise.<sup>[[3]](#references)</sup>
* **Extraction en sandbox** – Decompress into a disposable directory using an extractor with path/symlink checks (for example, bsdtar's default secure checks or 7-Zip ≥ 25.00), then verify resulting paths stay inside the directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Surveillance des endpoints** – Alert on new executables written to `Startup`/`Run`/`cron` locations shortly after an archive is opened by WinRAR/7-Zip/etc.

## Atténuation et durcissement

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ contain fixes for the cited path/symlink issues.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. On Unix, drop privileges & mount a **chroot/namespace** before extraction; on Windows, use **AppContainer** or a sandbox.
4. If writing custom code, normalise with `realpath()`/`PathCanonicalize()` **before** create/write, and reject any entry that escapes the destination.

## Autres cas affectés / historiques

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (fixed in v0.16.3).<sup>[[7]](#references)</sup>
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [1] [Trend Micro ZDI-25-949 – Traversal de symlink ZIP dans 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip dans mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prévenir Zip Slip dans .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Chaîne HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Mettez à jour les outils WinRAR maintenant : RomCom et d’autres exploitent une vulnérabilité zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgation publique d’une vulnérabilité critique d’écrasement arbitraire de fichiers : Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01 : go-slug vulnérable à une attaque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Méthode Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Indicateurs d’extraction sécurisée de bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit Proof-of-Concept signalé pour CVE-2025-11001 dans 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
