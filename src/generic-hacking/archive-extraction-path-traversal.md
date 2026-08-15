# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## 概要

多くの archive format（ZIP、RAR、TAR、7-ZIP など）では、各エントリに独自の **internal path** を持たせることができます。extraction utility がそのパスを無条件に受け入れると、`..` や **absolute path**（例：`C:\Windows\System32\`）を含む細工されたファイル名が、ユーザーが選択したディレクトリの外部に書き込まれます。
このクラスの脆弱性は、一般に *Zip-Slip* または **archive extraction path traversal** と呼ばれています。<sup>[[6]](#references)</sup>

影響は任意ファイルの上書きから、Windows の *Startup* folder のような **auto-run** location に payload を配置することによる、直接的な **remote code execution (RCE)** の達成まで多岐にわたります。

## 根本原因

1. Attacker は、1 つ以上の file header に以下を含む archive を作成します。
* Relative traversal sequences（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* Absolute paths（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* または target dir の外部に解決される細工された **symlinks**（*nix* 上の ZIP/TAR で一般的）。
2. Victim は、embedded path を信頼する（または symlinks をたどる）vulnerable tool を使って archive を extraction します。これは、パスを sanitise したり、選択した directory 配下に限定して extraction したりしません。
3. file は attacker-controlled location に書き込まれ、次回 system または user がその path を trigger した際に executed/loaded されます。

### .NET `Path.Combine` + `ZipArchive` traversal

一般的な .NET anti-pattern は、意図した destination と **user-controlled** な `ZipArchiveEntry.FullName` を結合し、path normalisation なしで extraction することです。<sup>[[4]](#references)[[8]](#references)</sup>
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
- `entry.FullName` が `..\\` で始まる場合は traversal が発生します。**absolute path** の場合、左側のコンポーネントが完全に破棄され、extraction identity として **arbitrary file write** が可能になります。
- scheduled scanner に監視されている sibling の `app` directory に書き込むための Proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
その ZIP を監視対象の inbox に配置すると、`C:\samples\app\0xdf.txt` が生成され、`C:\samples\queue\` の外部への traversal が可能であることと、後続の primitives（例：DLL hijacks）が有効になることが証明されます。

## Advanced Archive-Breakout Primitives

extraction は独立した filename checks ではなく、filesystem mutations の連続として扱ってください。解析時には安全な entry でも、先行する member が link を作成または置換した後には unsafe になる可能性があります。同じ問題は、extractor が directory を安全なものとして cache した後、その type が変更される場合にも発生します。<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: `pivot -> /tmp` を作成し、通常の member を `pivot/PWNED.txt` として extraction します。extractor が最初の member を follow して 2 番目の member を materialise する場合、2 番目の name に `..` がなくても write が外部へ抜け出します。
* **Directory-cache/TOCTOU collision**: directory `d/sub/` を出力し、`d/sub` を `/tmp` への symlink に置換してから、`d/sub/PWNED.txt` を出力します。これは、directory を一度だけ validate または cache し、final write の前に再チェックしない extractor を対象とします。
* **Hardlink read/overwrite**: TAR と RAR は hardlink を表現できます。既存の host file への hardlink により、後続の component が extracted name を提供した場合に、その内容が露出する可能性があります。一方、衝突する通常の entry は、link された inode を上書きできます。これは、同一 filesystem の制約と OS の hardlink permission rules によって制限されます。
* **Pre-existing or cross-archive pivot**: 空でない destination を使って再試行します。各 archive が stateless な header-name check を通過していても、ある archive が link を仕込み、後続の extraction がその link 経由で write できる場合があります。<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

name は、それを受け取る filesystem の semantics を使って比較してください。有用な differential cases には、case-insensitive filesystem 上での `LINK` と `link`、NFC と NFD の Unicode 表記、`ﬁle` と `file` のような compatibility-equivalent names、path を directory から symlink に変更する duplicate members、Windows 上でのみ backslash が separator として解釈されるケースなどがあります。また、NTFS では ADS-bearing names もテストしてください。これらのケースにより、validator には 2 つの path が見えても、filesystem は 1 つとして解決する可能性があります。<sup>[[5]](#references)[[11]](#references)</sup>

したがって、compact corpus では **directory → symlink → child**、**symlink → colliding regular file**、**hardlink → colliding regular file**、`/` と `\` の混在、absolute/rooted names、`.tar.gz` のような compressed wrappers の順序付き combinations をテストする必要があります。テストは disposable VM/container 内でのみ実行し、destination と想定される外部の canary path の両方を監視してください。<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 用 WinRAR とその Windows RAR/UnRAR components は、extraction 中の filenames の validate に失敗していました。この flaw は NTFS alternate data streams (ADS) を使用して選択された extraction path を bypass し、意図しない locations に files を write していました。<sup>[[5]](#references)</sup>
次のような entry を含む malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
は **外部** に出て、ユーザーの *Startup* フォルダー内に配置されることになります。ESETは、悪意のあるLNKファイルがそこに展開され、ユーザーのログオン時に実行されることで、persistenceとRCEへの経路が提供される事例を確認しました。<sup>[[5]](#references)</sup>

### PoC Archiveの作成（Linux/Mac）

CVE-2025-8088はADS名にtraversal pathを使用するため、専用のgeneratorでRARを作成し、その後、vulnerableなWinRAR buildを使用した隔離lab内でのみextractをテストしてください。<sup>[[5]](#references)</sup>

### 実環境で確認されたExploitation

ESETは、RomCom（Storm-0978/UNC2596）によるspear-phishing campaignを報告しました。このcampaignでは、CVE-2025-8088を悪用するRAR archiveを添付し、customized backdoorを展開してransomware operationを促進していました。<sup>[[5]](#references)</sup>

## Newer Cases (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entryの **symbolic link** がextract中にdereferenceされ、attackerがdestination directoryから抜け出して任意のpathをoverwriteできました。ユーザー操作はarchiveの *opening/extracting* だけです。<sup>[[1]](#references)</sup>
* **Affected**: **25.00** 未満の7-Zip build。symbolic-link processingのflawは **25.00**（2025年7月）以降でfixされました。<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` またはservice-run locationをoverwrite → 次回のlogonまたはservice restart時にcodeが実行される。
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
このarchiveには、extraction directoryの外部を指すsymlink entryが含まれています。使い捨てのtargetを使用し、extractorがそれをfollowしないことを確認してください。write-through testには、symlink配下のregular-file entryも必要です。

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` はZIP symlinkをextractした後、後続のregular memberが同じnameを持つ場合にそれをdereferenceできます。これにより、一見in-rootへのwriteがout-of-rootへのwriteに変わります。<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1（現在はdeprecatedのproject）。<sup>[[2]](#references)</sup>
* **Fix**: `mholt/archives` ≥ 0.1.0へswitchするか、linkをrejectし、destinationをopenする直前に毎回再resolveしてください。<sup>[[2]](#references)</sup>
* **Minimal collision generator**（その後 `archiver.Unarchive("exploit.zip", "/tmp/safe")` を呼び出す）:<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython filtered TAR extraction bypass (CVE-2026-11940)

`tarfile.extractall(filter="data")` と `filter="tar"` でさえ、link-order bypassの影響を受けたことがあります。このケースでは、hardlinkが、より深いpathにarchiveされたsymlinkを参照していました。fallback extractionは、その深いlocationにおけるrelative symlinkをvalidateしましたが、同じrelative targetをhardlinkのより浅いlocationに再作成したため、そこから外部へescapeできました。これは有用なgeneral testです。validationとmaterialisationで、base directoryまたは最終member typeの扱いが一致しないようにします。<sup>[[12]](#references)</sup>

## Detection Tips

* **Static inspection** – member nameとlink targetの両方を列挙します。`../`、`..\\`、absolute/rooted path、symlink、hardlink、special file、duplicate name、type change、case/Unicode-equivalent collisionをflagします。exploitが先行するmemberに依存する可能性があるため、review中はentry orderを保持してください。<sup>[[11]](#references)</sup>
* **Canonicalisation** – resolved parentとfinal basenameを結合した結果が、resolved destination配下に残ることを確認します（raw string prefixではなくpath componentを比較します）。先行する各memberの後に再確認してください。1回だけ行う`realpath(join(dest, name))` testは、link replacementに対してvulnerableであり、まだ作成されていないleafでは失敗する可能性があります。<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – path/symlink checkを備えたextractor（たとえばbsdtarのdefault secure checkまたは7-Zip ≥ 25.00）を使用して、新しい使い捨てdirectoryへdecompressし、その後、生成されたtreeに外部へ向かうlinkがないことを確認します。隔離によって、すでにtriggerされたescapeがhost pathへ到達しないようにする必要があります。<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – extraction自体が外部fileを作成しなかった場合でも、previewer、CDN、file browser、package pipelineが後からextracted nameをopenまたはserveすると、残存したsymlinkまたはhardlinkがarbitrary-file-read primitiveになる可能性があります。<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zipなどでarchiveがopenされた直後に、`Startup`/`Run`/`cron` locationへ新しいexecutableがwriteされた場合にalertを出します。

## Mitigation & Hardening

1. **Extractorをupdateする** – WinRAR 7.13+ と7-Zip 25.00+には、今回引用したpath/symlink issueのfixが含まれています。<sup>[[1]](#references)[[5]](#references)</sup>
2. 可能な場合は、“**Do not extract paths**” / “**Ignore paths**” を指定してarchiveをextractします。untrusted inputでは、applicationが明示的に必要としない限り、symbolic link、hardlink、device、FIFOをrejectしてください。<sup>[[9]](#references)[[11]](#references)</sup>
3. **新しい空のdirectory**へextractします。attackerがreplace可能なpathを含むtreeへuntrusted memberをmergeせず、以前のarchiveが作成したdirectoryを再利用しないでください。<sup>[[11]](#references)</sup>
4. Unixではprivilegeをdropし、destinationを **chroot/mount namespace** 内にisolateします。Windowsでは **AppContainer** またはsandboxを使用します。post-extraction scanだけでは不十分です。scanの前にescaped writeが発生するためです。<sup>[[11]](#references)</sup>
5. custom codeでは、target OSのseparator/case/Unicode ruleを適用し、memberとlink targetの両方をvalidateします。linkをfollowせずにdestinationをresolveしてopenし、containment checkと後続のcreate/replace operationを分離しないでください。validatorは、write pathとまったく同じbaseおよびlink-emulation semanticsを使用する必要があります。<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – 多数のJava/Go/JS libraryに影響した、Snykによる大規模な *Zip-Slip* advisory。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）におけるslug内のTAR extraction traversal（v0.16.3でfix）。<sup>[[7]](#references)</sup>
* header stringはvalidateするものの、link targetおよび各writeで使用される最終filesystem pathをvalidateしない、あらゆるcustom extraction logic。<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NETでZip Slipを防止する](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 今すぐWinRAR toolsをupdate：RomComなどがzero-day vulnerability（CVE-2025-8088）をexploiting](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – CriticalなArbitrary File Overwrite VulnerabilityのPublic Disclosure：Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01：go-slugがZip Slip Attack（CVE-2025-0377）に対してVulnerable](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-ZipにおけるCVE-2025-11001のProof-of-Concept Exploitが報告される](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slips、tar-slips、symlinks、hardlinks、collisionsなどを使ったHacking fun](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
