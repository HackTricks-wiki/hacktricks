# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概要

多くの archive format（ZIP、RAR、TAR、7-ZIP など）では、各エントリに独自の **internal path** を持たせることができます。抽出 utility がそのパスを無条件に信頼すると、`..` や **absolute path**（例: `C:\Windows\System32\`）を含む細工されたファイル名が、ユーザーが選択した directory の外側に書き込まれます。
この種の vulnerability は、一般に *Zip-Slip* または **archive extraction path traversal** として知られています。<sup>[[6]](#references)</sup>

影響は任意のファイルの上書きから、Windows の *Startup* folder のような **auto-run** location に payload を配置して、直接 **remote code execution (RCE)** を達成することまで及びます。

## Root Cause

1. Attacker は、1 つ以上の file header に次の内容を含む archive を作成します。
* Relative traversal sequences（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* Absolute paths（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* または、target dir の外側を指すように解決される細工された **symlinks**（*nix* の ZIP/TAR で一般的）。
2. Victim は、埋め込まれたパスを信頼する（または symlinks に従う）vulnerable tool を使って archive を抽出します。この tool は、パスを sanitise したり、選択した directory 配下での抽出を強制したりしません。
3. ファイルが attacker の制御する location に書き込まれ、次回 system または user がそのパスを trigger した際に実行または load されます。

### .NET `Path.Combine` + `ZipArchive` traversal

一般的な .NET の anti-pattern は、意図した destination と **user-controlled** な `ZipArchiveEntry.FullName` を組み合わせ、パスを normalisation せずに抽出することです。<sup>[[4]](#references)[[8]](#references)</sup>
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
- `entry.FullName` が `..\\` で始まる場合、traversal が発生します。**absolute path** の場合は左側のコンポーネントが完全に破棄され、extract の identity として**任意ファイル書き込み**が可能になります。
- scheduled scanner によって監視されている sibling の `app` directory に書き込む proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
その ZIP を監視対象の inbox に投入すると、`C:\samples\app\0xdf.txt` が生成され、`C:\samples\queue\` の外部への traversal が可能であることが証明され、後続のプリミティブ（例：DLL hijacks）が利用可能になります。

## 実世界の例 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 向け WinRAR およびその Windows RAR/UnRAR components は、extraction 中のファイル名の検証に失敗していました。この脆弱性では、NTFS alternate data streams (ADS) を使用して選択された extraction path をバイパスし、意図しない場所にファイルを書き込んでいました。<sup>[[5]](#references)</sup>
次のような entry を含む悪意のある RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
は **外部** の選択された出力ディレクトリに出て、ユーザーの *Startup* フォルダー内に配置されることになります。ESET は、悪意のある LNK ファイルがそこに unpack され、ユーザーのログオン時に実行されることで、persistence と RCE への経路を提供することを確認しました。<sup>[[5]](#references)</sup>

### PoC Archive の作成（Linux/Mac）

CVE-2025-8088 は ADS 名に traversal path を使用するため、専用の generator で RAR を作成し、その後、脆弱な WinRAR build を用いた隔離された lab 内でのみ extraction をテストしてください。<sup>[[5]](#references)</sup>

### 実環境で確認された Exploitation

ESET は、RomCom（Storm-0978/UNC2596）による spear-phishing campaign を報告しました。これらの campaign では、CVE-2025-8088 を悪用する RAR archive を添付し、customized backdoor を deploy するとともに、ransomware operation を促進していました。<sup>[[5]](#references)</sup>

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: extraction 中に **symbolic link** である ZIP entry が dereference され、攻撃者が destination directory の外部へ escape して任意の path を overwrite できました。ユーザー操作は archive の *opening/extracting* だけです。<sup>[[1]](#references)</sup>
* **Affected**: **25.00** より前の 7-Zip build。symbolic-link processing の flaw は **25.00**（2025 年 7 月）以降で修正されています。<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` または service-run location を overwrite → 次回の logon または service restart 時に code が実行されます。
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
この archive には extraction directory の外部を指す symlink entry が含まれます。使い捨ての target を使用し、extractor がそれを follow しないことを確認してください。write-through test には、symlink 配下の regular-file entry も必要です。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` は `../` および symlinked ZIP entry を follow し、`outputDir` の外部に write します。<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1（project は現在 deprecated）。
* **Fix**: `mholt/archives` ≥ 0.1.0 に切り替えるか、write 前に canonical-path check を実装します。
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – archive entry を一覧表示し、`../`、`..\\`、*absolute path*（`/`、`C:`）を含む name、または target が extraction dir の外部にある *symlink* type の entry に flag を付けます。
* **Canonicalisation** – `realpath(join(dest, name))` が `realpath(dest)` の内部に留まることを確認します（単なる raw string prefix ではなく、path component を比較します）。それ以外は reject します。<sup>[[3]](#references)</sup>
* **Sandbox extraction** – path/symlink check を備えた extractor（例えば、bsdtar の default secure check または 7-Zip ≥ 25.00）を使用して、使い捨ての directory に decompress し、その後、生成された path が directory 内に留まっていることを確認します。<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip などで archive が開かれた直後に、`Startup`/`Run`/`cron` location に新しい executable が write された場合は alert を出します。

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ および 7-Zip 25.00+ には、d path/symlink issue に対する fix が含まれています。<sup>[[1]](#references)[[5]](#references)</sup>
2. 可能な場合は、「**Do not extract paths**」/「**Ignore paths**」を指定して archive を extract します。
3. Unix では extraction 前に privilege を drop し、**chroot/namespace** を mount します。Windows では **AppContainer** または sandbox を使用します。
4. custom code を作成する場合は、create/write **前** に `realpath()`/`PathCanonicalize()` で normalize し、destination から escape する entry をすべて reject します。

## Additional Affected / Historical Cases

* 2018 – 多数の Java/Go/JS library に影響した、Snyk による大規模な *Zip-Slip* advisory。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）における slug 内の TAR extraction traversal（v0.16.3 で fix）。<sup>[[7]](#references)</sup>
* write 前に `PathCanonicalize` / `realpath` を呼び出さない、あらゆる custom extraction logic。

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET で Zip Slip を防止](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 今すぐ WinRAR tools を update：RomCom などが zero-day vulnerability（CVE-2025-8088）を exploitation](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability「Zip Slip」の Public Disclosure](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01：go-slug が Zip Slip Attack（CVE-2025-0377）に対して Vulnerable](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip における CVE-2025-11001 の Proof-of-Concept Exploit を報告](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
