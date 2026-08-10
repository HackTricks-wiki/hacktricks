# Archive Extraction Path Traversal（"Zip-Slip" / WinRAR CVE-2025-8088）

## 概要

多くのアーカイブ形式（ZIP、RAR、TAR、7-ZIP など）では、各エントリに独自の **internal path** を指定できます。展開ユーティリティがそのパスを無条件に信頼すると、`..` や **absolute path**（例：`C:\Windows\System32\`）を含む細工されたファイル名によって、ユーザーが選択したディレクトリの外部に書き込まれてしまいます。
この種類の脆弱性は、一般に *Zip-Slip* または **archive extraction path traversal** と呼ばれています。<sup>[[6]](#references)</sup>

影響は任意ファイルの上書きから、Windows の *Startup* フォルダーなどの **auto-run** ロケーションに payload を配置することによる、直接的な **remote code execution (RCE)** の達成にまで及びます。

## Root Cause

1. 攻撃者は、1 つ以上のファイルヘッダーに次の内容を含むアーカイブを作成します。
* Relative traversal sequences（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* Absolute paths（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* または、target dir の外部に解決される細工された **symlinks**（*nix* の ZIP/TAR で一般的）。
2. Victim は、埋め込まれたパスを信頼する（または symlinks に従う）脆弱な tool を使ってアーカイブを展開します。この tool はパスを sanitise したり、選択したディレクトリ配下への展開を強制したりしません。
3. ファイルは攻撃者が制御するロケーションに書き込まれ、次回システムまたはユーザーがそのパスをトリガーした際に実行またはロードされます。

### .NET `Path.Combine` + `ZipArchive` traversal

よくある .NET の anti-pattern は、意図した destination と **user-controlled** な `ZipArchiveEntry.FullName` を結合し、パスの normalisation を行わずに展開することです。<sup>[[4]](#references)[[8]](#references)</sup>
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
- `entry.FullName` が `..\\` で始まる場合は traversal が発生します。**absolute path** の場合、左側の component が完全に破棄され、extraction identity として **arbitrary file write** が可能になります。
- scheduled scanner によって監視されている sibling の `app` directory に書き込むための Proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
その ZIP を監視対象の inbox に配置すると、`C:\samples\app\0xdf.txt` が作成され、`C:\samples\queue\` の外部への traversal が可能であることが証明され、後続の primitives（例: DLL hijacks）が有効になります。

## 実際の事例 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 向け WinRAR とその Windows RAR/UnRAR components は、extraction 中の filenames の検証に失敗していました。この flaw は NTFS alternate data streams (ADS) を使用して選択された extraction path を bypass し、意図しない locations に files を書き込むものでした。<sup>[[5]](#references)</sup>
次のような entry を含む malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **outside** the selected output directory and inside the user’s *Startup* folder. ESET observed malicious LNK files being unpacked there and executed at user logon, providing persistence and a path to RCE.<sup>[[5]](#references)</sup>

### PoC Archive の作成 (Linux/Mac)

CVE-2025-8088 は ADS name 内の traversal path を使用するため、専用の generator で RAR を作成し、その後、脆弱な WinRAR build を使用した隔離ラボ内でのみ extraction をテストしてください。<sup>[[5]](#references)</sup>

### 実環境で確認された Exploitation

ESET は、RomCom (Storm-0978/UNC2596) による spear-phishing campaigns を報告しました。これらの campaigns では、CVE-2025-8088 を悪用する RAR archives を添付し、customised backdoors を展開して ransomware operations を促進していました。<sup>[[5]](#references)</sup>

## 新しい Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: extraction 中に **symbolic links** である ZIP entries が dereference され、攻撃者が destination directory の外部へ脱出して任意の paths を overwrite できました。User interaction は archive の *opening/extracting* だけです。<sup>[[1]](#references)</sup>
* **Affected**: **25.00** より前の 7-Zip builds。symbolic-link processing flaw は **25.00** (July 2025) 以降で修正されました。<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` または service-run locations を overwrite → 次回の logon または service restart 時に code が実行される。
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
この archive には extraction directory の外部を指す symlink entry が含まれています。使い捨ての target を使用し、extractor がそれを follow しないことを確認してください。write-through test には、symlink 配下の regular-file entry も必要です。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` は `../` および symlinked ZIP entries を follow し、`outputDir` の外部に書き込みます。<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: `mholt/archives` ≥ 0.1.0 に切り替えるか、write 前に canonical-path checks を実装してください。
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – archive entries を一覧表示し、`../`、`..\\`、*absolute paths* (`/`, `C:`) を含む name、または target が extraction dir の外部にある *symlink* type の entries に flag を立てます。
* **Canonicalisation** – `realpath(join(dest, name))` が `realpath(dest)` 内にとどまることを確認します (raw string prefix だけでなく、path components を比較します)。それ以外は reject してください。<sup>[[3]](#references)</sup>
* **Sandbox extraction** – path/symlink checks を備えた extractor (例えば、bsdtar の default secure checks または 7-Zip ≥ 25.00) を使用し、使い捨ての directory に decompress してから、生成された paths が directory 内にとどまることを確認します。<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – archive が WinRAR/7-Zip などで開かれた直後に、`Startup`/`Run`/`cron` locations に新しい executables が書き込まれた場合に alert を出します。

## Mitigation & Hardening

1. **Extractor を update** – WinRAR 7.13+ および 7-Zip 25.00+ には、引用した path/symlink issues の fixes が含まれています。<sup>[[1]](#references)[[5]](#references)</sup>
2. 可能な場合は、アーカイブを “**Do not extract paths**” / “**Ignore paths**” を指定して extract します。
3. Unix では、extraction 前に privileges を drop し、**chroot/namespace** を mount します。Windows では **AppContainer** または sandbox を使用します。
4. custom code を書く場合は、create/write **前**に `realpath()`/`PathCanonicalize()` で normalise し、destination から escape する entries を reject します。

## Additional Affected / Historical Cases

* 2018 – 多数の Java/Go/JS libraries に影響した、Snyk による大規模な *Zip-Slip* advisory。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) の slugs における TAR extraction traversal (v0.16.3 で修正)。<sup>[[7]](#references)</sup>
* write 前に `PathCanonicalize` / `realpath` を呼び出さない、あらゆる custom extraction logic。

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET で Zip Slip を防止](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 今すぐ WinRAR tools を update: RomCom などが zero-day vulnerability (CVE-2025-8088) を exploit](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability の Public Disclosure: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug が Zip Slip Attack (CVE-2025-0377) に対して Vulnerable](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip の CVE-2025-11001 に対する Proof-of-Concept Exploit を報告](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
