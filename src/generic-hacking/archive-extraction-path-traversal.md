# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概要

多くの archive format（ZIP、RAR、TAR、7-ZIP など）では、各エントリに独自の **internal path** を持たせることができます。extraction utility がそのパスを無条件に受け入れると、`..` や **absolute path**（例: `C:\Windows\System32\`）を含む細工されたファイル名が、ユーザーが選択したディレクトリの外部に書き込まれます。
この種の脆弱性は、一般に *Zip-Slip* または **archive extraction path traversal** と呼ばれています。<sup>[[6]](#references)</sup>

影響は任意ファイルの上書きから、Windows の *Startup* フォルダーなどの **auto-run** location に payload を配置して **remote code execution (RCE)** を直接達成することまで及びます。

## Root Cause

1. Attacker は、1 つ以上の file header に次の内容を含む archive を作成します。
* Relative traversal sequences（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* Absolute paths（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* または、target dir の外部に解決される細工された **symlinks**（*nix* の ZIP/TAR で一般的）。
2. Victim は、選択したディレクトリ配下に extraction を強制したり、パスを sanitise したりせず、埋め込まれたパスを信頼する（または symlinks に従う）vulnerable tool で archive を extract します。
3. ファイルが attacker の制御する location に書き込まれ、次回 system または user がそのパスを trigger した際に実行または load されます。

### .NET `Path.Combine` + `ZipArchive` traversal

一般的な .NET の anti-pattern は、意図した destination と **user-controlled** な `ZipArchiveEntry.FullName` を combine し、パスの normalisation を行わずに extract することです。<sup>[[4]](#references)[[8]](#references)</sup>
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
- `entry.FullName` が `..\\` で始まる場合、traversal が発生します。**absolute path** の場合、左側のコンポーネントが完全に破棄され、extraction identity として **arbitrary file write** が可能になります。
- scheduled scanner に監視されている sibling `app` directory に書き込むための Proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
その ZIP を監視対象の inbox に配置すると、`C:\samples\app\0xdf.txt` が生成され、`C:\samples\queue\` の外部への traversal が可能であることが証明され、後続のプリミティブ（例：DLL hijacks）が可能になります。

## 実際の事例 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 向け WinRAR とその Windows RAR/UnRAR components は、展開時に filenames の検証に失敗していました。この flaw では NTFS alternate data streams (ADS) を使用して選択された extraction path を回避し、意図しない locations に files を書き込むことが可能でした。<sup>[[5]](#references)</sup>
次のような entry を含む malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
は、選択した出力ディレクトリの**外側**かつユーザーの *Startup* フォルダ内に配置されることになります。ESET は、悪意のある LNK ファイルがそこに展開され、ユーザーのログオン時に実行されることで、persistence と RCE への経路を提供していたことを確認しました。<sup>[[5]](#references)</sup>

### PoC Archive の作成（Linux/Mac）

CVE-2025-8088 は ADS 名に traversal path を使用するため、専用の generator で RAR を作成し、脆弱な WinRAR build を使った隔離 lab 内でのみ extraction をテストしてください。<sup>[[5]](#references)</sup>

### 実環境で確認された Exploitation

ESET は、RomCom（Storm-0978/UNC2596）による spear-phishing campaign を報告しました。この campaign では、CVE-2025-8088 を悪用する RAR archive を添付し、customised backdoor を展開して ransomware operation を促進していました。<sup>[[5]](#references)</sup>

## 新しい事例（2024–2025）

### 7-Zip ZIP symlink traversal → RCE（CVE-2025-11001 / ZDI-25-949）
* **Bug**: **symbolic link** である ZIP entry が extraction 中に dereference され、攻撃者が destination directory の外へ脱出して任意の path を overwrite できました。ユーザーに必要な操作は archive を*開く／extract する*ことだけです。<sup>[[1]](#references)</sup>
* **Affected**: **25.00** より前の 7-Zip build。symbolic-link processing の flaw は **25.00**（2025 年 7 月）以降で修正されています。<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` または service-run location を overwrite → 次回の logon または service restart 時に code が実行される。
* **簡易 symlink-handling fixture（Linux）**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
この archive には extraction directory の外を指す symlink entry が含まれています。使い捨ての target を使用し、extractor が symlink を follow しないことを確認してください。write-through test では、symlink 配下に regular-file entry も必要です。

### Go mholt/archiver Unarchive() Zip-Slip（CVE-2025-3445）
* **Bug**: `archiver.Unarchive()` は `../` および symlink された ZIP entry を follow し、`outputDir` の外に write します。<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1（project は現在 deprecated）。
* **Fix**: `mholt/archives` ≥ 0.1.0 に切り替えるか、write 前に canonical-path check を実装します。
* **最小 reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – archive entry を列挙し、`../`、`..\\`、*absolute path*（`/`、`C:`）を含む name、または target が extraction dir の外にある *symlink* type の entry を flag します。
* **Canonicalisation** – `realpath(join(dest, name))` が `realpath(dest)` の内側に留まることを確認します（raw string prefix だけでなく、path component を比較）。それ以外は reject します。<sup>[[3]](#references)</sup>
* **Sandbox extraction** – path/symlink check を備えた extractor（例: bsdtar の default secure check または 7-Zip ≥ 25.00）を使用して、使い捨て directory に decompress し、その後 resulting path が directory 内に留まっていることを確認します。<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip などで archive が開かれた直後に、`Startup`/`Run`/`cron` location に新しい executable が write された場合に alert を出します。

## Mitigation & Hardening

1. **Extractor を update** – WinRAR 7.13+ および 7-Zip 25.00+ には、引用した path/symlink issue の fix が含まれています。<sup>[[1]](#references)[[5]](#references)</sup>
2. 可能な場合は、**“Do not extract paths”** / **“Ignore paths”** を指定して archive を extract します。
3. Unix では extraction 前に privileges を drop し、**chroot/namespace** を mount します。Windows では **AppContainer** または sandbox を使用します。
4. custom code を write する場合は、create/write **前**に `realpath()`/`PathCanonicalize()` で normalise し、destination から脱出する entry を reject します。

## その他の Affected / Historical Cases

* 2018 – Snyk による大規模な *Zip-Slip* advisory。多数の Java/Go/JS library に影響しました。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）における slug 内 TAR extraction traversal（v0.16.3 で fix）。<sup>[[7]](#references)</sup>
* write 前に `PathCanonicalize` / `realpath` を call しない custom extraction logic 全般。

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal（CVE-2025-11001）](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip（CVE-2025-3445）](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET で Zip Slip を防止する方法](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 今すぐ WinRAR tools を update: RomCom などが zero-day vulnerability（CVE-2025-8088）を exploitation](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical な任意 file overwrite vulnerability: Zip Slip の公開 disclosure](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug が Zip Slip attack（CVE-2025-0377）に vulnerable](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip における CVE-2025-11001 の Proof-of-Concept Exploit が報告](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
