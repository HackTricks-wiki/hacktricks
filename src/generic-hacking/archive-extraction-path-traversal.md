# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## 概要

多くのアーカイブ形式（ZIP、RAR、TAR、7-ZIP など）では、各エントリに独自の**内部パス**を含めることができます。展開ユーティリティがそのパスを無条件に尊重すると、`..` や**絶対パス**（例: `C:\Windows\System32\`）を含む細工されたファイル名が、ユーザーが指定したディレクトリの外に書き込まれます。  
この種の脆弱性は、*Zip-Slip* または **archive extraction path traversal** として広く知られています。<sup>[[6]](#references)</sup>

影響は任意のファイルの上書きから、Windows の *Startup* フォルダーなどの**自動実行**される場所にペイロードを配置して、直接 **remote code execution (RCE)** を達成することまで多岐にわたります。

## 根本原因

1. 攻撃者が、1 つ以上のファイルヘッダーに次のいずれかを含むアーカイブを作成します。
   * 相対パスによるトラバーサルシーケンス（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
   * 絶対パス（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
   * または、対象ディレクトリの外を指すように細工された**シンボリックリンク**（*nix* の ZIP/TAR でよく見られる）。
2. 被害者が、パスをサニタイズしたり、指定ディレクトリ配下への展開を強制したりせず、埋め込まれたパスを信頼する（またはシンボリックリンクをたどる）脆弱なツールでアーカイブを展開します。
3. ファイルが攻撃者の制御する場所に書き込まれ、次回、システムまたはユーザーがそのパスを利用した際に実行または読み込まれます。

### .NET `Path.Combine` + `ZipArchive` によるトラバーサル

よくある .NET のアンチパターンは、意図した保存先と**ユーザー制御可能な** `ZipArchiveEntry.FullName` を結合し、パスを正規化せずに展開することです。<sup>[[4]](#references)[[8]](#references)</sup>

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

- `entry.FullName` が `..\\` で始まる場合、上位ディレクトリへ移動します。**絶対パス**の場合は左側のコンポーネントが完全に破棄され、展開先を基準とした **arbitrary file write** が可能になります。
- 定期スキャナーが監視する隣接する `app` ディレクトリに書き込むための proof-of-concept archive:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

監視対象の inbox にこの ZIP を置くと、`C:\samples\app\0xdf.txt` が作成され、`C:\samples\queue\` の外への traversal が実証されます。また、後続の攻撃手法（DLL hijack など）が可能になります。

### ユーザー制御可能な展開先ディレクトリ

アーカイブ内のメンバー名だけでなく、**extractor に渡されるディレクトリ**もテストしてください。アプリケーションは、そのディレクトリをタイトル、プロジェクト名、その他のリクエストフィールドから生成する場合があります。`../../../../app/module` のような値を指定すると、extractor がメンバーを処理する前に、展開先をアップロード領域の外に移動できます。この場合、`api.py` という安全なベース名だけを含むアーカイブでも、アプリケーションコードを上書きできます。<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

これは classic Zip-Slip とは別の containment boundary です。解決後の展開ルートと、各メンバーの解決後のパスの両方を検証してください。ルートのチェックには、文字列のプレフィックスではなくパスの各要素を使用できます。<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

安全なテストでは、有効なアーカイブにcanary fileを1つ含め、展開先ディレクトリを選択する可能性のある各フィールドにpath traversalシーケンスを配置します。意図したディレクトリと、使い捨ての外部パスの両方を監視してください。展開先からインポート済みモジュールに到達できる場合、そのモジュールを上書きすると、workerの再読み込み時にcode executionにつながる可能性があります。再読み込み中のHTTP 500や接続リセットは、書き込みが失敗した証拠にはなりません。<sup>[[14]](#references)[[15]](#references)</sup> より広範な[file upload methodology](../pentesting-web/file-upload/)も参照してください。

## 高度なArchive-Breakoutプリミティブ

展開処理は、独立したファイル名チェックではなく、一連のファイルシステム変更として捉えてください。パース時点では安全なエントリでも、先行するメンバーがリンクを作成または置換すると危険になることがあります。同様の問題は、展開ツールがディレクトリを安全と判断してキャッシュした後、その種類が変更される場合にも発生します。<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: `pivot -> /tmp`を作成し、その後、通常のメンバーを`pivot/PWNED.txt`として展開します。展開ツールが2つ目のメンバーを書き込む際に最初のメンバーをたどる場合、2つ目の名前に`..`がなくても書き込み先が逸脱します。
* **Directory-cache/TOCTOU collision**: ディレクトリ`d/sub/`を作成し、`d/sub`を`/tmp`へのsymlinkに置き換えてから、`d/sub/PWNED.txt`を出力します。これは、ディレクトリを一度だけ検証またはキャッシュし、最終的な書き込み前に再確認しない展開ツールを狙います。
* **Hardlink read/overwrite**: TARとRARではhardlinkを表現できます。既存のホストファイルへのhardlinkは、後続の処理で展開先の名前が提供されると、その内容を露出させる可能性があります。一方、名前が衝突する通常のエントリは、リンク先のinodeを上書きする可能性があります。これは、同一ファイルシステムであること、およびOSのhardlink権限ルールによって制限されます。
* **Pre-existing or cross-archive pivot**: 空ではない展開先で再試行します。各アーカイブがステートレスなヘッダー名チェックを通過しても、あるアーカイブでリンクを仕込み、後続の展開でそのリンクを通じて書き込める場合があります。<sup>[[11]](#references)</sup>

### ファイルシステムの同一視による衝突

ファイル名は、展開先のファイルシステムのセマンティクスに従って比較してください。有用な差分テストケースには、大文字小文字を区別しないファイルシステムにおける`LINK`と`link`、NFCとNFDのUnicode表記、`ﬁle`と`file`のような互換等価名、パスをディレクトリからsymlinkに変える重複メンバー、Windowsでのみ区切り文字として解釈されるバックスラッシュがあります。NTFSではADSを含む名前もテストしてください。こうしたケースでは、validatorには2つのパスに見えても、ファイルシステムでは1つに解決されることがあります。<sup>[[5]](#references)[[11]](#references)</sup>

そのため、コンパクトなテストコーパスでは、**directory → symlink → child**、**symlink → colliding regular file**、**hardlink → colliding regular file**、`/`と`\`の混在、絶対パスまたはrooted name、`.tar.gz`のような圧縮ラッパーを組み合わせた順序付きテストを実施します。使い捨てのVM/container内だけで実行し、展開先と、意図した外部canary pathの両方を監視してください。<sup>[[11]](#references)</sup>

ZIP固有の構造的な曖昧さにより、事前スキャンと実際の展開ツールとで、認識されるエントリ名やツリーが異なる場合があります。1つのZIPライブラリの出力だけを信用せず、[Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion)を参照してください。

## 実例 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows版WinRARおよびWindows用RAR/UnRARコンポーネントは、展開時のファイル名を検証できていませんでした。この脆弱性はNTFS alternate data streams (ADS)を利用して指定された展開先パスを迂回し、意図しない場所にファイルを書き込みました。<sup>[[5]](#references)</sup>
次のようなエントリを含む悪意のあるRARアーカイブ:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

選択した出力ディレクトリの**外側**にあり、ユーザーの *Startup* フォルダー内に展開されることになります。ESETは、悪意のあるLNKファイルがそこに展開され、ユーザーのログオン時に実行されることで、永続化とRCEへの足がかりを得る事例を確認しました。<sup>[[5]](#references)</sup>

### PoCアーカイブの作成（Linux/Mac）

CVE-2025-8088ではADS名にパストラバーサルのパスが使われるため、専用のgeneratorを使ってRARを作成し、脆弱なWinRARビルドを使って隔離されたラボ内でのみ展開テストを行ってください。<sup>[[5]](#references)</sup>

### 実環境で確認された悪用

ESETは、CVE-2025-8088を悪用するRARアーカイブを添付し、カスタマイズされたバックドアを展開してランサムウェア活動を支援する、RomCom（Storm-0978/UNC2596）によるスピアフィッシングキャンペーンを報告しました。<sup>[[5]](#references)</sup>

## 新しい事例（2024–2026）

### 7-ZipのZIPシンボリックリンクトラバーサル → RCE（CVE-2025-11001 / ZDI-25-949）
* **バグ**: **シンボリックリンク**であるZIPエントリが展開時に参照先へたどられ、攻撃者が展開先ディレクトリから抜け出して任意のパスを上書きできました。ユーザーが行う操作は、アーカイブを*開く／展開する*だけです。<sup>[[1]](#references)</sup>
* **影響を受けるバージョン**: **25.00**より前の7-Zipビルド。このシンボリックリンク処理の脆弱性は**25.00**（2025年7月）以降で修正されました。<sup>[[1]](#references)[[10]](#references)</sup>
* **影響する経路**: `Start Menu/Programs/Startup`やサービスによって実行される場所を上書き → 次回ログオン時またはサービス再起動時にコードが実行されます。
* **シンボリックリンク処理の簡易テスト用fixture（Linux）**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  このアーカイブには、展開先ディレクトリの外を指す symlink エントリが含まれています。使い捨てのターゲットを用意し、展開ツールがそのリンクをたどらないことを確認してください。write-through テストには、symlink の下に通常ファイルのエントリも必要です。

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **バグ**: `archiver.Unarchive()` は ZIP の symlink を展開した後、後続の通常メンバーの名前が同じ場合にそのリンクをたどり、一見ルート内への書き込みに見える操作をルート外への書き込みに変える可能性があります。<sup>[[2]](#references)</sup>
* **影響を受けるバージョン**: `github.com/mholt/archiver` ≤ 3.5.1（プロジェクトは現在非推奨）。<sup>[[2]](#references)</sup>
* **修正**: `mholt/archives` ≥ 0.1.0 に切り替えるか、リンクを拒否し、各書き込み先を開く直前に再解決してください。<sup>[[2]](#references)</sup>
* **最小衝突ジェネレーター**（続けて `archiver.Unarchive("exploit.zip", "/tmp/safe")` を呼び出す）:<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### CPython のフィルター付き TAR 展開の bypass (CVE-2026-11940)

`tarfile.extractall(filter="data")` と `filter="tar"` にも、リンク順序による bypass が存在していました。このケースでは、hardlink が、より深いパスにアーカイブされた symlink を参照していました。フォールバック展開では、その深い場所を基準に相対 symlink が検証されましたが、hardlink の浅い場所に再作成されたため、同じ相対ターゲットがそこから外部へ抜け出しました。これは汎用的なテストとして有用です。検証時と実体化時で、基準ディレクトリまたは最終的なメンバーの種類に食い違いが生じるようにします。<sup>[[12]](#references)</sup>

### symlink チェーンを経由した Node `tar` の hardlink ターゲットの逸脱 (GHSA-83g3-92jg-28cx)

Node.js の `tar` パッケージの `tar.extract()` は、字句上は展開先の範囲内に見えるものの、先に処理された2つの symlink を経由すると展開ルートの外に解決される hardlink を受け入れていました。この攻撃はデフォルトの展開オプションで成立します。展開先の親ディレクトリのチェックでは hardlink のルート内の名前は確認されていましたが、hardlink のターゲットは、チェーン全体を解決して範囲内かを確認せずにファイルシステムへ渡されていました。影響を受けるのは `tar` ≤ 7.5.7 で、この問題は 7.5.8 で修正されています。<sup>[[13]](#references)</sup>

重要なテストフィクスチャは、以下の文字列そのものではなく、メンバー間の**順序関係**です。<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

抽出に成功すると、`exfil` は出力ツリー内に見える状態で残りますが、選択した外部ファイルと inode を共有します。これを読み取るとそのファイルが leak し、書き込むと元のファイルが変更されます。この bypass は、最終的な pathname のみを検証する、絶対パスのプレフィックスを除去する、または hardlink header 内の `..` をブロックするだけでは不十分であることを示しています。リンク先は、それ以前に抽出されたすべての filesystem state を適用した後に検証してください。<sup>[[13]](#references)</sup>

## 検出のヒント

* **静的検査** – member 名とリンク先の両方を列挙します。`../`、`..\\`、絶対パス／rooted path、symlink、hardlink、特殊ファイル、重複名、型の変更、case／Unicode 上同等な名前の衝突を検出します。exploit が先行する member に依存する場合があるため、レビュー中はエントリの順序を維持してください。<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **正規化** – 解決済みの親パスと最終 basename の組み合わせが、解決済みの展開先の配下にあることを確認します（生の文字列 prefix ではなく、パスの各要素を比較します）。先行する各メンバーの処理後に再確認してください。一度だけ `realpath(join(dest, name))` を検査する方法は、リンクの置き換えに対して脆弱であり、まだ作成されていない leaf では失敗する可能性があります。<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox での展開** – パスや symlink を検査する extractor（例: bsdtar のデフォルトの安全な検査、または 7-Zip ≥ 25.00）を使い、新しく作成した使い捨てディレクトリに展開してから、生成された tree に外部を指すリンクがないことを確認します。すでに発生した脱出がホストのパスに到達しないよう、隔離する必要があります。<sup>[[1]](#references)[[9]](#references)</sup>
* **後続の読み込みも重要** – 残存した symlink や hardlink は、展開時に外部ファイルが作成されていなくても、後で previewer、CDN、file browser、package pipeline などが展開された名前を開いたり配信したりすることで、任意ファイル読み取りの primitive になり得ます。<sup>[[11]](#references)</sup>
* **エンドポイントの監視** – WinRAR/7-Zip などで archive を開いた直後に、`Startup`/`Run`/`cron` の場所へ新しい実行ファイルが書き込まれた場合にアラートを出します。

## 緩和策と堅牢化

1. **Extractor を更新する** – WinRAR 7.13+、7-Zip 25.00+、Node `tar` 7.5.8+ には、引用されている path/symlink/link-target の問題に対する修正が含まれています。<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. 可能な場合は、「**パスを展開しない**」/「**パスを無視する**」を指定して archive を展開します。信頼できない入力では、アプリケーションが明示的に必要としない限り、symbolic link、hardlink、device、FIFO を拒否します。<sup>[[9]](#references)[[11]](#references)</sup>
3. **新しい空のディレクトリ**に展開します。攻撃者が置き換え可能なパスを含む tree に、信頼できないメンバーをマージしないでください。また、以前の archive が作成したディレクトリを再利用しないでください。<sup>[[11]](#references)</sup>
4. Unix では権限を落とし、展開先を **chroot/mount namespace** 内に隔離します。Windows では **AppContainer** または sandbox を使用します。展開後のスキャンだけでは不十分です。脱出による書き込みはスキャンより前に発生するためです。<sup>[[11]](#references)</sup>
5. 独自コードでは、対象 OS の separator/case/Unicode の規則を適用し、メンバーとリンク先の両方を検証します。リンクをたどらずに展開先を解決して開き、包含チェックと後続の作成・置換処理を分離しないでください。validator は、書き込み処理とまったく同じ base およびリンクのエミュレーション規則を使用する必要があります。<sup>[[11]](#references)[[12]](#references)</sup>

## その他の影響事例 / 過去の事例

* 2018 – Snyk による大規模な *Zip-Slip* アドバイザリ。多数の Java/Go/JS ライブラリに影響。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）の slug における TAR 展開 traversal（v0.16.3 で修正）。<sup>[[7]](#references)</sup>
* header 文字列だけを検証し、リンク先や書き込みごとに使用される最終的な filesystem path を検証しない、あらゆる独自の展開処理。<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip の symlink による ZIP traversal（CVE-2025-11001）](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver の Zip-Slip（CVE-2025-3445）](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET で Zip Slip を防ぐ](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno の ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 今すぐ WinRAR tools を更新: RomCom などが zero-day vulnerability（CVE-2025-8088）を悪用](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – 重大な任意ファイル上書き脆弱性 Zip Slip の公開](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug が Zip Slip Attack に対して脆弱（CVE-2025-0377）](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar の安全な展開フラグ](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip の CVE-2025-11001 に対する Proof-of-Concept Exploit が報告される](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slip、tar-slip、symlink、hardlink、collision などを使った hacking の実験](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile の展開 filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – symlink chain を介した node-tar の hardlink target escape](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – ユーザー制御の SCORM 展開 root](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Frappe LMS の複数の脆弱性による Remote Code Execution](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
