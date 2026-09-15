# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## 概要

多くの archive format（ZIP、RAR、TAR、7-ZIP など）では、各エントリに独自の **internal path** を持たせることができます。展開 utility がそのパスを無条件に受け入れると、`..` を含む細工されたファイル名や **absolute path**（例: `C:\Windows\System32\`）によって、ユーザーが指定した directory の外側にファイルが書き込まれます。
この種類の vulnerability は、一般に *Zip-Slip* または **archive extraction path traversal** と呼ばれています。<sup>[[6]](#references)</sup>

影響は任意ファイルの上書きから、Windows の *Startup* folder のような **auto-run** location に payload を配置して、直接 **remote code execution (RCE)** を達成することまで及びます。

## Root Cause

1. Attacker は、1 つ以上の file header に以下を含む archive を作成します。
* Relative traversal sequences（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* Absolute paths（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* または、target dir の外側を指す細工された **symlinks**（*nix* の ZIP/TAR で一般的）。
2. Victim は、embedded path を信頼する（または symlinks を追従する）vulnerable tool を使って archive を展開します。この tool は、path を sanitise したり、指定された directory 配下への展開を強制したりしません。
3. ファイルは attacker が制御する location に書き込まれ、次回 system または user がその path を trigger した際に実行または load されます。

### .NET `Path.Combine` + `ZipArchive` traversal

一般的な .NET anti-pattern は、意図した destination と **user-controlled** な `ZipArchiveEntry.FullName` を結合し、path normalisation を行わずに展開することです。<sup>[[4]](#references)[[8]](#references)</sup>
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
- `entry.FullName` が `..\\` で始まる場合は traversal が発生します。**absolute path** の場合、左側のコンポーネント全体が破棄され、extraction identity として **arbitrary file write** が可能になります。
- scheduled scanner に監視されている sibling `app` directory に書き込む Proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
監視対象の inbox にその ZIP を投入すると、`C:\samples\app\0xdf.txt` が生成され、`C:\samples\queue\` の外部への traversal が可能であること、さらに後続のプリミティブ（例: DLL hijack）が可能になることが証明されます。

## Advanced Archive-Breakout Primitives

展開は、独立したファイル名チェックの集合ではなく、filesystem に対する一連の変更として扱ってください。解析時には安全なエントリでも、先行するメンバーが link を作成または置換した後には安全でなくなる可能性があります。同じ問題は、extractor がディレクトリを安全なものとして cache し、その後で種類が変更された場合にも発生します。<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: `pivot -> /tmp` を作成し、通常のメンバーを `pivot/PWNED.txt` として展開します。extractor が 1 つ目のメンバーに従って 2 つ目を materialize する場合、2 つ目の名前に `..` がなくても書き込みが外部へ抜け出します。
* **Directory-cache/TOCTOU collision**: ディレクトリ `d/sub/` を出力し、`d/sub` を `/tmp` への symlink に置き換えた後、`d/sub/PWNED.txt` を出力します。これは、ディレクトリを一度だけ検証または cache し、最終的な書き込み前に再検証しない extractor を対象とします。
* **Hardlink read/overwrite**: TAR と RAR は hardlink を表現できます。既存の host ファイルへの hardlink によって、後続の component が展開された名前を提供する場合、その内容が露出する可能性があります。一方、衝突する通常のエントリは、link された inode を上書きできます。これは、同一 filesystem の制約と OS の hardlink 権限ルールによって制限されます。
* **Pre-existing or cross-archive pivot**: 空でない destination に対して再試行します。各 archive が stateless な header-name check を通過していても、ある archive が link を配置し、後続の extraction がその link 経由で書き込める場合があります。<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

受け入れ先となる filesystem のセマンティクスを使用して名前を比較します。役立つ差分ケースには、case-insensitive filesystem における `LINK` と `link`、NFC と NFD の Unicode 表記、`ﬁle` と `file` のような互換性上同値の名前、directory から symlink へ path を変更する duplicate member、Windows でのみ separator として解釈される backslash などがあります。また、NTFS では ADS を含む名前もテストします。これらのケースによって、validator には 2 つの path が見えても、filesystem は 1 つとして解決する可能性があります。<sup>[[5]](#references)[[11]](#references)</sup>

したがって、コンパクトな corpus では、**directory → symlink → child**、**symlink → colliding regular file**、**hardlink → colliding regular file**、`/` と `\` の混在、absolute/rooted name、`.tar.gz` のような compressed wrapper の順序付き組み合わせをテストすべきです。これは disposable VM/container 内でのみ実行し、destination と想定外の canary path の両方を監視してください。<sup>[[11]](#references)</sup>

ZIP 固有の構造上の曖昧性により、pre-scan と実際の extractor が異なる entry name や tree を観測する可能性があります。1 つの ZIP library の出力だけを信頼するのではなく、[Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) を参照してください。

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 用の WinRAR と、その Windows RAR/UnRAR components は、extraction 中の filename の検証に失敗していました。この flaw は NTFS alternate data streams (ADS) を利用して、選択された extraction path を bypass し、意図しない場所にファイルを書き込みました。<sup>[[5]](#references)</sup>
次のような entry を含む悪意のある RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
最終的に選択した出力ディレクトリの**外側**、かつユーザーの*Startup*フォルダ内に配置されることになります。ESETは、そこに悪意のあるLNKファイルが展開され、ユーザーログオン時に実行されることで、persistenceとRCEへの経路が提供されることを確認しました。<sup>[[5]](#references)</sup>

### PoC Archiveの作成（Linux/Mac）

CVE-2025-8088はADS名にtraversal pathを使用するため、専用のgeneratorでRARを作成し、その後、脆弱なWinRAR buildを用いた隔離されたlab内でのみ展開をテストしてください。<sup>[[5]](#references)</sup>

### 実環境で確認されたExploit

ESETは、RomCom（Storm-0978/UNC2596）が、CVE-2025-8088を悪用するRAR archiveを添付し、customized backdoorを配布してransomware operationsを促進するspear-phishing campaignを実施していたと報告しました。<sup>[[5]](#references)</sup>

## 新しい事例（2024–2026）

### 7-Zip ZIP symlink traversal → RCE（CVE-2025-11001 / ZDI-25-949）
* **Bug**: ZIP entryの**symbolic link**が展開時にdereferenceされるため、攻撃者はdestination directoryから脱出し、任意のpathをoverwriteできます。ユーザー操作はarchiveの*opening/extracting*だけです。<sup>[[1]](#references)</sup>
* **Affected**: **25.00**より前の7-Zip build。symbolic-link processingのflawは**25.00**（2025年7月）以降で修正されています。<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup`またはservice-run locationをoverwrite → 次回のlogonまたはservice restart時にcodeが実行される。
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
このarchiveには、extraction directoryの外側を指すsymlink entryが含まれています。使い捨てのtargetを使用し、extractorがそれをfollowしないことを確認してください。write-through testには、symlink配下のregular-file entryも必要です。

### Go mholt/archiver `Unarchive()` symlink collision（CVE-2025-3445）
* **Bug**: `archiver.Unarchive()`はZIP symlinkをextractした後、後続のregular memberが同じnameを持つ場合にそれをdereferenceできます。これにより、一見in-rootに見えるwriteがout-of-root writeに変わります。<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1（現在はdeprecatedのproject）。<sup>[[2]](#references)</sup>
* **Fix**: `mholt/archives` ≥ 0.1.0へswitchするか、linkをrejectし、destinationをopenする直前に毎回再resolveします。<sup>[[2]](#references)</sup>
* **Minimal collision generator**（その後、`archiver.Unarchive("exploit.zip", "/tmp/safe")`をcall）:<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython filtered TAR extraction bypass（CVE-2026-11940）

`tarfile.extractall(filter="data")`や`filter="tar"`でさえ、link-order bypassの影響を受けたことがあります。このケースでは、より深いpathにarchiveされたsymlinkをhardlinkが参照していました。fallback extractionは、その深いlocationにあるrelative symlinkをvalidationしましたが、同じrelative targetをhardlinkのより浅いlocationに再作成したため、targetが脱出しました。これは有用なgeneral testです。validationとmaterialisationで、base directoryまたは最終member typeの扱いが一致しないようにします。<sup>[[12]](#references)</sup>

### Node `tar` symlink chainを介したhardlink target escape（GHSA-83g3-92jg-28cx）

Node.js `tar` packageの`tar.extract()`は、lexicallyは内部に含まれているように見えるものの、2つの先行するsymlinkを介してextraction rootの外側にresolveされるhardlinkを受け入れていました。このattackはdefault extraction optionsで機能します。destination-parent checkはhardlinkのin-root nameを対象としていましたが、hardlink targetはcontainmentのためのcomplete chainをresolveせずにfilesystemへ渡されていました。`tar` ≤ 7.5.7がaffectedで、7.5.8でissueがpatchされています。<sup>[[13]](#references)</sup>

重要なtest fixtureは、これらのliteral nameではなく、member間の**ordered relationship**です。<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
抽出に成功すると、`exfil` は出力ツリー内に目に見える形で残りますが、選択した外部ファイルと inode を共有します。そのため、これを読み取るとそのファイルが leak し、書き込むと元のファイルが変更されます。この bypass は、最終 pathname のみを確認すること、絶対 prefix を除去すること、または hardlink header 内の `..` をブロックすることだけでは不十分な理由を示しています。以前に抽出されたすべての filesystem state を適用した後で link target を検証してください。<sup>[[13]](#references)</sup>

## 検出のヒント

* **Static inspection** – member name と link target の両方を一覧表示します。`../`、`..\\`、absolute/rooted path、symlink、hardlink、special file、重複した name、type change、case/Unicode-equivalent collision を検出対象にします。exploit が前の member に依存する可能性があるため、レビュー中は entry order を保持してください。<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
7z l -slt suspect.7z          # technical metadata, one field per line
zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
```

* **Canonicalisation** – 解決後の parent と最終 basename が、解決後の destination 配下に残ることを確認します（raw string prefix ではなく path component を比較します）。先行する各 member の後に再確認してください。`realpath(join(dest, name))` を一度だけ確認する方法は、link replacement に対して脆弱であり、まだ作成されていない leaf では失敗する可能性があります。<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – path/symlink check 機能を備えた extractor（例: bsdtar のデフォルトの secure check または 7-Zip ≥ 25.00）を使用し、新しく作成した使い捨て directory に decompress してから、結果の tree に外部を指す link がないことを確認します。Isolation により、すでに発生した escape が host path に到達できないようにする必要があります。<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – 抽出自体が外部ファイルを作成しなかった場合でも、残存した symlink または hardlink は、previewer、CDN、file browser、package pipeline が後から抽出された name を開く、または提供するときに arbitrary-file-read primitive となる可能性があります。<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip などで archive が開かれた直後に、`Startup`/`Run`/`cron` location に新しい executable が書き込まれた場合は alert を発生させます。

## Mitigation & Hardening

1. **Extractor を update する** – WinRAR 7.13+、7-Zip 25.00+、Node `tar` 7.5.8+ には、引用されている path/symlink/link-target issue に対する fix が含まれています。<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. 可能な場合は、「**Do not extract paths**」/「**Ignore paths**」を使用して archive を extract します。untrusted input については、application が明示的に必要としない限り、symbolic link、hardlink、device、FIFO を reject してください。<sup>[[9]](#references)[[11]](#references)</sup>
3. **新しい空の directory** に extract します。untrusted member を、attacker が replace 可能な path を含む tree に merge しないでください。また、以前の archive によって作成された directory を再利用しないでください。<sup>[[11]](#references)</sup>
4. Unix では privilege を drop し、destination を **chroot/mount namespace** 内に isolate します。Windows では **AppContainer** または sandbox を使用します。post-extraction scan だけでは不十分です。scan より前に escaped write が発生するためです。<sup>[[11]](#references)</sup>
5. Custom code では、target OS の separator/case/Unicode rule を適用し、member と link target の両方を検証します。link を follow せずに destination を resolve して open し、containment check と、その後の create/replace operation を分離しないでください。validator は write path とまったく同じ base および link-emulation semantics を使用する必要があります。<sup>[[11]](#references)[[12]](#references)</sup>

## その他の影響を受けた / 過去の事例

* 2018 – 多数の Java/Go/JS library に影響した、Snyk による大規模な *Zip-Slip* advisory。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）における slug 内の TAR extraction traversal（v0.16.3 で fix）。<sup>[[7]](#references)</sup>
* header string は検証するものの、link target と各 write に使用される最終 filesystem path を検証しない、あらゆる custom extraction logic。<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET で Zip Slip を防止する](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 今すぐ WinRAR tools を update: RomCom などが zero-day vulnerability を悪用（CVE-2025-8088）](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical な arbitrary file overwrite vulnerability の public disclosure: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug は Zip Slip attack に対して vulnerable（CVE-2025-0377）](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip の CVE-2025-11001 に対する Proof-of-Concept Exploit が報告される](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slip、tar-slip、symlink、hardlink、collision などを使った hacking の楽しみ](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – symlink chain を介した node-tar hardlink target escape](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
