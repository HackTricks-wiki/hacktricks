# AdaptixC2の設定抽出とTTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2は、Windows x86/x64 beacon（EXE/DLL/service EXE/raw shellcode）とBOFをサポートする、モジュール型のオープンソースpost-exploitation/C2フレームワークです。<sup>[[1]](#references)</sup> このページでは、以下について説明します。
- RC4でパックされた設定がどのように埋め込まれているか、およびbeaconから抽出する方法
- HTTP/SMB/TCP listenerのネットワーク/profileインジケーター
- 実環境で確認された一般的なloaderおよびpersistence TTPsと、関連するWindows techniqueページへのリンク

最近のupstreamリリースにはDNS/DoH beacon listenerと、独立したGopher agent/listenerファミリーも含まれているため、個々のsampleが従来型のbeacon agentを使用している場合でも、現在のAdaptixインフラストラクチャは従来のHTTP/SMB/TCP以外の要素を公開している可能性があります。<sup>[[2]](#references)</sup>

## Beaconのprofileとフィールド

AdaptixC2は、主に次の3種類のbeaconをサポートしています。<sup>[[1]](#references)</sup>
- BEACON_HTTP: server/port/SSL、method、URI、header、user-agent、カスタムparameter名を設定できるweb C2
- BEACON_SMB: 名前付きpipeを使用するpeer-to-peer C2（イントラネット）
- BEACON_TCP: protocolの開始位置を難読化するため、markerを先頭に付加できる直接socket通信

これらは、初期のAdaptix分析で公開されたbeaconのレイアウトであり、現在でもsample側から設定を抽出する際の最も一般的な出発点です。<sup>[[1]](#references)</sup> ただし、現在のupstreamビルドにはserver側の`BeaconDNS`およびGopher extenderも含まれているため、稼働中のAdaptix環境がHTTP/SMB/TCPインフラストラクチャのみを公開していると想定しないでください。<sup>[[2]](#references)</sup>

HTTP beacon設定で確認される一般的なprofileフィールド（復号後）：<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32)、servers (文字列のarray)、ports (u32のarray)
- http_method、uri、parameter、user_agent、http_headers（長さ付き文字列）
- ans_pre_size (u32)、ans_size (u32) – responseサイズの解析に使用
- kill_date (u32)、working_time (u32)
- sleep_delay (u32)、jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

最近のBeaconHTTPビルドでは、複数のURI、user-agent、Host header、serverを対象に、順次またはランダムに切り替える設定もサポートされています。<sup>[[2]](#references)</sup> 脅威ハンティングの観点では、従来型のRC4パック済みbeaconファミリーのままでも、感染したホスト1台から複数のcallback経路やheaderの組み合わせへ通信が分散する可能性があります。

beaconビルドのデフォルトHTTP profileの例：<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["172.16.196.1"],
  "ports": [4443],
  "http_method": "POST",
  "uri": "/uri.php",
  "parameter": "X-Beacon-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 2,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

観測された悪意のある HTTP プロファイル（実際の攻撃）:<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["tech-system[.]online"],
  "ports": [443],
  "http_method": "POST",
  "uri": "/endpoint/api",
  "parameter": "X-App-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 4,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

## 暗号化された設定のパッキングと読み込み経路

operator が builder で Create をクリックすると、AdaptixC2 は暗号化された profile を beacon の末尾に blob として埋め込みます。形式は次のとおりです:<sup>[[1]](#references)</sup>
- 4 bytes: configuration size (uint32、リトルエンディアン)
- N bytes: RC4 で暗号化された configuration data
- 16 bytes: RC4 key

beacon loader は末尾から 16-byte key をコピーし、N-byte block をその場で RC4 復号します:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

実践上の意味:<sup>[[1]](#references)</sup>
- 構造全体は、多くの場合 PE の .rdata セクション内にあります。
- 抽出は決定論的です。サイズを読み、そのサイズ分の ciphertext を読み、その直後に配置された 16-byte key を読み取ってから、RC4 で復号します。

## Configuration extraction workflow (defenders)

beacon のロジックを模倣する extractor を作成します:<sup>[[1]](#references)</sup>
1) PE 内の blob を特定します（一般的には .rdata）。現実的な方法は、.rdata をスキャンして、妥当な [size|ciphertext|16-byte key] の配置を探し、RC4 を試すことです。
2) 最初の 4 bytes を読み取る → size (uint32 LE)。
3) 次の N=size bytes を読み取る → ciphertext。
4) 最後の 16 bytes を読み取る → RC4 key。
5) ciphertext を RC4 で復号します。その後、復号した profile を次のように解析します:
   - 上記のとおり、u32/boolean スカラー
   - 長さプレフィックス付き文字列（u32 length の後に bytes。末尾に NUL が付く場合があります）
   - 配列: servers_count の後に、個数分の [string, u32 port] ペア

事前に抽出した blob を対象に動作する、最小限の Python proof-of-concept（単体で動作し、外部依存なし）:

```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ K)
    return bytes(out)

class P:
    def __init__(self, buf: bytes):
        self.b = buf; self.o = 0
    def u32(self) -> int:
        v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
    def u8(self) -> int:
        v = self.b[self.o]; self.o += 1; return v
    def s(self) -> str:
        L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
        return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    cfg = {}
    cfg['agent_type']    = p.u32()
    cfg['use_ssl']       = bool(p.u8())
    n                    = p.u32()
    cfg['servers']       = []
    cfg['ports']         = []
    for _ in range(n):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method']   = p.s()
    cfg['uri']           = p.s()
    cfg['parameter']     = p.s()
    cfg['user_agent']    = p.s()
    cfg['http_headers']  = p.s()
    cfg['ans_pre_size']  = p.u32()
    cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
    cfg['kill_date']     = p.u32()
    cfg['working_time']  = p.u32()
    cfg['sleep_delay']   = p.u32()
    cfg['jitter_delay']  = p.u32()
    cfg['listener_type'] = 0
    cfg['download_chunk_size'] = 0x19000
    return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```

Tips:
- 自動化する場合は、PE parserを使って.rdataを読み込み、sliding windowを適用します。各offset oについて、size = u32(.rdata[o:o+4])、ct = .rdata[o+4:o+4+size]、candidate key = 次の16バイトとして試し、RC4で復号して、文字列フィールドがUTF-8としてデコードでき、長さが妥当か確認します。
- 同じlength-prefixed規則に従って、SMB/TCPプロファイルを解析します。

## カスタムlistenerプロファイル: 従来のHTTPスキーマだけにハードコードしない

外側のパッキング形式（`u32 size | RC4 ciphertext | 16-byte key`）は再利用できるため、攻撃者がカスタマイズしたlistenerでも、復号後のフィールドレイアウトを完全に変えながら、同じ抽出ワークフローを維持できます。

最近の良い例として、2026年3月のTropic Trooperのキャンペーンがあります。抽出されたAdaptix beaconには標準的なHTTP/TCPプロファイルが含まれていませんでした。代わりに、復号されたblobには次のようなGitHub transportパラメータが格納されていました。<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host`（例: `api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

実用的なparser戦略:
- まず、通常どおり外側のRC4 blobを検出します。
- 復号後は、すぐにHTTP parserを適用するのではなく、sentinel文字列とフィールドの妥当性に基づいて処理を分岐します。
- 有効なsentinelの例には、`api.github.com`、`/issues?state=open`、HTTP verbs/URIs、named pipe形式の文字列、明らかに妥当なserver/port配列などがあります。
- HTTP parserが失敗しても、平文に一貫性のあるlength-prefixed UTF-8文字列が含まれている場合は、false positiveとして破棄せず、サンプルを保持して別のスキーマを試します。

このキャンペーンでは、カスタムlistenerはGitHub issuesをC2 transportとして使用し、beaconは`ipinfo.io`に問い合わせて外部IPを取得していました。GitHub APIでは、被害者の送信元アドレスをoperatorに直接知らせることができないためです。<sup>[[5]](#references)</sup>

## Network fingerprintingとhunting

HTTP:<sup>[[1]](#references)</sup>
- 一般的な特徴: operatorが選択したURI（例: /uri.php、/endpoint/api）へのPOST
- beacon IDに使われるカスタムheaderパラメータ（例: X‑Beacon‑Id、X‑App‑Id）
- Firefox 20または同時期のChromeビルドを模倣したUser-Agent
- sleep_delay/jitter_delayから確認できるpolling間隔
- 新しいビルドではcallbackごとにURI、User-Agent、Host header、serverをローテーションすることがあるため、単一のpath/UAの組み合わせを前提とせず、珍しいheader名、response-sizeのパターン、TLSの再利用、タイミングを基にクラスタリングします。<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Webのegressが制限されているイントラネットC2向けのSMB named-pipe listener
- TCP beaconは、protocolの開始位置を分かりにくくするため、通信の前に数バイトを付加する場合がある

現在のupstream teamserverのデフォルト
- 現在の`profile.yaml`には、teamserverの`0.0.0.0:4321`、endpoint `/endpoint`、証明書/keyのファイル名`server.rsa.crt`と`server.rsa.key`、およびHTTP、SMB、TCP、DNS、Beacon agent、Gopher用のextenderが含まれています。<sup>[[2]](#references)</sup>
- 一致するrouteがない場合、デフォルトのerror handlerは`Server: AdaptixC2`と`Adaptix-Version: v1.2`を返します。<sup>[[4]](#references)</sup>
- 標準の404 bodyには`AdaptixC2 404`と`You need to enter the correct connection details`が含まれます。<sup>[[4]](#references)</sup>
- 2026年のインターネット全体を対象としたscanでは、4321で公開されているteamserverと43211で稼働するbeacon listenerが多数見つかりました。このため、両portは初期pivotとして有用ですが、すべてを網羅するものとして扱うべきではありません。<sup>[[4]](#references)</sup>

DNS/DoH listenerのfingerprint:<sup>[[4]](#references)</sup>
- 現在のBeaconDNS extenderは権威ある応答を返します（`AA=true`）。
- beacon protocolの形式に一致しないquery（特に、設定されたdomainより前のlabelが5個未満の名前）には、一般に`TXT "OK"`で応答します。
- 設定されたbase TTLが0のままの場合、listenerは10秒をbaseとして使用し、最大59秒のjitterを追加します。
- HTTP listenerが公開されていない場合、短いlabelを使ったactive probeが有用です。

## インシデントで確認されたLoaderとpersistenceのTTP

メモリ内PowerShell loader:<sup>[[1]](#references)</sup>
- Base64/XOR payloadをダウンロードします（Invoke‑RestMethod / WebClient）。<sup>[[9]](#references)</sup>
- unmanaged memoryを確保してshellcodeをコピーし、VirtualProtectを介して保護属性を0x40（PAGE_EXECUTE_READWRITE）に変更します。<sup>[[7]](#references)</sup>
- .NETのdynamic invocation（Marshal.GetDelegateForFunctionPointer + delegate.Invoke()）を介して実行します。<sup>[[6]](#references)</sup>

トロイの木馬化された署名付きソフトウェア / staged shellcode loader:<sup>[[5]](#references)</sup>
- 2026年のTropic Trooperの一連の攻撃では、トロイの木馬化されたSumatraPDF実行ファイル（TOSHIS loader）が使われました。このloaderはPEのentry pointをpatchする代わりに、`_security_init_cookie`を悪意のあるコードへリダイレクトしました。
- loaderはAdler-32 hashingを使ってAPIを解決し、decoy PDFをダウンロードして第2段階のshellcodeを取得。WinCrypt経由でAES-128-CBCを使って復号し（ハードコードされたseedから`CryptDeriveKey`）、Adaptix beaconをメモリ内でreflectiveに実行しました。
- その後、persistenceは`\MSDNSvc`や`\MicrosoftUDN`などの無害そうな名前を付けたscheduled taskに移行し、およそ2時間ごとにagentを再起動するよう設定されました。

メモリ内実行とAMSI/ETWに関する考慮事項については、次のページを確認してください。

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

確認されたpersistenceの仕組み:<sup>[[1]](#references)</sup>
- logon時にloaderを再起動するStartup folderのshortcut（.lnk）
- Registry Run key（HKCU/HKLM ...\CurrentVersion\Run）。loader.ps1を起動するため、「Updater」のような無害そうな名前が使われることがよくあります。<sup>[[10]](#references)</sup>
- 影響を受けやすいprocess向けに、%APPDATA%\Microsoft\Windows\Templatesへmsimg32.dllを配置するDLL search-order hijack

手法の詳細と確認方法:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Huntingのアイデア
- PowerShellでのRW→RX遷移: powershell.exe内でVirtualProtectによりPAGE_EXECUTE_READWRITEへ変更する動作。<sup>[[8]](#references)</sup>
- Dynamic invocationのパターン（GetDelegateForFunctionPointer）
- `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404`、または`You need to enter the correct connection details`を含む、一致するrouteがないHTTPS 404。<sup>[[4]](#references)</sup>
- 不審なdomain配下の短いqueryに対して、`AA=true`かつ`TXT "OK"`を含むDNS応答。<sup>[[4]](#references)</sup>
- `/repos/<owner>/<repo>/issues`へのGitHub API通信に続き、同じloader/beaconのchainから発生する`ipinfo.io`へのlookup。<sup>[[5]](#references)</sup>
- ユーザーまたは共通のStartup folderにあるStartup .lnk。<sup>[[1]](#references)</sup>
- 不審なRun key（例: "Updater"）や、update.ps1/loader.ps1などのloader名。<sup>[[1]](#references)</sup>
- decoy documentを表示する前に`_security_init_cookie`をdownloader codeへリダイレクトするトロイの木馬化されたPEサンプル。<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates配下のユーザーが書き込み可能なDLL pathにあるmsimg32.dll。<sup>[[1]](#references)</sup>

## OpSecフィールドに関する注意

- KillDate: agentが自己終了するtimestamp。<sup>[[1]](#references)</sup>
- WorkingTime: 業務活動に紛れ込むためにagentを稼働させる時間帯。<sup>[[1]](#references)</sup>

これらのフィールドは、クラスタリングや、観測された静穏期間の説明に利用できます。

## YARAと静的解析の手掛かり

Unit 42は、beacon（C/C++およびGo）とloaderのAPI-hashing定数を対象とする基本的なYARAを公開しています。<sup>[[1]](#references)</sup> PEの.rdata末尾付近にある[size|ciphertext|16-byte-key]レイアウト、デフォルトのHTTP profile文字列、さらに`AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open`、`ipinfo.io`などの新しいserver/listener markerを検出するruleで補完することを検討してください。<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: 実際の攻撃で利用される新たなオープンソースFramework (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: 大規模なオープンソースC2 Frameworkのfingerprinting (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic TrooperがAdaptixC2とカスタムBeacon Listenerへ移行 (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [メモリ保護定数 – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
