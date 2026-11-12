# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2は、Windows x86/x64 beacon（EXE/DLL/service EXE/raw shellcode）とBOFをサポートする、モジュール式のオープンソース post-exploitation/C2 frameworkです。<sup>[[1]](#references)</sup> このページでは、以下について説明します。
- RC4でパックされた設定がどのように埋め込まれているか、およびbeaconから抽出する方法
- HTTP/SMB/TCP listenerのネットワーク/profile indicator
- 実環境で確認された一般的なloaderおよびpersistence TTPと、関連するWindows techniqueページへのリンク

最近のupstreamリリースにはDNS/DoH beacon listenerと、独立したGopher agent/listenerファミリーも含まれています。そのため、特定のsampleが従来のbeacon agentを使っている場合でも、最新のAdaptixインフラストラクチャは従来のHTTP/SMB/TCP以外の通信経路を公開している可能性があります。<sup>[[2]](#references)</sup>

## Beacon profiles and fields

AdaptixC2は、主に3種類のbeaconをサポートしています。<sup>[[1]](#references)</sup>
- BEACON_HTTP: server/port/SSL、method、URI、header、user-agent、カスタムparameter名を設定可能なweb C2
- BEACON_SMB: named-pipeによるpeer-to-peer C2（イントラネット）
- BEACON_TCP: 直接socketを使用し、protocol開始位置を難読化するためにmarkerを先頭に追加可能

これらは初期のAdaptix分析で公開されたbeaconのレイアウトであり、現在もsample側から抽出する際の最も一般的な出発点です。<sup>[[1]](#references)</sup> ただし、現在のupstream buildにはserver側の`BeaconDNS`およびGopher extenderも含まれているため、稼働中のAdaptix環境がHTTP/SMB/TCPインフラストラクチャのみを公開していると決めつけないでください。<sup>[[2]](#references)</sup>

以下のfield概要とJSON sampleは、2025年に分析されたHTTP形式を説明するものであり、新しいupstream build向けのparser仕様ではありません。これらのsampleで一般的なfield（復号後）：<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (stringのarray), ports (u32のarray)
- http_method, uri, parameter, user_agent, http_headers（長さprefix付きstring）
- ans_pre_size (u32), ans_size (u32) – response sizeの解析に使用
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

最近のBeaconHTTP buildは、operatorが複数のURI、user-agent、Host header、serverを対象に、順次またはランダムに切り替える機能もサポートしています。<sup>[[2]](#references)</sup> これはhuntingの観点では、単一の感染hostが、従来のRC4でパックされたbeaconファミリーのまま、複数のcallback経路やheaderの組み合わせに通信を分散できることを意味します。

HTTP profileのdefault例（beacon buildから）：<sup>[[1]](#references)</sup>

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

## 暗号化された設定のパッキングと読み込みの流れ

オペレーターが builder で Create をクリックすると、AdaptixC2 は暗号化されたプロファイルを beacon にコンパイルします。PE や shellcode の末尾にあると決めつけず、セクションをスキャンするか、サンプル内の `getProfile()` をたどってプロファイルのバイト列を特定してください。パック形式は次のとおりです:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bytes: configuration size (uint32, little‑endian)
- N bytes: RC4 で暗号化された configuration data
- 16 bytes: RC4 key

beacon のローダーは末尾から 16-byte の key をコピーし、N-byte のブロックをインプレースで RC4 復号します:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

実用上の意味:<sup>[[1]](#references)</sup>
- 構造全体は、多くの場合 PE の .rdata セクション内にあります。
- 抽出は決定論的です。サイズを読み取り、そのサイズ分の ciphertext を読み取り、その直後に配置された 16‑byte key を読み取ってから、RC4 で復号します。

## Configuration extraction workflow (defenders)

beacon を切り出す前の一般的なサンプルのトリアージについては、[Malware Analysis](malware-analysis.md) を参照してください。

beacon のロジックを模倣する extractor を作成します:<sup>[[1]](#references)</sup>
1) PE 内（一般的には .rdata）で blob を見つけます。実用的な方法として、.rdata をスキャンして妥当な [size|ciphertext|16‑byte key] の配置を探し、RC4 を試します。
2) 先頭の 4 bytes を読み取る → size（uint32 LE）。
3) 続く N=size bytes を読み取る → ciphertext。
4) 最後の 16 bytes を読み取る → RC4 key。
5) ciphertext を RC4 で復号します。その後、次のようにプレーンな profile を解析します:
   - 上記のとおり u32/boolean スカラー値
   - 長さプレフィックス付き文字列（u32 の長さの後に bytes が続く。末尾に NUL が付く場合があります）
   - 配列: servers_count の後に、その数だけ [string, u32 port] のペアが続く

2025 年のフィールド順に並んだ、抽出済み blob 用のレガシー HTTP Python proof-of-concept（単体で動作し、外部依存なし）。最近の stock build には、以下の current-schema parser を使用してください:<sup>[[1]](#references)[[11]](#references)</sup>

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

### 現行の stock HTTP および DNS プロファイルを解析する

現在の upstream は、最初に6つの little-endian `u32` 値を格納します。agent watermark/type、kill date、working time、sleep、jitter、listener watermark/type の順です。続く HTTP 固有データは、1バイトの SSL フラグから始まります。legacy の例とは異なり、URI、user-agent、Host header の各リストには件数があり、その後に rotation mode と proxy settings が続きます。そのため、legacy parser は kill-date フィールドを SSL フラグとして読み取り始め、これらのビルドでは誤った結果を生成します。このプロファイルの文字列長と整数値は little-endian 形式で、空でない packed strings には末尾の NUL が含まれます。<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

上記の `P` および `rc4` helper を使用して、復号済みの **stock HTTP** plaintext にこの parser を適用します。HTTP プロファイルには proxy の username と password が含まれる場合があるため、RC4 key は公開レポートに記載しないでください。<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>現行の stock HTTP plaintext プロファイルを解析する</summary>

```python
def parse_current_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    keys = ('agent_type', 'kill_date', 'working_time',
            'sleep_delay', 'jitter_delay', 'listener_type')
    cfg = {key: p.u32() for key in keys}
    cfg['use_ssl'] = bool(p.u8())
    count = p.u32()
    if not 0 < count <= 128:
        raise ValueError('implausible server count')
    cfg['servers'] = []
    cfg['ports'] = []
    for _ in range(count):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method'] = p.s()
    def strings():
        n = p.u32()
        if n > 128:
            raise ValueError('implausible string count')
        return [p.s() for _ in range(n)]
    cfg['uris'] = strings()
    cfg['parameter'] = p.s()
    cfg['user_agents'] = strings()
    cfg['http_headers'] = p.s()
    cfg['ans_pre_size'] = p.u32()
    cfg['ans_size'] = p.u32() + cfg['ans_pre_size']
    cfg['host_headers'] = strings()
    cfg['rotation_mode'] = p.u32()  # 0=sequential, 1=random
    cfg['proxy_type'] = p.u32()     # 0=none, 1=HTTP, 2=HTTPS
    cfg['proxy_host'] = p.s()
    cfg['proxy_port'] = p.u32()
    cfg['proxy_username'] = p.s()
    cfg['proxy_password'] = p.s()
    if p.o != len(plain):
        raise ValueError('unexpected trailing bytes or wrong schema')
    return cfg
```

</details>

標準の DNS beacon では、同じ6つの共通 `u32` フィールドを読み取り、続けて長さプレフィックス付きの `domain`、`resolvers`、`doh_resolvers`、`qtype` 文字列を読み取ります。`pkt_size`、`label_size`、`ttl`、`burst_enabled`、`burst_sleep`、`burst_jitter`、`dns_mode` は `u32` として読み取り、その後に長さプレフィックス付きの DoH user-agent 文字列を読み取ります。`dns_mode` は UDP、DoH、および2種類のフォールバック方向を区別します。これは別のレイアウトです。DNS の平文を HTTP parser に無理に通さないでください。<sup>[[12]](#references)[[13]](#references)</sup>

ヒント:
- 自動化する場合は、PE parser で .rdata を読み取り、スライディングウィンドウを適用します。各オフセット o について、size = u32(.rdata[o:o+4]) を試し、ct = .rdata[o+4:o+4+size]、candidate key = 次の16バイトとします。RC4 で復号し、文字列フィールドが UTF-8 としてデコードでき、長さが妥当か確認します。
- SMB/TCP profile は、同じ長さプレフィックスの規則に従って解析します。

## カスタム listener profile: 従来の HTTP schema のみにハードコードしない

外側のパッキング形式（`u32 size | RC4 ciphertext | 16-byte key`）は再利用できるため、攻撃者がカスタマイズした listener でも同じ抽出ワークフローを維持しつつ、復号後のフィールドレイアウトを完全に変更できます。

最近の好例は、2026年3月の Tropic Trooper のキャンペーンです。抽出された Adaptix beacon には標準的な HTTP/TCP profile が含まれていませんでした。代わりに、復号された blob には次のような GitHub transport パラメータが格納されていました。<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host`（例: `api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

実用的な parser の方針:
- まず、通常どおり外側の RC4 blob を検出します。
- 復号後は、すぐに HTTP parser に通すのではなく、sentinel 文字列とフィールドの妥当性に基づいて分岐します。
- 有効な sentinel には、`api.github.com`、`/issues?state=open`、HTTP verb/URI、named-pipe 形式の文字列、明らかに妥当な server/port 配列などがあります。
- HTTP parser が失敗しても、平文に整合性のある長さプレフィックス付き UTF-8 文字列が含まれている場合は、false positive として破棄せず、サンプルを保持して別の schema を試します。

このキャンペーンでは、カスタム listener は GitHub issues を C2 transport として使用し、beacon は `ipinfo.io` に問い合わせて外部 IP を取得していました。GitHub API では、被害者の送信元アドレスを operator に直接知らせることができないためです。<sup>[[5]](#references)</sup> 別方式の issue と repository file を使う handshake については、[GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md) を参照してください。

## ネットワークフィンガープリンティングとハンティング

HTTP:<sup>[[1]](#references)</sup>
- 一般的な特徴: operator が選択した URI（例: /uri.php、/endpoint/api）への POST
- beacon ID に使われるカスタム header parameter（例: X‑Beacon‑Id、X‑App‑Id）
- Firefox 20 や最近の Chrome build を模倣する user-agent
- sleep_delay/jitter_delay から確認できる polling 間隔
- 新しい build では callback ごとに URI、user-agent、Host header、server をローテーションできるため、単一の path/UA の組み合わせを前提とせず、珍しい header 名、response size のパターン、TLS の再利用、タイミングを基にクラスタリングします。<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Web egress が制限されている環境でのイントラネット C2 用 SMB named-pipe listener
- TCP beacon は、protocol の開始位置を難読化するため、通信の前に数バイトを付加する場合がある

現在の upstream teamserver のデフォルト
- 現在の `profile.yaml` には、teamserver の `0.0.0.0:4321`、endpoint `/endpoint`、証明書/鍵のファイル名 `server.rsa.crt` と `server.rsa.key`、および HTTP、SMB、TCP、DNS、Beacon agent、Gopher 用 extender が含まれています。<sup>[[2]](#references)</sup>
- 一致する route がない場合、デフォルトの error handler は `Server: AdaptixC2` と `Adaptix-Version: v1.2` を返します。<sup>[[4]](#references)</sup>
- 標準の 404 body には `AdaptixC2 404` と `You need to enter the correct connection details` が含まれます。<sup>[[4]](#references)</sup>
- 2026年のインターネット全体を対象とした scan では、`4321` で公開された teamserver と `43211` で公開された beacon listener が多数見つかりました。どちらの port も有用な調査の起点になりますが、網羅的なものと見なさないでください。<sup>[[4]](#references)</sup>

DNS/DoH listener のフィンガープリント:<sup>[[4]](#references)</sup>
- 現行の BeaconDNS extender は権威応答します（`AA=true`）。
- beacon protocol の形式に一致しない query、特に設定済み domain より前の label が5個未満の名前には、通常 `TXT "OK"` を返します。
- 設定された base TTL がゼロの場合、listener は10秒の base を使用し、最大59秒の jitter を加えます。
- HTTP listener が公開されていない場合、短い label を使った active probe が有効です。

## インシデントで確認された loader と persistence の TTP

メモリ内 PowerShell loader:<sup>[[1]](#references)</sup>
- Base64/XOR payload をダウンロードします（Invoke‑RestMethod / WebClient）。<sup>[[9]](#references)</sup>
- unmanaged memory を割り当てて shellcode をコピーし、VirtualProtect を使って保護属性を 0x40（PAGE_EXECUTE_READWRITE）に切り替えます。<sup>[[7]](#references)</sup>
- .NET の dynamic invocation（Marshal.GetDelegateForFunctionPointer + delegate.Invoke()）で実行します。<sup>[[6]](#references)</sup>

トロイの木馬化された署名付きソフトウェア / 段階的 shellcode loader:<sup>[[5]](#references)</sup>
- 2026年の Tropic Trooper の攻撃チェーンでは、トロイの木馬化された SumatraPDF executable（TOSHIS loader）が使われました。この loader は PE entry point を patch する代わりに、`_security_init_cookie` を悪意ある code にリダイレクトしました。
- loader は Adler-32 hashing で API を解決し、おとりの PDF をダウンロードして第2段階の shellcode を取得し、ハードコードされた seed から WinCrypt の `CryptDeriveKey` を使って AES-128-CBC で復号した後、メモリ内で Adaptix beacon を reflectively 実行しました。
- その後の persistence には、`\MSDNSvc` や `\MicrosoftUDN` など無害に見える名前の scheduled task が使われ、agent をおよそ2時間ごとに再起動するよう設定されました。

メモリ内実行と AMSI/ETW の考慮事項については、次のページを確認してください。

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

確認された persistence の仕組み:<sup>[[1]](#references)</sup>
- logon 時に loader を再起動する Startup folder の shortcut（.lnk）
- Registry Run key（HKCU/HKLM ...\CurrentVersion\Run）。多くの場合、`Updater` など無害に見える名前で loader.ps1 を起動します。<sup>[[10]](#references)</sup>
- 影響を受けやすい process を狙い、%APPDATA%\Microsoft\Windows\Templates に msimg32.dll を配置する DLL search-order hijack

手法の詳細と確認事項:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

ハンティングのアイデア
- PowerShell が RW→RX の遷移を起こしているか確認します。powershell.exe 内で VirtualProtect が PAGE_EXECUTE_READWRITE を指定しているケースです。<sup>[[8]](#references)</sup>
- dynamic invocation のパターン（GetDelegateForFunctionPointer）
- `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404`、または `You need to enter the correct connection details` を含む、一致しない HTTPS 404。<sup>[[4]](#references)</sup>
- 疑わしい domain 配下の短い query に対する、`AA=true` と `TXT "OK"` を含む DNS response。<sup>[[4]](#references)</sup>
- `/repos/<owner>/<repo>/issues` への GitHub API traffic に続き、同じ loader/beacon チェーンから発生する `ipinfo.io` への lookup。<sup>[[5]](#references)</sup>
- user または共通の Startup folder にある起動用 .lnk。<sup>[[1]](#references)</sup>
- 疑わしい Run key（例: `Updater`）や、update.ps1/loader.ps1 のような loader 名。<sup>[[1]](#references)</sup>
- おとりの文書を表示する前に `_security_init_cookie` を downloader code にリダイレクトする、トロイの木馬化された PE sample。<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates 配下の user-writable な DLL path にある msimg32.dll。<sup>[[1]](#references)</sup>

## OpSec field に関する注記

- KillDate: agent が自己終了するタイムスタンプ。<sup>[[1]](#references)</sup>
- WorkingTime: 業務活動に紛れて agent を稼働させる時間帯。<sup>[[1]](#references)</sup>

これらの field はクラスタリングに利用でき、活動が確認されない時間帯の説明にも役立ちます。

## YARA と静的解析の手掛かり

Unit 42 は、beacon（C/C++ と Go）および loader の API-hashing constant を検出する基本的な YARA を公開しています。<sup>[[1]](#references)</sup> PE の .rdata 末尾付近にある [size|ciphertext|16-byte-key] layout、デフォルトの HTTP profile 文字列、新しい server/listener marker（`AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open`、`ipinfo.io`）を探す rule で補完することを検討してください。<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: 実際の攻撃で利用された新たなオープンソース・フレームワーク（Unit 42）](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework ドキュメント](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: 大規模なオープンソース C2 フレームワークのフィンガープリンティング（Censys）](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper、AdaptixC2 とカスタム Beacon Listener に移行（Zscaler ThreatLabz）](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [メモリ保護定数 – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2 profile の生成（pl_main.go）](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2 beacon profile parser（AgentConfig.cpp）](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2 DNS profile の生成（pl_utils.go）](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2 profile のパッキング（pl_packer.go）](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
