# AdaptixC2 Configuration Extraction and TTPs

AdaptixC2は、Windows x86/x64 beacon（EXE/DLL/service EXE/raw shellcode）とBOFをサポートする、モジュール式のオープンソース post-exploitation/C2 frameworkです。<sup>[[1]](#references)</sup> このページでは以下について説明します。
- RC4でpackedされたconfigurationがどのように埋め込まれているか、およびbeaconから抽出する方法
- HTTP/SMB/TCP listenerのnetwork/profile indicators
- 実環境で確認されている一般的なloaderおよびpersistence TTPsと、関連するWindows technique pagesへのリンク

最近のupstreamリリースでは、DNS/DoH beacon listenerと、独立したGopher agent/listener familyも提供されています。そのため、特定のsampleが従来のbeacon agentを使用している場合でも、最新のAdaptix infrastructureは従来のHTTP/SMB/TCP surface以外の要素を公開している可能性があります。<sup>[[2]](#references)</sup>

## Beacon profiles and fields

AdaptixC2は、3種類の主要なbeacon typeをサポートしています。<sup>[[1]](#references)</sup>
- BEACON_HTTP: configurableなserver/port/SSL、method、URI、header、user-agent、custom parameter nameを備えたweb C2
- BEACON_SMB: named-pipe peer-to-peer C2（intranet）
- BEACON_TCP: protocol startをobfuscateするためのprepended markerを任意で付加できるdirect socket

これらは、初期のAdaptix analysisで公開されたbeacon layoutであり、現在もsample-side extractionの最も一般的な出発点です。<sup>[[1]](#references)</sup> ただし、現在のupstream buildではserver sideに`BeaconDNS`とGopher extenderも提供されているため、稼働中のすべてのAdaptix deploymentがHTTP/SMB/TCP infrastructureのみを公開しているとは限りません。<sup>[[2]](#references)</sup>

HTTP beacon configで確認される一般的なprofile field（decryption後）：<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32)、servers（stringのarray）、ports（u32のarray）
- http_method、uri、parameter、user_agent、http_headers（length-prefixed string）
- ans_pre_size (u32)、ans_size (u32) – response sizeのparseに使用
- kill_date (u32)、working_time (u32)
- sleep_delay (u32)、jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

最近のBeaconHTTP buildでは、複数のURI、user-agent、Host header、server間のoperator-selected rotationもサポートされており、sequentialまたはrandom selectionを使用できます。<sup>[[2]](#references)</sup> Huntingの観点では、これは単一の感染hostが、従来のRC4-packed beacon familyを使用したまま、複数のcallback pathとheader combinationに分散して通信する可能性があることを意味します。

Example default HTTP profile（beacon build由来）：<sup>[[1]](#references)</sup>
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
## 暗号化された configuration のパッキングとロードパス

operator が builder で Create をクリックすると、AdaptixC2 は暗号化された profile を beacon の末尾 blob として埋め込みます。形式は次のとおりです:<sup>[[1]](#references)</sup>
- 4 bytes: configuration size (uint32、little-endian)
- N bytes: RC4-encrypted configuration data
- 16 bytes: RC4 key

beacon loader は末尾から 16-byte key をコピーし、N-byte block をその場で RC4-decrypt します:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Practical implications:<sup>[[1]](#references)</sup>
- 構造全体は、PE の .rdata セクション内に存在することが多い。
- Extraction は決定論的に行える。size を読み取り、そのサイズ分の ciphertext を読み取り、その直後に配置された 16 バイトの key を読み取り、その後 RC4 で復号する。

## Configuration extraction workflow (defenders)

beacon のロジックを模倣する extractor を作成する:<sup>[[1]](#references)</sup>
1) PE 内（一般的には .rdata）で blob を特定する。実用的な方法は、.rdata をスキャンして、妥当と思われる [size|ciphertext|16-byte key] のレイアウトを探し、RC4 を試行すること。
2) 最初の 4 バイトを読み取る → size（uint32 LE）。
3) 次の N=size バイトを読み取る → ciphertext。
4) 最後の 16 バイトを読み取る → RC4 key。
5) ciphertext を RC4 で復号する。その後、plain profile を次の形式で parse する:
- 上記のとおりの u32/boolean スカラー
- length-prefixed strings（u32 length に続いて bytes。末尾に NUL が存在する場合がある）
- arrays: servers_count に続いて、その数の [string, u32 port] ペア

pre-extracted blob に対して動作する、外部依存関係のない最小限の Python proof-of-concept:
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
- 自動化する場合は、PE parser を使用して .rdata を読み取り、sliding window を適用します。各 offset o について、size = u32(.rdata[o:o+4])、ct = .rdata[o+4:o+4+size]、candidate key = 次の 16 バイトを試します。RC4 で復号し、string fields が UTF-8 としてデコードでき、lengths が妥当であることを確認します。
- 同じ length-prefixed conventions に従って SMB/TCP profiles を解析します。

## Custom listener profiles: classic HTTP schema のみに hard-code しない

外側の packing format（`u32 size | RC4 ciphertext | 16-byte key`）は再利用できるため、actor がカスタマイズした listeners でも、復号後の field layout を完全に変更しながら同じ extraction workflow を維持できます。

最近の良い例は、2026 年 3 月の Tropic Trooper campaign です。この campaign で抽出された Adaptix beacon には standard HTTP/TCP profile が含まれていませんでした。代わりに、復号された blob には次のような GitHub transport parameters が格納されていました。<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host`（例: `api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

実用的な parser strategy:
- まず、通常どおり outer RC4 blob を正確に検出します。
- 復号後は、すぐに HTTP parser を強制するのではなく、sentinel strings と field sanity に基づいて分岐します。
- 有効な sentinel には、`api.github.com`、`/issues?state=open`、HTTP verbs/URIs、named-pipe-style strings、または明らかに有効な server/port arrays などがあります。
- HTTP parser が失敗しても、plaintext に一貫性のある length-prefixed UTF-8 strings が含まれている場合は、false positive として破棄せず、sample を保持して alternative schemas を試します。

この campaign では、custom listener が GitHub issues を C2 transport として使用していました。また、GitHub API は victim の source address を operator に直接明らかにしないため、beacon は外部 IP を把握する目的で `ipinfo.io` に問い合わせていました。<sup>[[5]](#references)</sup>

## Network fingerprinting and hunting

HTTP:<sup>[[1]](#references)</sup>
- 一般的な特徴: operator が選択した URIs（例: /uri.php、/endpoint/api）への POST
- beacon ID に使用される custom header parameter（例: X‑Beacon‑Id、X‑App‑Id）
- Firefox 20 または当時の Chrome builds を模倣した User-agents
- sleep_delay/jitter_delay によって確認できる polling cadence
- 新しい builds では callback ごとに URIs、user-agents、Host headers、servers を rotate できるため、単一の path/UA pair を想定するのではなく、珍しい header names、response-size patterns、TLS reuse、timing を基準に cluster 化します。<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- web egress が制限されている環境で intranet C2 に使用される SMB named-pipe listeners
- TCP beacons は protocol start を obfuscate するため、traffic の前に数バイトを付加する場合がある

Current upstream teamserver defaults
- `profile.yaml` には現在、teamserver `0.0.0.0:4321`、endpoint `/endpoint`、certificate/key filenames `server.rsa.crt` および `server.rsa.key`、さらに HTTP、SMB、TCP、DNS、Beacon agent、Gopher 用の extenders が含まれています。<sup>[[2]](#references)</sup>
- 一致する route がない場合、default error handler は `Server: AdaptixC2` および `Adaptix-Version: v1.2` を返します。<sup>[[4]](#references)</sup>
- stock 404 body には `AdaptixC2 404` および `You need to enter the correct connection details` が含まれます。<sup>[[4]](#references)</sup>
- 2026 年の Internet-wide scans では、`4321` で exposed teamservers が多数、`43211` で beacon listeners が多数確認されたため、両ポートは有用な seed pivots ですが、網羅的なものとして扱うべきではありません。<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- 現在の BeaconDNS extender は authoritative に応答します（`AA=true`）。
- beacon protocol shape に一致しない queries、特に configured domain より前の labels が 5 個未満の names には、通常 `TXT "OK"` で応答します。
- configured base TTL が zero のままの場合、listener は 10 秒の base を使用し、最大 59 秒の jitter を追加します。
- そのため、HTTP listener が exposed でない場合は、short-label active probes が有用です。

## Loader and persistence TTPs seen in incidents

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Base64/XOR payloads を Download します（Invoke‑RestMethod / WebClient）。<sup>[[9]](#references)</sup>
- unmanaged memory を Allocate し、shellcode を copy して、VirtualProtect により protection を 0x40（PAGE_EXECUTE_READWRITE）へ切り替えます。<sup>[[7]](#references)</sup>
- .NET dynamic invocation により実行します: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()。<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- 2026 年の Tropic Trooper chain では、trojanized SumatraPDF executable（TOSHIS loader）が `_security_init_cookie` を patching the PE entry point の代わりに malicious code へ redirect しました。
- loader は Adler-32 hashing により APIs を resolve し、decoy PDF を download し、second-stage shellcode を取得しました。その後、hardcoded seed から WinCrypt（`CryptDeriveKey`）を通じて AES-128-CBC で復号し、Adaptix beacon を memory 内で reflectively execute しました。
- Persistence は後に scheduled tasks へ移行し、`\MSDNSvc` や `\MicrosoftUDN` のような benign-looking names を使用して、agent をおよそ 2 時間ごとに再 launch するよう設定されました。

in-memory execution と AMSI/ETW considerations については、次の pages を確認してください。

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed:<sup>[[1]](#references)</sup>
- logon 時に loader を再 launch する Startup folder shortcut（.lnk）
- Registry Run keys（HKCU/HKLM ...\CurrentVersion\Run）。loader.ps1 を start するために、"Updater" のような benign-sounding names が使用されることがよくあります。<sup>[[10]](#references)</sup>
- susceptible processes 向けに `%APPDATA%\Microsoft\Windows\Templates` 配下へ msimg32.dll を drop する DLL search-order hijack

Technique deep-dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell が RW→RX transitions を spawn するケース: powershell.exe 内での PAGE_EXECUTE_READWRITE への VirtualProtect。<sup>[[8]](#references)</sup>
- Dynamic invocation patterns（GetDelegateForFunctionPointer）
- `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404`、または `You need to enter the correct connection details` を伴う unmatched HTTPS 404s。<sup>[[4]](#references)</sup>
- suspect domains 配下の short queries に対する、`AA=true` および `TXT "OK"` を伴う DNS responses。<sup>[[4]](#references)</sup>
- `/repos/<owner>/<repo>/issues` への GitHub API traffic と、同じ loader/beacon chain からの `ipinfo.io` lookups。<sup>[[5]](#references)</sup>
- user または common Startup folders 配下の Startup .lnk。<sup>[[1]](#references)</sup>
- suspicious Run keys（例: "Updater"）および update.ps1/loader.ps1 のような loader names。<sup>[[1]](#references)</sup>
- decoy document を表示する前に `_security_init_cookie` を downloader code へ redirect する trojanized PE samples。<sup>[[5]](#references)</sup>
- `%APPDATA%\Microsoft\Windows\Templates` 配下の user-writable DLL paths にある msimg32.dll。<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate: agent が self-expires する timestamp。<sup>[[1]](#references)</sup>
- WorkingTime: business activity に blend するため、agent が active であるべき hours。<sup>[[1]](#references)</sup>

これらの fields は clustering に使用でき、観測された quiet periods の説明にも役立ちます。

## YARA and static leads

Unit 42 は beacons（C/C++ および Go）と loader API-hashing constants 向けの basic YARA を公開しています。<sup>[[1]](#references)</sup> PE .rdata end 付近の [size|ciphertext|16-byte-key] layout、default HTTP profile strings、新しい server/listener markers（`AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open`、`ipinfo.io` など）を探す rules で補完することを検討してください。<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: 実際の攻撃で悪用された新しい Open-Source Framework（Unit 42）](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: 大規模な Open-Source C2 Framework の Fingerprinting（Censys）](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper が AdaptixC2 および Custom Beacon Listener へ Pivot（Zscaler ThreatLabz）](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
