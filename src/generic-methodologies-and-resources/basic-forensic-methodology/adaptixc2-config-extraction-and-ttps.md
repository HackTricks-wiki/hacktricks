# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 は、Windows x86/x64 beacon（EXE/DLL/service EXE/raw shellcode）と BOF support を備えた、modular な open-source post-exploitation/C2 framework です。このページでは以下について説明します。
- RC4-packed configuration がどのように埋め込まれているか、および beacon から抽出する方法
- HTTP/SMB/TCP listener の network/profile indicators
- 実環境で確認されている一般的な loader と persistence TTPs、および関連する Windows technique pages へのリンク

最近の upstream releases では DNS/DoH beacon listeners と、独立した Gopher agent/listener family も提供されています。そのため、特定の sample が classic beacon agent を使用している場合でも、modern Adaptix infrastructure は従来の HTTP/SMB/TCP surfaces 以外の情報を露出する可能性があります。

## Beacon profiles and fields

AdaptixC2 は、主に次の 3 種類の beacon をサポートします。
- BEACON_HTTP: configurable な servers/ports/SSL、method、URI、headers、user-agent、custom parameter name を備えた web C2
- BEACON_SMB: named-pipe peer-to-peer C2（intranet）
- BEACON_TCP: direct sockets。protocol start を obfuscate するため、先頭に marker を付加することも可能

これらは、初期の Adaptix analyses で公開された beacon layouts であり、現在も sample-side extraction の最も一般的な出発点です。ただし、current upstream builds には server side の `BeaconDNS` と Gopher extenders も含まれているため、稼働中のすべての Adaptix deployment が HTTP/SMB/TCP infrastructure のみを公開していると想定しないでください。

HTTP beacon configs で確認される一般的な profile fields（decryption 後）:
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response sizes の parse に使用
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Recent BeaconHTTP builds は、複数の URI、user-agents、Host headers、servers を operator が選択して rotation させる機能もサポートしており、sequential または random selection が可能です。hunting の観点では、これは classic RC4-packed beacon family を使用していても、単一の infected host が複数の callback paths と header combinations に通信を分散させる可能性があることを意味します。

Example default HTTP profile（beacon build 由来）:
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
観測された悪意のあるHTTPプロファイル（実際の攻撃）：
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
## 暗号化された設定のパッキングと読み込みパス

operator が builder で Create をクリックすると、AdaptixC2 は暗号化された profile を beacon の tail blob として埋め込みます。形式は次のとおりです。
- 4 bytes: configuration size (uint32, little-endian)
- N bytes: RC4-encrypted configuration data
- 16 bytes: RC4 key

beacon loader は末尾から 16-byte の key をコピーし、N-byte の block をその場で RC4-decrypt します。
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
実用上の意味:
- 構造全体は、多くの場合 PE の .rdata セクション内に存在します。
- 抽出は決定的です: size を読み取り、そのサイズ分の ciphertext を読み取り、その直後に配置された 16 バイトの key を読み取り、その後 RC4-decrypt します。

## Configuration extraction workflow (defenders)

beacon logic を模倣する extractor を作成します:
1) PE 内（一般的には .rdata）で blob の位置を特定します。実用的な方法は、.rdata をスキャンして、もっともらしい [size|ciphertext|16-byte key] のレイアウトを探し、RC4 を試行することです。
2) 先頭の 4 バイトを読み取る → size (uint32 LE)。
3) 次の N=size バイトを読み取る → ciphertext。
4) 最後の 16 バイトを読み取る → RC4 key。
5) ciphertext を RC4-decrypt します。その後、plain profile を次のように parse します:
- 上記の u32/boolean scalar
- length-prefixed string (u32 length の後に bytes が続く。末尾の NUL が存在する場合があります)
- arrays: servers_count の後に、[string, u32 port] ペアがその数だけ続く

pre-extracted blob で動作する最小限の Python proof-of-concept (standalone、外部依存なし):
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
- 自動化する場合は、PE parserを使って.rdataを読み取り、sliding windowを適用します。各offset oについて、size = u32(.rdata[o:o+4])、ct = .rdata[o+4:o+4+size]、candidate key = next 16 bytesを試します。RC4でdecryptし、string fieldsがUTF-8としてdecodeでき、lengthsが妥当であることを確認します。
- SMB/TCP profilesは、同じlength-prefixed conventionsに従ってparseします。

## Custom listener profiles: classic HTTP schemaだけをハードコードしない

外側のpacking format（`u32 size | RC4 ciphertext | 16-byte key`）は再利用できるため、actor-customized listenersでも同じextraction workflowを維持しながら、decrypted field layoutを完全に変更できます。

最近の良い例は、2026年4月のTropic Trooper campaignです。ここで抽出されたAdaptix beaconにはstandard HTTP/TCP profileが含まれていませんでした。代わりに、decrypted blobには次のようなGitHub transport parametersが保存されていました。
- `repo_owner`
- `repo_name`
- `api_host`（例：`api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

実用的なparser strategy：
- まず、通常どおりouter RC4 blobを検出します。
- decrypt後は、すぐにHTTP parserを強制するのではなく、sentinel stringsとfield sanityに基づいて分岐します。
- 有効なsentinelには、`api.github.com`、`/issues?state=open`、HTTP verbs/URIs、named-pipe-style strings、または明らかに有効なserver/port arraysなどがあります。
- HTTP parserが失敗しても、plaintextに整合性のあるlength-prefixed UTF-8 stringsが含まれている場合は、false positiveとして破棄せず、sampleを保持してalternative schemasを試します。

このcampaignでは、custom listenerはGitHub issuesをC2 transportとして使用していました。また、GitHub APIはoperatorにvictimのsource addressを直接通知しないため、beaconは外部IPを知る目的で`ipinfo.io`をqueryしていました。

## Network fingerprinting and hunting

HTTP
- Common: operatorが選択したURI（例：`/uri.php`、`/endpoint/api`）へのPOST
- beacon IDに使用されるcustom header parameter（例：`X-Beacon-Id`、`X-App-Id`）
- Firefox 20または当時のChrome buildsを模倣するUser-agents
- `sleep_delay`/`jitter_delay`によって確認できるpolling cadence
- 新しいbuildsでは、callbackごとにURIs、user-agents、Host headers、serversをrotateできるため、単一のpath/UA pairを前提にせず、珍しいheader names、response-size patterns、TLS reuse、timingを基準にcluster化する

SMB/TCP
- web egressが制限されるintranet C2向けのSMB named-pipe listeners
- TCP beaconsは、protocol startをobfuscateするため、trafficの前に数byteを付加する場合がある

Current upstream teamserver defaults
- `profile.yaml`には現在、teamserver `0.0.0.0:4321`、endpoint `/endpoint`、certificate/key filenames `server.rsa.crt`および`server.rsa.key`、HTTP、SMB、TCP、DNS、Beacon agent、Gopher向けextendersが含まれています
- unmatched routesでは、default error handlerが`Server: AdaptixC2`および`Adaptix-Version: v1.2`を返します
- stock 404 bodyには`AdaptixC2 404`および`You need to enter the correct connection details.`が含まれます
- 2026年のInternet-wide scansでは、`4321`でexposed teamserversが多数、`43211`でbeacon listenersが多数発見されたため、両方のportは有用なseed pivotsですが、網羅的なものとして扱うべきではありません

DNS/DoH listener fingerprints
- 現在のBeaconDNS extenderはauthoritatively回答します（`AA=true`）
- beacon protocol shapeに一致しないqueries、特にconfigured domainより前のlabelsが5未満のnamesには、通常`TXT "OK"`で回答します
- configured base TTLを0のままにすると、listenerは10秒のbaseを使用し、最大59秒のjitterを追加します
- そのため、HTTP listenerがexposedでない場合でも、short-label active probesが有用です

## Loader and persistence TTPs seen in incidents

In-memory PowerShell loaders
- Base64/XOR payloadsをdownload（Invoke-RestMethod / WebClient）
- unmanaged memoryをallocateし、shellcodeをcopyし、VirtualProtect経由でprotectionを0x40（PAGE_EXECUTE_READWRITE）に変更
- .NET dynamic invocationでexecute：Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Trojanized signed software / staged shellcode loaders
- 2026年のTropic Trooper chainでは、trojanized SumatraPDF executable（TOSHIS loader）が`_security_init_cookie`をPE entry pointのpatchではなくmalicious codeへredirectしました
- loaderはAdler-32 hashingでAPIsをresolveし、decoy PDFをdownloadし、second-stage shellcodeをfetchし、hardcoded seedからWinCrypt（`CryptDeriveKey`）を通じてAES-128-CBCでdecryptし、Adaptix beaconをmemory内でreflectively executeしました
- その後、persistenceは`\MSDNSvc`や`\MicrosoftUDN`などのbenign-looking namesを使用するscheduled tasksへ移行し、およそ2時間ごとにagentを再launchするよう設定されました

in-memory executionおよびAMSI/ETW considerationsについては、以下のページを確認してください。

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed
- logon時にloaderを再launchするStartup folder shortcut（.lnk）
- Registry Run keys（HKCU/HKLM ...\CurrentVersion\Run）。loader.ps1をstartするため、"Updater"のようなbenign-sounding namesが使われることが多い
- 脆弱なprocess向けに`%APPDATA%\Microsoft\Windows\Templates`配下へmsimg32.dllをdropするDLL search-order hijack

Technique deep-dives and checks：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShellがRW→RX transitionsをspawn：powershell.exe内部でVirtualProtectを使用してPAGE_EXECUTE_READWRITEへ変更
- Dynamic invocation patterns（GetDelegateForFunctionPointer）
- `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404`、または`You need to enter the correct connection details.`を含むunmatched HTTPS 404s
- 疑わしいdomains配下のshort queriesに対する、`AA=true`および`TXT "OK"`を伴うDNS responses
- `/repos/<owner>/<repo>/issues`へのGitHub API trafficに続く、同じloader/beacon chainからの`ipinfo.io` lookups
- userまたはcommon Startup folders配下のStartup .lnk
- suspicious Run keys（例："Updater"）、およびupdate.ps1/loader.ps1などのloader names
- decoy documentを表示する前に`_security_init_cookie`をdownloader codeへredirectするtrojanized PE samples
- `%APPDATA%\Microsoft\Windows\Templates`配下のuser-writable DLL pathsにあるmsimg32.dll

## Notes on OpSec fields

- KillDate：agentがself-expiresするtimestamp
- WorkingTime：business activityに紛れ込むため、agentがactiveであるべきhours

これらのfieldsは、clusteringや観測されたquiet periodsの説明に使用できます。

## YARA and static leads

Unit 42は、beacons（C/C++およびGo）とloader API-hashing constants向けのbasic YARAを公開しています。PE .rdata end付近にある[size|ciphertext|16-byte-key] layout、default HTTP profile strings、および`AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open`、`ipinfo.io`などの新しいserver/listener markersを探すrulesで補完することを検討してください。

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
