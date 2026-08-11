# AdaptixC2 Configuration Extraction と TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 は、Windows x86/x64 beacon（EXE/DLL/service EXE/raw shellcode）と BOF をサポートする、モジュール式のオープンソース post-exploitation/C2 framework です。<sup>[[1]](#references)</sup> このページでは以下について説明します。
- RC4-packed configuration がどのように埋め込まれているか、および beacon から抽出する方法
- HTTP/SMB/TCP listener の network/profile indicators
- 実環境で観測された一般的な loader と persistence TTPs、および関連する Windows technique pages への links

最近の upstream releases には DNS/DoH beacon listeners と、独立した Gopher agent/listener family も含まれています。そのため、特定の sample が classic beacon agent を使用している場合でも、現代の Adaptix infrastructure は元来の HTTP/SMB/TCP surfaces 以外も公開している可能性があります。<sup>[[2]](#references)</sup>

## Beacon profiles and fields

AdaptixC2 は 3 種類の主要な beacon types をサポートします。<sup>[[1]](#references)</sup>
- BEACON_HTTP: configurable な servers/ports/SSL、method、URI、headers、user-agent、custom parameter name を備えた web C2
- BEACON_SMB: named-pipe peer-to-peer C2（intranet）
- BEACON_TCP: protocol start を obfuscate するための prepended marker を任意で付加できる direct sockets

これらは初期の Adaptix analyses で公開された beacon layouts であり、現在も sample-side extraction の最も一般的な出発点です。<sup>[[1]](#references)</sup> ただし、現在の upstream builds には server side の `BeaconDNS` と Gopher extenders も含まれているため、稼働中のすべての Adaptix deployment が HTTP/SMB/TCP infrastructure のみを公開しているとは想定しないでください。<sup>[[2]](#references)</sup>

HTTP beacon configs で観測される典型的な profile fields（decryption 後）：<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response sizes の parse に使用
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

最近の BeaconHTTP builds は、複数の URIs、user-agents、Host headers、servers を対象に、sequential または random selection を行う operator-selected rotation もサポートしています。<sup>[[2]](#references)</sup> Hunting の観点では、これは 1 台の infected host が、classic RC4-packed beacon family を使用しているにもかかわらず、複数の callback paths と header combinations に対して通信を分散させる可能性があることを意味します。

Example default HTTP profile（beacon build から）：<sup>[[1]](#references)</sup>
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
観測された悪意のあるHTTP profile（実際の攻撃）:<sup>[[1]](#references)</sup>
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
## 暗号化された設定のパッキングとロードパス

オペレーターが builder で Create をクリックすると、AdaptixC2 は暗号化された profile を beacon の末尾 blob として埋め込みます。形式は次のとおりです:<sup>[[1]](#references)</sup>
- 4 bytes: configuration size (uint32, little-endian)
- N bytes: RC4-encrypted configuration data
- 16 bytes: RC4 key

beacon loader は末尾から 16-byte key をコピーし、N-byte block をその場で RC4-decrypt します:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
実用上の意味:<sup>[[1]](#references)</sup>
- 構造全体は、多くの場合 PE の .rdata セクション内に存在します。
- Extraction は決定論的です。サイズを読み取り、そのサイズ分の ciphertext を読み取り、その直後に配置された 16 バイトの key を読み取り、その後 RC4-decrypt します。

## Configuration extraction workflow (defenders)

beacon logic を模倣する extractor を作成します:<sup>[[1]](#references)</sup>
1) PE 内（一般的には .rdata）で blob を特定します。実用的な方法は、.rdata をスキャンして、妥当と思われる [size|ciphertext|16-byte key] のレイアウトを探し、RC4 を試行することです。
2) 最初の 4 バイトを読み取る → size (uint32 LE)。
3) 次の N=size バイトを読み取る → ciphertext。
4) 最後の 16 バイトを読み取る → RC4 key。
5) ciphertext を RC4-decrypt します。その後、plain profile を次のように parse します:
- 上記のとおり、u32/boolean の scalar
- length-prefixed strings（u32 length の後に bytes が続く形式。末尾に NUL が含まれる場合があります）
- arrays: servers_count に続いて、[string, u32 port] pair をその数だけ格納

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
ヒント:
- 自動化する場合は、PE parserを使用して.rdataを読み取り、sliding windowを適用します。各オフセットoについて、size = u32(.rdata[o:o+4])、ct = .rdata[o+4:o+4+size]、candidate key = 次の16バイトを試します。RC4で復号し、文字列フィールドがUTF-8としてデコードでき、長さが妥当か確認します。
- SMB/TCP profilesは、同じlength-prefixedの規則に従って解析します。

## Custom listener profiles: classic HTTP schemaだけをハードコードしない

外側のpacking format（`u32 size | RC4 ciphertext | 16-byte key`）は再利用できるため、actor-customized listenersでも同じ抽出ワークフローを維持しながら、復号後のfield layoutを完全に変更できます。

最近の良い例は、2026年3月のTropic Trooper campaignです。このcampaignで抽出されたAdaptix beaconにはstandard HTTP/TCP profileが含まれていませんでした。代わりに、復号されたblobには次のようなGitHub transport parametersが保存されていました:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host`（例: `api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

実用的なparser strategy:
- まず、通常どおりouter RC4 blobを正確に検出します。
- 復号後は、HTTP parserをすぐに強制するのではなく、sentinel stringsとfield sanityに基づいて分岐します。
- 有効なsentinelには、`api.github.com`、`/issues?state=open`、HTTP verbs/URIs、named-pipe-style strings、または明らかに有効なserver/port arraysなどがあります。
- HTTP parserが失敗しても、plaintextに一貫したlength-prefixed UTF-8 stringsが含まれている場合は、false positiveとして破棄せず、sampleを保持して別のschemaを試します。

このcampaignでは、custom listenerがGitHub issuesをC2 transportとして使用していました。また、GitHub APIはoperatorにvictimのsource addressを直接公開しないため、beaconは外部IPを知る目的で`ipinfo.io`に問い合わせていました。<sup>[[5]](#references)</sup>

## Network fingerprintingとhunting

HTTP:<sup>[[1]](#references)</sup>
- Common: operatorが選択したURIへのPOST（例: /uri.php、/endpoint/api）
- beacon IDに使用されるcustom header parameter（例: X‑Beacon‑Id、X‑App‑Id）
- Firefox 20または現在のChrome buildsを模倣するUser-agents
- sleep_delay/jitter_delayで確認できるpolling cadence
- 新しいbuildでは、callbackごとにURI、user-agents、Host headers、serversをrotateできるため、単一のpath/UA pairを前提とせず、珍しいheader names、response-size patterns、TLS reuse、timingを基準にcluster化します。<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- web egressが制限されているintranet C2向けのSMB named-pipe listeners
- TCP beaconsは、protocol startをobfuscateするため、trafficの前に数バイトを付加する場合があります

Current upstream teamserver defaults
- `profile.yaml`には現在、teamserver `0.0.0.0:4321`、endpoint `/endpoint`、certificate/key filenames `server.rsa.crt`および`server.rsa.key`、さらにHTTP、SMB、TCP、DNS、Beacon agent、Gopher向けのextendersが含まれています。<sup>[[2]](#references)</sup>
- 一致しないroutesでは、default error handlerが`Server: AdaptixC2`および`Adaptix-Version: v1.2`を返します。<sup>[[4]](#references)</sup>
- stock 404 bodyには`AdaptixC2 404`および`You need to enter the correct connection details`が含まれます。<sup>[[4]](#references)</sup>
- 2026年のInternet-wide scansでは、`4321`でexposed teamserversが多数、`43211`でbeacon listenersが多数確認されたため、両portはseed pivotsとして有用ですが、網羅的なものとして扱うべきではありません。<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- 現在のBeaconDNS extenderはauthoritatively応答します（`AA=true`）。
- beacon protocol shapeに一致しないqueries、特にconfigured domainの前に5個未満のlabelsしかないnamesには、通常`TXT "OK"`で応答します。
- configured base TTLをzeroのままにすると、listenerは10秒のbaseを使用し、最大59秒のjitterを追加します。
- そのため、HTTP listenerがexposedでない場合には、short-label active probesが有用です。

## Incidentsで確認されたLoaderとpersistence TTPs

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Base64/XOR payloadsをdownloadします（Invoke‑RestMethod / WebClient）。<sup>[[9]](#references)</sup>
- unmanaged memoryをallocateし、shellcodeをcopyした後、VirtualProtectを介してprotectionを0x40（PAGE_EXECUTE_READWRITE）に切り替えます。<sup>[[7]](#references)</sup>
- .NET dynamic invocationにより実行します: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()。<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- 2026年のTropic Trooper chainでは、trojanized SumatraPDF executable（TOSHIS loader）が、PE entry pointをpatchする代わりに`_security_init_cookie`をmalicious codeへredirectしました。
- loaderはAdler-32 hashingでAPIsをresolveし、decoy PDFをdownloadし、second-stage shellcodeをfetchした後、hardcoded seedからWinCrypt（`CryptDeriveKey`）を使用してAES-128-CBCで復号し、Adaptix beaconをmemory内でreflectively実行しました。
- その後、persistenceは`\MSDNSvc`や`\MicrosoftUDN`などのbenign-looking namesを持つscheduled tasksへ移行し、agentを約2時間ごとに再起動するよう設定されました。

in-memory executionとAMSI/ETW considerationsについては、次のページを確認してください:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

確認されたPersistence mechanisms:<sup>[[1]](#references)</sup>
- logon時にloaderを再起動するStartup folder shortcut（.lnk）
- Registry Run keys（HKCU/HKLM ...\CurrentVersion\Run）。多くの場合、"Updater"のようなbenign-sounding namesでloader.ps1をstartします。<sup>[[10]](#references)</sup>
- susceptible processes向けに、%APPDATA%\Microsoft\Windows\Templatesへmsimg32.dllをdropするDLL search-order hijack

Technique deep-divesとchecks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShellがRW→RX transitionsをspawnするケース: powershell.exe内部でVirtualProtectからPAGE_EXECUTE_READWRITEへ移行。<sup>[[8]](#references)</sup>
- Dynamic invocation patterns（GetDelegateForFunctionPointer）
- `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404`、または`You need to enter the correct connection details`を伴うunmatched HTTPS 404s。<sup>[[4]](#references)</sup>
- suspect domains配下のshort queriesに対する、`AA=true`および`TXT "OK"`を伴うDNS responses。<sup>[[4]](#references)</sup>
- `/repos/<owner>/<repo>/issues`へのGitHub API trafficに続き、同じloader/beacon chainから`ipinfo.io` lookupsが発生するケース。<sup>[[5]](#references)</sup>
- userまたはcommon Startup folders配下のStartup .lnk。<sup>[[1]](#references)</sup>
- Suspicious Run keys（例: "Updater"）、およびupdate.ps1/loader.ps1のようなloader names。<sup>[[1]](#references)</sup>
- decoy documentを表示する前に`_security_init_cookie`をdownloader codeへredirectするTrojanized PE samples。<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates配下のuser-writable DLL pathsにあるmsimg32.dll。<sup>[[1]](#references)</sup>

## OpSec fieldsに関するNotes

- KillDate: agentがself-expiresする時点以降のtimestamp。<sup>[[1]](#references)</sup>
- WorkingTime: business activityに紛れるためにagentがactiveであるべき時間帯。<sup>[[1]](#references)</sup>

これらのfieldsは、clusteringや確認されたquiet periodsの説明に利用できます。

## YARAとstatic leads

Unit 42は、beacons（C/C++およびGo）とloader API-hashing constants向けのbasic YARAを公開しています。<sup>[[1]](#references)</sup> PE .rdata end付近の[size|ciphertext|16-byte-key] layout、default HTTP profile strings、さらに`AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open`、`ipinfo.io`などの新しいserver/listener markersを探すrulesで補完することを検討してください。<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: 実際の攻撃で利用された新しいOpen-Source Framework (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: 大規模環境でのOpen-Source C2 FrameworkのFingerprinting (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper、AdaptixC2およびCustom Beacon ListenerへPivot (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
