# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2は、Windows x86/x64 beacon（EXE/DLL/service EXE/raw shellcode）とBOF supportを備えた、modularなopen-source post-exploitation/C2 frameworkです。<sup>[[1]](#references)</sup> このページでは以下について説明します。
- RC4-packed configurationがどのように埋め込まれているか、およびbeaconから抽出する方法
- HTTP/SMB/TCP listenersのnetwork/profile indicators
- 実環境で確認されている一般的なloaderおよびpersistence TTPsと、関連するWindows technique pagesへのリンク

Recent upstream releasesにはDNS/DoH beacon listenersと、独立したGopher agent/listener familyも含まれています。そのため、特定のsampleがclassic beacon agentを使用している場合でも、modern Adaptix infrastructureは従来のHTTP/SMB/TCP surfaces以外を公開している可能性があります。<sup>[[2]](#references)[[3]](#references)</sup>

## Beacon profiles and fields

AdaptixC2は、3種類のprimary beacon typesをサポートします。<sup>[[1]](#references)</sup>
- BEACON_HTTP: configurableなservers/ports/SSL、method、URI、headers、user-agent、custom parameter nameを備えたweb C2
- BEACON_SMB: named-pipe peer-to-peer C2（intranet）
- BEACON_TCP: protocol startをobfuscateするため、先頭にmarkerを付加できるdirect sockets

これらは、初期のAdaptix analysesでpublicly documentedされたbeacon layoutsであり、現在もsample-side extractionにおける最も一般的なstarting pointです。<sup>[[1]](#references)</sup> ただし、current upstream buildsにはserver sideの`BeaconDNS`およびGopher extendersも含まれているため、すべてのlive Adaptix deploymentがHTTP/SMB/TCP infrastructureのみを公開していると想定しないでください。<sup>[[2]](#references)</sup>

HTTP beacon configsで確認されるtypical profile fields（decryption後）：<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response sizesのparseに使用
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Recent BeaconHTTP buildsは、複数のURIs、user-agents、Host headers、servers間で、operatorが選択したrotationもサポートしており、sequentialまたはrandom selectionが可能です。<sup>[[2]](#references)</sup> Huntingの観点では、これはsingle infected hostが、classic RC4-packed beacon familyを使用し続けながら、複数のcallback pathsおよびheader combinationsへfan outする可能性があることを意味します。

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
観測された悪意のあるHTTPプロファイル（実際の攻撃）:<sup>[[1]](#references)</sup>
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

operator が builder で Create をクリックすると、AdaptixC2 は暗号化された profile を beacon 内の tail blob として埋め込みます。形式は次のとおりです:<sup>[[1]](#references)</sup>
- 4 bytes: configuration size (uint32, little‑endian)
- N bytes: RC4‑encrypted configuration data
- 16 bytes: RC4 key

beacon loader は末尾から 16-byte の key をコピーし、N-byte ブロックをその場で RC4-decrypt します:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
実務上の意味:<sup>[[1]](#references)</sup>
- 構造全体は、多くの場合 PE の .rdata セクション内に存在する。
- Extraction は決定論的に行える: size を読み取り、そのサイズ分の ciphertext を読み取り、その直後に配置された 16 バイトの key を読み取り、その後 RC4 でdecryptする。

## Configuration extraction workflow (defenders)

beacon logic を模倣する extractor を作成する:<sup>[[1]](#references)</sup>
1) PE 内（一般的には .rdata）で blob の位置を特定する。実用的な方法は、.rdata をスキャンして、妥当な [size|ciphertext|16-byte key] レイアウトを探し、RC4 を試行することである。
2) 最初の 4 バイトを読み取る → size (uint32 LE)。
3) 次の N=size バイトを読み取る → ciphertext。
4) 最後の 16 バイトを読み取る → RC4 key。
5) ciphertext を RC4-decryptする。その後、plain profile を次の形式で parse する:
- 上記のとおりの u32/boolean scalar
- length-prefixed string（u32 length に続いて bytes; 末尾に NUL が存在する場合がある）
- arrays: servers_count に続いて、その数の [string, u32 port] ペア

pre-extracted blob で動作する、external deps 不要の standalone な最小 Python proof-of-concept:
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
- 自動化する場合は、PE parserを使用して.rdataを読み取り、sliding windowを適用する: 各offset oについて、size = u32(.rdata[o:o+4])、ct = .rdata[o+4:o+4+size]、candidate key = 次の16バイトを試す。RC4‑decryptを行い、string fieldsがUTF‑8としてdecodeされ、lengthsが妥当であることを確認する。
- SMB/TCP profilesは、同じlength‑prefixed conventionsに従ってparseする。

## Custom listener profiles: classic HTTP schemaだけをハードコードしない

outer packing format（`u32 size | RC4 ciphertext | 16-byte key`）は再利用できるため、actor-customized listenersでも、decrypted field layoutを完全に変更しながら同じextraction workflowを維持できる。

最近の良い例は、2026年4月のTropic Trooper campaignである。このcampaignでextractedされたAdaptix beaconにはstandard HTTP/TCP profileが含まれていなかった。代わりに、decrypted blobには次のようなGitHub transport parametersが保存されていた:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host`（例: `api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Practical parser strategy:
- まず、通常どおりouter RC4 blobを正確にdetectする。
- decryption後は、HTTP parserをすぐに強制するのではなく、sentinel stringsとfield sanityに基づいて分岐する。
- 良いsentinelsには、`api.github.com`、`/issues?state=open`、HTTP verbs/URIs、named-pipe-style strings、または明らかに有効なserver/port arraysが含まれる。
- HTTP parserが失敗しても、plaintextに整合性のあるlength-prefixed UTF-8 stringsが含まれている場合は、false positiveとして破棄せず、sampleを保持してalternative schemasを試す。

このcampaignでは、custom listenerがGitHub issuesをC2 transportとして使用していた。また、GitHub APIはoperatorにvictimのsource addressを直接明らかにしないため、beaconは外部IPを知る目的で`ipinfo.io`にqueryしていた。<sup>[[5]](#references)</sup>

## Network fingerprinting and hunting

HTTP<sup>[[1]](#references)</sup>
- Common: operatorが選択したURIへのPOST（例: /uri.php、/endpoint/api）
- beacon IDに使用されるcustom header parameter（例: X‑Beacon‑Id、X‑App‑Id）
- Firefox 20または同時期のChrome buildsを模倣するUser‑agents
- sleep_delay/jitter_delayによって確認できるpolling cadence
- Newer buildsでは、callbackごとにURIs、user-agents、Host headers、serversをrotateできる。そのため、単一のpath/UA pairを前提とせず、uncommon header names、response-size patterns、TLS reuse、timingを基準にclusterする<sup>[[2]](#references)</sup>

SMB/TCP<sup>[[1]](#references)</sup>
- web egressが制限されるintranet C2向けのSMB named‑pipe listeners
- TCP beaconsはprotocol startをobfuscateするため、trafficの前に数バイトをprependする場合がある

Current upstream teamserver defaults
- `profile.yaml`には現在、teamserver `0.0.0.0:4321`、endpoint `/endpoint`、certificate/key filenames `server.rsa.crt`および`server.rsa.key`、HTTP、SMB、TCP、DNS、Beacon agent、Gopher用のextendersが同梱されている<sup>[[2]](#references)</sup>
- unmatched routesでは、default error handlerが`Server: AdaptixC2`および`Adaptix-Version: v1.2`を返す<sup>[[4]](#references)</sup>
- stock 404 bodyには`AdaptixC2 404`および`You need to enter the correct connection details.`が含まれる<sup>[[4]](#references)</sup>
- 2026年のInternet-wide scansでは、`4321`でexposed teamserversが多数、`43211`でbeacon listenersが多数発見された。そのため、両方のportsはseed pivotsとして有用だが、網羅的なものとして扱ってはならない<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints<sup>[[4]](#references)</sup>
- 現在のBeaconDNS extenderはauthoritatively replyする（`AA=true`）
- beacon protocol shapeに一致しないqueries、特にconfigured domainの前に5つ未満のlabelsを持つnamesには、通常`TXT "OK"`でreplyする
- configured base TTLをzeroのままにすると、listenerは10秒のbaseを使用し、最大59秒のjitterを追加する
- これにより、HTTP listenerがexposedされていない場合でも、short-label active probesが有用になる

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders<sup>[[1]](#references)</sup>
- Base64/XOR payloadsをdownloadする（Invoke‑RestMethod / WebClient）<sup>[[9]](#references)</sup>
- unmanaged memoryをallocateし、shellcodeをcopyし、VirtualProtect経由でprotectionを0x40（PAGE_EXECUTE_READWRITE）に切り替える<sup>[[7]](#references)</sup>
- .NET dynamic invocationでexecuteする: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders<sup>[[5]](#references)</sup>
- 2026年のTropic Trooper chainでは、trojanized SumatraPDF executable（TOSHIS loader）が`_security_init_cookie`をPE entry pointのpatchではなくmalicious codeへredirectした
- loaderはAdler-32 hashingによってAPIsをresolveし、decoy PDFをdownloadし、second-stage shellcodeをfetchし、hardcoded seedからWinCrypt（`CryptDeriveKey`）を介してAES-128-CBCでdecryptし、Adaptix beaconをmemory内でreflectively executeした
- Persistenceは後にscheduled tasksへ移行され、`\MSDNSvc`や`\MicrosoftUDN`などのbenign-looking namesを使用し、約2時間ごとにagentをre-launchするよう設定された

in‑memory executionおよびAMSI/ETW considerationsについては、次のpagesを確認する:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed<sup>[[1]](#references)</sup>
- logon時にloaderをre-launchするStartup folder shortcut（.lnk）
- Registry Run keys（HKCU/HKLM ...\CurrentVersion\Run）。多くの場合、"Updater"などのbenign-sounding namesでloader.ps1をstartする<sup>[[10]](#references)</sup>
- susceptible processes向けに、%APPDATA%\Microsoft\Windows\Templates配下へmsimg32.dllをdropするDLL search-order hijack

Technique deep-dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShellがRW→RX transitionsをspawnするケース: powershell.exe内でVirtualProtectからPAGE_EXECUTE_READWRITEへ移行<sup>[[8]](#references)</sup>
- Dynamic invocation patterns（GetDelegateForFunctionPointer）
- `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404`、または`You need to enter the correct connection details.`を伴うunmatched HTTPS 404s<sup>[[4]](#references)</sup>
- suspect domains配下のshort queriesに対する、`AA=true`および`TXT "OK"`を伴うDNS responses<sup>[[4]](#references)</sup>
- `/repos/<owner>/<repo>/issues`へのGitHub API trafficに続き、同じloader/beacon chainから`ipinfo.io` lookupsが発生するケース<sup>[[5]](#references)</sup>
- userまたはcommon Startup folders配下のStartup .lnk<sup>[[1]](#references)</sup>
- suspicious Run keys（例: "Updater"）、およびupdate.ps1/loader.ps1などのloader names<sup>[[1]](#references)</sup>
- decoy documentを表示する前に、`_security_init_cookie`をdownloader codeへredirectするtrojanized PE samples<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates配下のuser-writable DLL pathsにあるmsimg32.dll<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate: agentがself‑expiresするtimestamp<sup>[[1]](#references)</sup>
- WorkingTime: business activityに紛れるため、agentがactiveであるべきhours<sup>[[1]](#references)</sup>

これらのfieldsは、clusteringや、観測されたquiet periodsの説明に利用できる。

## YARA and static leads

Unit 42は、beacons（C/C++およびGo）とloader API-hashing constants向けのbasic YARAを公開している。<sup>[[1]](#references)</sup> PE .rdata end付近の[size|ciphertext|16-byte-key] layout、default HTTP profile strings、さらに`AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open`、`ipinfo.io`などのnewer server/listener markersを探すrulesで補完することを検討する。<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Real-World Attacksで利用された新しいOpen-Source Framework（Unit 42）](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: 大規模環境でのOpen-Source C2 FrameworkのFingerprinting（Censys）](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic TrooperがAdaptixC2およびCustom Beacon ListenerへPivot（Zscaler ThreatLabz）](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
