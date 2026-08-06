# AdaptixC2 配置提取与 TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 是一个模块化、开源的 post-exploitation/C2 framework，支持 Windows x86/x64 beacons（EXE/DLL/service EXE/raw shellcode）以及 BOF。<sup>[[1]](#references)</sup> 本页面介绍：
- 其 RC4-packed configuration 的嵌入方式，以及如何从 beacons 中提取配置
- HTTP/SMB/TCP listeners 的网络/profile indicators
- 在真实环境中观察到的常见 loader 和 persistence TTPs，并附有相关 Windows technique 页面的链接

近期 upstream releases 还提供 DNS/DoH beacon listeners，以及独立的 Gopher agent/listener 系列。因此，即使某个具体 sample 仍使用 classic beacon agent，现代 Adaptix infrastructure 暴露的内容也可能不止原始的 HTTP/SMB/TCP surfaces。<sup>[[2]](#references)[[3]](#references)</sup>

## Beacon profiles 和 fields

AdaptixC2 支持三种主要 beacon 类型：<sup>[[1]](#references)</sup>
- BEACON_HTTP：具有可配置 server/port/SSL、method、URI、headers、user-agent 和 custom parameter name 的 web C2
- BEACON_SMB：named-pipe peer-to-peer C2（intranet）
- BEACON_TCP：direct sockets，可选择添加 prepended marker 以混淆 protocol start

这些 beacon layouts 已在早期 Adaptix analyses 中公开记录，至今仍是从 sample 侧提取配置时最常见的起点。<sup>[[1]](#references)</sup> 不过，当前 upstream builds 还在 server side 提供 `BeaconDNS` 和 Gopher extenders，因此不要假设每个 live Adaptix deployment 只暴露 HTTP/SMB/TCP infrastructure。<sup>[[2]](#references)</sup>

HTTP beacon configs 中观察到的典型 profile fields（解密后）：<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers（length-prefixed strings）
- ans_pre_size (u32), ans_size (u32) – 用于解析 response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

近期的 BeaconHTTP builds 还支持 operator-selected rotation，在多个 URIs、user-agents、Host headers 和 servers 之间进行 sequential 或 random selection。<sup>[[2]](#references)</sup> 从 hunting 角度来看，这意味着单个 infected host 可能会访问多个 callback paths 和 header combinations，同时不会脱离 classic RC4-packed beacon family。

Example default HTTP profile（来自某个 beacon build）：<sup>[[1]](#references)</sup>
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
观察到的恶意 HTTP 配置（真实攻击）：<sup>[[1]](#references)</sup>
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
## 加密配置打包和加载路径

当 operator 在 builder 中点击 Create 时，AdaptixC2 会将加密 profile 作为 tail blob 嵌入 beacon 中。格式如下：<sup>[[1]](#references)</sup>
- 4 bytes：configuration size（uint32，小端序）
- N bytes：RC4-encrypted configuration data
- 16 bytes：RC4 key

beacon loader 从末尾复制 16-byte key，并在原地对 N-byte block 执行 RC4 解密：<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
实际影响：<sup>[[1]](#references)</sup>
- 整个结构通常位于 PE 的 .rdata section 中。
- 提取过程是确定性的：读取 size，读取该 size 对应的 ciphertext，读取紧随其后的 16-byte key，然后执行 RC4-decrypt。

## Configuration 提取 workflow（defenders）

编写一个模拟 beacon logic 的 extractor：<sup>[[1]](#references)</sup>
1) 在 PE 中定位 blob（通常位于 .rdata）。一种实用方法是扫描 .rdata，查找合理的 [size|ciphertext|16-byte key] 布局，并尝试 RC4。
2) 读取前 4 bytes → size（uint32 LE）。
3) 读取接下来的 N=size bytes → ciphertext。
4) 读取最后的 16 bytes → RC4 key。
5) 对 ciphertext 执行 RC4-decrypt。然后将 plain profile 解析为：
- 如上所述的 u32/boolean scalars
- length-prefixed strings（u32 length 后跟 bytes；末尾可能存在 NUL）
- arrays：servers_count，后跟相应数量的 [string, u32 port] pairs

可独立运行、无 external deps、适用于 pre-extracted blob 的最小 Python proof-of-concept：
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
提示：
- 在自动化时，使用 PE parser 读取 .rdata，然后应用 sliding window：对于每个偏移量 o，尝试 size = u32(.rdata[o:o+4])，ct = .rdata[o+4:o+4+size]，candidate key = 后续 16 字节；使用 RC4 解密，并检查字符串字段是否能解码为 UTF-8 且长度合理。
- 按照相同的 length-prefixed conventions 解析 SMB/TCP profiles。

## Custom listener profiles：不要只对经典 HTTP schema 进行硬编码

外层打包格式（`u32 size | RC4 ciphertext | 16-byte key`）是可复用的，因此 actor-customized listeners 可以在更改解密字段布局的同时，继续使用相同的 extraction workflow。

一个较新的典型示例是 2026 年 4 月的 Tropic Trooper campaign，其中提取出的 Adaptix beacon 不包含 standard HTTP/TCP profile。相反，解密后的 blob 存储了 GitHub transport parameters，例如：<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host`（例如 `api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

实用的 parser strategy：
- 首先像往常一样准确检测 outer RC4 blob。
- 解密后，根据 sentinel strings 和字段合理性进行分支，而不是立即强制使用 HTTP parser。
- 良好的 sentinels 包括 `api.github.com`、`/issues?state=open`、HTTP verbs/URIs、named-pipe-style strings，或明显有效的 server/port arrays。
- 如果 HTTP parser 失败，但 plaintext 包含连贯的 length-prefixed UTF-8 strings，应保留该 sample 并尝试 alternative schemas，而不是将其作为 false positive 丢弃。

在该 campaign 中，custom listener 使用 GitHub issues 作为 C2 transport，而 beacon 查询 `ipinfo.io` 以获取其 external IP，因为 GitHub API 不会直接向 operator 暴露 victim 的 source address。<sup>[[5]](#references)</sup>

## Network fingerprinting and hunting

HTTP<sup>[[1]](#references)</sup>
- 常见情况：向 operator-selected URIs 发送 POST（例如 /uri.php、/endpoint/api）
- 用于 beacon ID 的 custom header parameter（例如 X‑Beacon‑Id、X‑App‑Id）
- 模仿 Firefox 20 或当前 Chrome builds 的 User-agents
- 可通过 sleep_delay/jitter_delay 观察 polling cadence
- 较新的 builds 可以在 callbacks 之间轮换 URIs、user-agents、Host headers 和 servers，因此应根据不常见的 header names、response-size patterns、TLS reuse 及 timing 进行聚类，而不是假设只有单一的 path/UA pair<sup>[[2]](#references)</sup>

SMB/TCP<sup>[[1]](#references)</sup>
- 当 web egress 受限时，用于 intranet C2 的 SMB named-pipe listeners
- TCP beacons 可能会在 traffic 前添加几个字节，以混淆 protocol start

当前 upstream teamserver defaults
- `profile.yaml` 当前随 teamserver `0.0.0.0:4321`、endpoint `/endpoint`、certificate/key filenames `server.rsa.crt` 和 `server.rsa.key` 一起提供，并包含 HTTP、SMB、TCP、DNS、Beacon agent 和 Gopher 的 extenders<sup>[[2]](#references)</sup>
- 对于不匹配的 routes，default error handler 返回 `Server: AdaptixC2` 和 `Adaptix-Version: v1.2`<sup>[[4]](#references)</sup>
- stock 404 body 包含 `AdaptixC2 404` 和 `You need to enter the correct connection details.`<sup>[[4]](#references)</sup>
- 2026 年的 Internet-wide scans 发现许多暴露在 `4321` 上的 teamservers，以及许多位于 `43211` 上的 beacon listeners，因此这两个 ports 都是有用的 seed pivots，但不应视为 exhaustive<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints<sup>[[4]](#references)</sup>
- 当前 BeaconDNS extender 会权威响应（`AA=true`）
- 不符合 beacon protocol shape 的 queries——尤其是在 configured domain 之前少于 5 个 labels 的 names——通常会以 `TXT "OK"` 响应
- 如果 configured base TTL 保持为零，listener 会使用 10 秒 base，并添加最多 59 秒的 jitter
- 因此，当没有暴露 HTTP listener 时，short-label active probes 很有用

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders<sup>[[1]](#references)</sup>
- 下载 Base64/XOR payloads（Invoke‑RestMethod / WebClient）<sup>[[9]](#references)</sup>
- 分配 unmanaged memory，复制 shellcode，并通过 VirtualProtect 将 protection 切换为 0x40（PAGE_EXECUTE_READWRITE）<sup>[[7]](#references)</sup>
- 通过 .NET dynamic invocation 执行：Marshal.GetDelegateForFunctionPointer + delegate.Invoke()<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders<sup>[[5]](#references)</sup>
- 2026 年的一条 Tropic Trooper chain 使用了 trojanized SumatraPDF executable（TOSHIS loader），将 `_security_init_cookie` 重定向到 malicious code，而不是 patching PE entry point
- 该 loader 通过 Adler-32 hashing 解析 APIs，下载 decoy PDF，获取 second-stage shellcode，使用 WinCrypt 通过 AES-128-CBC 解密（从 hardcoded seed 调用 `CryptDeriveKey`），并在 memory 中 reflectively 执行 Adaptix beacon
- Persistence 随后转移到 scheduled tasks，使用 `\MSDNSvc` 或 `\MicrosoftUDN` 等看似 benign 的 names，配置为大约每两小时重新启动 agent

查看以下页面，了解 in‑memory execution 以及 AMSI/ETW considerations：

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

已观察到的 Persistence mechanisms<sup>[[1]](#references)</sup>
- Startup folder shortcut（.lnk），用于在 logon 时重新启动 loader
- Registry Run keys（HKCU/HKLM ...\CurrentVersion\Run），通常使用名为 "Updater" 等听起来 benign 的 names 来启动 loader.ps1<sup>[[10]](#references)</sup>
- DLL search‑order hijack：将 msimg32.dll 放入 %APPDATA%\Microsoft\Windows\Templates，影响易受攻击的 processes

Technique deep-dives and checks：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell spawning RW→RX transitions：powershell.exe 内部通过 VirtualProtect 切换到 PAGE_EXECUTE_READWRITE<sup>[[8]](#references)</sup>
- Dynamic invocation patterns（GetDelegateForFunctionPointer）
- Unmatched HTTPS 404s，包含 `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404` 或 `You need to enter the correct connection details.`<sup>[[4]](#references)</sup>
- 在可疑 domains 下，对 short queries 返回 `AA=true` 和 `TXT "OK"` 的 DNS responses<sup>[[4]](#references)</sup>
- GitHub API traffic 访问 `/repos/<owner>/<repo>/issues`，随后同一 loader/beacon chain 对 `ipinfo.io` 进行 lookups<sup>[[5]](#references)</sup>
- user 或 common Startup folders 下的 Startup .lnk<sup>[[1]](#references)</sup>
- 可疑的 Run keys（例如 "Updater"），以及 update.ps1/loader.ps1 等 loader names<sup>[[1]](#references)</sup>
- Trojanized PE samples 在显示 decoy document 之前，将 `_security_init_cookie` 重定向到 downloader code<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates 下 user-writable DLL paths 中包含 msimg32.dll<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate：agent 自我过期的 timestamp<sup>[[1]](#references)</sup>
- WorkingTime：agent 应处于 active 状态的 hours，用于与 business activity 融合<sup>[[1]](#references)</sup>

这些 fields 可用于 clustering，并解释观察到的 quiet periods。

## YARA and static leads

Unit 42 发布了针对 beacons（C/C++ 和 Go）以及 loader API-hashing constants 的 basic YARA。<sup>[[1]](#references)</sup> 可以考虑补充以下 rules：查找 PE .rdata 末尾附近的 [size|ciphertext|16‑byte‑key] layout、default HTTP profile strings，以及较新的 server/listener markers，例如 `AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open` 和 `ipinfo.io`。<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
