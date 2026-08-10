# AdaptixC2 配置提取与 TTPs

AdaptixC2 是一个模块化、开源的 post-exploitation/C2 framework，支持 Windows x86/x64 beacons（EXE/DLL/service EXE/raw shellcode）以及 BOF。<sup>[[1]](#references)</sup> 本页面介绍：
- 其 RC4-packed 配置的嵌入方式，以及如何从 beacons 中提取配置
- HTTP/SMB/TCP listeners 的网络/profile indicators
- 在实际环境中观察到的常见 loader 和 persistence TTPs，并提供相关 Windows technique 页面的链接

近期的 upstream releases 还提供 DNS/DoH beacon listeners 以及独立的 Gopher agent/listener 系列，因此现代 Adaptix 基础设施可能暴露出原始 HTTP/SMB/TCP surfaces 之外的更多特征，即使某个特定样本仍使用经典的 beacon agent。<sup>[[2]](#references)</sup>

## Beacon profiles 和字段

AdaptixC2 支持三种主要的 beacon 类型：<sup>[[1]](#references)</sup>
- BEACON_HTTP：带有可配置 servers/ports/SSL、method、URI、headers、user-agent 和自定义 parameter name 的 web C2
- BEACON_SMB：named-pipe peer-to-peer C2（intranet）
- BEACON_TCP：direct sockets，可选添加 prepended marker 以混淆 protocol start

这些 layouts 在早期 Adaptix 分析中已有公开文档记录，并且仍然是 sample-side extraction 最常见的起点。<sup>[[1]](#references)</sup> 但是，当前的 upstream builds 还在 server 端提供 `BeaconDNS` 和 Gopher extenders，因此不要假设每个 live Adaptix deployment 只暴露 HTTP/SMB/TCP infrastructure。<sup>[[2]](#references)</sup>

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

近期的 BeaconHTTP builds 还支持 operator-selected rotation，在多个 URIs、user-agents、Host headers 和 servers 之间进行 sequential 或 random selection。<sup>[[2]](#references)</sup> 从 hunting 的角度来看，这意味着单个 infected host 可能会通过多个 callback paths 和 header combinations 进行通信，而不会脱离经典的 RC4-packed beacon family。

示例默认 HTTP profile（来自一个 beacon build）：<sup>[[1]](#references)</sup>
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
观察到的恶意 HTTP profile（真实攻击）：<sup>[[1]](#references)</sup>
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
## 加密配置打包与加载路径

当 operator 在 builder 中点击 Create 时，AdaptixC2 会将加密的 profile 作为尾部 blob 嵌入 beacon。格式如下：<sup>[[1]](#references)</sup>
- 4 字节：配置大小（uint32，小端序）
- N 字节：经 RC4 加密的配置数据
- 16 字节：RC4 密钥

beacon loader 从末尾复制 16 字节密钥，并在原位置对 N 字节数据块执行 RC4 解密：<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
实际影响：<sup>[[1]](#references)</sup>
- 整个结构通常位于 PE 的 .rdata section 中。
- 提取过程是确定性的：读取 size，读取该大小的 ciphertext，读取紧随其后的 16-byte key，然后使用 RC4 解密。

## Configuration extraction workflow（defenders）

编写一个模拟 beacon logic 的 extractor：<sup>[[1]](#references)</sup>
1) 在 PE 中定位 blob（通常位于 .rdata）。一种实用方法是扫描 .rdata，查找可能的 [size|ciphertext|16-byte key] 布局，并尝试使用 RC4。
2) 读取前 4 bytes → size（uint32 LE）。
3) 读取接下来的 N=size bytes → ciphertext。
4) 读取最后的 16 bytes → RC4 key。
5) 使用 RC4 解密 ciphertext。然后将 plain profile 解析为：
- 如上所述的 u32/boolean scalars
- length-prefixed strings（u32 length 后跟 bytes；末尾可以存在 NUL）
- arrays：servers_count 后跟对应数量的 [string, u32 port] 对

可独立运行且无 external deps、适用于 pre-extracted blob 的最小 Python proof-of-concept：
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
- 在自动化处理时，使用 PE parser 读取 `.rdata`，然后应用滑动窗口：对于每个偏移量 o，尝试 `size = u32(.rdata[o:o+4])`、`ct = .rdata[o+4:o+4+size]`，将后续 16 字节作为 candidate key；使用 RC4 解密，并检查字符串字段是否能解码为 UTF-8 且长度合理。
- 按照相同的长度前缀约定解析 SMB/TCP profiles。

## Custom listener profiles：不要只硬编码经典 HTTP schema

外层打包格式（`u32 size | RC4 ciphertext | 16-byte key`）可以复用，因此 actor 定制的 listeners 仍可采用相同的提取流程，同时完全改变解密后的字段布局。

一个较新的典型案例是 2026 年 3 月的 Tropic Trooper campaign，其中提取出的 Adaptix beacon 不包含标准 HTTP/TCP profile。相反，解密后的 blob 存储了 GitHub transport 参数，例如：<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host`（例如 `api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

实用的 parser 策略：
- 首先像往常一样准确检测外层 RC4 blob。
- 解密后，根据 sentinel strings 和字段合理性进行分支，而不是立即强制使用 HTTP parser。
- 合适的 sentinel 包括 `api.github.com`、`/issues?state=open`、HTTP verbs/URIs、named-pipe 风格的 strings，或明显有效的 server/port arrays。
- 如果 HTTP parser 失败，但 plaintext 包含连贯的长度前缀 UTF-8 strings，应保留该 sample 并尝试 alternative schemas，而不是将其作为 false positive 丢弃。

在该 campaign 中，custom listener 使用 GitHub issues 作为 C2 transport，而 beacon 查询 `ipinfo.io` 来获取其外部 IP，因为 GitHub API 不会直接向 operator 暴露 victim 的 source address。<sup>[[5]](#references)</sup>

## Network fingerprinting and hunting

HTTP：<sup>[[1]](#references)</sup>
- 常见情况：向 operator 选择的 URIs 发送 POST（例如 `/uri.php`、`/endpoint/api`）
- 用于 beacon ID 的 custom header parameter（例如 `X-Beacon-Id`、`X-App-Id`）
- User-agents 模仿 Firefox 20 或当前 Chrome builds
- 可通过 `sleep_delay`/`jitter_delay` 观察 polling cadence
- 较新的 builds 可以在 callbacks 之间轮换 URIs、user-agents、Host headers 和 servers，因此应根据不常见的 header names、response-size patterns、TLS reuse 和 timing 进行聚类，而不是假设只有单一的 path/UA pair。<sup>[[2]](#references)</sup>

SMB/TCP：<sup>[[1]](#references)</sup>
- 在 web egress 受限的 intranet C2 中使用 SMB named-pipe listeners
- TCP beacons 可能会在 traffic 前添加几个字节，以混淆 protocol start

当前 upstream teamserver defaults
- `profile.yaml` 当前附带 teamserver `0.0.0.0:4321`、endpoint `/endpoint`、certificate/key filenames `server.rsa.crt` 和 `server.rsa.key`，以及用于 HTTP、SMB、TCP、DNS、Beacon agent 和 Gopher 的 extenders。<sup>[[2]](#references)</sup>
- 对于不匹配的 routes，默认 error handler 返回 `Server: AdaptixC2` 和 `Adaptix-Version: v1.2`。<sup>[[4]](#references)</sup>
- 默认的 404 body 包含 `AdaptixC2 404` 和 `You need to enter the correct connection details`。<sup>[[4]](#references)</sup>
- 2026 年的 Internet-wide scans 发现许多暴露在 `4321` 上的 teamservers，以及许多位于 `43211` 上的 beacon listeners，因此这两个 ports 可作为有用的 seed pivots，但不应视为穷尽性的。<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints：<sup>[[4]](#references)</sup>
- 当前的 BeaconDNS extender 会权威应答（`AA=true`）
- 不符合 beacon protocol shape 的 queries——尤其是在 configured domain 之前少于 5 个 labels 的 names——通常会返回 `TXT "OK"`
- 如果 configured base TTL 保持为零，listener 会使用 10 秒 base，并添加最多 59 秒的 jitter
- 因此，在未暴露 HTTP listener 时，short-label active probes 很有用

## Loader and persistence TTPs seen in incidents

内存中的 PowerShell loaders：<sup>[[1]](#references)</sup>
- 下载 Base64/XOR payloads（Invoke-RestMethod / WebClient）。<sup>[[9]](#references)</sup>
- 分配 unmanaged memory，复制 shellcode，并通过 VirtualProtect 将 protection 切换为 0x40（PAGE_EXECUTE_READWRITE）。<sup>[[7]](#references)</sup>
- 通过 .NET dynamic invocation 执行：Marshal.GetDelegateForFunctionPointer + delegate.Invoke()。<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders：<sup>[[5]](#references)</sup>
- 2026 年的 Tropic Trooper chain 使用了一个 trojanized SumatraPDF executable（TOSHIS loader），将 `_security_init_cookie` 重定向到 malicious code，而不是 patching PE entry point
- 该 loader 通过 Adler-32 hashing 解析 APIs，下载 decoy PDF，获取 second-stage shellcode，通过 WinCrypt 使用 AES-128-CBC 解密（从 hardcoded seed 调用 `CryptDeriveKey`），并在内存中 reflectively 执行 Adaptix beacon
- Persistence 随后转移到 scheduled tasks，使用 `\MSDNSvc` 或 `\MicrosoftUDN` 等看似正常的 names，并配置为大约每两小时重新启动 agent

查看以下页面，了解内存执行和 AMSI/ETW 相关事项：

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

观察到的 persistence mechanisms：<sup>[[1]](#references)</sup>
- Startup folder shortcut（.lnk），用于在 logon 时重新启动 loader
- Registry Run keys（HKCU/HKLM ...\CurrentVersion\Run），通常使用如 `"Updater"` 等听起来正常的 names 来启动 loader.ps1。<sup>[[10]](#references)</sup>
- DLL search-order hijack：将 msimg32.dll 放置在 `%APPDATA%\Microsoft\Windows\Templates` 下，影响易受攻击的 processes

Technique deep-dives and checks：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell spawning RW→RX transitions：在 powershell.exe 内部通过 VirtualProtect 切换到 PAGE_EXECUTE_READWRITE。<sup>[[8]](#references)</sup>
- Dynamic invocation patterns（GetDelegateForFunctionPointer）
- 包含 `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404` 或 `You need to enter the correct connection details` 的 unmatched HTTPS 404s。<sup>[[4]](#references)</sup>
- 对可疑 domains 下的 short queries 返回 `AA=true` 和 `TXT "OK"` 的 DNS responses。<sup>[[4]](#references)</sup>
- GitHub API traffic 访问 `/repos/<owner>/<repo>/issues`，随后同一 loader/beacon chain 查询 `ipinfo.io`。<sup>[[5]](#references)</sup>
- 位于 user 或 common Startup folders 下的 Startup .lnk。<sup>[[1]](#references)</sup>
- 可疑的 Run keys（例如 `"Updater"`），以及 update.ps1/loader.ps1 等 loader names。<sup>[[1]](#references)</sup>
- 将 `_security_init_cookie` 重定向到 downloader code、然后显示 decoy document 的 trojanized PE samples。<sup>[[5]](#references)</sup>
- `%APPDATA%\Microsoft\Windows\Templates` 下 user-writable DLL paths 中包含 msimg32.dll。<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate：agent self-expires 之后的 timestamp。<sup>[[1]](#references)</sup>
- WorkingTime：agent 应保持 active、以便融入 business activity 的 hours。<sup>[[1]](#references)</sup>

这些 fields 可用于 clustering，并解释观察到的 quiet periods。

## YARA and static leads

Unit 42 发布了针对 beacons（C/C++ 和 Go）以及 loader API-hashing constants 的 basic YARA。<sup>[[1]](#references)</sup> 可以补充一些 rules，用于查找 PE `.rdata` 末尾附近的 `[size|ciphertext|16-byte-key]` layout、默认 HTTP profile strings，以及较新的 server/listener markers，例如 `AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open` 和 `ipinfo.io`。<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2：一个在真实攻击中被利用的新型开源框架（Unit 42）](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2：大规模 fingerprinting 一个开源 C2 Framework（Censys）](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper 转向 AdaptixC2 和 Custom Beacon Listener（Zscaler ThreatLabz）](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
