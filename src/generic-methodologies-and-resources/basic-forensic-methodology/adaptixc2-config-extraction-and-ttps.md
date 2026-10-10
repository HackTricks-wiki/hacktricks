# AdaptixC2 配置提取与 TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 是一个模块化的开源 post-exploitation/C2 framework，支持 Windows x86/x64 beacon（EXE/DLL/service EXE/raw shellcode）和 BOF。<sup>[[1]](#references)</sup> 本页介绍：
- 如何嵌入 RC4 打包的配置，以及如何从 beacon 中提取配置
- HTTP/SMB/TCP listener 的网络/profile 指标
- 在野外观察到的常见 loader 和 persistence TTPs，并附上相关 Windows 技术页面的链接

近期上游版本还提供 DNS/DoH beacon listener，以及独立的 Gopher agent/listener 系列，因此，即使特定样本仍使用经典 beacon agent，现代 Adaptix 基础设施也可能暴露出原始 HTTP/SMB/TCP 以外的网络接口。<sup>[[2]](#references)</sup>

## Beacon 配置与字段

AdaptixC2 支持三种主要 beacon 类型：<sup>[[1]](#references)</sup>
- BEACON_HTTP：Web C2，可配置服务器/端口/SSL、方法、URI、headers、user-agent 和自定义参数名称
- BEACON_SMB：命名管道 peer-to-peer C2（内网）
- BEACON_TCP：直接使用 sockets，可选择添加前置标记以混淆协议起始位置

这些是早期 Adaptix 分析中公开记录的 beacon 布局，至今仍是从样本侧提取配置时最常见的起点。<sup>[[1]](#references)</sup> 不过，当前上游版本也在服务器端提供 `BeaconDNS` 和 Gopher 扩展，因此不要假设所有运行中的 Adaptix 部署都只暴露 HTTP/SMB/TCP 基础设施。<sup>[[2]](#references)</sup>

HTTP beacon 配置中常见的字段（解密后）：<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (string 数组), ports (u32 数组)
- http_method, uri, parameter, user_agent, http_headers（带长度前缀的字符串）
- ans_pre_size (u32), ans_size (u32) – 用于解析响应大小
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

近期的 BeaconHTTP 构建版本还支持操作员选择在多个 URI、user-agent、Host header 和服务器之间轮换，并可按顺序或随机选择。<sup>[[2]](#references)</sup> 从威胁狩猎的角度来看，这意味着单台受感染主机可能会通过多条回连路径和多种 header 组合进行通信，同时仍属于经典 RC4 打包的 beacon 系列。

默认 HTTP profile 示例（来自 beacon 构建版本）：<sup>[[1]](#references)</sup>

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

观察到的恶意 HTTP 配置文件（真实攻击）：<sup>[[1]](#references)</sup>

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

## 加密配置的打包与加载路径

操作员在 builder 中点击 Create 时，AdaptixC2 会将加密后的 profile 作为尾部 blob 嵌入 beacon。格式如下：<sup>[[1]](#references)</sup>
- 4 字节：配置大小（uint32，小端序）
- N 字节：RC4 加密的配置数据
- 16 字节：RC4 密钥

beacon loader 从末尾复制 16 字节密钥，并对 N 字节数据块进行原地 RC4 解密：<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

实际影响：<sup>[[1]](#references)</sup>
- 整个结构通常位于 PE 的 .rdata 节中。
- 提取过程具有确定性：读取 size，读取对应长度的 ciphertext，然后读取紧随其后的 16 字节 key，最后使用 RC4 解密。

## 配置提取工作流（防御者）

编写一个模拟 beacon 逻辑的提取器：<sup>[[1]](#references)</sup>
1) 在 PE 中定位该 blob（通常位于 .rdata 节）。一种实用的方法是在 .rdata 中扫描可能的 [size|ciphertext|16-byte key] 布局，并尝试使用 RC4 解密。
2) 读取前 4 个字节 → size（uint32 LE）。
3) 读取接下来的 N=size 个字节 → ciphertext。
4) 读取最后 16 个字节 → RC4 key。
5) 使用 RC4 解密 ciphertext。然后按以下方式解析明文 profile：
   - 如上所述的 u32/boolean 标量
   - 长度前缀字符串（u32 length 后跟字节；末尾可能带 NUL）
   - 数组：servers_count 后跟相应数量的 [string, u32 port] 对

适用于预先提取的 blob 的最简 Python 概念验证（独立运行，无外部依赖）：

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
- 自动化时，使用 PE parser 读取 .rdata，然后应用滑动窗口：对每个偏移 o，尝试 size = u32(.rdata[o:o+4])，ct = .rdata[o+4:o+4+size]，候选 key = 后续 16 个字节；使用 RC4 解密，并检查字符串字段是否能解码为 UTF-8、长度是否合理。
- 按照相同的长度前缀惯例解析 SMB/TCP profiles。

## 自定义 listener profiles：不要只硬编码经典 HTTP schema

外层打包格式（`u32 size | RC4 ciphertext | 16-byte key`）可以重复使用，因此 actor 定制的 listeners 可以沿用相同的提取流程，同时完全改变解密后的字段布局。

一个很好的近期案例是 2026 年 3 月的 Tropic Trooper campaign：提取出的 Adaptix beacon 不包含标准 HTTP/TCP profile。相反，解密后的 blob 存储了 GitHub transport 参数，例如：<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host`（例如 `api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

实用的 parser 策略：
- 首先像往常一样检测外层 RC4 blob。
- 解密后，根据 sentinel strings 和字段合理性进行分支判断，而不是立即强行套用 HTTP parser。
- 有用的 sentinel 包括 `api.github.com`、`/issues?state=open`、HTTP verbs/URIs、类似 named pipe 的 strings，或明显有效的 server/port arrays。
- 如果 HTTP parser 失败，但明文包含连贯的、带长度前缀的 UTF-8 strings，应保留该样本并尝试其他 schema，而不是将其作为误报丢弃。

在该 campaign 中，自定义 listener 使用 GitHub issues 作为 C2 transport，而 beacon 会查询 `ipinfo.io` 来获取其外部 IP，因为 GitHub API 不会直接向 operator 揭示受害者的源地址。<sup>[[5]](#references)</sup>

## 网络指纹识别与 hunting

HTTP：<sup>[[1]](#references)</sup>
- 常见情况：向 operator 选择的 URIs 发送 POST（例如 /uri.php、/endpoint/api）
- 用于 beacon ID 的自定义 header 参数（例如 X‑Beacon‑Id、X‑App‑Id）
- 模仿 Firefox 20 或当代 Chrome builds 的 user-agents
- 通过 sleep_delay/jitter_delay 可以观察到轮询间隔
- 较新的 builds 可以在 callbacks 之间轮换 URIs、user-agents、Host headers 和 servers，因此应依据不常见的 header names、response-size patterns、TLS 复用和时序进行聚类，而不要假定只有一组 path/UA。<sup>[[2]](#references)</sup>

SMB/TCP：<sup>[[1]](#references)</sup>
- 在 web 出口受限时，使用 SMB named-pipe listeners 进行内网 C2
- TCP beacons 可能会在流量前添加几个字节，以混淆协议起始位置

当前 upstream teamserver defaults
- `profile.yaml` 当前提供的默认配置为 teamserver `0.0.0.0:4321`、endpoint `/endpoint`、证书/密钥文件名 `server.rsa.crt` 和 `server.rsa.key`，以及 HTTP、SMB、TCP、DNS、Beacon agent 和 Gopher 的 extenders。<sup>[[2]](#references)</sup>
- 对于不匹配的 routes，默认 error handler 会返回 `Server: AdaptixC2` 和 `Adaptix-Version: v1.2`。<sup>[[4]](#references)</sup>
- 默认的 404 body 包含 `AdaptixC2 404` 和 `You need to enter the correct connection details`。<sup>[[4]](#references)</sup>
- 2026 年的全网扫描发现，许多暴露的 teamservers 使用 `4321` 端口，许多 beacon listeners 使用 `43211` 端口，因此这两个端口可用于初步排查，但不应视为全面覆盖。<sup>[[4]](#references)</sup>

DNS/DoH listener 指纹：<sup>[[4]](#references)</sup>
- 当前 BeaconDNS extender 会进行权威应答（`AA=true`）
- 与 beacon protocol 格式不匹配的查询——尤其是配置域名前少于 5 个 labels 的名称——通常会收到 `TXT "OK"` 应答
- 如果配置的 base TTL 保持为零，listener 会使用 10 秒的 base，并额外增加最多 59 秒的 jitter
- 因此，在没有暴露 HTTP listener 时，可以使用短 label 进行主动探测

## 事件中发现的 Loader 和 Persistence TTPs

内存中的 PowerShell loaders：<sup>[[1]](#references)</sup>
- 下载 Base64/XOR payloads（Invoke‑RestMethod / WebClient）。<sup>[[9]](#references)</sup>
- 分配非托管内存、复制 shellcode，并通过 VirtualProtect 将保护属性切换为 0x40（PAGE_EXECUTE_READWRITE）。<sup>[[7]](#references)</sup>
- 通过 .NET dynamic invocation 执行：Marshal.GetDelegateForFunctionPointer + delegate.Invoke()。<sup>[[6]](#references)</sup>

木马化的签名软件 / 分阶段 shellcode loaders：<sup>[[5]](#references)</sup>
- 2026 年的一条 Tropic Trooper attack chain 使用了木马化的 SumatraPDF executable（TOSHIS loader），将 `_security_init_cookie` 重定向到恶意代码，而不是修补 PE entry point
- 该 loader 通过 Adler-32 hashing 解析 APIs，下载诱饵 PDF，获取第二阶段 shellcode，通过 WinCrypt（使用硬编码 seed 调用 `CryptDeriveKey`）以 AES-128-CBC 解密，并在内存中反射执行 Adaptix beacon
- 后续通过计划任务实现 persistence，任务名称看似无害，例如 `\MSDNSvc` 或 `\MicrosoftUDN`，并配置为大约每两小时重新启动 agent

请参阅以下页面，了解内存执行和 AMSI/ETW 相关事项：

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

观察到的 Persistence mechanisms：<sup>[[1]](#references)</sup>
- Startup folder shortcut（.lnk），用于在用户登录时重新启动 loader
- Registry Run keys（HKCU/HKLM ...\CurrentVersion\Run），通常使用类似 "Updater" 的无害名称来启动 loader.ps1。<sup>[[10]](#references)</sup>
- DLL search-order hijack：在 %APPDATA%\Microsoft\Windows\Templates 下放置 msimg32.dll，影响易受攻击的进程

技术深入分析与检查：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting 思路
- PowerShell 触发 RW→RX 转换：powershell.exe 内部的 VirtualProtect 调用 PAGE_EXECUTE_READWRITE。<sup>[[8]](#references)</sup>
- Dynamic invocation patterns（GetDelegateForFunctionPointer）
- 不匹配的 HTTPS 404 响应中包含 `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404` 或 `You need to enter the correct connection details`。<sup>[[4]](#references)</sup>
- 可疑域名下的短查询收到包含 `AA=true` 和 `TXT "OK"` 的 DNS responses。<sup>[[4]](#references)</sup>
- GitHub API 流量访问 `/repos/<owner>/<repo>/issues`，随后同一 loader/beacon chain 查询 `ipinfo.io`。<sup>[[5]](#references)</sup>
- 用户或公共 Startup folders 下的 Startup .lnk。<sup>[[1]](#references)</sup>
- 可疑的 Run keys（例如 "Updater"），以及 update.ps1/loader.ps1 等 loader 名称。<sup>[[1]](#references)</sup>
- 木马化 PE samples 在显示诱饵文档前，将 `_security_init_cookie` 重定向到 downloader code。<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates 下用户可写的 DLL 路径中出现 msimg32.dll。<sup>[[1]](#references)</sup>

## OpSec fields 说明

- KillDate：agent 自行失效的时间戳。<sup>[[1]](#references)</sup>
- WorkingTime：agent 应保持活跃的时段，以便与日常业务活动融为一体。<sup>[[1]](#references)</sup>

这些字段可用于聚类，并解释观察到的静默时段。

## YARA 和静态分析线索

Unit 42 发布了针对 beacons（C/C++ 和 Go）及 loader API-hashing constants 的基础 YARA 规则。<sup>[[1]](#references)</sup> 可考虑补充规则，检测 PE .rdata 末尾附近的 [size|ciphertext|16-byte-key] 布局、默认 HTTP profile strings，以及较新的 server/listener markers，例如 `AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open` 和 `ipinfo.io`。<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2：一种用于真实攻击的新型开源框架（Unit 42）](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework 文档](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2：大规模指纹识别开源 C2 框架（Censys）](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper 转向 AdaptixC2 和自定义 Beacon Listener（Zscaler ThreatLabz）](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft 文档](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [内存保护常量 – Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
