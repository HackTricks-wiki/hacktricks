# AdaptixC2 配置提取与 TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 是一个模块化的开源 post-exploitation/C2 框架，支持 Windows x86/x64 beacon（EXE/DLL/service EXE/raw shellcode）和 BOF。<sup>[[1]](#references)</sup> 本页介绍：
- RC4 打包的配置如何嵌入，以及如何从 beacon 中提取
- HTTP/SMB/TCP listener 的网络和 profile 指标
- 在实际环境中观察到的常见 loader 和 persistence TTPs，并附有相关 Windows 技术页面的链接

近期的上游版本还提供 DNS/DoH beacon listener，以及独立的 Gopher agent/listener 系列。因此，即使某个样本仍使用经典 beacon agent，现代 Adaptix 基础设施也可能暴露出经典 HTTP/SMB/TCP 接口之外的内容。<sup>[[2]](#references)</sup>

## Beacon profiles 和字段

AdaptixC2 支持三种主要的 beacon 类型：<sup>[[1]](#references)</sup>
- BEACON_HTTP：Web C2，可配置服务器/端口/SSL、method、URI、headers、user-agent 和自定义参数名称
- BEACON_SMB：基于命名管道的点对点 C2（内网）
- BEACON_TCP：直接套接字连接，可选择添加前置标记以混淆协议起始位置

这些是早期 Adaptix 分析中公开记录的 beacon 布局，至今仍是从样本侧提取信息最常见的起点。<sup>[[1]](#references)</sup>不过，当前上游版本也在服务器端提供 `BeaconDNS` 和 Gopher 扩展，因此不要假设每个运行中的 Adaptix 部署都只暴露 HTTP/SMB/TCP 基础设施。<sup>[[2]](#references)</sup>

以下字段摘要和 JSON 样本描述的是 2025 年分析的 HTTP 格式；它们并非较新上游版本的解析器规范。这些样本解密后的典型字段包括：<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (字符串数组), ports (u32 数组)
- http_method, uri, parameter, user_agent, http_headers（带长度前缀的字符串）
- ans_pre_size (u32), ans_size (u32) – 用于解析响应大小
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

近期的 BeaconHTTP 构建版本还支持由操作员选择在多个 URI、user-agent、Host header 和服务器之间轮换，并可按顺序或随机选择。<sup>[[2]](#references)</sup>从威胁狩猎的角度看，这意味着单台受感染主机可以通过多种回连路径和 header 组合进行通信，同时仍属于经典 RC4 打包的 beacon 系列。

示例默认 HTTP profile（来自 beacon 构建版本）：<sup>[[1]](#references)</sup>

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

## 加密配置打包与加载路径

当操作员在 builder 中点击 Create 时，AdaptixC2 会将加密配置编译进 beacon。不要假设它位于 PE 或 shellcode 的末尾：通过扫描 section 或在样本中追踪 `getProfile()` 来定位配置字节。打包格式为：<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 字节：配置大小（uint32，小端）
- N 字节：RC4 加密的配置数据
- 16 字节：RC4 密钥

beacon loader 会从末尾复制 16 字节的密钥，并对 N 字节的数据块进行原地 RC4 解密：<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

实际影响：<sup>[[1]](#references)</sup>
- 整个结构通常位于 PE 的 .rdata 节中。
- 提取过程是确定性的：读取长度，读取该长度的密文，然后读取紧随其后的 16 字节密钥，再使用 RC4 解密。

## 配置提取工作流（防御者）

有关在提取 beacon 前进行常规样本分流，请参阅 [Malware Analysis](malware-analysis.md)。

编写一个模拟 beacon 逻辑的提取器：<sup>[[1]](#references)</sup>
1) 在 PE 中定位该数据块（通常位于 .rdata）。一种实用的方法是扫描 .rdata，寻找合理的 [size|ciphertext|16-byte key] 布局并尝试 RC4。
2) 读取前 4 字节 → 长度（uint32 LE）。
3) 读取接下来的 N=size 字节 → 密文。
4) 读取最后 16 字节 → RC4 密钥。
5) 使用 RC4 解密密文。然后按以下方式解析明文配置文件：
   - 如上所述的 u32/boolean 标量
   - 长度前缀字符串（u32 长度后跟字节；末尾可能有 NUL）
   - 数组：servers_count 后跟相应数量的 [string, u32 port] 对

适用于 2025 年字段顺序中预提取数据块的旧版 HTTP Python 概念验证代码（独立运行，无外部依赖）。近期 stock 构建请使用下方的 current-schema 解析器：<sup>[[1]](#references)[[11]](#references)</sup>

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

### 解析当前的 stock HTTP 和 DNS 配置

当前 upstream 会先打包六个 little-endian `u32` 值：agent watermark/type、kill date、working time、sleep、jitter 和 listener watermark/type。接下来是 HTTP 专属数据，以一个字节的 SSL 标志开头。与 legacy 示例不同，数据中包含带计数的 URI、user-agent 和 Host-header 列表，后面接着 rotation mode 和 proxy 设置。因此，在这些版本中，legacy parser 会从 kill-date 字段开始读取 SSL 标志，导致结果错误。此配置中的字符串长度和整数值使用 little-endian 编码；非空的打包字符串末尾带有 NUL。<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

使用上面的 `P` 和 `rc4` helper，将此 parser 用于解密后的 **stock HTTP** 明文。不要在公开报告中泄露 RC4 key：HTTP 配置可能包含 proxy 用户名和密码。<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>解析当前的 stock HTTP 明文配置</summary>

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

对于标准 DNS beacon，读取相同的六个常见 `u32` 字段，然后读取带长度前缀的 `domain`、`resolvers`、`doh_resolvers` 和 `qtype` 字符串。将 `pkt_size`、`label_size`、`ttl`、`burst_enabled`、`burst_sleep`、`burst_jitter` 和 `dns_mode` 读取为 `u32`，然后读取带长度前缀的 DoH user-agent 字符串。`dns_mode` 用于区分 UDP、DoH 以及两种回退方向。这是单独的布局：不要强行用 HTTP parser 解析 DNS 明文。<sup>[[12]](#references)[[13]](#references)</sup>

提示：
- 自动化时，使用 PE parser 读取 .rdata，然后应用滑动窗口：对每个偏移量 o，尝试 size = u32(.rdata[o:o+4])、ct = .rdata[o+4:o+4+size]，并将接下来的 16 个字节作为候选密钥；用 RC4 解密，并检查字符串字段能否解码为 UTF-8，且长度是否合理。
- 按照相同的长度前缀约定解析 SMB/TCP profiles。

## 自定义 listener profiles：不要只对经典 HTTP schema 进行硬编码

外层打包格式（`u32 size | RC4 ciphertext | 16-byte key`）可以复用，因此即使攻击者定制的 listeners 完全改变了解密后的字段布局，也仍可沿用相同的提取流程。

近期的一个典型例子是 2026 年 3 月的 Tropic Trooper campaign：提取出的 Adaptix beacon 不包含标准 HTTP/TCP profile。相反，解密后的 blob 存储了 GitHub transport 参数，例如：<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host`（例如 `api.github.com`）
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

实用的 parser 策略：
- 首先像往常一样检测外层 RC4 blob。
- 解密后，根据 sentinel strings 和字段合理性进行分支判断，而不是立刻强行套用 HTTP parser。
- 有用的 sentinel 包括 `api.github.com`、`/issues?state=open`、HTTP verbs/URIs、类似 named pipe 的字符串，或明显有效的 server/port 数组。
- 如果 HTTP parser 解析失败，但明文包含结构连贯、带长度前缀的 UTF-8 字符串，应保留样本并尝试其他 schema，而不是将其判定为误报并丢弃。

在该 campaign 中，自定义 listener 使用 GitHub issues 作为 C2 transport，而 beacon 查询 `ipinfo.io` 以获取其外部 IP，因为 GitHub API 不会直接向 operator 显示受害者的源地址。<sup>[[5]](#references)</sup>

## 网络指纹识别与狩猎

HTTP：<sup>[[1]](#references)</sup>
- 常见情况：向 operator 选定的 URI 发送 POST（例如 /uri.php、/endpoint/api）
- 使用自定义 header 参数作为 beacon ID（例如 X‑Beacon‑Id、X‑App‑Id）
- User-agent 模仿 Firefox 20 或当代 Chrome builds
- 可通过 sleep_delay/jitter_delay 观察轮询节奏
- 较新的 builds 可以在 callbacks 之间轮换 URI、user-agents、Host headers 和 servers，因此应根据少见的 header 名称、响应大小模式、TLS 复用情况和时间特征进行聚类，而不要假设路径/UA 组合是固定的。<sup>[[2]](#references)</sup>

SMB/TCP：<sup>[[1]](#references)</sup>
- 在 Web 出站流量受限的内网 C2 场景中使用 SMB named-pipe listeners
- TCP beacons 可能会在流量前添加几个字节，以混淆协议起始位置

当前上游 teamserver 默认值
- `profile.yaml` 当前包含 teamserver `0.0.0.0:4321`、endpoint `/endpoint`、证书/密钥文件名 `server.rsa.crt` 和 `server.rsa.key`，以及 HTTP、SMB、TCP、DNS、Beacon agent 和 Gopher 的 extenders。<sup>[[2]](#references)</sup>
- 对于未匹配的 routes，默认 error handler 会返回 `Server: AdaptixC2` 和 `Adaptix-Version: v1.2`。<sup>[[4]](#references)</sup>
- 标准 404 body 包含 `AdaptixC2 404` 和 `You need to enter the correct connection details`。<sup>[[4]](#references)</sup>
- 2026 年的全网扫描发现，许多暴露的 teamservers 使用端口 `4321`，许多 beacon listeners 使用端口 `43211`，因此这两个端口适合作为初始 pivot，但不应视为完整范围。<sup>[[4]](#references)</sup>

DNS/DoH listener 指纹：<sup>[[4]](#references)</sup>
- 当前 BeaconDNS extender 会进行权威应答（`AA=true`）
- 不符合 beacon 协议格式的查询——尤其是配置域名前的标签少于 5 个的名称——通常会收到 `TXT "OK"` 应答
- 如果配置的基础 TTL 保持为零，listener 会使用 10 秒的基础值，并增加最多 59 秒的 jitter
- 因此，在没有暴露 HTTP listener 时，短标签主动探测很有用

## 事件中发现的 Loader 和持久化 TTPs

内存中的 PowerShell loaders：<sup>[[1]](#references)</sup>
- 下载 Base64/XOR payloads（Invoke‑RestMethod / WebClient）。<sup>[[9]](#references)</sup>
- 分配非托管内存、复制 shellcode，并通过 VirtualProtect 将保护属性切换为 0x40（PAGE_EXECUTE_READWRITE）。<sup>[[7]](#references)</sup>
- 通过 .NET dynamic invocation 执行：Marshal.GetDelegateForFunctionPointer + delegate.Invoke()。<sup>[[6]](#references)</sup>

木马化的签名软件 / 分阶段 shellcode loaders：<sup>[[5]](#references)</sup>
- 2026 年的 Tropic Trooper 攻击链使用了木马化的 SumatraPDF executable（TOSHIS loader），将 `_security_init_cookie` 重定向到恶意代码，而不是修补 PE entry point
- Loader 通过 Adler-32 hashing 解析 APIs，下载诱饵 PDF，获取第二阶段 shellcode，通过 WinCrypt 使用 AES-128-CBC 解密（从硬编码 seed 调用 `CryptDeriveKey`），并在内存中以反射方式执行 Adaptix beacon
- 后续通过计划任务实现持久化，使用 `\MSDNSvc` 或 `\MicrosoftUDN` 等看似良性的名称，并配置为大约每两小时重新启动 agent

查看这些页面，了解内存中执行以及 AMSI/ETW 相关注意事项：

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

观察到的持久化机制：<sup>[[1]](#references)</sup>
- Startup folder 中的快捷方式（.lnk），用于在用户登录时重新启动 loader
- Registry Run keys（HKCU/HKLM ...\CurrentVersion\Run），通常使用 "Updater" 等看似良性的名称来启动 loader.ps1。<sup>[[10]](#references)</sup>
- DLL search-order hijack：在易受影响的进程的 %APPDATA%\Microsoft\Windows\Templates 下放置 msimg32.dll

技术深入分析与检查：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

狩猎思路
- PowerShell 进程产生 RW→RX 转换：powershell.exe 内的 VirtualProtect 调用将内存设为 PAGE_EXECUTE_READWRITE。<sup>[[8]](#references)</sup>
- Dynamic invocation 模式（GetDelegateForFunctionPointer）
- 未匹配的 HTTPS 404 响应中出现 `Server: AdaptixC2`、`Adaptix-Version`、`AdaptixC2 404` 或 `You need to enter the correct connection details`。<sup>[[4]](#references)</sup>
- 可疑域名下的短查询收到带有 `AA=true` 和 `TXT "OK"` 的 DNS 响应。<sup>[[4]](#references)</sup>
- GitHub API 流量访问 `/repos/<owner>/<repo>/issues`，随后同一 loader/beacon 攻击链查询 `ipinfo.io`。<sup>[[5]](#references)</sup>
- 用户或公共 Startup folders 下的启动 .lnk。<sup>[[1]](#references)</sup>
- 可疑的 Run keys（例如 "Updater"），以及 update.ps1/loader.ps1 等 loader 名称。<sup>[[1]](#references)</sup>
- 木马化的 PE 样本在显示诱饵文档前，将 `_security_init_cookie` 重定向到 downloader 代码。<sup>[[5]](#references)</sup>
- 用户可写的 %APPDATA%\Microsoft\Windows\Templates 下存在包含 msimg32.dll 的 DLL 路径。<sup>[[1]](#references)</sup>

## 关于 OpSec 字段的说明

- KillDate：agent 自行失效的时间戳。<sup>[[1]](#references)</sup>
- WorkingTime：agent 应保持活动、以融入业务活动的时段。<sup>[[1]](#references)</sup>

这些字段可用于聚类，并帮助解释观察到的静默时段。

## YARA 与静态线索

Unit 42 发布了针对 beacons（C/C++ 和 Go）以及 loader API-hashing 常量的基础 YARA 规则。<sup>[[1]](#references)</sup> 可考虑补充检测规则，检查 PE .rdata 末尾附近的 [size|ciphertext|16-byte-key] 布局、默认 HTTP profile 字符串，以及较新的 server/listener 标记，例如 `AdaptixC2 404`、`You need to enter the correct connection details.`、`Adaptix-Version`、`server.rsa.crt`、`server.rsa.key`、`api.github.com`、`/issues?state=open` 和 `ipinfo.io`。<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2：一种在真实攻击中被利用的新型开源框架（Unit 42）](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework 文档](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2：大规模识别开源 C2 框架指纹（Censys）](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper 转向 AdaptixC2 和自定义 Beacon Listener（Zscaler ThreatLabz）](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft 文档](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [内存保护常量 – Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2 profile 生成（pl_main.go）](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2 beacon profile parser（AgentConfig.cpp）](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2 DNS profile 生成（pl_utils.go）](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2 profile 打包（pl_packer.go）](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
