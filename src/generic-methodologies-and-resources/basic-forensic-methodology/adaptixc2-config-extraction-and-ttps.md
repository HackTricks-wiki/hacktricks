# AdaptixC2 配置提取和 TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 是一个模块化、开源的 post‑exploitation/C2 框架，具有 Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) 和 BOF 支持。本页记录：
- 如何嵌入其 RC4‑packed 配置以及如何从 beacons 中提取它
- HTTP/SMB/TCP listeners 的网络/配置 指示器
- 在野外观察到的常见 loader 和 persistence TTPs，及指向相关 Windows 技术页面的链接

## Beacon profiles and fields

AdaptixC2 支持三种主要的 beacon 类型：
- BEACON_HTTP: web C2，具有可配置的 servers/ports/SSL、method、URI、headers、user‑agent 和自定义 parameter 名称
- BEACON_SMB: named‑pipe peer‑to‑peer C2（intranet）
- BEACON_TCP: direct sockets，可选地在前面添加 prepended marker 以混淆协议起始

在 HTTP beacon 配置中观察到的典型配置字段（解密后）：
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (长度前缀字符串)
- ans_pre_size (u32), ans_size (u32) – 用于解析响应大小
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Example default HTTP profile (from a beacon build):
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
观察到的恶意 HTTP 配置文件（真实攻击）：
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

当 operator 在 builder 中点击 Create 时，AdaptixC2 会将加密的配置作为尾部 blob 嵌入到 beacon 中。格式如下：
- 4 bytes: 配置大小 (uint32, little‑endian)
- N bytes: RC4 加密的配置数据
- 16 bytes: RC4 密钥

beacon loader 会从尾部复制 16‑byte 密钥，并就地用 RC4 对 N‑byte 块解密：
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Practical implications:
- 整个结构通常位于 PE .rdata 节内。
- 提取是确定性的：读取 size，读取该大小的 ciphertext，读取紧接其后的 16‑byte key，然后用 RC4 解密。

## 配置提取工作流程（防御者）

编写一个模仿 beacon 逻辑的提取器：
1) 在 PE 内定位 blob（通常在 .rdata）。一种务实的方法是扫描 .rdata，寻找可能的 [size|ciphertext|16‑byte key] 布局并尝试用 RC4。
2) 读取前 4 字节 → size (uint32 LE)。
3) 读取接下来的 N=size 字节 → ciphertext。
4) 读取最后 16 字节 → RC4 key。
5) 使用 RC4 解密 ciphertext。然后将解密后的配置解析为：
- u32/布尔标量，如上所述
- 长度前缀字符串（u32 长度后跟字节；可能存在结尾的 NUL）
- 数组：servers_count，后跟相应数量的 [string, u32 port] 对

适用于预提取 blob 的最小 Python 概念验证（独立运行，无外部依赖）：
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
提示:
- 在自动化时，使用 PE parser 读取 .rdata，然后应用滑动窗口：for each offset o, try size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt 并检查字符串字段能否解码为 UTF‑8 且长度合理。
- 按照相同的长度前缀约定解析 SMB/TCP profiles。

## 网络指纹与狩猎

HTTP
- 常见：POST 到操作员选择的 URIs（例如 /uri.php、/endpoint/api）
- 使用自定义头参数作为 beacon ID（例如 X‑Beacon‑Id、X‑App‑Id）
- User‑agent 模仿 Firefox 20 或同期的 Chrome 构建
- 轮询节奏可通过 sleep_delay/jitter_delay 观察到

SMB/TCP
- 在 web 出站受限的内网 C2 中使用 SMB 命名管道监听器
- TCP beacons 可能在流量前加上几字节以混淆协议起始

## 事件中观察到的 Loader 和 持久化 TTPs

内存中 PowerShell loaders
- 下载 Base64/XOR payloads（Invoke‑RestMethod / WebClient）
- 分配非托管内存，复制 shellcode，通过 VirtualProtect 将保护切换为 0x40 (PAGE_EXECUTE_READWRITE)
- 通过 .NET 动态调用执行：Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

有关内存执行与 AMSI/ETW 考量，请查看这些页面：

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

观察到的持久化机制
- Startup 文件夹快捷方式 (.lnk) 用于在登录时重新启动 loader
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run)，通常使用像 "Updater" 这样的听起来无害的名称来启动 loader.ps1
- 通过将 msimg32.dll 放在 %APPDATA%\Microsoft\Windows\Templates 下对易受影响进程实施 DLL 搜索顺序劫持

技术深度解析与检查：

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

狩猎思路
- PowerShell 触发的 RW→RX 转换：在 powershell.exe 内调用 VirtualProtect 设置为 PAGE_EXECUTE_READWRITE
- 动态调用模式 (GetDelegateForFunctionPointer)
- 用户或公共 Startup 文件夹下的 Startup .lnk
- 可疑的 Run 键（例如 "Updater"），以及像 update.ps1/loader.ps1 的 loader 名称
- 位于 %APPDATA%\Microsoft\Windows\Templates 且用户可写的 DLL 路径中包含 msimg32.dll

## 关于 OpSec 字段的说明

- KillDate：代理在此时间戳之后自我过期
- WorkingTime：代理应在此时间段内活跃，以便与业务活动混入

这些字段可用于聚类分析并解释观察到的静默期。

## YARA 与 静态线索

Unit 42 发布了针对 beacons (C/C++ and Go) 和 loader API‑hashing 常量的基础 YARA 规则。可以考虑补充规则，查找靠近 PE .rdata 末尾的 [size|ciphertext|16‑byte‑key] 布局以及默认 HTTP profile 字符串。

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
