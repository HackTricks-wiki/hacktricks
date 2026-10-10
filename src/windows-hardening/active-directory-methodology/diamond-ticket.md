# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**与 golden ticket 类似**，diamond ticket 是一种 TGT，可用于**以任意用户身份访问任意服务**。golden ticket 完全离线伪造，使用该域的 krbtgt hash 加密，然后传入登录会话以供使用。由于域控制器不会跟踪其（或它们）合法签发的 TGT，因此会欣然接受使用其自身 krbtgt hash 加密的 TGT。<sup>[[1]](#references)</sup>

检测 golden ticket 使用情况有两种常见技术：

- 查找没有对应 AS-REQ 的 TGS-REQ。
- 查找包含异常值的 TGT，例如 Mimikatz 默认的 10 年有效期。

**Diamond ticket** 是通过**修改 DC 签发的合法 TGT 中的字段**来生成的。具体方法是**请求**一个 **TGT**，使用域的 krbtgt hash **解密**它，**修改**票据中所需的字段，然后**重新加密**。这**克服了 golden ticket 的上述两个缺点**，因为：<sup>[[1]](#references)</sup>

- TGS-REQ 前面会有一个 AS-REQ。
- TGT 由 DC 签发，因此包含的详细信息都符合域的 Kerberos 策略。虽然 golden ticket 也能准确伪造这些信息，但过程更复杂，也更容易出错。

### 要求与工作流

- **加密材料**：krbtgt AES256 key（首选）或 NTLM hash，用于解密并重新签名 TGT。
- **合法 TGT blob**：通过 `/tgtdeleg`、`asktgt`、`s4u` 获取，或从内存中导出票据。
- **上下文数据**：目标用户 RID、组 RID/SID，以及（可选）从 LDAP 获取的 PAC 属性。
- **服务密钥**（仅当计划重新生成服务票据时需要）：要冒充的服务 SPN 的 AES key。

1. 通过 AS-REQ 为任意受控用户获取 TGT（Rubeus `/tgtdeleg` 很方便，因为它会强制客户端在没有凭据的情况下执行 Kerberos GSS-API 交互）。
2. 使用 krbtgt key 解密返回的 TGT，并修补 PAC 属性（用户、组、登录信息、SID、设备声明等）。
3. 使用相同的 krbtgt key 重新加密/签名票据，并将其注入当前登录会话（`kerberos::ptt`、`Rubeus.exe ptt` 等）。
4. 可选：提供有效的 TGT blob 和目标服务密钥，对服务票据重复此过程，以降低网络上的可见性。

### Rubeus 最新 tradecraft（2024 年及以后）

Huntress 的近期研究通过将此前仅适用于 golden/silver ticket 的 `/ldap` 和 `/opsec` 改进移植到 Rubeus 的 `diamond` 操作中，使其更加完善。`/ldap` 现在会通过查询 LDAP **并挂载 SYSVOL** 来获取真实的 PAC 上下文，从而提取账户/组属性以及 Kerberos/密码策略（例如 `GptTmpl.inf`）；`/opsec` 则通过执行两步预身份验证交换，并强制使用仅 AES 加密和符合实际情况的 KDCOptions，使 AS-REQ/AS-REP 流程与 Windows 保持一致。这大幅减少了 PAC 字段缺失或有效期与策略不匹配等明显特征。<sup>[[3]](#references)</sup>

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap`（可选 `/ldapuser` 和 `/ldappassword`）会查询 AD 和 SYSVOL，以镜像目标用户的 PAC 策略数据。
- `/opsec` 会强制进行类似 Windows 的 AS-REQ 重试，清除容易引起注意的标志，并固定使用 AES256。
- `/tgtdeleg` 无需接触受害者的明文密码或 NTLM/AES 密钥，同时仍可返回可解密的 TGT。

### 服务票据重铸

同一版 Rubeus 更新还新增了将 diamond 技术应用于 TGS blob 的功能。向 `diamond` 提供一个**经过 base64 编码的 TGT**（来自 `asktgt`、`/tgtdeleg` 或先前伪造的 TGT）、**服务 SPN** 和 **服务 AES 密钥**，即可在不接触 KDC 的情况下生成逼真的服务票据——本质上是一种更隐蔽的 silver ticket。<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

当你已经控制了一个 service account key（例如通过 `lsadump::lsa /inject` 或 `secretsdump.py` 导出），并希望生成一张一次性的 TGS，使其完全符合 AD policy、时间线和 PAC 数据，而不产生任何新的 AS/TGS 流量时，此工作流非常理想。<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

一种有时称为 **sapphire ticket** 的较新变体，将 Diamond 的“真实 TGT”作为基础，并结合 **S4U2self+U2U** 来窃取高权限 PAC，再将其植入你自己的 TGT。它不会凭空添加额外的 SID，而是为一个高权限用户请求 U2U S4U2self ticket，并让 `sname` 指向低权限请求者；KRB_TGS_REQ 会在 `additional-tickets` 中携带请求者的 TGT，并设置 `ENC-TKT-IN-SKEY`，从而可以使用该用户的 key 解密 service ticket。随后，你提取高权限 PAC，将其拼接到合法的 TGT 中，再使用 krbtgt key 重新签名。<sup>[[2]](#references)[[5]](#references)</sup>

Impacket 的 `ticketer.py` 现在通过 `-impersonate` + `-request` 提供 sapphire 支持（实时 KDC 交换）：<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` 接受用户名或 SID；`-request` 需要有效的用户凭据以及 krbtgt 密钥材料（AES/NTLM），才能解密/修补票据。

使用此变体时需要注意的关键 OPSEC 特征：<sup>[[5]](#references)</sup>

- TGS-REQ 会携带 `ENC-TKT-IN-SKEY` 和 `additional-tickets`（受害者 TGT）——这在正常流量中很少见。
- `sname` 通常与请求用户相同（自助访问），而 Event ID 4769 会显示调用方和目标是相同的 SPN/用户。
- 预期会出现成对的 4768/4769 条目，客户端计算机相同，但 CNAMES 不同（低权限请求者 vs. 特权 PAC 所有者）。

### OPSEC 与检测说明

- 传统的 hunter 启发式规则（没有 AS 的 TGS、有效期长达数十年）仍适用于 golden tickets，但 diamond tickets 主要会在 **PAC 内容或组映射看起来不合理** 时暴露。填充 PAC 的所有字段（登录时段、用户配置文件路径、设备 ID），避免自动比对立即标记伪造内容。<sup>[[3]](#references)</sup>
- **不要过度添加组/RID**。如果只需要 `512`（Domain Admins）和 `519`（Enterprise Admins），就到此为止，并确保目标帐户在 AD 的其他位置确实可能属于这些组。过多的 `ExtraSids` 会露出破绽。
- Sapphire 风格的替换会留下 U2U 痕迹：`ENC-TKT-IN-SKEY` + `additional-tickets`，再加上 4769 中指向某个用户（通常是请求者）的 `sname`，以及后续一个来源于伪造票据的 4624 登录。应关联这些字段，而不是只检查是否缺少 AS-REQ。<sup>[[5]](#references)</sup>
- Microsoft 已开始逐步停止 **RC4 服务票据签发**，以应对 CVE-2026-20833；在 KDC 上强制使用仅 AES 的 etype 既能强化域安全，也与 diamond/sapphire 工具的做法保持一致（/opsec 已强制使用 AES）。在伪造 PAC 中混用 RC4 会越来越显眼。<sup>[[6]](#references)</sup>
- Splunk 的 Security Content 项目提供 diamond tickets 的 attack-range 遥测数据，以及 *Windows Domain Admin Impersonation Indicator* 等检测规则，这些规则会关联异常的 Event ID 4768/4769/4624 序列和 PAC 组变更。重放该数据集（或使用上述命令生成自己的数据）有助于验证 SOC 对 T1558.001 的覆盖情况，并为规避提供具体的告警逻辑。<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – 珍贵宝石：新一代 Kerberos 攻击（2022）](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket：我们热衷于玩转票据（2023）](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – 重新剖析 Kerberos Diamond Ticket（2025）](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket 攻击数据与检测规则（2023）](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – 宝石的阴暗面：Diamond & Sapphire Ticket（2025）](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – 针对 CVE-2026-20833 强制执行 RC4 服务票据策略](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
