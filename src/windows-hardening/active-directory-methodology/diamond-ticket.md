# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**与 golden ticket 类似**，diamond ticket 是一种 TGT，可用于**以任意用户身份访问任意服务**。Golden ticket 完全离线伪造，使用该域的 krbtgt 哈希加密，然后传入登录会话以供使用。由于域控制器不会跟踪其（或其他域控制器）合法签发过的 TGT，因此会欣然接受使用其自身 krbtgt 哈希加密的 TGT。<sup>[[1]](#references)</sup>

有两种常见技术可用于检测 golden ticket 的使用：

- 查找没有对应 AS-REQ 的 TGS-REQ。
- 查找具有异常值的 TGT，例如 Mimikatz 默认的 10 年有效期。

**Diamond ticket** 是通过**修改 DC 签发的合法 TGT 中的字段**制作的。具体做法是**请求**一个 **TGT**，使用域的 krbtgt 哈希**解密**该 TGT，**修改**票据中所需的字段，然后将其**重新加密**。这**克服了 golden ticket 的上述两个缺点**，原因如下：<sup>[[1]](#references)</sup>

- TGS-REQ 前面会有一个 AS-REQ。
- TGT 由 DC 签发，因此会包含符合域 Kerberos 策略的所有正确细节。虽然也可以在 golden ticket 中准确伪造这些信息，但过程更复杂，也更容易出错。

### 要求与工作流程

- **加密材料**：krbtgt AES256 密钥（首选）或 NTLM 哈希，用于解密并重新签名 TGT。
- **合法 TGT blob**：通过 `/tgtdeleg`、`asktgt`、`s4u` 获取，或从内存中导出票据。
- **上下文数据**：目标用户 RID、组 RID/SID，以及（可选）通过 LDAP 获取的 PAC 属性。
- **服务密钥**（仅当计划重新生成服务票据时需要）：要冒充的服务 SPN 的 AES 密钥。

1. 通过 AS-REQ 为任意受控用户获取 TGT（Rubeus `/tgtdeleg` 很方便，因为它会强制客户端在没有凭据的情况下执行 Kerberos GSS-API 流程）。
2. 使用 krbtgt 密钥解密返回的 TGT，修补 PAC 属性（用户、组、登录信息、SID、设备声明等）。
3. 使用相同的 krbtgt 密钥重新加密/签名票据，并将其注入当前登录会话（`kerberos::ptt`、`Rubeus.exe ptt` 等）。
4. 可选：提供有效的 TGT blob 和目标服务密钥，对服务票据重复此过程，以在网络传输中保持隐蔽。

### 更新后的 Rubeus tradecraft（2024+）

Huntress 最近的工作通过将此前仅适用于 golden/silver ticket 的 `/ldap` 和 `/opsec` 改进移植到 Rubeus 的 `diamond` 操作中，使其得到升级。`/ldap` 现在会查询 LDAP **并**挂载 SYSVOL，以获取真实的 PAC 上下文，包括账户/组属性以及 Kerberos/密码策略（例如 `GptTmpl.inf`）；`/opsec` 则通过执行两步预身份验证交换，并强制使用仅 AES 加密和符合实际情况的 KDCOptions，使 AS-REQ/AS-REP 流程与 Windows 一致。这大幅减少了 PAC 字段缺失或有效期与策略不符等明显指标。<sup>[[3]](#references)</sup>

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

- `/ldap`（可选使用 `/ldapuser` 和 `/ldappassword`）会查询 AD 和 SYSVOL，以镜像目标用户的 PAC 策略数据。
- `/opsec` 会强制进行类似 Windows 的 AS-REQ 重试，清除易引起注意的标志，并固定使用 AES256。
- `/tgtdeleg` 无需接触受害者的明文密码或 NTLM/AES 密钥，同时仍会返回可解密的 TGT。

### Service-ticket recutting

同一版 Rubeus 更新还增加了将 diamond 技术应用于 TGS 数据块的能力。向 `diamond` 提供一个**经过 base64 编码的 TGT**（来自 `asktgt`、`/tgtdeleg` 或先前伪造的 TGT）、**服务 SPN** 和 **服务 AES 密钥**，即可在不接触 KDC 的情况下铸造逼真的服务票据——相当于更隐蔽的 silver ticket。<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

当你已经控制了一个服务帐户密钥（例如，通过 `lsadump::lsa /inject` 或 `secretsdump.py` dump 出来），并希望制作一张一次性 TGS，使其完全符合 AD 策略、时间线和 PAC 数据，且不产生任何新的 AS/TGS 流量时，这个工作流非常理想。<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

一种有时称为 **sapphire ticket** 的新变体，将 Diamond 的“真实 TGT”作为基础，并结合 **S4U2self+U2U** 来窃取特权 PAC，再将其放入你自己的 TGT。你无需伪造额外的 SID，而是为高权限用户请求一张 U2U S4U2self ticket，并让 `sname` 指向低权限请求者；KRB_TGS_REQ 会在 `additional-tickets` 中携带请求者的 TGT，并设置 `ENC-TKT-IN-SKEY`，从而可以使用该用户的密钥解密服务票据。随后，你可以提取特权 PAC，将其拼接到合法的 TGT 中，再使用 krbtgt 密钥重新签名。<sup>[[2]](#references)[[5]](#references)</sup>

Impacket 的 `ticketer.py` 现在通过 `-impersonate` + `-request` 提供 sapphire 支持（与 KDC 实时交互）：<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` 接受用户名或 SID；`-request` 需要有效的用户凭据和 krbtgt 密钥材料（AES/NTLM），用于解密/修补票据。

使用此变体时的关键 OPSEC 痕迹：<sup>[[5]](#references)</sup>

- TGS-REQ 会携带 `ENC-TKT-IN-SKEY` 和 `additional-tickets`（受害者 TGT）——这在正常流量中很少见。
- `sname` 通常等于发起请求的用户（自助式访问），且 Event ID 4769 会显示调用方和目标是同一个 SPN/用户。
- 预计会出现成对的 4768/4769 条目，其中客户端计算机相同，但 CNAME 不同（低权限请求方与特权 PAC 所有者）。

### OPSEC 与检测说明

- 传统的 hunter 启发式规则（没有 AS 的 TGS、生命周期长达数十年的票据）仍适用于 golden ticket，但 diamond ticket 主要会在 **PAC 内容或组映射看起来不可能成立** 时暴露。填充每个 PAC 字段（登录时段、用户配置文件路径、设备 ID），避免自动比对立即标记伪造内容。<sup>[[3]](#references)</sup>
- **不要过度添加组/RID**。如果你只需要 `512`（Domain Admins）和 `519`（Enterprise Admins），就到此为止，并确保目标账户在 AD 的其他位置看起来确实属于这些组。过多的 `ExtraSids` 会露出破绽。
- Sapphire 式替换会留下 U2U 痕迹：`ENC-TKT-IN-SKEY` + `additional-tickets`，以及在 4769 中指向某个用户（通常是请求方）的 `sname`，之后还会出现一个源自伪造票据的 4624 登录。应关联这些字段，而不只是查找缺少 AS-REQ 的情况。<sup>[[5]](#references)</sup>
- Microsoft 已开始逐步淘汰 **RC4 服务票据签发**，原因是 CVE-2026-20833；在 KDC 上强制仅使用 AES etypes，既能强化域安全，也与 diamond/sapphire 工具的做法一致（/opsec 已强制使用 AES）。在伪造的 PAC 中混入 RC4 会越来越显眼。<sup>[[6]](#references)</sup>
- Splunk 的 Security Content 项目提供 diamond ticket 的 attack-range 遥测数据及相关检测规则，例如 *Windows Domain Admin Impersonation Indicator*；该规则会关联异常的 Event ID 4768/4769/4624 序列和 PAC 组变更。重放该数据集（或使用上述命令自行生成数据）有助于验证 SOC 对 T1558.001 的覆盖情况，同时也能为你提供可用于规避的具体告警逻辑。<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – 珍贵宝石：新一代 Kerberos 攻击（2022）](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket：我们热衷于玩转票据（2023）](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – 重新解读 Kerberos Diamond Ticket（2025）](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket 攻击数据与检测规则（2023）](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – 宝石的阴暗面：Diamond 与 Sapphire Ticket（2025）](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – CVE-2026-20833 的 RC4 服务票据强制实施](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
