# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**和 golden ticket 一样**，diamond ticket 是一种可用于**以任意用户身份访问任意服务**的 TGT。golden ticket 完全离线伪造，使用该域的 krbtgt hash 加密，然后传入 logon session 使用。由于域控制器不会跟踪自己合法签发过的 TGT，因此会接受使用其自身 krbtgt hash 加密的 TGT。<sup>[[1]](#references)</sup>

检测 golden ticket 使用情况通常有两种方法：

- 查找没有对应 AS-REQ 的 TGS-REQ。
- 查找具有异常值的 TGT，例如 Mimikatz 默认的 10 年有效期。

**diamond ticket** 的生成方式是**修改由 DC 签发的合法 TGT 的字段**。具体过程是**请求**一个 **TGT**，使用域的 krbtgt hash **解密**该 TGT，**修改**所需的 ticket 字段，然后**重新加密**。这**克服了 golden ticket 的上述两个缺点**，因为：<sup>[[1]](#references)</sup>

- TGS-REQ 前面会有对应的 AS-REQ。
- TGT 由 DC 签发，因此会包含域 Kerberos policy 中的所有正确细节。虽然这些细节也可以在 golden ticket 中准确伪造，但过程更复杂，也更容易出错。

### Requirements & workflow

- **Cryptographic material**：krbtgt AES256 key（首选）或 NTLM hash，用于解密并重新签名 TGT。
- **Legitimate TGT blob**：通过 `/tgtdeleg`、`asktgt`、`s4u` 获取，或从内存中导出 tickets。
- **Context data**：目标用户 RID、组 RID/SID，以及（可选）通过 LDAP 获取的 PAC attributes。
- **Service keys**：（仅当计划重新生成 service tickets 时需要）待 impersonate 的 service SPN 的 AES key。

1. 通过 AS-REQ 为任意受控用户获取 TGT（Rubeus 的 `/tgtdeleg` 很方便，因为它会强制客户端在没有 credentials 的情况下执行 Kerberos GSS-API dance）。
2. 使用 krbtgt key 解密返回的 TGT，修改 PAC attributes（用户、组、logon info、SID、device claims 等）。
3. 使用相同的 krbtgt key 重新加密并签名 ticket，然后将其注入当前 logon session（`kerberos::ptt`、`Rubeus.exe ptt` 等）。
4. 可选：提供有效的 TGT blob 和目标 service key，对 service ticket 重复此过程，以保持 wire 上的 stealth。

### Updated Rubeus tradecraft (2024+)

Huntress 的近期研究通过移植此前仅存在于 golden/silver tickets 中的 `/ldap` 和 `/opsec` 改进，更新了 Rubeus 内部的 `diamond` action。现在，`/ldap` 会通过查询 LDAP 获取真实的 PAC context，并挂载 SYSVOL 以提取 account/group attributes 以及 Kerberos/password policy（例如 `GptTmpl.inf`）；`/opsec` 则通过执行两步 preauth exchange，并强制使用仅 AES 和符合实际的 KDCOptions，使 AS-REQ/AS-REP flow 与 Windows 保持一致。这会显著减少明显的 indicators，例如缺失的 PAC fields 或与 policy 不匹配的 lifetimes。<sup>[[3]](#references)</sup>
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
- `/ldap`（可选 `/ldapuser` 和 `/ldappassword`）查询 AD 和 SYSVOL，以镜像目标用户的 PAC policy data。
- `/opsec` 强制执行类似 Windows 的 AS-REQ retry，将嘈杂的 flags 置零，并固定使用 AES256。
- `/tgtdeleg` 让你无需接触受害者的明文密码或 NTLM/AES key，同时仍能返回一个可解密的 TGT。

### Service-ticket 重新生成

同一次 Rubeus refresh 还新增了将 diamond technique 应用于 TGS blobs 的能力。向 `diamond` 提供一个**经过 base64 编码的 TGT**（来自 `asktgt`、`/tgtdeleg` 或之前 forged 的 TGT）、**service SPN** 和 **service AES key**，即可在不接触 KDC 的情况下生成逼真的 service tickets——本质上是一种更隐蔽的 silver ticket。<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
当你已经控制了一个 service account key（例如通过 `lsadump::lsa /inject` 或 `secretsdump.py` dump 得到），并且希望生成一个一次性的 TGS，使其完全符合 AD policy、时间线和 PAC 数据，同时不产生任何新的 AS/TGS 流量时，此 workflow 非常理想。<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

一种有时称为 **sapphire ticket** 的较新变体，将 Diamond 的“real TGT”基础与 **S4U2self+U2U** 结合起来，以窃取特权 PAC 并将其放入自己的 TGT。你不是伪造额外的 SIDs，而是为高权限用户请求一个 U2U S4U2self ticket，其中 `sname` 指向低权限 requester；KRB_TGS_REQ 会在 `additional-tickets` 中携带 requester 的 TGT，并设置 `ENC-TKT-IN-SKEY`，从而可以使用该用户的 key 解密 service ticket。随后提取特权 PAC，并在使用 krbtgt key 重新签名之前，将其拼接到合法的 TGT 中。<sup>[[2]](#references)[[5]](#references)</sup>

Impacket 的 `ticketer.py` 现在通过 `-impersonate` + `-request`（live KDC exchange）提供 sapphire 支持：<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` 接受用户名或 SID；`-request` 需要有效的实时用户凭据以及用于解密/修补 tickets 的 krbtgt 密钥材料（AES/NTLM）。

使用此变体时的关键 OPSEC 特征：<sup>[[5]](#references)</sup>

- TGS-REQ 将携带 `ENC-TKT-IN-SKEY` 和 `additional-tickets`（受害者 TGT）——这在正常流量中很少见。
- `sname` 通常等于请求用户（自助式访问），Event ID 4769 会显示调用方和目标为相同的 SPN/用户。
- 预计会出现成对的 4768/4769 记录，客户端计算机相同，但 CNAMES 不同（低权限请求者与特权 PAC 所有者）。

### OPSEC 与检测说明

- 传统 hunter 启发式规则（没有 AS 的 TGS、长达十年的有效期）仍适用于 golden tickets，但 diamond tickets 主要会在 **PAC 内容或组映射看起来不可能** 时暴露。填充 PAC 的每个字段（登录时间、用户配置文件路径、设备 ID），避免自动化比较立即标记伪造内容。<sup>[[3]](#references)</sup>
- **不要过度添加组/RID**。如果只需要 `512`（Domain Admins）和 `519`（Enterprise Admins），就到此为止，并确保目标账户在 AD 的其他位置看起来确实属于这些组。过多的 `ExtraSids` 会暴露异常。
- Sapphire 风格的交换会留下 U2U 指纹：`ENC-TKT-IN-SKEY` + `additional-tickets`，以及在 4769 中指向某个用户（通常是请求者）的 `sname`，随后还有一个来源于伪造 ticket 的 4624 登录。应关联这些字段，而不只是寻找缺少 no-AS-REQ 的情况。<sup>[[5]](#references)</sup>
- Microsoft 已开始逐步淘汰 **RC4 service ticket issuance**，原因是 CVE-2026-20833；在 KDC 上强制使用仅 AES 的 etypes 既能强化域安全，也与 diamond/sapphire tooling 保持一致（/opsec 已强制使用 AES）。在伪造 PAC 中混入 RC4 将越来越容易暴露。<sup>[[6]](#references)</sup>
- Splunk 的 Security Content 项目提供 diamond tickets 的 attack-range telemetry，以及 *Windows Domain Admin Impersonation Indicator* 等 detections；这些内容会关联异常的 Event ID 4768/4769/4624 序列和 PAC 组变更。重放该数据集（或使用上面的 commands 自行生成数据）有助于验证 SOC 对 T1558.001 的覆盖范围，同时也会为你提供可用于规避的具体 alert 逻辑。<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
