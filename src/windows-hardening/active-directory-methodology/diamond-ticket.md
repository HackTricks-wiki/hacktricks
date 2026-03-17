# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket 是一个 TGT，可用于 **以任何用户身份访问任何服务**。A golden ticket 完全离线伪造，用该域的 krbtgt hash 加密，然后注入登录会话使用。因为域控制器不会追踪它们合法签发的 TGT，所以它们会接受用自身 krbtgt hash 加密的 TGT。

有两种常见方法可以检测 golden tickets 的使用：

- 查找没有对应 AS-REQ 的 TGS-REQs。
- 查找具有荒谬值的 TGTs，例如 Mimikatz 的默认 10 年有效期。

A **diamond ticket** 是通过 **修改由 DC 签发的合法 TGT 的字段** 制作的。实现方式是 **请求** 一个 **TGT**、用域的 krbtgt hash **解密** 它、**修改** 票证的目标字段，然后 **重新加密**。这解决了 golden ticket 提到的两个缺点，因为：

- TGS-REQs 会有先前的 AS-REQ。
- 该 TGT 由 DC 签发，因此会包含域 Kerberos 策略的所有正确细节。虽然在 golden ticket 中也可以精确伪造这些，但更复杂且容易出错。

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Updated Rubeus tradecraft (2024+)

最近 Huntress 对 Rubeus 中的 `diamond` action 进行了现代化改造，将之前仅在 golden/silver tickets 中存在的 `/ldap` 和 `/opsec` 改进移植过来。`/ldap` 现在通过查询 LDAP 并挂载 SYSVOL 来提取真实的 PAC 上下文、账户/组属性以及 Kerberos/密码策略（例如 `GptTmpl.inf`），而 `/opsec` 通过执行两步 preauth 交换并强制使用 AES-only 和现实的 KDCOptions，使 AS-REQ/AS-REP 流程匹配 Windows。这大大减少了明显的指示器，例如缺失的 PAC 字段或与策略不匹配的生存期。
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
- `/ldap`（可选 `/ldapuser` 与 `/ldappassword`）查询 AD 和 SYSVOL，以镜像目标用户的 PAC 策略数据。
- `/opsec` 强制执行类似 Windows 的 AS-REQ 重试，清零噪声标志并坚持使用 AES256。
- `/tgtdeleg` 在不接触受害者明文密码或 NTLM/AES 密钥的情况下，仍返回可解密的 TGT。

### 服务票据重铸

同一次 Rubeus 更新增加了将 diamond 技术应用到 TGS blobs 的能力。通过向 `diamond` 提供一个 **base64-encoded TGT**（来自 `asktgt`、`/tgtdeleg` 或先前伪造的 TGT）、**service SPN**，和 **service AES key**，你可以在不接触 KDC 的情况下铸造出真实感很强的服务票据——实际上是一种更隐蔽的 silver ticket。
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow is ideal when you already control a service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) and want to cut a one-off TGS that perfectly matches AD policy, timelines, and PAC data without issuing any new AS/TGS traffic.

### Sapphire-style PAC swaps (2025)

一种新变体，有时称为 **sapphire ticket**，将 Diamond 的 "real TGT" 基础与 **S4U2self+U2U** 结合，用于窃取一个特权 PAC 并将其放入你自己的 TGT。你不再伪造额外的 SIDs，而是为一个高权限用户请求一个面向 U2U 的 S4U2self 票证，其中 `sname` 指向低权限的请求者；KRB_TGS_REQ 在 `additional-tickets` 中携带请求者的 TGT 并设置 `ENC-TKT-IN-SKEY`，这使得该服务票证可以用该用户的密钥解密。然后你提取该特权 PAC 并将其拼接到你合法的 TGT 中，最后使用 krbtgt key 重新签名。

Impacket's `ticketer.py` now ships sapphire support via `-impersonate` + `-request` (live KDC exchange):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` 接受用户名或 SID；`-request` 需要有效用户凭据以及 krbtgt 密钥材料（AES/NTLM）来解密/修补票证。

Key OPSEC tells when using this variant:

- TGS-REQ 会携带 `ENC-TKT-IN-SKEY` 和 `additional-tickets`（受害者 TGT）——在正常流量中很少见。
- `sname` 通常等于请求用户（自助访问），并且 Event ID 4769 显示调用者和目标为相同的 SPN/用户。
- 预计会出现配对的 4768/4769 条目，来自相同的客户端计算机但不同的 CNAME（低权限请求者 vs. 特权 PAC 所有者）。

### OPSEC & detection notes

- 传统的检测启发式（TGS 无 AS、十年级别的有效期）仍适用于 golden tickets，但 diamond tickets 主要在 **PAC 内容或组映射看起来不可能** 时显现。填充每个 PAC 字段（logon hours、user profile paths、device IDs），以免自动化比对立即标记伪造。
- **不要超量分配 groups/RIDs**。如果你只需要 `512` (Domain Admins) 和 `519` (Enterprise Admins)，就止步于此，并确保目标账户在 AD 的其他位置合理地属于这些组。过多的 `ExtraSids` 会暴露行迹。
- Sapphire-style swaps 会留下 U2U 指纹：`ENC-TKT-IN-SKEY` + `additional-tickets`，加上在 4769 中指向某个用户（通常是请求者）的 `sname`，以及随后源自伪造票证的 4624 登录。关联这些字段，而不要仅仅寻找 no-AS-REQ 的缺口。
- Microsoft 已开始逐步淘汰 **RC4 service ticket issuance**，这是由于 CVE-2026-20833；在 KDC 上强制仅允许 AES etypes 一方面强化了域安全，另一方面也与 diamond/sapphire 工具链保持一致（/opsec 已经强制 AES）。在伪造的 PAC 中混入 RC4 将越来越显眼。
- Splunk 的 Security Content 项目分发了针对 diamond tickets 的 attack-range 遥测以及诸如 *Windows Domain Admin Impersonation Indicator* 的检测，该检测会关联异常的 Event ID 4768/4769/4624 序列和 PAC 组更改。回放该数据集（或使用上面的命令自行生成）有助于验证 SOC 对 T1558.001 的覆盖，同时为你提供具体的告警逻辑以便规避。

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
