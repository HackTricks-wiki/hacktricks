# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**像 golden ticket 一样**, a diamond ticket 是一个可以用来 **以任意用户身份访问任意服务** 的 TGT。A golden ticket 完全离线伪造，使用该域的 krbtgt 哈希加密，然后注入到登录会话中使用。因为 域控制器 并不追踪它们合法颁发的 TGT，所以它们会接受任何用自身 krbtgt 哈希加密的 TGT。

有两种常见方法可以检测 golden tickets 的使用：

- 查找没有对应 AS-REQ 的 TGS-REQs。
- 查找具有荒谬值的 TGTs，例如 Mimikatz 默认的 10-year lifetime。

A **diamond ticket** 是通过 **修改由 DC 颁发的合法 TGT 的字段** 来制作的。实现方式是 **请求** 一个 **TGT**，用域的 krbtgt 哈希 **解密** 它，**修改** 票据中需要更改的字段，然后 **重新加密**。这克服了前面提到的两个 golden ticket 的缺点，因为：

- TGS-REQs 会有前置的 AS-REQ。
- TGT 是由 DC 颁发的，这意味着它会具有域的 Kerberos 策略中的所有正确细节。虽然这些在 golden ticket 中可以被精确伪造，但更复杂且容易出错。

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. 通过 AS-REQ 获取任一受控用户的 TGT（Rubeus `/tgtdeleg` 很方便，因为它在没有凭据的情况下强制客户端执行 Kerberos GSS-API 协商）。
2. 使用 krbtgt key 解密返回的 TGT，修补 PAC attributes（用户、组、登录信息、SIDs、设备声明等）。
3. 用相同的 krbtgt key 重新加密/签名票据并将其注入到当前登录会话中（`kerberos::ptt`, `Rubeus.exe ptt`...）。
4. 可选地，通过提供有效的 TGT blob 加上目标服务 key 来在 service ticket 上重复此过程，以在网络上传输时保持隐蔽。

### Updated Rubeus tradecraft (2024+)

近期 Huntress 的工作现代化了 Rubeus 中的 `diamond` action，将之前仅用于 golden/silver tickets 的 `/ldap` 和 `/opsec` 改进移植过来。`/ldap` 现在直接从 AD 自动填充准确的 PAC attributes（user profile、logon hours、sidHistory、domain policies），而 `/opsec` 通过执行两步的 pre-auth 序列并强制使用 AES-only crypto，使 AS-REQ/AS-REP 流程与 Windows 客户端无法区分。这大幅减少了诸如空白设备 ID 或不现实的有效期窗口之类的明显指示器。
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap`（可选 `/ldapuser` & `/ldappassword`）查询 AD 和 SYSVOL 以镜像目标用户的 PAC 策略数据。
- `/opsec` 强制进行类似 Windows 的 AS-REQ 重试，清零噪声标志并坚持使用 AES256。
- `/tgtdeleg` 在仍返回可解密的 TGT 的同时，不接触受害者的 cleartext password 或 NTLM/AES key。

### 服务票证重铸

同样的 Rubeus 刷新增加了将 diamond technique 应用于 TGS blobs 的能力。通过向 `diamond` 提供一个来自 `asktgt`、`/tgtdeleg` 或先前伪造的 TGT 的 **base64-encoded TGT**、**service SPN** 和 **service AES key**，你可以在不接触 KDC 的情况下铸造逼真的服务票证——实际上是一种更隐蔽的 silver ticket。
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow is ideal when you already control a service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) and want to cut a one-off TGS that perfectly matches AD policy, timelines, and PAC data without issuing any new AS/TGS traffic.

### OPSEC 与检测注意事项

- 传统的 hunter 启发式（TGS without AS，十年级别的有效期）仍然适用于 golden tickets，但 diamond tickets 主要在 **PAC 内容或组映射看起来不可能** 时显现。填写每个 PAC 字段（logon hours, user profile paths, device IDs），以免自动化比对立即标记伪造。
- **不要超额订阅 groups/RIDs**。如果只需要 `512`（Domain Admins）和 `519`（Enterprise Admins），就做到这一步，并确保目标账户在 AD 的其他位置合理地属于这些组。过多的 `ExtraSids` 会暴露端倪。
- Splunk 的 Security Content 项目提供关于 diamond tickets 的 attack-range 遥测数据，以及诸如 *Windows Domain Admin Impersonation Indicator* 之类的检测，该检测关联异常的 Event ID 4768/4769/4624 序列与 PAC 组变更。重放该数据集（或使用上面的命令生成自己的数据）有助于验证 SOC 对 T1558.001 的覆盖，同时为你提供具体的告警逻辑以便规避。

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
