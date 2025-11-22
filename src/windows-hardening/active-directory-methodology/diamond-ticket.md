# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket 是一个 TGT，可以用来 **以任意用户身份访问任何服务**。A golden ticket 是完全离线伪造的，用该域的 krbtgt hash 加密，然后注入到登录会话中使用。因为域控制器不会跟踪它（或它们）合法签发的 TGT，所以它们会接受任何用自身 krbtgt hash 加密的 TGT。

有两种常见技术可以检测 golden tickets 的使用：

- 查找没有对应 AS-REQ 的 TGS-REQs。
- 查找具有荒谬值的 TGT，例如 Mimikatz 的默认 10 年有效期。

一个 **diamond ticket** 是通过 **修改由 DC 签发的合法 TGT 的字段** 来制造的。实现方法是请求一个 TGT，用域的 krbtgt key 解密它，修改票据中需要变更的字段，然后重新加密。这样可以 **克服前面提到的两个 golden ticket 的缺点**，因为：

- TGS-REQs 会有先前的 AS-REQ。
- TGT 由 DC 签发，这意味着它会具有域 Kerberos 策略中的所有正确细节。尽管这些在 golden ticket 中也可以精确伪造，但更加复杂且容易出错。

### Requirements & workflow

- **Cryptographic material**: krbtgt AES256 key（首选）或 NTLM hash，用于解密和重新签名 TGT。
- **Legitimate TGT blob**: 通过 `/tgtdeleg`、`asktgt`、`s4u` 获取，或从内存导出票据。
- **Context data**: 目标用户 RID、组 RIDs/SIDs，以及（可选）从 LDAP 获得的 PAC attributes。
- **Service keys**（仅当计划重新生成 service tickets 时需要）: 要模拟的服务 SPN 的 AES key。

1. 通过 AS-REQ 获取任意受控用户的 TGT（Rubeus `/tgtdeleg` 很方便，因为它可以在不提供凭据的情况下强制客户端执行 Kerberos GSS-API 流程）。
2. 使用 krbtgt key 解密返回的 TGT，修补 PAC attributes（用户、组、登录信息、SIDs、设备声明等）。
3. 使用相同的 krbtgt key 重新加密/签名票据并将其注入当前登录会话（`kerberos::ptt`、`Rubeus.exe ptt` 等）。
4. 可选地，通过提供有效的 TGT blob 及目标服务 key 来对 service ticket 重复该过程，以在网络上保持隐蔽。

### Updated Rubeus tradecraft (2024+)

最近 Huntress 的工作将 Rubeus 内的 `diamond` action 现代化，移植了之前仅对 golden/silver tickets 存在的 `/ldap` 和 `/opsec` 改进。`/ldap` 现在会直接从 AD 自动填充准确的 PAC attributes（用户配置文件、登录时间、sidHistory、域策略），而 `/opsec` 则通过执行两步预认证序列并强制使用 AES-only crypto，使 AS-REQ/AS-REP 流程与 Windows 客户端无法区分。这大大减少了诸如空设备 ID 或不现实的有效期窗口等明显指征。
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) 查询 AD 和 SYSVOL 以镜像目标用户的 PAC 策略数据。
- `/opsec` 强制类似 Windows 的 AS-REQ 重试，清零噪声标志并坚持使用 AES256。
- `/tgtdeleg` 在仍返回可解密的 TGT 的同时，不接触受害者的明文密码或 NTLM/AES 密钥。

### Service-ticket recutting

同一次 Rubeus 刷新新增了将 diamond technique 应用于 TGS blobs 的能力。通过向 `diamond` 提供 **base64-encoded TGT**（来自 `asktgt`、`/tgtdeleg` 或先前伪造的 TGT）、**service SPN** 和 **service AES key**，你可以在不接触 KDC 的情况下铸造逼真的 service tickets——实际上是一种更隐蔽的 silver ticket。
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
当你已经掌控一个服务账户密钥（例如通过 `lsadump::lsa /inject` 或 `secretsdump.py` 导出）并且想要制作一个一次性的 TGS，在不发出任何新的 AS/TGS 流量的情况下完美匹配 AD（Active Directory）策略、时间线和 PAC 数据时，此工作流程最为理想。

### OPSEC 与 检测注意事项

- 传统的猎手启发式（TGS without AS、十年以上的有效期）仍然适用于 golden tickets，但 diamond tickets 主要在 **PAC 内容或组映射看起来不可能** 时暴露。对每个 PAC 字段（登录时段、用户配置文件路径、设备 ID）都进行填充，以免自动比较立即标记伪造票据。
- **不要给组/RIDs 过度订阅**。如果你只需要 `512` (Domain Admins) 和 `519` (Enterprise Admins)，就止步于此，并确保目标账户在 AD 的其他位置看起来合理地属于这些组。过多的 `ExtraSids` 会暴露破绽。
- Splunk 的 Security Content project 分发了关于 diamond tickets 的攻击范围遥测以及诸如 *Windows Domain Admin Impersonation Indicator* 之类的检测，该检测将异常的 Event ID 4768/4769/4624 序列与 PAC 组更改相关联。重放该数据集（或使用上面的命令生成自己的数据）有助于验证 SOC 对 T1558.001 的覆盖，同时为你提供可用于规避的具体告警逻辑。

## 参考资料

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
