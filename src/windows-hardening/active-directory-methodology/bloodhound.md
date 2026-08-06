# BloodHound とその他の Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: このページでは、Active Directory の関係を **enumerate** および **visualise** するための、特に便利なユーティリティをいくつか紹介します。ステルス性の高い **Active Directory Web Services (ADWS)** チャネル経由での収集については、上記のリファレンスを確認してください。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) は、以下を可能にする高度な **AD viewer & editor** です。

* GUI によるディレクトリツリーの閲覧
* オブジェクト属性および security descriptors の編集
* offline analysis 用の snapshot の作成および比較

### Quick usage

1. ツールを起動し、任意のドメイン資格情報を使用して `dc01.corp.local` に接続します。
2. `File ➜ Create Snapshot` から offline snapshot を作成します。
3. `File ➜ Compare` で 2 つの snapshot を比較し、permission drifts を特定します。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) は、ドメインから大量の artefacts (ACLs、GPOs、trusts、CA templates …) を抽出し、**Excel report** を生成します。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound（グラフ可視化）

[BloodHound](https://github.com/SpecterOps/BloodHound) は、グラフ理論を使用して、オンプレミスの AD、Entra ID、および OpenGraph を通じて取り込んだ追加の攻撃対象領域データ内に存在する、隠れた権限関係を明らかにします。<sup>[[1]](#references)</sup>

### Deployment（Docker CE）
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### コレクター

* `SharpHound.exe` / `Invoke-BloodHound` – native または PowerShell variant
* `RustHound-CE` – Linux、macOS、Windows 対応の cross-platform CE collector
* `NetExec --bloodhound` – Linux から LDAP-driven collection を素早く実行
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection（上部の link を参照）

> BloodHound CE `v8+` では、OpenGraph の導入に伴い collector の output format が変更されました。legacy BloodHound または古い CE インストールから upgrade した後は、data を import する前に current collectors で discovery を再実行してください。<sup>[[1]](#references)</sup>

#### SharpHound の一般的な mode
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
CollectorsはJSONを生成し、それがBloodHound GUI経由で取り込まれます。

#### ドメインに参加していないWindowsホストからのSharpHound

operator VMが対象ドメインに参加していない場合は、DNSをDCに向け、**network-only**シェルを開始し、DC上の`SYSVOL`/`NETLOGON`を参照できることを確認してから、リモートドメインに対してcollectします。
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
これは、ドメインに参加させるべきでない使い捨てのジャンプボックスやオペレーター用ワークステーションに役立ちます。

#### Linux/macOSからのクロスプラットフォーム収集
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` は、Windows 以外の host から CE-compatible な出力が必要な場合のデフォルトとして適しています。<sup>[[2]](#references)</sup> `NetExec` は、LDAP validation や spraying にすでに使用していて、すばやく graph import したい場合に便利です。非-AD datasets では、BloodHound OpenGraph を [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) などの collectors で拡張できます。<sup>[[1]](#references)</sup>

### ADPathFinder（OpenGraph の path prioritisation）

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) は、graph が大きすぎて手動で pivot できない場合に、BloodHound CE/OpenGraph の上位で動作します。ある principal が 1 つの target に到達できるかだけを確認するのではなく、複数の low-privileged users や computers から high-value objects への shortest paths を計算し、同じ edges を再利用する paths をグループ化して、最初に remediation すべき共有 choke point を明らかにします。<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
`MSSQLHound` と `ConfigManBearPig` のデータをインポートすると、1つの finding で [AD CS](ad-certificates.md)、[MSSQL AD abuse](abusing-ad-mssql.md)、[SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) を横断でき、それぞれを別々の手掛かりとして扱わずに済みます。<sup>[[4]](#references)</sup> 共有パスの例:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- すべてのエッジで**実効セキュリティコンテキスト**を追跡します。あるパスは、通常ユーザーから開始された場合でも、いずれかの遷移が特権ドメイン identity として実行された時点でドメインにとってクリティカルになります。
- グループ化された findings は、**choke-point remediation** に最適です。1つの SQL impersonation permission、linked-server trust、certificate-template abuse path、または SCCM assignment を削除するだけで、多数の shortest paths を一度に崩壊させられます。
- 「medium」の findings は**グラフコンテキスト**で再優先順位付けします。SMB signing の無効化、WebClient exposure、delegation のミス、または NTLM-relayable SQL servers は、compromised node から Domain Admins、Domain Controllers、CAs、または SCCM site servers への onward paths がある場合、より高い優先度に値します。
- `NTDS.dit` の出力と hashcat potfile もある場合、`--pwd` は cracked passwords を BloodHound properties と相関付けます。これにより、通常の password reuse と、privileged、Kerberoastable、AS-REP roastable、または path-relevant accounts 上で cracked された creds を素早く区別できます。

### Privilege & logon-right collection

Windows の**token privileges**（例: `SeBackupPrivilege`、`SeDebugPrivilege`、`SeImpersonatePrivilege`、`SeAssignPrimaryTokenPrivilege`）は DACL checks を bypass できるため、ドメイン全体でこれらをマッピングすると、ACL-only graphs が見落とす local LPE edges を明らかにできます。**Logon rights**（`SeInteractiveLogonRight`、`SeRemoteInteractiveLogonRight`、`SeNetworkLogonRight`、`SeServiceLogonRight`、`SeBatchLogonRight` と、それらに対応する `SeDeny*`）は token が存在する前に LSA によって適用され、deny が優先されます。そのため、これらは lateral movement（RDP/SMB/scheduled task/service logon）を実質的に制御します。<sup>[[3]](#references)</sup>

可能な場合は**collectors を elevated で実行**します。UAC は interactive admins に対して（`NtFilterToken` 経由で）filtered token を作成し、sensitive privileges を削除するとともに、admin SIDs を deny-only としてマークします。non-elevated shell から privileges を列挙すると、高価値な privileges が見えず、BloodHound はその edges を ingest できません。<sup>[[3]](#references)</sup>

現在、相補的な SharpHound collection strategies が2つ存在します。<sup>[[3]](#references)</sup>

- **GPO/SYSVOL parsing（stealthy、low-privilege）：**
1. LDAP（`(objectCategory=groupPolicyContainer)`）経由で GPOs を列挙し、それぞれの `gPCFileSysPath` を読み取ります。
2. SYSVOL から `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` を取得し、privilege/logon-right names を SIDs にマッピングする `[Privilege Rights]` section を parse します。
3. OUs/sites/domains 上の `gPLink` を介して GPO links を解決し、linked containers 内の computers を一覧化して、それらの rights を対象マシンに帰属させます。
4. 利点: normal user で動作し、静かです。欠点: GPO 経由で push された rights しか確認できません（local tweaks は見落とされます）。

- **LSA RPC enumeration（noisy、accurate）：**
- target の local admin を持つ context から Local Security Policy を開き、各 privilege/logon right に対して `LsaEnumerateAccountsWithUserRight` を呼び出し、RPC 経由で割り当てられた principals を列挙します。
- 利点: local または GPO 外で設定された rights を取得できます。欠点: noisy な network traffic が発生し、すべての host で admin が必要です。

**これらの edges によって明らかになる abuse path の例:** `CanRDP` ➜ user が `SeBackupPrivilege` も持つ host ➜ filtered tokens を回避するため elevated shell を開始 ➜ backup semantics を使用して、restrictive DACLs にもかかわらず `SAM` と `SYSTEM` hives を読み取る ➜ exfiltrate して `secretsdump.py` を offline で実行し、lateral movement/privilege escalation 用の local Administrator NT hash を復元します。<sup>[[3]](#references)</sup>

### BloodHound で Kerberoasting の優先順位を付ける

graph context を使用して、roasting を対象に絞ります。

1. ADWS-compatible collector で一度だけ collect し、offline で作業します。
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP を import し、compromised principal を owned として mark した後、built-in queries（*Kerberoastable Users*、*Shortest Paths to Domain Admins*）を実行して、admin/infra rights を持つ SPN accounts を明らかにします。
3. blast radius に基づいて SPNs の優先順位を付け、cracking の前に `pwdLastSet`、`lastLogon`、および許可されている encryption types を確認します。
4. 選択した tickets のみを request し、offline で crack した後、新しい access を使って BloodHound に再 query します。
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) は**Group Policy Objects**を列挙し、misconfigurations を強調表示します。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) は Active Directory の**健全性チェック**を実行し、リスクスコア付きの HTML レポートを生成します。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## 参考資料

- [1] [OpenGraph を搭載した BloodHound Community Edition v8 がリリース: Active Directory と Entra ID を超えた Identity Attack Paths](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [ACL を超えて: BloodHound による Windows Privilege Escalation Paths のマッピング](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: BloodHound CE における OpenGraph Attack Path Mapping](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
