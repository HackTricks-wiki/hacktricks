# BloodHound とその他の Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: このページでは、Active Directory の関係を **enumerate** および **visualise** するための、特に有用なユーティリティをいくつかまとめています。ステルス性の高い **Active Directory Web Services (ADWS)** チャネル経由での収集については、上記のリファレンスを確認してください。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) は、以下を可能にする高度な **AD viewer & editor** です。

* GUI によるディレクトリツリーの閲覧
* オブジェクト属性および security descriptors の編集
* offline analysis 用の snapshot の作成および比較

### Quick usage

1. ツールを起動し、任意の domain credentials で `dc01.corp.local` に接続します。
2. `File ➜ Create Snapshot` から offline snapshot を作成します。
3. `File ➜ Compare` で 2 つの snapshot を比較し、permission drift を確認します。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) は、domain から大量の artefacts (ACLs、GPOs、trusts、CA templates …) を抽出し、**Excel report** を生成します。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound（グラフ可視化）

[BloodHound](https://github.com/SpecterOps/BloodHound) はグラフ理論を使用して、オンプレミスの AD、Entra ID、および OpenGraph を通じて取り込んだ追加の攻撃サーフェスデータ内に存在する、隠れた権限関係を明らかにします。

### Deployment（Docker CE）
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collector

* `SharpHound.exe` / `Invoke-BloodHound` – native または PowerShell variant
* `RustHound-CE` – Linux、macOS、Windows 向けの cross-platform CE collector
* `NetExec --bloodhound` – Linux から LDAP 駆動で素早く collection
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection（上部の link を参照）

> BloodHound CE `v8+` では、OpenGraph の導入に伴い collector の output format が変更されました。legacy BloodHound または古い CE install から upgrade した後は、data を import する前に、現在の collector で discovery を再実行してください。

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
コレクターはJSONを生成し、それをBloodHound GUIで取り込みます。

#### 非ドメイン参加WindowsホストからのSharpHound

オペレーターVMが対象ドメインに参加していない場合は、DNSをDCに向け、**network-only** shellを起動し、DC上の`SYSVOL`/`NETLOGON`を参照できることを確認してから、リモートドメインに対して収集します：
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
これは、domain-joined にすべきでない使い捨ての jump box やオペレーター用ワークステーションに便利です。

#### Linux/macOS からの cross-platform collection
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` は、Windows 以外のホストから CE-compatible output が必要な場合に適したデフォルトです。`NetExec` は、LDAP validation や spraying にすでに使用していて、すばやく graph import したい場合に便利です。AD 以外のデータセットでは、BloodHound OpenGraph を [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) などの collector で拡張できます。

### ADPathFinder（OpenGraph の path prioritisation）

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) は、graph が大きすぎて手動で pivot するのが難しい場合に、BloodHound CE/OpenGraph 上で動作します。1 つの principal が 1 つの target に到達できるかだけを確認するのではなく、多数の low-privileged users や computers から high-value objects への shortest paths を計算し、同じ edges を再利用する paths をグループ化して、最初に remediation すべき共有 choke point を明らかにします。
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
`MSSQLHound` と `ConfigManBearPig` の data をインポートすると、複数の lead を個別に残すのではなく、1つの finding で [AD CS](ad-certificates.md)、[MSSQL AD abuse](abusing-ad-mssql.md)、[SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) を横断できます。共有パスの例:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- 各エッジで **effective security context** を追跡する。通常のユーザーから開始した場合でも、ある遷移が privileged domain identity として実行されると、そのパスは domain-critical になる。
- Grouped findings は **choke-point remediation** に最適である。1つの SQL impersonation permission、linked-server trust、certificate-template abuse path、または SCCM assignment を削除するだけで、多数の shortest paths を一度に無効化できる。
- 「medium」の findings は **graph context** で再優先順位付けする。SMB signing の無効化、WebClient exposure、delegation の誤設定、または NTLM-relayable SQL servers は、侵害されたノードから Domain Admins、Domain Controllers、CAs、または SCCM site servers への onward paths が存在する場合、より高い優先度に値する。
- `NTDS.dit` の出力と hashcat potfile もある場合、`--pwd` は cracked passwords と BloodHound properties を相関させる。そのため、通常の password reuse と、privileged、Kerberoastable、AS-REP roastable、または path-relevant accounts 上の cracked creds を迅速に区別できる。

### Privilege & logon-right collection

Windows の **token privileges**（例: `SeBackupPrivilege`、`SeDebugPrivilege`、`SeImpersonatePrivilege`、`SeAssignPrimaryTokenPrivilege`）は DACL checks を bypass できる。そのため、これらをドメイン全体で mapping すると、ACL-only graphs では見落とされる local LPE edges を明らかにできる。**Logon rights**（`SeInteractiveLogonRight`、`SeRemoteInteractiveLogonRight`、`SeNetworkLogonRight`、`SeServiceLogonRight`、`SeBatchLogonRight` および対応する `SeDeny*`）は token が存在する前に LSA によって enforcement され、deny が優先される。そのため、lateral movement（RDP/SMB/scheduled task/service logon）を実質的に制限する。

**可能な場合は collectors を elevated で実行する**。UAC は interactive admins に対して（`NtFilterToken` 経由で）filtered token を作成し、sensitive privileges を削除して admin SIDs を deny-only としてマークする。non-elevated shell から privileges を enumerate すると、高価値な privileges が見えず、BloodHound はその edges を ingest できない。

現在、相補的な SharpHound collection strategies が2つ存在する。

- **GPO/SYSVOL parsing（stealthy、low-privilege）:**
1. LDAP（`(objectCategory=groupPolicyContainer)`）経由で GPOs を enumerate し、それぞれの `gPCFileSysPath` を読み取る。
2. SYSVOL から `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` を取得し、privilege/logon-right names を SIDs に mapping する `[Privilege Rights]` section を parse する。
3. OUs/sites/domains の `gPLink` によって GPO links を resolve し、linked containers 内の computers を列挙して、それらの rights を対象マシンに attribute する。
4. 利点: normal user で動作し、quiet である。欠点: GPO 経由で push された rights しか見えない（local tweaks は見落とされる）。

- **LSA RPC enumeration（noisy、accurate）:**
- target に対する local admin を持つ context から Local Security Policy を開き、各 privilege/logon right について `LsaEnumerateAccountsWithUserRight` を call し、RPC 経由で assigned principals を enumerate する。
- 利点: locally または GPO 外で設定された rights を取得できる。欠点: noisy network traffic が発生し、すべての host で admin requirement がある。

**これらの edges によって明らかになる abuse path の例:** `CanRDP` ➜ ユーザーが `SeBackupPrivilege` も持つ host ➜ filtered tokens を避けるため elevated shell を開始 ➜ backup semantics を使用して、restrictive DACLs にもかかわらず `SAM` および `SYSTEM` hives を読み取る ➜ exfiltrate して `secretsdump.py` を offline で実行し、lateral movement/privilege escalation 用の local Administrator NT hash を recovery する。

### BloodHound で Kerberoasting の優先順位を付ける

graph context を使用して、roasting の対象を絞り込む。

1. ADWS-compatible collector で一度だけ collect し、offline で作業する。
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP を import し、compromised principal を owned として mark する。組み込み query（*Kerberoastable Users*、*Shortest Paths to Domain Admins*）を実行して、admin/infra rights を持つ SPN accounts を見つける。
3. blast radius に基づいて SPNs の優先順位を付ける。cracking の前に `pwdLastSet`、`lastLogon`、および allowed encryption types を確認する。
4. 選択した tickets のみを request し、offline で crack してから、新しい access で BloodHound に再 query する。
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) は **Group Policy Objects** を enumerate し、misconfigurations を強調表示する。
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

- [OpenGraph を搭載した BloodHound Community Edition v8 がリリース: Active Directory と Entra ID を超えた Identity Attack Paths](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [ACL を超えて: BloodHound を使用した Windows Privilege Escalation Paths のマッピング](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: BloodHound CE における OpenGraph Attack Path Mapping](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
