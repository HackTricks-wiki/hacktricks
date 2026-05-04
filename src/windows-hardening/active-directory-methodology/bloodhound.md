# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: このページでは、Active Directory の関係性を**enumerate**して可視化するための最も便利なユーティリティをいくつかまとめています。 目立たない **Active Directory Web Services (ADWS)** チャネルでの収集については、上記のリファレンスを参照してください。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) は高度な **AD viewer & editor** で、以下を可能にします:

* ディレクトリツリーの GUI ブラウジング
* オブジェクト属性とセキュリティ記述子の編集
* オフライン分析のためのスナップショット作成 / 比較

### Quick usage

1. ツールを起動し、任意のドメイン認証情報で `dc01.corp.local` に接続します。
2. `File ➜ Create Snapshot` でオフラインスナップショットを作成します。
3. `File ➜ Compare` で 2 つのスナップショットを比較し、権限の変化を見つけます。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) は、ドメインから大量のアーティファクト (ACLs, GPOs, trusts, CA templates …) を抽出し、**Excel report** を生成します。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/SpecterOps/BloodHound) はグラフ理論を使って、オンプレ AD、Entra ID、そして OpenGraph 経由で取り込んだ追加の attack-surface データ内にある隠れた権限関係を明らかにします。

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – ネイティブまたは PowerShell 版
* `RustHound-CE` – Linux、macOS、Windows 向けのクロスプラットフォーム CE collector
* `NetExec --bloodhound` – Linux からの高速な LDAP ベースの収集
* `AzureHound` – Entra ID の列挙
* **SoaPy + BOFHound** – ADWS 収集（上部のリンクを参照）

> BloodHound CE `v8+` では、OpenGraph の導入により collector の出力形式が変更されました。旧 BloodHound または古い CE インストールからアップグレードした後は、データをインポートする前に現在の collectors で再度 discovery を実行してください。

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
コレクターは JSON を生成し、BloodHound GUI を通じて取り込まれます。

#### ドメイン参加していない Windows ホストからの SharpHound

オペレーター VM が対象ドメインに参加していない場合は、DNS を DC に向け、**network-only** シェルを起動し、DC 上の `SYSVOL`/`NETLOGON` が見えることを確認してから、リモートドメインに対して収集します:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
これは、domain-joined であるべきではない disposable jump box や operator workstation に有用です。

#### Linux/macOS からの cross-platform collection
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` は、Windows 以外のホストから CE 互換の出力が欲しいときの良いデフォルトです。`NetExec` は、すでに LDAP validation や spraying に使っていて、手早く graph import したい場合に便利です。AD 以外のデータセットでは、BloodHound OpenGraph は [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) のような collector で拡張できます。

### Privilege & logon-right collection

Windows の **token privileges**（例: `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`）は DACL チェックを bypass できるため、これらを domain-wide で mapping すると、ACL のみの graph では見えない local LPE edge が露出します。**Logon rights**（`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` とそれらの `SeDeny*` 対応）は、token が存在する前に LSA によって強制され、deny が優先されるため、lateral movement（RDP/SMB/scheduled task/service logon）を実質的に制限します。

可能なら **collector は昇格した状態で実行** してください。UAC は interactive admin に対して filtered token を作成し（`NtFilterToken` 経由）、sensitive privileges を削除し、admin SID を deny-only としてマークします。非昇格の shell から privileges を列挙すると、高価値な privilege は見えず、BloodHound も edge を ingest できません。

現在は、相補的な SharpHound collection 戦略が 2 つあります:

- **GPO/SYSVOL parsing（stealthy, low-privilege）:**
1. LDAP で GPO を列挙し（`(objectCategory=groupPolicyContainer)`）、各 `gPCFileSysPath` を読み取る。
2. SYSVOL から `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` を取得し、privilege/logon-right 名を SID に mapping する `[Privilege Rights]` セクションを解析する。
3. `gPLink` を使って OU/site/domain の GPO link を解決し、リンク先 container 内の computer を列挙して、その rights をそれらの machine に帰属させる。
4. 利点: 通常ユーザーで動作し、静か; 欠点: GPO 経由で push された rights しか見えない（local の変更は見逃す）。

- **LSA RPC enumeration（noisy, accurate）:**
- ターゲット上で local admin を持つ context から Local Security Policy を開き、各 privilege/logon right について `LsaEnumerateAccountsWithUserRight` を呼び出して、RPC 経由で割り当てられた principal を列挙する。
- 利点: local に設定された rights や GPO 外で設定された rights も取得できる; 欠点: network traffic が noisy で、各 host で admin 権限が必要。

**これらの edge から見つかる abuse path の例:** `CanRDP` ➜ あなたの user も `SeBackupPrivilege` を持つ host ➜ filtered token を避けるために elevated shell を起動 ➜ restrictive な DACL  باوجودでも backup semantics を使って `SAM` と `SYSTEM` hive を読み取る ➜ exfiltrate して `secretsdump.py` を offline で実行し、local Administrator の NT hash を recover して lateral movement/privilege escalation に使う。

### BloodHound で Kerberoasting を優先する

graph context を使って roasting を targeted に保ちます:

1. ADWS 互換の collector で 1 回収集し、offline で作業する:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP を import し、compromised principal を owned にマークして、built-in query（*Kerberoastable Users*, *Shortest Paths to Domain Admins*）を実行し、admin/infra 権限を持つ SPN account を surface する。
3. blast radius で SPN を優先順位付けし、cracking 前に `pwdLastSet`, `lastLogon`, および許可された encryption types を確認する。
4. 選択した ticket のみを request し、offline で crack してから、新しい access で BloodHound を再 query する:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) は **Group Policy Objects** を列挙し、misconfigurations を強調表示します。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) は Active Directory の **health-check** を実行し、risk scoring 付きの HTML レポートを生成します。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## References

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
