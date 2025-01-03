# MySQL File priv to SSRF/RCE

{{#include ../../../banners/hacktricks-training.md}}

**This is a summary of the MySQL/MariaDB/Percona techniques from [https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/](https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/)**.

### Server-Side Request Forgery (SSRF) via SQL Functions

In the exploration of SQL Out of Band data exfiltration, the `LOAD_FILE()` function is commonly employed to initiate network requests. This function, however, is constrained by the operating system it operates on and the database's startup configurations.

The `secure_file_priv` global variable, if unset, defaults to `/var/lib/mysql-files/`, limiting file access to this directory unless set to an empty string (`""`). This adjustment necessitates modifications in the database's configuration file or startup parameters.

Given `secure_file_priv` is disabled (`""`), and assuming the necessary file and `file_priv` permissions are granted, files outside the designated directory can be read. Yet, the capability for these functions to make network calls is highly dependent on the operating system. On Windows systems, network calls to UNC paths are feasible due to the operating system's understanding of UNC naming conventions, potentially leading to the exfiltration of NTLMv2 hashes.

This SSRF method is limited to TCP port 445 and does not permit port number modification, though it can be used to access shares with full read privileges and, as demonstrated in prior research, to steal hashes for further exploitation.

### Remote Code Execution (RCE) via User Defined Functions (UDF)

MySQL databases offer the use of User Defined Functions (UDF) from external library files. If these libraries are accessible within specific directories or the system's `$PATH`, they can be invoked from within MySQL.

This technique allows for the execution of network/HTTP requests through a UDF, provided several conditions are met, including write access to the `@@plugin_dir`, `file_priv` set to `Y`, and `secure_file_priv` disabled.

For instance, the `lib_mysqludf_sys` library or other UDF libraries enabling HTTP requests can be loaded to perform SSRF. The libraries must be transferred to the server, which can be achieved through hex or base64 encoding of the library's contents and then writing it to the appropriate directory.

The process varies if the `@@plugin_dir` is not writable, especially for MySQL versions above `v5.0.67`. In such cases, alternative paths that are writable must be used.

Automation of these processes can be facilitated by tools such as SQLMap, which supports UDF injection, and for blind SQL injections, output redirection or DNS request smuggling techniques may be utilized.

{{#include ../../../banners/hacktricks-training.md}}



