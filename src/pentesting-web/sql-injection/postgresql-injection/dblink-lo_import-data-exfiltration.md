# PostgreSQL `dblink` and `lo_import` Data Exfiltration

{{#include ../../../banners/hacktricks-training.md}}

In the documented challenge, PostgreSQL's `lo_import` function loads a server-side file as a large object and returns its object identifier (OID). When direct access to the imported object's contents is unavailable, the OID is embedded in a `dblink_connect` connection string and sent to an attacker-controlled PostgreSQL endpoint as an out-of-band exfiltration channel. This technique requires the relevant function privileges, the `dblink` extension, and outbound network access from the database server.<sup>[[1]](#references)</sup>

The complete challenge solution also explains how to validate each prerequisite and capture the resulting connection.<sup>[[1]](#references)</sup>

## References

- [1] [PDKT-Team - FBCTF 2019 hr_admin_module writeup](https://github.com/PDKT-Team/ctf/blob/master/fbctf2019/hr-admin-module/README.md)

{{#include ../../../banners/hacktricks-training.md}}
