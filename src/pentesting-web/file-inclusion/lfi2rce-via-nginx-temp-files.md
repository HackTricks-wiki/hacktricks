# LFI2RCE via Nginx temp files

{{#include ../../banners/hacktricks-training.md}}

## Vulnerable configuration

[Example from bierbaumer.net](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/) showed that even the following one-liner is enough when PHP runs behind an nginx reverse proxy that buffers request bodies to disk:

```php
<?php
$action = $_GET['action'] ?? 'read';
$path   = $_GET['file'] ?? 'index.php';
$action === 'read' ? readfile($path) : include $path;
```

The nginx side typically keeps default temp paths such as `/var/lib/nginx/body` and `/var/lib/nginx/fastcgi`. When a request body or upstream response is larger than the in-memory buffer (≈8 KB by default), nginx transparently writes the data to a temp file, keeps the file descriptor open, and only unlinks the file name. Any PHP `include` that follows symbolic links (like `/proc/<pid>/fd/<fd>`) can still execute the unlinked contents, giving you RCE through LFI.

## Why nginx temp files are abusable

* Request bodies that exceed the buffer threshold are flushed to `client_body_temp_path` (defaults to `/tmp/nginx/client-body` or `/var/lib/nginx/body`).
* The file name is random, but the file descriptor remains reachable under `/proc/<nginx_pid>/fd/<fd>`. As long as the request body has not completed (or you keep the TCP stream hanging), nginx keeps the descriptor open even though the path entry is unlinked.
* PHP’s include/require resolves those `/proc/.../fd/...` symlinks, so an attacker with LFI can hop through procfs to execute the buffered temp file even after nginx deletes it.

## Classic exploitation workflow (recap)

1. **Enumerate worker PIDs.** Fetch `/proc/<pid>/cmdline` over the LFI until you find strings like `nginx: worker process`. The number of workers rarely exceeds the CPU count, so you only have to scan the lower PID space.
2. **Force nginx to create the temp file.** Send very large POST/PUT bodies (or proxied responses) so that nginx spills to `/var/lib/nginx/body/XXXXXXXX`. Make sure the backend never reads the entire body—e.g., keep-alive the upload thread so nginx keeps the descriptor open.
3. **Map descriptors to files.** With the PID list, generate traversal chains such as `/proc/<pidA>/cwd/proc/<pidB>/root/proc/<pidC>/fd/<fd>` to bypass any `realpath()` normalization before PHP resolves the final `/proc/<victim_pid>/fd/<interesting_fd>` target. Brute-forcing file descriptors 10–45 is usually enough because nginx reuses that range for body temp files.
4. **Include for execution.** When you hit the descriptor that still points to the buffered body, a single `include` or `require` call runs your payload—even though the original filename has already been unlinked. If you only need file read, switch to `readfile()` to exfiltrate the temporary contents instead of executing them.

## Modern variations (2024–2025)

Ingress controllers and service meshes now routinely expose nginx instances with additional attack surface. CVE-2025-1974 ("IngressNightmare") is a good example of how the classic temp-file trick evolves:

* Attackers push a malicious shared object as a request body. Because the body is >8 KB, nginx buffers it to `/tmp/nginx/client-body/cfg-<random>`. By intentionally lying in the `Content-Length` header (e.g., claiming 1 MB and never sending the last chunk) the temp file remains pinned for ~60 seconds.
* The vulnerable ingress-nginx template code allowed injecting directives into the generated nginx config. Combining that with the lingering temp file made it possible to brute-force `/proc/<pid>/fd/<fd>` links until the attacker discovered the buffered shared object.
* Injecting `ssl_engine /proc/<pid>/fd/<fd>;` forced nginx to load the buffered `.so`. Constructors inside the shared object yielded immediate RCE inside the ingress controller pod, which in turn exposed Kubernetes secrets.

A trimmed-down reconnaissance snippet for this style of attack looks like:

<details>
<summary>Quick procfs scanner</summary>

```python
#!/usr/bin/env python3
import os

def find_tempfds(pid_range=range(100, 4000), fd_range=range(10, 80)):
    for pid in pid_range:
        fd_dir = f"/proc/{pid}/fd"
        if not os.path.isdir(fd_dir):
            continue
        for fd in fd_range:
            try:
                path = os.readlink(f"{fd_dir}/{fd}")
                if "client-body" in path or "nginx" in path:
                    yield pid, fd, path
            except OSError:
                continue

for pid, fd, path in find_tempfds():
    print(f"use ?file=/proc/{pid}/fd/{fd}  # {path}")
```

</details>

Run it from any primitive (command injection, template injection, etc.) you already have. Feed the discovered `/proc/<pid>/fd/<fd>` paths back into your LFI parameter to include the buffered payload.

## Practical tips

* When nginx disables buffering (`proxy_request_buffering off`, `client_body_buffer_size` tuned high, or `proxy_max_temp_file_size 0`), the technique becomes much harder—so always enumerate config files and response headers to check whether buffering is still enabled.
* Hanging uploads are noisy but effective. Use multiple processes to flood workers so that at least one temp file stays around long enough for your LFI brute force to catch it.
* In Kubernetes or other orchestrators, privilege boundaries may look different, but the primitive is the same: find a way to drop bytes into nginx buffers, then walk `/proc` from anywhere you can issue file system reads.

## Labs

- [https://bierbaumer.net/security/php-lfi-with-nginx-assistance/php-lfi-with-nginx-assistance.tar.xz](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/php-lfi-with-nginx-assistance.tar.xz)
- [https://2021.ctf.link/internal/challenge/ed0208cd-f91a-4260-912f-97733e8990fd/](https://2021.ctf.link/internal/challenge/ed0208cd-f91a-4260-912f-97733e8990fd/)
- [https://2021.ctf.link/internal/challenge/a67e2921-e09a-4bfa-8e7e-11c51ac5ee32/](https://2021.ctf.link/internal/challenge/a67e2921-e09a-4bfa-8e7e-11c51ac5ee32/)

## References

- [https://bierbaumer.net/security/php-lfi-with-nginx-assistance/](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)
- [https://www.opswat.com/blog/ingressnightmare-cve-2025-1974-remote-code-execution-vulnerability-remediation](https://www.opswat.com/blog/ingressnightmare-cve-2025-1974-remote-code-execution-vulnerability-remediation)

{{#include ../../banners/hacktricks-training.md}}
