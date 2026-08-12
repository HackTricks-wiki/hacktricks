# LFI2RCE via PHP_SESSION_UPLOAD_PROGRESS

{{#include ../../banners/hacktricks-training.md}}

## Basic Info

With an LFI, PHP's upload-progress feature can create a session file even when the application did not otherwise start a session and `session.auto_start=Off`. This requires `session.upload_progress.enabled=On`, a multipart upload containing the configured progress field (normally `PHP_SESSION_UPLOAD_PROGRESS`), and a controllable session identifier.<sup>[[4]](#references)</sup>

```bash
$ curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange'
$ ls -a /var/lib/php/sessions/
. ..
$ curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange' -d 'PHP_SESSION_UPLOAD_PROGRESS=blahblahblah'
$ ls -a /var/lib/php/sessions/
. ..
$ curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange' -F 'PHP_SESSION_UPLOAD_PROGRESS=blahblahblah'  -F 'file=@/etc/passwd'
$ ls -a /var/lib/php/sessions/
. .. sess_iamorange

In the last example the session will contain the string blahblahblah
```

The progress value becomes part of serialized session data. If the LFI can include that session file while it exists, attacker-controlled PHP code in the value may execute.

> [!TIP]
> PHP defaults `session.upload_progress.cleanup` to `On`, so progress data is removed as soon as the upload is processed. Exploitation is therefore a race unless cleanup has been disabled.<sup>[[4]](#references)</sup>

### The CTF

In the [**original CTF**](https://blog.orange.tw/posts/2018-10-hitcon-ctf-2018-one-line-php-challenge/) where this technique is described, winning the race was not enough: the loaded content also needed to start with the string `@<?php`.<sup>[[1]](#references)</sup>

The default `session.upload_progress.prefix` adds `upload_progress_` before the attacker-controlled key in the serialized session data, producing content such as `upload_progress_controlledcontentbyattacker`.

The trick to **remove the initial prefix** was to **base64encode the payload 3 times** and then decode it via `convert.base64-decode` filters, this is because when **base64 decoding PHP will remove the weird characters**, so after 3 times **only** the **payload** **sent** by the attacker will **remain** (and then the attacker can control the initial part).<sup>[[1]](#references)</sup>

More information is available in the original writeup and the final exploit.<sup>[[1]](#references)[[2]](#references)</sup>\
Another writeup in [https://spyclub.tech/2018/12/21/one-line-and-return-of-one-line-php-writeup/](https://spyclub.tech/2018/12/21/one-line-and-return-of-one-line-php-writeup/)<sup>[[3]](#references)</sup>

## References

- [1] [HITCON CTF 2018 - One Line PHP Challenge (Orange Tsai)](https://blog.orange.tw/posts/2018-10-hitcon-ctf-2018-one-line-php-challenge/)
- [2] [exp_for_php.py - final exploit script (orangetw/My-CTF-Web-Challenges)](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2018/one-line-php-challenge/exp_for_php.py)
- [3] [One Line PHP Challenge and the Return of One Line PHP Challenge writeup](https://spyclub.tech/2018/12/21/one-line-and-return-of-one-line-php-writeup/)
- [4] [PHP manual — Session upload progress](https://www.php.net/manual/en/session.upload-progress.php)

{{#include ../../banners/hacktricks-training.md}}
