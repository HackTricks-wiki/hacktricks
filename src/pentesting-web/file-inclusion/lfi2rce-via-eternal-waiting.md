# LFI2RCE via Eternal waiting

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

PHP stores accepted uploads in a temporary directory until the request ends, unless the application moves or renames them. If `upload_tmp_dir` is unset, PHP falls back to the system temporary directory, which is commonly `/tmp` on Unix-like targets; confirm the effective configuration instead of assuming that path. The exact directory and generated filename format depend on the platform and PHP configuration; names such as `php[a-zA-Z0-9]{6}` are common observations, not a guaranteed contract.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup> Some container images have also been observed generating names without digits, so derive the actual alphabet from the target environment before estimating the brute-force space.

In a local file inclusion, **if you manage to include that uploaded file, you will get RCE**.

By default, PHP accepts at most 20 uploaded files in one request through the configurable `max_file_uploads` directive.<sup>[[3]](#references)</sup>

```
; Maximum number of files that can be uploaded via a single request
max_file_uploads = 20
```

Also, the **number of potential filenames are 62\*62\*62\*62\*62\*62 = 56800235584**

### Other techniques

Other techniques relies in attacking PHP protocols (you won't be able if you only control the last part of the path), disclosing the path of the file, abusing expected files, or **making PHP suffer a segmentation fault so uploaded temporary files aren't deleted**.\
This technique is **very similar to the last one but without needed to find a zero day**.

### Eternal wait technique

In this technique **we only need to control a relative path**. If we manage to upload files and make the **LFI never end**, we will have "enough time" to **brute-force uploaded files** and **find** any of the ones uploaded.

**Pros of this technique**:

- You just need to control a relative path inside an include
- Doesn't require nginx or unexpected level of access to log files
- Doesn't require a 0 day to cause a segmentation fault
- Doesn't require a path disclosure

The **main problems** of this technique are:

- Need a specific file(s) to be present (there might be more)
- The **insane** amount of potential file names: **56800235584**
  - If the server **isn't using digits** the total potential amount is: **19770609664**
- By default **only 20 files** can be uploaded in a **single request**.
- The **max number of parallel workers** of the used server.
  - This limit with the previous ones can make this attack last too much
- **Timeout for a PHP request**. Ideally this should be eternal or should kill the PHP process without deleting the temp uploaded files, if not, this will also be a pain

So, how can you **make a PHP include never end**? Just by including the file **`/sys/kernel/security/apparmor/revision`** (**not available in Docker containers** unfortunately...).

Try it just calling:

```bash
php -a # open php cli
include("/sys/kernel/security/apparmor/revision");
```

## Apache2

Apache's simultaneous-request limit is not universally 150; it depends on the active MPM and `MaxRequestWorkers`. Measure the target or use its actual configuration before applying the calculations below.<sup>[[4]](#references)</sup> The previously quoted values of 150 concurrent workers and a hypothetical tuned 8,000-worker configuration are useful only as historical calculation examples, not defaults that can be assumed on a target. The linked deployment guide shows one Apache event-MPM and PHP-FPM configuration.<sup>[[1]](#references)</sup>

By default, (as I can see in my tests), a **PHP process can last eternally**.

Let's do some maths:

- We can use **149 connections** to generate **149 \* 20 = 2980 temp files** with our webshell.
- Then, use the **last connection** to **brute-force** potential files.
- At a speed of **10 requests/s** the times are:
  - 56800235584 / 2980 / 10 / 3600 \~= **530 hours** (50% chance in 265h)
  - (without digits) 19770609664 / 2980 / 10 / 3600 \~= 185h (50% chance in 93h)

> [!WARNING]
> Note that in the previous example we are **completely DoSing other clients**!

If the Apache server is improved and we could abuse **4000 connections** (half way to the max number). We could create `3999*20 = 79980` **files** and the **number** would be **reduced** to around **19.7h** or **6.9h** (10h, 3.5h 50% chance).

## PHP-FPM

When the site uses **PHP-FPM** instead of an in-process Apache PHP module, the pool's request timeout may affect the technique.

PHP-FPM configures **`request_terminate_timeout`** in the pool configuration, commonly under **`/etc/php/<php-version>/fpm/pool.d/www.conf`**. A value of `0` disables the timeout by default; configured values use seconds unless another unit is supplied.<sup>[[5]](#references)</sup> When a worker is forcibly killed, temporary-file cleanup behavior should be confirmed against the target PHP/FPM version rather than assumed.

On deployments where forced worker termination bypasses normal end-of-request cleanup, the uploaded temporary files remain on disk. Once that behavior is confirmed in the lab or target version, repeatedly timing out upload requests can create thousands of candidate files, substantially increasing the probability of finding one through the LFI while using fewer long-lived connections. This orphaned-file condition is the acceleration mechanism; without it, ordinary request cleanup removes the temporary uploads.

To **reduce the DoS impact**, suppose the attacker uses only **100 concurrent connections** and PHP-FPM's **`request_terminate_timeout`** is **30 seconds**. With the 20-file-per-request example above, the estimated temporary-file generation rate is `100*20/30 = 66.67` files per second.

Then, to generate **10000 files** an attacker would need: **`10000/66.67 = 150s`** (to generate **100000 files** the time would be **25min**).

Then, the attacker could use those **100 connections** to perform a **search brute-force**.  Supposing a speed of 300 req/s the time needed to exploit this is the following:

- 56800235584 / 10000 / 300 / 3600 \~= **5.25 hours** (50% chance in 2.63h)
- (with 100000 files) 56800235584 / 100000 / 300 / 3600 \~= **0.525 hours** (50% chance in 0.263h)

Yes, it's possible to generate 100000 temporary files in an EC2 medium size instance:

<figure><img src="../../images/image (240).png" alt=""><figcaption></figcaption></figure>

> [!WARNING]
> Note that in order to trigger the timeout it would be **enough to include the vulnerable LFI page**, so it enters in an eternal include loop.

## Nginx

It looks like by default Nginx supports **512 parallel connections** at the same time (and this number can be improved).

## References

- [1] [How To Configure Apache HTTP with mpm_event and PHP-FPM on Ubuntu 18.04](https://www.digitalocean.com/community/tutorials/how-to-configure-apache-http-with-mpm-event-and-php-fpm-on-ubuntu-18-04)
- [2] [PHP manual – POST method uploads](https://www.php.net/manual/en/features.file-upload.post-method.php)
- [3] [PHP manual – Core `php.ini` directives](https://www.php.net/manual/en/ini.core.php)
- [4] [Apache HTTP Server – MPM common directives](https://httpd.apache.org/docs/current/en/mod/mpm_common.html)
- [5] [PHP manual – FPM configuration](https://www.php.net/manual/en/install.fpm.configuration.php)

{{#include ../../banners/hacktricks-training.md}}
