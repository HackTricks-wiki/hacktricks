# LFI to RCE via Temporary File Uploads

{{#include ../../banners/hacktricks-training.md}}

**Check the full details of this technique in [https://gynvael.coldwind.pl/download.php?f=PHP_LFI_rfc1867_temporary_files.pdf](https://gynvael.coldwind.pl/download.php?f=PHP_LFI_rfc1867_temporary_files.pdf)**<sup>[[1]](#references)</sup>

## **PHP File uploads**

When PHP receives a `multipart/form-data` POST containing a file upload, it stores the body in a temporary file. Application code can persist it with `move_uploaded_file()`; otherwise PHP removes it at the end of the request. The exploit races an LFI against that cleanup.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **Security Alert: Attackers, aware of the temporary files' location, might exploit a Local File Inclusion vulnerability to execute code by accessing the file during upload.**

The challenge for unauthorized access lies in predicting the temporary file's name, which is intentionally randomized.

### Exploitation on Windows Systems

In the historical Windows implementation described by the research, PHP used `GetTempFileName`, producing a name shaped like `<path>\<pre><uuuu>.TMP`. Notably:

- The default path is typically `C:\Windows\Temp`.
- The prefix is usually "php".
- The `<uuuu>` represents a unique hexadecimal value. Crucially, due to the function's limitation, only the lower 16 bits are used, allowing for a maximum of 65,535 unique names with constant path and prefix, making brute force feasible.

Moreover, the exploitation process is simplified on Windows systems. A peculiarity in the `FindFirstFile` function permits the use of wildcards in Local File Inclusion (LFI) paths. This enables crafting an include path like the following to locate the temporary file:

```
http://site/vuln.php?inc=c:\windows\temp\php<<
```

In certain situations, a more specific mask (like `php1<<` or `phpA<<`) might be required. One can systematically try these masks to discover the uploaded temporary file.

### Exploitation on GNU/Linux Systems

On GNU/Linux, temporary names have substantially more entropy, so direct name brute force is generally impractical; other disclosure or race primitives may still expose the pathname.<sup>[[1]](#references)</sup>

## References

- [1] [PHP LFI rfc1867 file upload temporary files (gynvael.coldwind.pl)](https://gynvael.coldwind.pl/download.php?f=PHP_LFI_rfc1867_temporary_files.pdf)
- [2] [PHP manual — POST method uploads](https://www.php.net/manual/en/features.file-upload.post-method.php)

{{#include ../../banners/hacktricks-training.md}}
