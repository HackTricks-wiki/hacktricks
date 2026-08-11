# Cache Poisoning via URL discrepancies

{{#include ../../banners/hacktricks-training.md}}

This is a summary of the techniques proposed in the post [https://portswigger.net/research/gotta-cache-em-all](https://portswigger.net/research/gotta-cache-em-all) in order to perform cache poisoning attacks **abusing discrepancies between cache proxies and web servers.**<sup>[[1]](#references)</sup>

> [!TIP]
> The goal is to make the cache classify a request as cacheable while the origin routes the same URL to a dynamic endpoint. If the cache key preserves a suffix or normalized path that the origin discards, the attacker may store a personalized response, an XSS/redirect response, or a reference to attacker-controlled JavaScript under a reusable key.

## Delimiters

**URL delimiters** vary by framework and server, impacting how requests are routed and responses are handled.<sup>[[1]](#references)</sup> Some common origin delimiters are:

- **Semicolon**: Used in Spring for matrix variables (e.g. `/hello;var=a/world;var1=b;var2=c` → `/hello/world`).
- **Dot**: Can select a response format in Ruby on Rails (e.g. `/MyAccount.css` may route to `/MyAccount` with a CSS format).
- **Null Byte**: Truncates paths in OpenLiteSpeed (e.g. `/MyAccount%00aaa` → `/MyAccount`).
- **Newline Byte**: Separates URL components in Nginx (e.g. `/users/MyAccount%0aaaa` → `/account/MyAccount`).

Other specific delimiters might be found following this process:

- **Step 1**: Identify non-cacheable requests and use them to monitor how URLs with potential delimiters are handled.
- **Step 2**: Append random suffixes to paths and compare the server's response to determine if a character functions as a delimiter.
- **Step 3**: Introduce potential delimiters before the random suffix to see if the response changes, indicating delimiter usage.<sup>[[1]](#references)</sup>

## Normalization & Encodings

- **Purpose**: URL parsers in both cache and origin servers normalize URLs to extract paths for endpoint mapping and cache keys.
- **Process**: Identifies path delimiters, extracts and normalizes the path by decoding characters and removing dot-segments.

### **Encodings**

Different HTTP servers and proxies like Nginx, Node, and CloudFront decode delimiters differently, leading to inconsistencies across CDNs and origin servers that could be exploited. For example, if the web server perform this transformation `/myAccount%3Fparam` → `/myAccount?param` but the cache server keeps as key the path `/myAccount%3Fparam`, there is an inconsistency.<sup>[[1]](#references)</sup>

A way to check for these inconsistencies is to send requests URL encoding different chars after loading the path without any encoding and check if the encoded path response came from the cached response.<sup>[[1]](#references)</sup>

### Dot segment

Dot-segment normalization is another source of discrepancies. For `/static/../home/index` or `/aaa..\home/index`, one component may key the literal path while another resolves dot segments or backslashes. Compare a cache-busted baseline with the normalized and non-normalized variants, and use only non-sensitive test accounts because a successful cache-deception probe may publish a response.<sup>[[1]](#references)</sup>

## Static Resources

Many caches apply default or configured rules that make apparently static resources cacheable.<sup>[[1]](#references)</sup> Common classifiers include:

- **The extension**: By default, Cloudflare considers a documented list of extensions cacheable and does not cache HTML or JSON merely because of MIME type. Actual storage still depends on method, response code, cache-control, size, plan, and cache rules; “cacheable by extension” does not mean a response is always cached.<sup>[[2]](#references)</sup> The current default list includes: 7z, csv, gif, midi, png, tif, zip, avi, doc, gz, mkv, ppt, tiff, zst, avif, docx, ico, mp3, pptx, ttf, apk, dmg, iso, mp4, ps, webm, bin, ejs, jar, ogg, rar, webp, bmp, eot, jpg, otf, svg, woff, bz2, eps, jpeg, pdf, svgz, woff2, class, exe, js, pict, swf, xls, css, flac, mid, pls, tar, and xlsx.
  - A delimiter plus a static extension may store a dynamic response: the cache keys `/home$image.png`, while the origin treats `$image.png` as a delimiter/suffix and routes to `/home`.
- **Well-known static directories**: Custom cache rules often classify paths such as `/static`, `/assets`, `/wp-content`, `/media`, `/templates`, `/public`, or `/shared` as static. These are conventions, not universal cache behavior.
  - A delimiter, static directory, and encoded traversal can produce the same mismatch; for example, one component may key `/home/..%2fstatic/something` as `/static/something` while the origin responds with `/home`.
  - **Static dirs + dots**: A request to `/static/..%2Fhome` or to `/static/..%5Chome` might be cached as is but the response might be `/home`
- **Static files:** Cache rules may special-case files such as `/robots.txt`, `/favicon.ico`, or `/index.html`. A path such as `/home/..%2Frobots.txt` may therefore be keyed as `/robots.txt` while the origin responds with `/home`.<sup>[[1]](#references)</sup>

## References

- [1] [Gotta cache 'em all: bending the rules of web cache exploitation](https://portswigger.net/research/gotta-cache-em-all)
- [2] [Cloudflare — Default cache behavior and cached extensions](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/)

{{#include ../../banners/hacktricks-training.md}}
