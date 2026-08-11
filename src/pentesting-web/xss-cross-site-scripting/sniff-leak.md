# Sniff Leak

{{#include ../../banners/hacktricks-training.md}}

## Leak Script Content by Interpreting It as UTF-16

If a `text/plain` response lacks the `X-Content-Type-Options: nosniff` header, a browser may accept it as a script. In the cited challenge, an attacker-controlled prefix supplies a UTF-16 byte-order mark and valid JavaScript bytes. The remaining secret is then decoded as valid identifier characters, allowing the script to expose it through a property of `window`.<sup>[[1]](#references)</sup>

## Leak Content by Treating It as an ICO Image

In a related challenge, a crafted prefix makes the response parse as an ICO image and positions one secret byte in the image-width field. Loading successive variants as cross-origin images and reading their `width` reveals the secret one byte at a time.<sup>[[2]](#references)</sup>

## References

- [1] [UIUCTF 2022 Writeup – "modernism" (UTF-16 content-sniffing leak)](https://blog.huli.tw/2022/08/01/en/uiuctf-2022-writeup/#modernism21-solves)
- [2] [UIUCTF 2022 Writeup – "precisionism" (ICO content-sniffing leak)](https://blog.huli.tw/2022/08/01/en/uiuctf-2022-writeup/#precisionism3-solves)

{{#include ../../banners/hacktricks-training.md}}
