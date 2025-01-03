# Sniff Leak

{{#include ../../banners/hacktricks-training.md}}

## Leak script content by converting it to UTF16

[**This writeup**](https://blog.huli.tw/2022/08/01/en/uiuctf-2022-writeup/#modernism21-solves) leaks a text/plain because there is no `X-Content-Type-Options: nosniff` header by adding some initial characters that will make javascript think that the content is in UTF-16 so th script doesn't breaks.

## Leak script content by treating it as an ICO

[**The next writeup**](https://blog.huli.tw/2022/08/01/en/uiuctf-2022-writeup/#precisionism3-solves) leaks the script content by loading it as if it was an ICO image accessing the `width` parameter.

{{#include ../../banners/hacktricks-training.md}}



