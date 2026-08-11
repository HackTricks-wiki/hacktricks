# Same-Site Leaks (SS-Leaks)

{{#include ../../banners/hacktricks-training.md}}

Same-site leaks (SS-Leaks) adapt cross-site leak techniques to HTML injection on the target site. The linked research uses nested `<object>` fallbacks, lazy loading, and responsive images to convert differences such as HTTP `200` versus `404` responses into requests to an attacker-controlled endpoint, even when `SameSite=Lax` cookies and a restrictive Content Security Policy prevent simpler XS-Leak techniques.<sup>[[1]](#references)</sup>

## References

- [1] [Zeyu Zhang - From XS-Leaks to SS-Leaks](https://infosec.zeyu2001.com/2023/from-xs-leaks-to-ss-leaks)

{{#include ../../banners/hacktricks-training.md}}
