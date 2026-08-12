# Phone Number Injections

{{#include ../banners/hacktricks-training.md}}

Applications often treat a phone number as a simple string even though a `tel` URI may contain semicolon-delimited parameters such as `ext`, `isub`, and `phone-context`.<sup>[[1]](#references)</sup> If an application accepts these suffixes but different components validate, store, render, or forward them inconsistently, the suffix may reach an injection sink or bypass controls based on exact string comparison. Test for XSS, SQL injection, SSRF, parser discrepancies, and downstream telephony issues only where the application's data flow makes the corresponding sink plausible.<sup>[[2]](#references)</sup>

<figure><img src="../images/image (461).png" alt="Structure of a telephone URI with a global or local number and optional parameters"><figcaption>Telephone URI structure and common optional parameters.</figcaption></figure>

<figure><img src="../images/image (941).png" alt="Examples of malicious phone-number parameters targeting XSS, SSRF, OTP rate limits, and telephony parsers"><figcaption>Potential issues caused by inconsistent handling of phone-number parameters.</figcaption></figure>

## OTP Rate-Limit Bypass

If a rate limiter keys attempts by the exact submitted string but the delivery provider normalizes multiple parameterized values to the same destination, an attacker may rotate suffixes to obtain separate attempt counters for one account. The figure illustrates the concept with changing `ext` values; successful exploitation depends on the application's and provider's normalization behavior.<sup>[[2]](#references)</sup>

<figure><img src="../images/image (116).png" alt="OTP spraying example that rotates telephone URI extension values to obtain separate rate-limit counters"><figcaption>Conceptual OTP spraying through inconsistent phone-number normalization.</figcaption></figure>

## References

- [1] [RFC 3966 - The `tel` URI for Telephone Numbers](https://www.rfc-editor.org/rfc/rfc3966.html)
- [2] [NahamCon EU 2022 - RTFR (Read The Bleeping RFC), securinti](https://www.youtube.com/watch?v=4ZsTKvfP1g0)

{{#include ../banners/hacktricks-training.md}}
