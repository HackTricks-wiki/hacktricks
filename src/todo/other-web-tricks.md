# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

## Host header

Back ends sometimes trust the HTTP `Host` field when constructing absolute links. If a password-reset email uses an attacker-supplied host, requesting a reset for a victim can send a token-bearing link through an attacker-controlled domain. Also test forwarded-host fields, duplicate Host handling, and absolute-form request targets at each proxy hop.<sup>[[1]](#references)</sup>

> [!WARNING]
> A user click may not be necessary: **mail security scanners, preview services, or other intermediaries can automatically request the attacker-controlled link**, disclosing the reset token.

## Session booleans

Some applications record a completed verification as a boolean in the session, then let a different endpoint rely on that flag. After legitimately passing the check for one resource, test whether the same flag incorrectly authorizes a different user, object, or workflow. This is a second-order authorization/state-reuse flaw, not merely an IDOR.<sup>[[2]](#references)</sup>

## Registration functionality

Try to register as an already existent user. Try also using equivalent characters (dots, lots of spaces and Unicode).

## Email-change state confusion

Register an email address and change it before confirming. Check whether the confirmation for the new address is sent to the old address, or whether confirming the old token activates the new address. Confirmation tokens must be bound to the exact account, pending address, purpose, and current state.

## Exposed Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

The HTTP `TRACE` method requests a loop-back of the received request for diagnostics. RFC 9110 requires recipients to omit sensitive fields such as credentials and cookies from the reflected content, but unsafe implementations or intermediary-added headers may still disclose internal request transformations. Browsers prevent script-generated TRACE requests, so the historical cross-site tracing attack also depends on a separate way to inject protected fields.<sup>[[3]](#references)</sup>![Image showing a TRACE response](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, section 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)

{{#include ../banners/hacktricks-training.md}}
