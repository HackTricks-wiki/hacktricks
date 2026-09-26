# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

Burp Intruder includes the following built-in payload generators and transformations:<sup>[[1]](#references)</sup>

- **Simple list:** Use a configured list of strings as payloads.
- **Runtime file:** Read one payload per line at runtime. This is useful for large lists because Burp does not load the entire file into memory.
- **Case modification:** Generate the unmodified value, lowercase and uppercase forms, `Propername` (first letter uppercase and the rest lowercase), or `ProperName` (first letter uppercase with the remaining characters unchanged). Burp discards duplicate results.
- **Numbers:** Generate sequential or random numbers within a configured range.
- **Brute forcer:** Generate every permutation for a chosen character set and minimum/maximum length.

## Extensions and companion tools

- **Collabfiltrator** generates payloads that execute commands and exfiltrate their output through DNS queries to Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exports Burp findings for use in other reporting workflows.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** converts HTTP requests into scripts in several languages.<sup>[[4]](#references)</sup>

## Multi-session authorization testing with Session Switcher

[Session Switcher](https://github.com/doyensec/burp-session-switcher) is a Java extension for Burp Suite `2025.5+` that stores cookies and uncommon headers as named credential profiles. Selecting a profile in an editable request editor, including Repeater or an intercepted Proxy request, replaces the request's authentication material. This is a replay aid, **not an authorization bypass**: use it to send the same request as different accounts when checking horizontal access, vertical role boundaries, tenant isolation, and [IDOR/BOLA](../pentesting-web/idor.md) as part of the [web testing methodology](../pentesting-web/web-vulnerabilities-methodology.md).<sup>[[5]](#references)[[8]](#references)</sup>

### Repeatable identity-differential workflow

The following workflow keeps the resource/action and the acting identity as separate test variables, reducing false results caused by stale tokens or the wrong browser session.<sup>[[5]](#references)[[8]](#references)</sup>

1. Authenticate test accounts representing each relevant user, role, and tenant in separate browser profiles or containers.
2. Open a request carrying one identity's cookies and headers, select **Sessions > New**, and give the profile an unambiguous name such as `tenant-a-user` or `tenant-b-admin`. Repeat for every test identity.
3. Send a candidate request to Repeater and replay it without changing its method, endpoint, parameters, or object identifier while switching only the selected session. Compare response data and observable state changes, not only status codes.
4. For object-level checks, replay a request for an object known to belong to account A while selecting account B's profile. For function-level checks, replay the same privileged action with lower-privileged profiles.
5. After reauthentication or token rotation, use **Update** on a current browser request or configure an Auto Update rule before repeating the comparison.

### Capture and injection semantics

Review the update/injection modes before testing because a hybrid request containing credentials from two identities can invalidate the comparison. Current defaults mirror all request cookies into a profile, update only already-stored uncommon headers, mirror the selected profile's cookies into the destination request (removing its existing cookies), and add the profile's headers. The selector can be limited to an exact subdomain, the top-level application domain (default), or all saved profiles.<sup>[[7]](#references)</sup>

- **Mirror** is useful when the complete cookie set defines an identity and stale destination cookies must be removed.
- **Update existing** follows rotating values without learning unrelated cookies or headers from browser traffic.
- **Add all** preserves extra values already stored in the profile or request; verify that this does not leave identity-bearing data from the previous session.
- **Do nothing** excludes either cookies or headers from profile updates when that credential class is irrelevant.

### Proxy-based session synchronization

Auto Update rules associate Proxy traffic with a saved profile and refresh its cookies/headers. Prefer a stable discriminator such as a dedicated request header, a profile-specific `User-Agent` marker, an identifying cookie, `X-PwnFox-Color`, or a JWT claim; combine it with scope/domain/path conditions so unrelated applications cannot update the profile. All conditions in one rule are evaluated as logical `AND` in order, so put restrictive checks first; implement `OR` by creating multiple rules targeting the same profile. Negative matching is also supported.<sup>[[6]](#references)</sup>

For each matching rule, choose **Mirror request**, **Add all**, **Update existing**, or **Do nothing** independently for cookies and headers. Request-only rules run when Proxy receives the request; adding a response-status, response-header, or response-body condition postpones evaluation until the response arrives. A highlight color can mark matching traffic, which helps verify that each browser identity updates only its intended profile.<sup>[[6]](#references)</sup>

Saved profiles live in the Burp project, and JSON project-data exports include the sessions and therefore their cookies and headers. Treat both files as live credential material, restrict access to them, and delete the stored extension data after the engagement.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Session Switcher source and usage documentation](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Session Switcher Auto Update Rules](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Session Switcher settings](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: Simplifying Multi-Session Authorization Testing in Burp Suite](https://blog.doyensec.com/2026/06/17/session-switcher.html)

{{#include ../banners/hacktricks-training.md}}
