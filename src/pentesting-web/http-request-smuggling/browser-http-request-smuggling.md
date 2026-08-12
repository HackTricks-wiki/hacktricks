# Browser HTTP Request Smuggling

{{#include ../../banners/hacktricks-training.md}}

Browser-powered desynchronization, also called client-side request smuggling, uses a victim's browser to place a misframed request on a persistent connection. A subsequent request can then be interpreted out of sync by the server. Unlike classic front-end/back-end (FE/BE) request smuggling, the payload is constrained to syntax a browser can send.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Testing considerations

- Use only headers and syntax that a browser can emit through navigation, Fetch, or form submission. Traditional header obfuscations such as unusual linear whitespace (LWS), duplicate `Transfer-Encoding` (`TE`) fields, or an invalid `Content-Length` (`CL`) generally cannot be emitted by browser JavaScript.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>
- Look for endpoints and intermediaries that reflect input, cache responses, or reuse connections. Potential impact includes cache poisoning, disclosure of front-end-injected headers, and bypasses of front-end path or method controls.
- Connection reuse is essential: the crafted request must share the same HTTP/1.1 or HTTP/2 connection with a later request for the desynchronization to affect it. Connection-locked or otherwise stateful server behavior can increase the impact.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>
- Prefer primitives that do not require custom headers, such as path confusion, query-string injection, and body shaping through form-encoded POST requests.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>
- Distinguish a real server-side desynchronization from HTTP pipelining artifacts. Repeat the test without connection reuse and, where applicable, use the HTTP/2 nested-response technique.<sup>[[3]](#references)</sup>

## References

- [1] [PortSwigger Research - Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [2] [PortSwigger Web Security Academy - Client-side desync](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync)
- [3] [PortSwigger Research - How to distinguish HTTP pipelining from request smuggling](https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling)

{{#include ../../banners/hacktricks-training.md}}
