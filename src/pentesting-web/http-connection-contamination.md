# HTTP Connection Contamination

{{#include ../banners/hacktricks-training.md}}

This page summarizes James Kettle's research on HTTP connection contamination.<sup>[[1]](#references)</sup>

Web browsers can reuse one HTTP/2 connection for different origins through **connection coalescing** when the origins resolve compatibly and the TLS certificate is valid for them. This conflicts with **first-request routing** in a reverse proxy, where the proxy selects a back end from the first request on a connection and then sends later requests on that connection to the same back end.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

For example, suppose `wordpress.example.com` and `secure.example.com` share a reverse proxy, IP address, and a wildcard certificate such as `*.example.com`. If the browser coalesces their requests while the proxy pins the connection to the first host, a request intended for `secure.example.com` may reach the WordPress back end. A vulnerability there—such as reflected XSS—could then affect the security context of the other origin.<sup>[[1]](#references)</sup>

To observe connection coalescing, use the browser's network tools or a packet analyzer such as Wireshark. The following snippet issues sequential cross-origin requests for a controlled test:<sup>[[1]](#references)</sup>

```javascript
fetch("//sub1.hackxor.net/", { mode: "no-cors", credentials: "include" }).then(
  () => {
    fetch("//sub2.hackxor.net/", { mode: "no-cors", credentials: "include" })
  }
)
```

The research also explains why HTTP/3 can widen the affected configurations: its connection-reuse design removes the HTTP/2 requirement that both origins resolve to the same IP address. Besides exposing more first-request-routing deployments, this means that a compromised server holding a wildcard certificate could potentially attack sibling origins without an active man-in-the-middle position.<sup>[[1]](#references)</sup>

This issue requires the relevant conditions to coincide—cross-origin connection reuse, first-request routing, and an exploitable behavior on the wrongly selected back end. A shared IP address or wildcard certificate alone is not sufficient.<sup>[[1]](#references)</sup>

At the time of the original research, first-request routing was relatively uncommon and HTTP/2 exploitation was complex, which limited the observed prevalence. HTTP/3's broader connection-reuse rules are why the same design mistake warrants continued testing.<sup>[[1]](#references)</sup>

Avoid first-request routing; select and validate the upstream independently for every request. Treat broad wildcard certificates and shared front ends as factors that increase impact, and test HTTP/2 and HTTP/3 paths separately.<sup>[[1]](#references)</sup>

## References

- [1] [HTTP/3 connection contamination: an upcoming threat? (James Kettle)](https://portswigger.net/research/http-3-connection-contamination)
- [2] [HTTP/2 connection coalescing (Daniel Stenberg)](https://daniel.haxx.se/blog/2016/08/18/http2-connection-coalescing/)

{{#include ../banners/hacktricks-training.md}}
